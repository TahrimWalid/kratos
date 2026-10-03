"""Which way a target is read (SSH / sub-agent / SSH-then-sub-agent), the
explicit target links behind that choice, and how the result says so
(docs/subagent_read_routing.md §3, §5)."""
from __future__ import annotations

from pathlib import Path

import pytest

from kratos import kratos_config as kc
from kratos.adapters import ssh_remote
from kratos.adapters.ssh_remote import SSHResult
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import routing


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "_active_target_override", "203.0.113.10")
    kc.set_active_data_dir(tmp_path)
    routing.clear_cache()
    routing.clear_ssh_down()
    store = SubAgentStore(tmp_path / "kratos.db")
    code = store.create_pairing_code(name="web-01")["code"]
    target_id = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.3.0")["target_id"]
    calls: dict[str, list] = {"ssh": [], "agent": []}

    def fake_ssh(cmd, timeout=None):
        calls["ssh"].append(cmd)
        return ssh_state["result"]

    def fake_agent(link, probe, params):
        calls["agent"].append((link.target_id, probe, params))
        return agent_state["reply"]

    ssh_state = {"result": SSHResult(ok=True, returncode=0, stdout="USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n", stderr="")}
    agent_state = {"reply": {"status": "ok", "data": {"returncode": 0, "stdout": "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.0 1 1 ? Ss 00:00 0:01 /sbin/init\n", "stderr": ""}}}
    real_agent_read = routing.agent_read
    monkeypatch.setattr(ssh_remote, "run_remote_command", fake_ssh)
    monkeypatch.setattr(routing, "agent_read", fake_agent)
    yield {"store": store, "target_id": target_id, "calls": calls, "ssh": ssh_state, "agent": agent_state,
           "real_agent_read": real_agent_read}
    kc.set_active_data_dir(None)
    routing.clear_cache()
    routing.clear_ssh_down()


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------
def test_link_crud_and_validation(env):
    store, tid = env["store"], env["target_id"]
    assert store.get_link("203.0.113.10") is None
    store.set_link(" 203.0.113.10 ", tid, routing.MODE_SUBAGENT)
    assert store.get_link("203.0.113.10")["mode"] == "subagent"
    link = routing.active_link()
    assert link and link.target_id == tid and link.label == "web-01" and not link.revoked
    store.set_link("203.0.113.10", tid, routing.MODE_SSH_FIRST)
    assert routing.active_link().mode == "ssh_first"
    with pytest.raises(ValueError):
        store.set_link("203.0.113.10", tid, "sometimes")
    with pytest.raises(ValueError):
        store.set_link("203.0.113.10", "tgt_nope", routing.MODE_SUBAGENT)
    assert store.remove_link("203.0.113.10") and routing.active_link() is None


def test_loopback_and_unlinked_targets_never_route(env):
    env["store"].set_link("web.example", env["target_id"], routing.MODE_SUBAGENT)
    assert routing.link_for("127.0.0.1", kc.get_active_data_dir()) is None
    assert routing.link_for("other.example", kc.get_active_data_dir()) is None
    assert routing.link_for("WEB.example", kc.get_active_data_dir()) is not None  # hostnames are case-insensitive


def test_a_repaired_box_keeps_its_links(env):
    store, old = env["store"], env["target_id"]
    store.set_link("203.0.113.10", old, routing.MODE_SUBAGENT)
    code = store.create_pairing_code(name="web-01", replaces_target_id=old)["code"]
    new = store.redeem_pairing_code(code, agent_id="a2", hostname="web-01", agent_version="0.3.0")["target_id"]
    assert store.get_link("203.0.113.10")["target_id"] == new


def test_a_revoked_box_reads_are_refused_with_a_way_out(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    env["store"].revoke_target(env["target_id"])
    routing.clear_cache()
    link = routing.active_link()
    assert link.revoked
    out = env["real_agent_read"](link, "clock", {})
    assert out["status"] == "offline" and "no longer paired" in out["reason"]


# ---------------------------------------------------------------------------
# Transport choice
# ---------------------------------------------------------------------------
def test_unlinked_target_uses_ssh_unchanged(env):
    with routing.collect_notes() as notes:
        rows = ssh_remote.fetch_processes()
    assert env["calls"]["ssh"] == ["ps aux"] and env["calls"]["agent"] == [] and notes == []
    assert rows == []


def test_subagent_only_target_never_tries_ssh(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    with routing.collect_notes() as notes:
        rows = ssh_remote.fetch_processes()
    assert env["calls"]["ssh"] == [] and env["calls"]["agent"] == [(env["target_id"], "processes", {})]
    assert rows[0]["command"] == "/sbin/init"
    assert "through its sub-agent (web-01)" in notes[0]


def test_ssh_first_falls_back_only_on_a_connection_failure(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SSH_FIRST)
    env["ssh"]["result"] = SSHResult(ok=False, returncode=1, stdout="", stderr="ps: broken")
    assert isinstance(ssh_remote.fetch_processes(), SSHResult)          # a command failure is a real answer
    assert env["calls"]["agent"] == []

    env["ssh"]["result"] = SSHResult(ok=False, returncode=255, stdout="",
                                     stderr="ssh: connect to host 203.0.113.10 port 22: Connection timed out\n")
    with routing.collect_notes() as notes:
        rows = ssh_remote.fetch_processes()
    assert rows[0]["command"] == "/sbin/init" and len(env["calls"]["agent"]) == 1
    assert "SSH to 203.0.113.10 failed (ssh: connect to host" in notes[0] and "its sub-agent (web-01)" in notes[0]

    ssh_calls = len(env["calls"]["ssh"])
    ssh_remote.fetch_processes()  # remembered: no second SSH timeout in the same investigation
    assert len(env["calls"]["ssh"]) == ssh_calls and len(env["calls"]["agent"]) == 2


def test_fallback_failure_names_both_paths(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SSH_FIRST)
    env["ssh"]["result"] = SSHResult(ok=False, returncode=255, stdout="", stderr="Permission denied (publickey).")
    env["agent"]["reply"] = {"status": "offline", "reason": "the sub-agent on web-01 isn't connected"}
    out = ssh_remote.fetch_processes()
    assert isinstance(out, SSHResult) and "SSH failed (Permission denied" in out.stderr and "isn't connected" in out.stderr


def test_free_command_text_never_goes_to_the_agent(env, monkeypatch):
    monkeypatch.undo()  # the real run_remote_command
    kc.set_active_data_dir(env["store"].db_path.parent)
    monkeypatch.setattr(kc, "_active_target_override", "203.0.113.10")
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    routing.clear_cache()

    def no_process(*a, **k):
        raise AssertionError("must not run ssh")

    monkeypatch.setattr("subprocess.run", no_process)
    for res in (ssh_remote.run_remote_command("cat /etc/shadow"), ssh_remote.run_remote_script("id")):
        assert not res.ok and "not available over the sub-agent" in res.stderr


def test_journal_window_truncation_from_the_agent_cap_is_kept(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    env["agent"]["reply"] = {"status": "ok", "data": {"returncode": 0, "truncated": True, "stderr": "",
                                                      "stdout": '{"__REALTIME_TIMESTAMP":"1790000000000000","MESSAGE":"m"}\n'}}
    entries, window = ssh_remote.fetch_journalctl_entries("sshd", 1789990000, 10)
    assert len(entries) == 1 and window.truncated
    assert env["calls"]["agent"][0][1:] == ("journal_fetch", {"unit": "sshd", "since": 1789990000, "until": None, "lines": 10})


def test_agent_unreadable_marker_and_integrity_unverifiable(env):
    from kratos.adapters.baseline import diff_file_integrity

    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    env["agent"]["reply"] = {"status": "ok", "data": {"returncode": 0, "stderr": "",
                                                      "stdout": "PRESENT\t/etc/sudoers\tabc\nUNREADABLE\t/etc/crontab\n"}}
    current = ssh_remote.fetch_file_hashes()
    assert current == {"/etc/sudoers": "abc", "/etc/crontab": ssh_remote.AGENT_UNREADABLE_SENTINEL}
    baseline = {"/etc/sudoers": ssh_remote.UNREADABLE_SENTINEL, "/etc/crontab": "def", "/etc/passwd": "p"}
    diff = diff_file_integrity(baseline, {**current, "/etc/passwd": "p2"})
    assert [c["path"] for c in diff["changed"]] == ["/etc/passwd"]
    assert {u["path"] for u in diff["unverifiable"]} == {"/etc/sudoers", "/etc/crontab"}


def test_custom_yara_rules_are_never_sent(env, monkeypatch):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    out = ssh_remote.fetch_yara_scan("/var/www", "rule x { condition: true }", custom_rules=True)
    assert isinstance(out, SSHResult) and "custom rules can't be sent" in out.stderr
    assert env["calls"]["agent"] == []
    env["agent"]["reply"] = {"status": "ok", "data": {"matches": [{"rule": "EICAR", "file": "/var/www/e", "strings": []}],
                                                      "files_scanned": 3, "skipped_credential": 1, "truncated": False}}
    got = ssh_remote.fetch_yara_scan("/var/www", "ignored -- the box's own rules are used")
    assert got == [{"rule": "EICAR", "file": "/var/www/e", "strings": []}]
    assert got.scan_info["files_scanned"] == 3 and env["calls"]["agent"][0][2] == {"path": "/var/www"}


# ---------------------------------------------------------------------------
# Tools: network scans refused, transport stamped on results, gaps named
# ---------------------------------------------------------------------------
def test_network_scans_refuse_and_record_the_gap(env, tmp_path, monkeypatch):
    from kratos.agent import tools

    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)

    def no_scan(*a, **k):
        raise AssertionError("must not scan")

    monkeypatch.setattr(tools, "_run_nmap_scan", no_scan)
    for fn in (tools.tool_run_nmap_scan, tools.tool_run_vuln_scan):
        out = fn(tmp_path)
        assert out["status"] == "error" and "network scan not available" in out["observation"]
        assert "was not checked" in out["coverage_gap"]
    # self-monitoring of Kratos's own host is unaffected
    assert routing.network_scan_refusal("127.0.0.1") is None


def test_ssh_first_targets_still_get_network_scans(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SSH_FIRST)
    assert routing.network_scan_refusal() is None


def test_tool_results_carry_the_transport(env, tmp_path):
    from kratos.agent.loop import execute_tool_call

    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    out = execute_tool_call("list_processes", {}, tmp_path)
    assert out["status"] == "ok" and "through its sub-agent (web-01)" in out["result"]["transport"]
    assert list(out["result"])[0] == "transport"


def test_answer_that_ignores_a_gap_gets_a_note():
    from kratos.agent.loop import _unstated_coverage_gaps

    gaps = ["network exposure (open ports/services) of web was not checked"]
    assert _unstated_coverage_gaps(gaps, "All clear: no brute force, ports look fine.") == gaps
    assert _unstated_coverage_gaps(gaps, "No brute force. Open ports were not checked (no network path).") == []
    assert _unstated_coverage_gaps([], "anything") == []


def test_the_transport_note_is_shown_and_a_fallback_stands_out():
    from kratos.tui_mk2 import render as R
    from kratos.tui_mk2 import theme as T

    assert R.transport_chip({"status": "ok"}) is None and R.transport_chip(None) is None
    via = R.transport_chip({"transport": "read through its sub-agent (web-01)"})
    assert "sub-agent (web-01)" in via.plain and str(via.spans[-1].style) == T.TEXT_MUTED
    fb = R.transport_chip({"transport": "SSH to web-01 failed (timed out); read through its sub-agent (web-01) instead"})
    assert str(fb.spans[-1].style) == T.ATTENTION


def test_privileged_accounts_read_through_the_agent(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    env["agent"]["reply"] = {"status": "ok", "data": {"returncode": 0, "stderr": "", "stdout":
                             "GROUP\tsudo:x:27:alice\nPASSWD\talice\t1000\t1000\t/bin/bash\nSUDOERS_OK\n"}}
    inv, since = ssh_remote.fetch_privileged_accounts(30)
    assert "alice" in inv.accounts and env["calls"]["ssh"] == []
    assert env["calls"]["agent"][0][1] == "privileged_accounts" and env["calls"]["agent"][0][2] == {"since": since}


def test_the_yara_sweep_goes_root_by_root_through_the_agent(env):
    env["store"].set_link("203.0.113.10", env["target_id"], routing.MODE_SUBAGENT)
    replies = {
        "/home": {"status": "ok", "data": {"matches": [{"rule": "EICAR", "file": "/home/u/e", "strings": []}],
                                           "skipped_credential": 2}},
        "/srv": {"status": "refused", "reason": "yara_scan: /srv does not exist on this box"},
    }
    seen = []

    def agent(link, probe, params):
        seen.append(params)
        return replies[params["path"]]

    routing.agent_read = agent
    out = ssh_remote.fetch_yara_sweep(("/home", "/srv"), "ignored")
    assert seen == [{"path": "/home"}, {"path": "/srv"}]
    assert out["scanned"] == ["/home"] and out["matches"][0]["rule"] == "EICAR"
    assert "2 credential file(s)" in out["agent_notes"][0] and out["matched_content"]
    custom = ssh_remote.fetch_yara_sweep(("/home",), "rule x { condition: true }", custom_rules=True)
    assert isinstance(custom, SSHResult) and "custom rules can't be sent" in custom.stderr


def test_guard8_leaves_a_known_subagent_coverage_limit_alone():
    from kratos.agent.loop import _CAPABILITY_GAP_RE, _KNOWN_COVERAGE_LIMIT_RE, _gap_sentence

    text = "Kratos does not have a tool to scan open ports through the sub-agent. Logins look normal."
    m = _CAPABILITY_GAP_RE.search(text)
    assert m and _KNOWN_COVERAGE_LIMIT_RE.search(_gap_sentence(text, m))
    real = "Kratos does not have a tool to list SUID binaries on the target."
    m2 = _CAPABILITY_GAP_RE.search(real)
    assert m2 and not _KNOWN_COVERAGE_LIMIT_RE.search(_gap_sentence(real, m2))
