"""list_privileged_accounts (eval A6): parsing of the target probe, account-change events,
honest evidence gaps, the snapshot diff, and the PRIV-* findings. No SSH: the probe's
output is a captured fixture fed through the real parser and tool."""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kratos.adapters import findings_engine as FE
from kratos.adapters import ssh_remote
from kratos.adapters import privileged_accounts as PA
from kratos.adapters.ssh_remote import SSHResult
from kratos.agent import tools

NOW = time.time()
SINCE = int(NOW - 30 * 86400)


def _probe(*, events=(), extra_sudo="", uid0="", sudoers_ok=True, head=None, group_mtime=None) -> str:
    lines = [
        f"GROUP\tsudo:x:27:ubuntu{extra_sudo}",
        "GROUP\tdocker:x:998:deploy",
        "GROUP\tshadow:x:42:",
        "PASSWD\troot\t0\t0\t/bin/bash",
        "PASSWD\tubuntu\t1000\t1000\t/bin/bash",
        "PASSWD\tdeploy\t1001\t1001\t/bin/bash",
        "PASSWD\teviladmin\t1002\t1002\t/usr/sbin/nologin",
        "PASSWD\tnobody\t65534\t65534\t/usr/sbin/nologin",
    ]
    if uid0:
        lines.append(f"PASSWD\t{uid0}\t0\t0\t/bin/sh")
    lines.append(f"MTIME\t/etc/group\t{int(group_mtime or NOW - 90 * 86400)}")
    if sudoers_ok:
        lines += ["SUDOERS\t/etc/sudoers:root\tALL=(ALL:ALL) ALL", "SUDOERS\t/etc/sudoers:%sudo\tALL=(ALL:ALL) ALL",
                  "SUDOERS\t/etc/sudoers:Defaults\tenv_reset", "SUDOERS\t/etc/sudoers.d/90-ops:ops ALL=(ALL) NOPASSWD: /usr/bin/systemctl",
                  "SUDOERS_OK"]
    else:
        lines.append("SUDOERS_ERR\tthe SSH user cannot read sudoers (no passwordless sudo)")
    lines += [f"EVT\t{e}" for e in events] + ["EVTSRC\tjournal"]
    if head is not None:
        lines.append(f"JHEAD\t{head}")
    return "\n".join(lines) + "\n"


ADD_EVENT = f"{NOW - 3600:.6f} tgt usermod[4242]: add 'eviladmin' to group 'sudo'"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_inventory_covers_groups_uid0_primary_group_and_sudoers():
    inv = PA.parse_output(_probe(extra_sudo=",eviladmin"))
    assert set(inv.accounts) == {"root", "ubuntu", "deploy", "eviladmin", "ops"}
    assert inv.accounts["deploy"]["via"] == ["member of 'docker' (root-equivalent group)"]
    assert inv.accounts["eviladmin"]["login_shell"] is False  # still listed: nologin doesn't remove sudo rights
    assert inv.accounts["ops"]["local_account"] is False and "sudoers grant" in inv.accounts["ops"]["via"][0]
    assert all(g["subject"] != "Defaults" for g in inv.sudoers_grants)


@pytest.mark.parametrize("line,action,user,extra", [
    ("1700000000.1 h usermod[1]: add 'bob' to group 'sudo'", "added_to_group", "bob", {"group": "sudo"}),
    ("1700000000.1 h usermod[1]: add 'bob' to shadow group 'sudo'", "added_to_group", "bob", {"group": "sudo"}),
    ("1700000000.1 h gpasswd[1]: user bob added by root to group wheel", "added_to_group", "bob", {"group": "wheel"}),
    ("1700000000.1 h gpasswd[1]: user bob removed by root from group sudo", "removed_from_group", "bob", {"group": "sudo"}),
    ("1700000000.1 h useradd[1]: new user: name=bob, UID=0, GID=0, home=/root, shell=/bin/sh", "user_created", "bob", {"uid": 0}),
    ("1700000000.1 h usermod[1]: change user 'bob' UID from '1005' to '0'", "uid_changed", "bob", {"uid": 0}),
    ("1700000000.1 h userdel[1]: delete user 'bob'", "user_deleted", "bob", {}),
])
def test_event_parsing(line, action, user, extra):
    ev = PA.parse_event(line)
    assert ev["action"] == action and ev["user"] == user and ev["ts"] == pytest.approx(1700000000.1)
    for k, v in extra.items():
        assert ev[k] == v


def test_unrelated_lines_are_not_events():
    assert PA.parse_event("1700000000.1 h usermod[1]: lock user 'bob' password") is None
    assert PA.parse_event("garbage") is None


def test_notable_events_are_only_privilege_grants():
    inv = PA.parse_output(_probe(events=[
        ADD_EVENT,
        f"{NOW - 10:.1f} h usermod[1]: add 'bob' to group 'audio'",
        f"{NOW - 5:.1f} h useradd[1]: new user: name=x, UID=1009, GID=1009, home=/home/x",
    ]))
    assert [(e["user"], e.get("group")) for e in PA.notable_events(inv)] == [("eviladmin", "sudo")]


# ---------------------------------------------------------------------------
# Evidence gaps -- "no recent change" is never claimed on missing data
# ---------------------------------------------------------------------------
def test_gaps_name_a_short_journal_and_an_unexplained_group_change():
    head = NOW - 2 * 86400
    inv = PA.parse_output(_probe(head=head, group_mtime=NOW - 5 * 86400))
    gaps = PA.evidence_gaps(inv, SINCE)
    assert any("only go back to" in g for g in gaps)
    assert any("/etc/group was modified" in g for g in gaps)


def test_gaps_when_no_event_log_or_sudoers():
    out = _probe(sudoers_ok=False).replace("EVTSRC\tjournal", "EVTERR\tno journalctl on the target")
    gaps = PA.evidence_gaps(PA.parse_output(out), SINCE)
    assert any("unavailable" in g for g in gaps) and any("sudoers could not be read" in g for g in gaps)


def test_no_gaps_when_the_journal_covers_the_whole_window():
    inv = PA.parse_output(_probe(head=SINCE - 86400))
    assert PA.evidence_gaps(inv, SINCE) == []


def test_probe_script_is_valid_posix_sh():
    script = PA.build_script(SINCE, "sudo -n ")
    for sh in ("/bin/sh", "/usr/bin/dash"):
        if os.path.exists(sh):
            r = subprocess.run([sh, "-n"], input=script, text=True, capture_output=True)
            assert r.returncode == 0, r.stderr


# ---------------------------------------------------------------------------
# The tool + snapshots + findings
# ---------------------------------------------------------------------------
@pytest.fixture
def fake_target(monkeypatch):
    from kratos import kratos_config

    prev = kratos_config.get_active_target()
    kratos_config.set_active_target("10.0.0.5")
    state = {"out": _probe()}
    monkeypatch.setattr(ssh_remote, "run_remote_script", lambda script, **kw: SSHResult(ok=True, returncode=0, stdout=state["out"], stderr=""))
    monkeypatch.setattr(tools, "_ssh_target_label", lambda: "ubuntu@10.0.0.5")
    yield state
    kratos_config.set_active_target(prev)


def test_tool_reports_a_new_sudo_member_and_the_findings_engine_flags_it(tmp_path, fake_target):
    first = tools.tool_list_privileged_accounts(tmp_path)
    assert first["changed_since_last_check"]["previous_snapshot_at"] is None
    assert [a["user"] for a in first["privileged_accounts"]][0] == "root"

    fake_target["out"] = _probe(extra_sudo=",eviladmin", events=[ADD_EVENT], head=SINCE - 86400)
    time.sleep(0.01)
    second = tools.tool_list_privileged_accounts(tmp_path)
    assert second["changed_since_last_check"]["added"] == ["eviladmin"]
    assert second["recent_privilege_grants"][0]["user"] == "eviladmin"
    assert second["recent_privilege_grants"][0]["in_effect"] is True

    report_json, _ = FE.write_findings_report(tmp_path)
    report = json.loads(report_json.read_text())
    ids = {f["id"]: f for f in report["findings"]}
    assert ids["PRIV-001"]["severity"] == "high" and "eviladmin" in ids["PRIV-001"]["title"]
    assert "PRIV-003" not in ids  # explained by the logged event, so not double-reported
    assert "eviladmin" in " ".join(ids["PRIV-004"]["evidence"])
    assert "privileged_accounts" not in report["missing_inputs"]


def test_uid0_backdoor_and_unexplained_addition(tmp_path, fake_target):
    tools.tool_list_privileged_accounts(tmp_path)
    fake_target["out"] = _probe(uid0="toor", extra_sudo=",eviladmin")  # no events explain either
    time.sleep(0.01)
    tools.tool_list_privileged_accounts(tmp_path)
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    ids = {f["id"]: f for f in report["findings"]}
    assert "toor" in ids["PRIV-002"]["title"] and ids["PRIV-002"]["severity"] == "high"
    assert ids["PRIV-003"]["title"].endswith("eviladmin") and ids["PRIV-003"]["severity"] == "medium"


def test_an_old_snapshot_no_longer_feeds_findings(tmp_path, fake_target):
    fake_target["out"] = _probe(extra_sudo=",eviladmin", events=[ADD_EVENT])
    res = tools.tool_list_privileged_accounts(tmp_path)
    snap = Path(res["snapshot_file"])
    data = json.loads(snap.read_text())
    data["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=FE.PRIVILEGED_SNAPSHOT_MAX_AGE_HOURS + 1)).isoformat()
    snap.write_text(json.dumps(data))
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert not any(f["id"].startswith("PRIV-") for f in report["findings"])


def test_ssh_failure_is_an_error_not_an_empty_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_remote, "run_remote_script", lambda script, **kw: SSHResult(ok=False, returncode=255, stdout="", stderr="Permission denied (publickey)"))
    res = tools.tool_list_privileged_accounts(tmp_path)
    assert res["status"] == "error" and "Permission denied" in res["observation"]


def test_snapshots_are_queryable_as_of_a_time(tmp_path, fake_target):
    from kratos.timewin import snapshots as S

    tools.tool_list_privileged_accounts(tmp_path)
    s = S.latest(tmp_path, "privileged_accounts")
    assert s is not None and set(S.summarize(s)["accounts"]) == {"root", "ubuntu", "deploy", "ops"}


def test_grants_to_deleted_or_demoted_accounts_are_history_not_current_risk(tmp_path, fake_target):
    """Live finding: an eval user deleted after the run still had 'added to sudo'
    events in the journal, and the model called it an active threat."""
    fake_target["out"] = _probe(events=[
        f"{NOW - 7200:.1f} h usermod[1]: add 'ghost' to group 'sudo'",       # account since deleted
        f"{NOW - 3600:.1f} h usermod[1]: add 'deploy' to group 'sudo'",      # left sudo; still privileged via docker
        ADD_EVENT,                                                             # eviladmin: still in sudo
    ], extra_sudo=",eviladmin")
    res = tools.tool_list_privileged_accounts(tmp_path)
    assert [g["user"] for g in res["recent_privilege_grants"]] == ["eviladmin"]
    past = {g["user"]: g["now"] for g in res["past_privilege_grants_no_longer_in_effect"]}
    assert past == {"ghost": "account no longer exists",
                    "deploy": "no longer in effect (the account is still privileged another way)"}
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    priv1 = next(f for f in report["findings"] if f["id"] == "PRIV-001")
    assert "ghost" not in priv1["title"] and "deploy" not in priv1["title"]


def test_members_of_a_group_granted_sudo_in_sudoers_are_listed():
    out = _probe(events=[f"{NOW - 60:.1f} h gpasswd[1]: user carol added by root to group devops"]).replace(
        "SUDOERS_OK", "SUDOERS\t/etc/sudoers.d/devops:%devops ALL=(ALL) ALL\nSUDOERS_OK\nSGROUP\tdevops:x:1500:carol,dave")
    inv = PA.parse_output(out)
    assert inv.accounts["carol"]["via"] == ["member of 'devops' (granted sudo in sudoers)"]
    assert "dave" in inv.accounts
    [grant] = PA.notable_events(inv)  # being added to such a group is a privilege grant too
    assert grant["user"] == "carol" and PA.grant_in_effect(inv, grant)


def test_a_snapshot_of_another_machine_never_feeds_this_targets_report(tmp_path, fake_target):
    from kratos import kratos_config

    fake_target["out"] = _probe(extra_sudo=",eviladmin", events=[ADD_EVENT])
    tools.tool_list_privileged_accounts(tmp_path)
    kratos_config.set_active_target("10.0.0.99")  # user switched targets
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert not any(f["id"].startswith("PRIV-") for f in report["findings"])
    kratos_config.set_active_target("10.0.0.5")
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert any(f["id"] == "PRIV-001" for f in report["findings"])


def test_probe_script_resolves_sudoers_groups():
    script = PA.build_script(SINCE, "")
    assert "SGROUP" in script and "%[A-Za-z0-9_.-]+" in script



def test_the_same_script_runs_over_ssh_and_through_the_agent():
    """One builder for both transports; only the sudoers privilege prefix differs (a root agent
    reads sudoers directly)."""
    ssh = PA.build_script(1790000000, "sudo -n ")
    root_agent = PA.build_script(1790000000, "", sudo="")
    assert ssh.startswith("SUDO='sudo -n'\n") and root_agent.startswith("SUDO=''\n")
    assert ssh.split("\n", 1)[1].replace("sudo -n journalctl", "journalctl") == root_agent.split("\n", 1)[1]
    assert "sudo -n grep" not in ssh  # sudoers is read through $SUDO, never a hard-coded sudo


def test_the_agent_read_is_validated_and_needs_a_time():
    from kratos.subagent import reads

    assert reads.validate_params("privileged_accounts", {"since": 1790000000}) == {"since": 1790000000.0}
    for bad in ({}, {"since": "yesterday"}, {"since": 1790000000, "script": "id"}):
        with pytest.raises(reads.ReadParamError):
            reads.validate_params("privileged_accounts", bad)
