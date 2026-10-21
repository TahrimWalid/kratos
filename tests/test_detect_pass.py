"""The detection pass (kratos.detect.run) and its findings (kratos.detect.findings).

High-water mark, a new pack looking back once, coverage lines for log sources a
machine doesn't give, rules turned off per machine, one machine's events never
raising another machine's finding, counting rules across two passes, the per-pass
budget, detection events (alert, rule author, Kratos-written message), and SIGMA
findings through the findings engine (lifecycle, labels, credit)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from kratos import settings_store
from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.detect import pack as P
from kratos.detect import run as R
from kratos.detect import settings as S
from kratos.detect import store as ST
from kratos.detect.findings import build, load_recent
from kratos.events import converters as C
from kratos.events.store import EventStore
from kratos.lifecycle.decide import Actor
from kratos.logsources.parsers import Parsed
from kratos.subagent import detect as D
from tests._untrusted_corpus import CORPUS, assert_screen_safe

A, B = "198.51.100.10", "198.51.100.20"          # two monitored machines (documentation addresses)
NOW = time.time()
PERSON = Actor(user="alice", interface="cli")


def _ctx(target: str) -> C.ReadContext:
    return C.ReadContext(target=target, transport="ssh", read="test", coverage="complete")


def exec_event(target: str, ts: float, exe: str, *args: str, user: str = "alice"):
    """An auditd program start, as the auditd parser hands it over."""
    p = Parsed(ts=ts, action="process_started", provider="auditd", outcome="success", message="SYSCALL EXECVE",
               original=f"type=EXECVE msg=audit({ts:.3f}:1): argc={len(args)}",
               fields={"process_executable": exe, "process_name": exe.rsplit("/", 1)[-1],
                       "process_command_line": " ".join(args), "process_args": list(args), "user_name": user,
                       "audit_types": ["SYSCALL", "EXECVE", "PATH"], "sequence": int(ts)})
    return C.from_parsed(p, ctx=_ctx(target), dataset="kratos.auditd")


def failed_login(target: str, ts: float, ip: str, user: str = "carol"):
    iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))
    msg = f"Failed password for invalid user {user} from {ip} port {int(ts) % 60000 + 1024} ssh2"
    return C.from_auth_event(classify_auth_message(iso, target, "sshd", msg, msg), ctx=_ctx(target))


def _store(data_dir: Path, *events) -> int:
    return EventStore(data_dir / "kratos.db").add(events)


def _detections(data_dir: Path, target: str):
    return EventStore(data_dir / "kratos.db").query(target, dataset="kratos.detect", limit=10000)


USERDEL = "SIGMA-08F26069"        # User Has Been Deleted Via Userdel (process_creation, medium)
CHATTR_AUDITD = "SIGMA-A5B977D6"   # Remove Immutable File Attribute - Auditd (auditd, medium)


# ---------------------------------------------------------------------------- the pass
def test_a_match_becomes_one_detection_event_with_the_rules_credit(tmp_path):
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    rep = R.run_pass(A, tmp_path, now=NOW)
    assert rep.status == "ok" and [m["rule_id"] for m in rep.matches] == [USERDEL]
    [det] = _detections(tmp_path, A)
    rule = P.shipped().pack.by_id[USERDEL].meta
    assert det.kind == "alert" and det.dataset == "kratos.detect" and det.rule_id == USERDEL
    assert det.rule_author and det.rule_author[0] in rule["author"] and det.rule_license == "DRL-1.1"
    assert det.rule_name == rule["title"] and det.rule_reference == rule["source"]["url"]
    assert det.message == f"{rule['title']} (rule {USERDEL} by {rule['author']})"     # Kratos-written only
    assert det.host_name == A and det.process_executable == "/usr/sbin/userdel"
    assert len(det.detect_matched) == 1 and det.detect_level == "medium"


def test_the_high_water_mark_reads_each_stored_event_once(tmp_path):
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    first = R.run_pass(A, tmp_path, now=NOW)
    second = R.run_pass(A, tmp_path, now=NOW)
    assert first.events == 1 and second.events == 0 and second.matches == []
    _store(tmp_path, exec_event(A, NOW - 30, "/usr/bin/chattr", "chattr", "-i", "/etc/passwd"))
    third = R.run_pass(A, tmp_path, now=NOW)
    assert third.events == 1 and {m["rule_id"] for m in third.matches} >= {CHATTR_AUDITD}
    assert len({d.event_id for d in _detections(tmp_path, A)}) == len(_detections(tmp_path, A))


def test_evaluating_the_same_events_again_stores_no_duplicate_detection(tmp_path):
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    R.run_pass(A, tmp_path, now=NOW)
    conn = __import__("sqlite3").connect(tmp_path / "kratos.db")
    conn.execute("DELETE FROM detect_runs")       # forget the high-water mark
    conn.commit()
    conn.close()
    again = R.run_pass(A, tmp_path, now=NOW)
    assert len(again.matches) == 1 and again.new_detections == 0 and len(_detections(tmp_path, A)) == 1


def test_a_new_pack_looks_back_once_over_the_stored_window(tmp_path):
    _store(tmp_path, exec_event(A, NOW - 30 * 3600, "/usr/sbin/userdel", "userdel", "old"),
           exec_event(A, NOW - 2 * 3600, "/usr/sbin/userdel", "userdel", "recent"))
    rep = R.run_pass(A, tmp_path, now=NOW)
    pp = rep.packs[0]
    assert pp.lookback and pp.events == 1                       # only the last 24 h (detect.lookback_hours)
    runs = ST.recent_runs(tmp_path, A)
    assert runs[0].lookback and runs[0].status == "ok"
    later = R.run_pass(A, tmp_path, now=NOW)
    assert not later.packs[0].lookback and later.events == 0


def test_one_machines_events_never_raise_another_machines_detection(tmp_path):
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    rep_b = R.run_pass(B, tmp_path, now=NOW)
    assert rep_b.events == 0 and rep_b.matches == [] and _detections(tmp_path, B) == []
    doc_b = json.loads(Path(rep_b.snapshot).read_text())
    assert doc_b["target"] == B and doc_b["detections"] == []
    R.run_pass(A, tmp_path, now=NOW)
    assert [d.host_name for d in _detections(tmp_path, A)] == [A]
    from kratos.adapters.findings_engine import find_latest_inputs
    assert json.loads(Path(find_latest_inputs(tmp_path, B)["detections"]).read_text())["target"] == B
    assert json.loads(Path(find_latest_inputs(tmp_path, A)["detections"]).read_text())["target"] == A


def test_a_machine_without_a_log_source_gets_a_coverage_line_not_silence(tmp_path):
    _store(tmp_path, failed_login(A, NOW - 60, "203.0.113.9"))       # only the SSH log: no auditd at all
    rep = R.run_pass(A, tmp_path, now=NOW)
    cov = {c.key: c for c in rep.coverage}
    assert cov["linux/sshd"].state == "checked"
    assert cov["linux/auditd"].state == "not_checked" and "auditd" in cov["linux/auditd"].note
    assert cov["linux/process_creation"].state == "not_checked"
    doc = json.loads(Path(rep.snapshot).read_text())
    note = [f for f in build(doc) if f.id == "DETECT-001"]
    assert note and note[0].severity == "info"
    assert any("program starts" in line for line in note[0].evidence)
    assert any("does not mean the machine is clean" in r for r in note[0].recommendation)


def test_sudo_commands_alone_give_partial_program_start_coverage(tmp_path):
    msg = "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/userdel eve"
    iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(NOW - 60))
    ev = C.from_auth_event(classify_auth_message(iso, A, "sudo", msg, msg), ctx=_ctx(A))
    _store(tmp_path, ev)
    rep = R.run_pass(A, tmp_path, now=NOW)
    cov = {c.key: c for c in rep.coverage}
    assert cov["linux/process_creation"].state == "partial"
    assert "only commands run through sudo" in cov["linux/process_creation"].note
    assert USERDEL in {m["rule_id"] for m in rep.matches}          # the sudo-run userdel is still caught


def test_rules_turned_off_for_a_machine_or_everywhere_are_not_evaluated(tmp_path):
    ST.set_rule_enabled(tmp_path, USERDEL, False, target=A, reason="admin script deletes test users", actor=PERSON)
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"),
           exec_event(B, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    assert R.run_pass(A, tmp_path, now=NOW).matches == []
    assert [m["rule_id"] for m in R.run_pass(B, tmp_path, now=NOW).matches] == [USERDEL]
    ST.set_rule_enabled(tmp_path, USERDEL, False, target=None, reason="noise everywhere", actor=PERSON)
    ST.set_rule_enabled(tmp_path, USERDEL, True, target=A, reason="watch this one", actor=PERSON)
    assert USERDEL not in ST.disabled_rules(tmp_path, A) and USERDEL in ST.disabled_rules(tmp_path, B)
    o = {(x.rule_id, x.target): x for x in ST.overrides(tmp_path)}[(USERDEL, "*")]
    assert o.actor == "alice via cli" and o.reason == "noise everywhere" and not o.enabled


def test_turning_rules_off_is_for_people_only(tmp_path):
    with settings_store.tool_call_scope("some_tool"):
        with pytest.raises(ST.OverrideError, match="agent tools may not"):
            ST.set_rule_enabled(tmp_path, USERDEL, False, target=A, reason="x", actor=PERSON)
    with pytest.raises(ST.OverrideError, match="needs a person"):
        ST.set_rule_enabled(tmp_path, USERDEL, False, target=A, reason="x", actor=object())
    with pytest.raises(ST.OverrideError, match="reason"):
        ST.set_rule_enabled(tmp_path, USERDEL, False, target=A, reason="  ", actor=PERSON)


# ---------------------------------------------------------------------------- counting rules
COUNT_ID = "SIGMA-C0C0C0C0"


def _count_pack(tmp_path: Path, threshold: int = 3, window: int = 300) -> None:
    rule = {"id": COUNT_ID, "title": "SSH password guessing burst", "level": "high", "author": "Test Author",
            "license": "DRL-1.1", "sigma_id": "c0c0c0c0-0000-4000-8000-000000000001",
            "logsource": {"product": "linux", "service": "sshd", "category": None},
            "scope": {"datasets": ["kratos.auth"], "where": None},
            "match": {"op": "eq", "field": "event.action", "value": "ssh_failed_login"},
            "count": {"window_seconds": window, "group_by": "source.ip", "op": "gte", "threshold": threshold},
            "tags": ["attack.credential-access", "attack.t1110.001"], "attack": ["T1110.001"]}
    pack = {"format": D.FORMAT, "format_version": 1, "pack_id": "local-test", "pack_version": 1, "rules": [rule]}
    pack["sha256"] = D.pack_digest(pack)
    P.write_imported(tmp_path, pack)


def _count_detections(tmp_path: Path, target: str):
    return [d for d in _detections(tmp_path, target) if d.rule_id == COUNT_ID]


def test_a_burst_straddling_two_passes_is_counted_and_reported_once(tmp_path):
    _count_pack(tmp_path)
    ip = "203.0.113.50"
    _store(tmp_path, *(failed_login(A, NOW - 100 + i * 10, ip) for i in range(2)))
    assert R.run_pass(A, tmp_path, now=NOW).matches == []                      # 2 of 3: not yet
    _store(tmp_path, failed_login(A, NOW - 70, ip))
    second = R.run_pass(A, tmp_path, now=NOW)
    assert [(m["rule_id"], m["group"]) for m in second.matches if m["rule_id"] == COUNT_ID] == [(COUNT_ID, ip)]
    _store(tmp_path, *(failed_login(A, NOW - 60 + i, ip) for i in range(5)))  # the same burst goes on
    assert [m for m in R.run_pass(A, tmp_path, now=NOW).matches if m["rule_id"] == COUNT_ID] == []
    [det] = _count_detections(tmp_path, A)
    assert det.detect_group == ip and det.detect_count == 3 and len(det.detect_matched) == 3


def test_a_counting_rule_becomes_one_finding_per_group(tmp_path):
    _count_pack(tmp_path)
    for ip in ("203.0.113.50", "203.0.113.51"):
        _store(tmp_path, *(failed_login(A, NOW - 100 + i, ip) for i in range(3)))
    rep = R.run_pass(A, tmp_path, now=NOW)
    found = [f for f in build(json.loads(Path(rep.snapshot).read_text())) if f.id == COUNT_ID]
    assert sorted(f.subject for f in found) == ["203.0.113.50", "203.0.113.51"]
    assert all(f.severity == "high" and [a["technique_id"] for a in f.attack] == ["T1110.001"] for f in found)
    assert all(f.detection_rule["author"] == "Test Author" for f in found)


# ---------------------------------------------------------------------------- budget
def test_the_pass_stops_at_its_event_budget_and_catches_up_next_time(tmp_path):
    settings_store.set(S.MAX_EVENTS, 100, data_dir=tmp_path, actor="test")
    _store(tmp_path, *(exec_event(A, NOW - 600 + i, "/usr/bin/true", "true", str(i)) for i in range(250)))
    first = R.run_pass(A, tmp_path, now=NOW)
    assert first.status == "partial" and first.behind and first.events == 100
    doc = json.loads(Path(first.snapshot).read_text())
    assert doc["complete"] is False
    assert any("behind" in line for f in build(doc) if f.id == "DETECT-001" for line in f.evidence)
    second = R.run_pass(A, tmp_path, now=NOW)
    third = R.run_pass(A, tmp_path, now=NOW)
    assert (second.events, third.events) == (100, 50) and third.status == "ok" and not third.behind


def test_the_pass_stops_at_its_time_budget(tmp_path):
    _store(tmp_path, *(exec_event(A, NOW - 600 + i, "/usr/bin/true", "true", str(i)) for i in range(50)))
    rep = R.run_pass(A, tmp_path, now=NOW, deadline=time.monotonic() - 1)
    assert rep.status == "partial" and rep.behind and rep.events == 0


def test_a_refused_imported_pack_is_listed_not_used(tmp_path):
    folder = P.imported_dir(tmp_path)
    folder.mkdir(parents=True)
    (folder / "broken.json").write_text('{"format": "kratos-detect-pack", "rules": []}')
    rep = R.run_pass(A, tmp_path, now=NOW)
    assert [p.pack_id for p in rep.packs] == ["sigma-linux"]
    assert rep.refused and "broken.json" in rep.refused[0]["path"]
    note = [f for f in build(json.loads(Path(rep.snapshot).read_text())) if f.id == "DETECT-001"][0]
    assert any("refused" in line for line in note.evidence)


# ---------------------------------------------------------------------------- untrusted text (A.4)
def test_machine_text_in_a_matched_event_never_reaches_a_title(tmp_path):
    evil = CORPUS[sorted(CORPUS)[0]]
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", evil, user=evil[:20]))
    rep = R.run_pass(A, tmp_path, now=NOW)
    [f] = [f for f in build(json.loads(Path(rep.snapshot).read_text())) if f.id == USERDEL]
    assert f.title == P.shipped().pack.by_id[USERDEL].meta["title"]
    for line in [f.title, *f.evidence, *f.entities, f.subject]:
        assert_screen_safe(line, where="SIGMA finding")
        assert evil not in line
    [det] = _detections(tmp_path, A)
    assert evil not in (det.message or "")


# ---------------------------------------------------------------------------- through the findings engine
def test_sigma_findings_reach_the_report_with_lifecycle_labels_and_credit(tmp_path, monkeypatch):
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.run_context import run_scope

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: A)
    _store(tmp_path, exec_event(A, NOW - 60, "/usr/bin/chattr", "chattr", "-i", "/etc/passwd"))
    with run_scope("cli", target=A):
        R.run_pass(A, tmp_path)
        out_json, out_md = FE.write_findings_report(data_dir=tmp_path)
    data = json.loads(Path(out_json).read_text())
    assert "by " in Path(out_md).read_text()
    found = {f["id"]: f for f in data["findings"]}
    f = found[CHATTR_AUDITD]
    assert f["detection_rule"]["author"] and f["detection_rule"]["license"] == "DRL-1.1"
    assert f["state"] == "open" and f["finding_key"] and f["subject"] == "alice"
    assert [a["technique_id"] for a in f["attack"]] == ["T1222.002"]
    assert any("by " + f["detection_rule"]["author"] in line for line in f["evidence"])
    assert all("detection_rule" not in g for rid, g in found.items() if not rid.startswith("SIGMA-"))


def test_an_old_snapshot_is_not_a_current_reading(tmp_path):
    rep = R.run_pass(A, tmp_path, now=NOW)
    path = Path(rep.snapshot)
    doc = json.loads(path.read_text())
    doc["checked_at"] = "2020-01-01T00:00:00+00:00"
    path.write_text(json.dumps(doc))
    assert load_recent(path) is None


def test_a_fresh_data_folder_is_a_quiet_pass_not_a_failure(tmp_path):
    rep = R.run_pass(A, tmp_path / "fresh", now=NOW)
    assert rep.status == "ok" and rep.events == 0 and rep.matches == []
    assert all(c.state == "not_checked" for c in rep.coverage)       # and it says so: nothing was there to check


# ---------------------------------------------------------------------------- Kratos's own logins
RECON = "SIGMA-0CF7A157"           # Linux Recon Indicators: matches the persistence check's own SUID search


def _audit(target, ts, action, *, pid, ses, exe=None, args=()):
    fields = {"process_pid": pid, "audit_session": str(ses), "user_name": "ubuntu",
              "audit_types": ["SYSCALL", "EXECVE"] if exe else ["USER_START"]}
    if exe:
        fields.update(process_executable=exe, process_name=exe.rsplit("/", 1)[-1],
                      process_command_line=" ".join(args), process_args=list(args))
    p = Parsed(ts=ts, action=action, provider="auditd", outcome="success", message=action,
               original=f"type=X msg=audit({ts:.3f}:{pid}): ses={ses}", fields=fields)
    return C.from_parsed(p, ctx=_ctx(target), dataset="kratos.auditd")


def _accepted(target, ts, pid, fp):
    import dataclasses

    iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))
    msg = f"Accepted publickey for ubuntu from 192.0.2.1 port 50000 ssh2: ED25519 {fp}"
    ev = dataclasses.replace(classify_auth_message(iso, target, "sshd", msg, msg), pid=pid)
    return C.from_auth_event(ev, ctx=_ctx(target))


def test_kratos_own_ssh_commands_are_set_aside_and_another_logins_are_not(tmp_path, monkeypatch):
    import base64
    import os

    from kratos.detect import own

    key_line = "ssh-ed25519 " + base64.b64encode(os.urandom(51)).decode() + " kratos@test"   # built at runtime
    fp = own.fingerprint(key_line)
    monkeypatch.setattr(own, "kratos_fingerprint", lambda: fp)
    find = ("find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f")
    t0 = NOW - 300
    _store(tmp_path,
           _accepted(A, t0, 5180, fp),                                              # Kratos logs in ...
           _audit(A, t0 + 0.3, "session_started", pid=5180, ses=168),
           _audit(A, t0 + 1, "process_started", pid=5201, ses=168, exe="/usr/bin/find", args=find),  # ... its read
           _accepted(A, t0 + 60, 6000, "SHA256:" + "A" * 43),                       # someone else, same account
           _audit(A, t0 + 60.3, "session_started", pid=6000, ses=169),
           _audit(A, t0 + 61, "process_started", pid=6100, ses=169, exe="/usr/bin/find", args=find))
    rep = R.run_pass(A, tmp_path, now=NOW)
    hits = [m for m in rep.matches if m["rule_id"] == RECON]
    assert len(hits) == 1 and rep.own_events == 2          # its login record and its find
    [det] = [d for d in _detections(tmp_path, A) if d.rule_id == RECON]
    assert det.process_pid is None or det.process_pid == 6100
    assert json.loads(Path(rep.snapshot).read_text())["kratos_own_events"] == 2


def test_a_reused_sshd_pid_long_after_does_not_mark_a_login_as_kratos(tmp_path, monkeypatch):
    from kratos.detect import own

    fp = "SHA256:" + "B" * 43
    monkeypatch.setattr(own, "kratos_fingerprint", lambda: fp)
    t0 = NOW - 3600
    _store(tmp_path, _accepted(A, t0, 5180, fp), _audit(A, t0 + 0.3, "session_started", pid=5180, ses=10),
           _audit(A, t0 + 1800, "session_started", pid=5180, ses=11))      # the same pid, half an hour later
    conn = __import__("sqlite3").connect(tmp_path / "kratos.db")
    try:
        assert set(own.own_sessions(conn, A, since=0, fp=fp)) == {"10"}
    finally:
        conn.close()


def test_fingerprint_matches_ssh_keygen_format():
    from kratos.detect import own

    blob = bytes(range(51))
    import base64
    import hashlib

    line = "ssh-ed25519 " + base64.b64encode(blob).decode() + " x"
    want = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert own.fingerprint(line) == want and own.fingerprint("garbage") is None


def test_a_session_id_counts_as_kratos_only_while_that_login_lasted(tmp_path, monkeypatch):
    """Audit session ids restart at every boot: an id Kratos once had can be someone else's later."""
    from kratos.detect import own
    from kratos.detect import store as ST2

    fp = "SHA256:" + "C" * 43
    monkeypatch.setattr(own, "kratos_fingerprint", lambda: fp)
    find = ("find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f")
    t0 = NOW - 6 * 3600
    _store(tmp_path,
           _accepted(A, t0, 700, fp), _audit(A, t0 + 0.2, "session_started", pid=700, ses=5),
           _audit(A, t0 + 30, "session_ended", pid=700, ses=5),
           # after a reboot someone else's login gets session 5 too, hours later
           _audit(A, NOW - 120, "process_started", pid=900, ses=5, exe="/usr/bin/find", args=find))
    rep = R.run_pass(A, tmp_path, now=NOW)
    assert [m["rule_id"] for m in rep.matches if m["rule_id"] == RECON] == [RECON] and rep.own_events == 2
    # an id read directly over Kratos's connection counts only around when Kratos saw it
    ST2.record_own_session(tmp_path, B, "9", now=NOW - 3 * 3600)
    assert own.is_own("9", NOW - 3 * 3600 + 30, ST2.own_sessions_recorded(tmp_path, B, since=0))
    assert not own.is_own("9", NOW - 60, ST2.own_sessions_recorded(tmp_path, B, since=0))


def test_coverage_is_exact_even_when_one_program_floods_the_log(tmp_path):
    """Kratos's own `sudo -n journalctl` lines must not hide that sshd's log is there."""
    sudo = "ubuntu : TTY=unknown ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl -n 50"
    events = [failed_login(A, NOW - 3000, "203.0.113.7")]
    for i in range(700):
        iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(NOW - 2000 + i))
        events.append(C.from_auth_event(classify_auth_message(iso, A, "sudo", sudo + f" {i}", sudo + f" {i}"),
                                        ctx=_ctx(A)))
    _store(tmp_path, *events)
    cov = {c.key: c for c in R.run_pass(A, tmp_path, now=NOW).coverage}
    assert cov["linux/sshd"].state == "checked"


def test_the_check_tells_the_digest_on_schedule_and_what_it_could_not_read(tmp_path):
    import time as _t

    from kratos.collect.registry import CheckContext
    from kratos.detect.check import SCHEDULE_NOTE, _run_detect

    _store(tmp_path, exec_event(A, NOW - 60, "/usr/sbin/userdel", "userdel", "bob"))
    ctx = CheckContext(target=A, target_key=A, data_dir=tmp_path, transport="local", dispatch=lambda *a: {},
                       deadline=_t.monotonic() + 30, now=NOW)
    res = _run_detect(ctx)
    assert res.status == "ok" and SCHEDULE_NOTE in res.summary and USERDEL in res.summary
    [gap] = res.coverage_gaps
    assert gap.startswith("detection rules with no log to read on this machine in the last 7 days: ")
    assert "file creation (5)" in gap and "SSH server log (1)" in gap and "program starts" not in gap
    assert all(ch.isprintable() for ch in res.summary)       # Kratos-written words, rule ids and counts only
