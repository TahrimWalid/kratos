"""The agent's watcher (C.2, kratos.subagent.watch): follows a (fake) journal and audit
log, evaluates the rules on each entry, spools matches, checkpoints, catches up,
records gaps, rate-limits floods -- without a network or a real journal."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from kratos.detect import pack as packs_mod
from kratos.subagent import detect as D
from kratos.subagent import watch as W

from tests._watch_fakes import (fake_journalctls, append, audit_exec, failed_ssh, journal_entry, make_fake_journalctl, sudo_line,
                                wait_for, write_audit)

MACHINE = "host.example"
CHATTR_RULE = "SIGMA-34979410"      # Remove Immutable File Attribute (program starts, incl. sudo commands)
USERADD_RULE = "SIGMA-759D0D51"     # Creation Of An User Account (auditd)


@pytest.fixture(autouse=True)
def _no_leaked_journalctl(tmp_path):
    """Stopping the watcher never leaves its journalctl running."""
    yield
    deadline = time.monotonic() + 10
    while fake_journalctls(tmp_path) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert fake_journalctls(tmp_path) == []


def _counting_pack(version: int = 1, threshold: int = 4) -> dict:
    rule = {
        "id": "SIGMA-AB12CD34", "title": "SSH password guessing from one address", "level": "high",
        "author": "Kratos test fixture", "license": "DRL-1.1", "sigma_id": "5a1f0c3e-2222-4c1a-9f00-c1c1c1c1c102",
        "logsource": {"product": "linux", "service": "sshd", "category": None},
        "scope": {"datasets": ["kratos.auth"], "where": {"op": "in", "field": "event.provider",
                                                          "values": ["sshd", "sshd-session"], "cased": True}},
        "match": {"op": "eq", "field": "event.action", "value": "ssh_failed_login", "cased": True},
        "count": {"window_seconds": 300, "group_by": "source.ip", "op": "gte", "threshold": threshold},
    }
    pack = {"format": D.FORMAT, "format_version": D.FORMAT_VERSION, "pack_id": "test-count", "pack_version": version,
            "rules": [rule], "skipped": []}
    pack["sha256"] = D.pack_digest(pack)
    D.validate_pack(pack)
    return pack


def _config(packs: list[dict], **settings) -> dict:
    return W.validate_push({"enabled": True, "machine": MACHINE, "packs": packs, "disabled": [],
                            "settings": settings}, None)


def _manager(tmp_path: Path, audit: Path | None = None, **kw) -> tuple[W.WatchManager, Path]:
    exe, data = make_fake_journalctl(tmp_path)
    m = W.WatchManager(str(tmp_path / "state"), audit_path=str(audit or tmp_path / "audit.log"),
                       journalctl=str(exe), **kw)
    m.check_auditd = lambda: True          # this host's auditd doesn't matter here
    return m, data


def _shipped() -> dict:
    return packs_mod.shipped().pack.raw


def _spooled(m: W.WatchManager) -> list[dict]:
    return [rec for rec, _n in m.spool.items.values()]


def test_a_sudo_command_matching_a_rule_is_spooled_with_a_bounded_event(tmp_path):
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        now = time.time()
        append(data, journal_entry(1, now, sudo_line("alice", "/usr/bin/chattr -i /etc/hostname"), comm="sudo"))
        rec = wait_for(lambda: next((r for r in _spooled(m) if r["rule_id"] == CHATTR_RULE), None))
        ev = rec["event"]
        assert ev["event.dataset"] == "kratos.auth" and ev["host.name"] == MACHINE
        assert ev["process.executable"] == "/usr/bin/chattr"
        assert len(ev["event.id"]) == 32 and rec["source"] == "journal"
        assert "event.original" not in ev or len(ev["event.original"]) <= W.EVENT_TEXT_MAX
        assert rec["pack_id"] == "sigma-linux" and isinstance(rec["seq"], int)
    finally:
        m.stop()


def test_audit_program_start_is_matched_and_kratos_own_children_are_not(tmp_path):
    audit = tmp_path / "audit.log"
    audit.write_text("")
    m, _data = _manager(tmp_path, audit=audit, own_pid=1111)
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["auditd"]["state"] == "watching")
        now = time.time()
        # the agent's own read (its child, then a grandchild) runs useradd -- set aside
        write_audit(audit, audit_exec(now, 10, "/bin/sh", ["sh", "-s"], pid=5000, ppid=1111))
        write_audit(audit, audit_exec(now + 0.1, 11, "/usr/sbin/useradd", ["useradd", "x"], pid=5001, ppid=5000))
        # a person's useradd -- matched
        write_audit(audit, audit_exec(now + 0.2, 12, "/usr/sbin/useradd", ["useradd", "eve"], pid=6001, ppid=6000))
        rec = wait_for(lambda: next((r for r in _spooled(m) if r["rule_id"] == USERADD_RULE), None))
        assert rec["event"]["process.pid"] == 6001
        time.sleep(1.0)
        assert [r["event"]["process.pid"] for r in _spooled(m) if r["rule_id"] == USERADD_RULE] == [6001]
    finally:
        m.stop()


def test_restart_mid_counting_window_keeps_the_count(tmp_path):
    m, data = _manager(tmp_path)
    m.apply(_config([_counting_pack()]))
    now = time.time()
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        append(data, *[journal_entry(i, now + i, failed_ssh("bob", "192.0.2.7"), comm="sshd") for i in (1, 2)])
        wait_for(lambda: m.last_ts["journal"] is not None and m.last_ts["journal"] >= now + 1.9)
    finally:
        m.stop()
    assert not _spooled(m)
    m2, _ = _manager(tmp_path)
    m2.load_saved()
    try:
        wait_for(lambda: m2.state["journal"]["state"] == "watching")
        append(data, *[journal_entry(i, now + i, failed_ssh("bob", "192.0.2.7"), comm="sshd") for i in (3, 4)])
        rec = wait_for(lambda: next(iter(_spooled(m2)), None))
        assert rec["rule_id"] == "SIGMA-AB12CD34" and rec["count"] == 4 and rec["group"] == "192.0.2.7"
        argv = [json.loads(l) for l in Path(str(data) + ".argv").read_text().splitlines()]
        assert any(a.startswith("--after-cursor=") for a in argv[-1])   # resumed from its checkpoint
    finally:
        m2.stop()


def test_catch_up_stops_at_the_limit_and_records_the_gap(tmp_path):
    old = time.time() - 3 * 3600
    # a checkpoint from 3 h ago: more than the 1 h catch-up limit
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "watch_checkpoint.json").write_text(json.dumps(
        {"journal_cursor": journal_entry(1, old, "x")["__CURSOR"], "journal_ts": old, "seq": 0}))
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()], max_catchup_seconds=3600))
    try:
        gap = wait_for(lambda: next(iter(m.gaps["journal"]), None))
        assert "catch-up limit" in gap["reason"] and gap["from"] == pytest.approx(old, abs=1)
        assert gap["to"] == pytest.approx(time.time() - 3600, abs=30)
        argv = json.loads(Path(str(data) + ".argv").read_text().splitlines()[-1])
        assert "--since" in argv and not any(a.startswith("--after-cursor") for a in argv)
    finally:
        m.stop()


def test_a_vacuumed_journal_is_a_recorded_gap_not_a_silent_skip(tmp_path):
    t0 = time.time() - 600
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "watch_checkpoint.json").write_text(json.dumps(
        {"journal_cursor": journal_entry(5, t0, "x")["__CURSOR"], "journal_ts": t0, "seq": 0}))
    m, data = _manager(tmp_path)
    # the journal now starts at t0+300: what was between t0 and then is gone
    append(data, journal_entry(50, t0 + 300, "y", comm="sshd"))
    m.apply(_config([_shipped()]))
    try:
        gap = wait_for(lambda: next(iter(m.gaps["journal"]), None))
        assert "removed" in gap["reason"] and gap["from"] == pytest.approx(t0, abs=1)
        assert gap["to"] == pytest.approx(t0 + 300, abs=1)
    finally:
        m.stop()


def test_journalctl_exiting_is_restarted_from_its_cursor_without_repeats(tmp_path):
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        now = time.time()
        append(data, journal_entry(1, now, sudo_line("alice", "/usr/bin/chattr -i /a"), comm="sudo"))
        wait_for(lambda: len(_spooled(m)) == 1)
        append(data, {"__EXIT__": 1})
        wait_for(lambda: m.state["journal"]["state"] == "restarting")
        assert "fake failure" in (m.state["journal"]["error"] or "")
        append(data, journal_entry(2, now + 1, sudo_line("alice", "/usr/bin/chattr -i /b"), comm="sudo"))
        wait_for(lambda: len(_spooled(m)) == 2, timeout=15)
        time.sleep(0.5)
        assert len(_spooled(m)) == 2        # the first one was not evaluated again
        assert m.state["journal"]["state"] == "watching"
    finally:
        m.stop()


def test_oversized_and_bad_utf8_entries_are_skipped_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "MAX_ENTRY_BYTES", 4096)
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        now = time.time()
        big = journal_entry(1, now, "z" * 10000, comm="sshd")
        bad = '{"__CURSOR": "' + journal_entry(2, now, "")["__CURSOR"] + '", "__REALTIME_TIMESTAMP": "' + \
            str(int(now * 1e6)) + '", "_COMM": "sudo", "MESSAGE": "\xff\xfe' + \
            sudo_line("alice", "/usr/bin/chattr -i /c") + '"}\n'
        append(data, big, {"__RAW__": "not json at all\n"}, {"__RAW__": bad})
        rec = wait_for(lambda: next(iter(_spooled(m)), None))
        assert rec["rule_id"] == CHATTR_RULE        # the bad bytes didn't stop the line being judged
        assert m.skipped["journal"] == 2
        assert m.state["journal"]["state"] == "watching"
    finally:
        m.stop()


def test_audit_log_rotation_mid_follow_and_truncation(tmp_path):
    audit = tmp_path / "audit.log"
    audit.write_text("")
    m, _ = _manager(tmp_path, audit=audit)
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["auditd"]["state"] == "watching")
        now = time.time()
        write_audit(audit, audit_exec(now, 1, "/usr/sbin/useradd", ["useradd", "a1"], pid=7001))
        os.rename(audit, str(audit) + ".1")              # auditd rotates
        audit.write_text("")
        write_audit(audit, audit_exec(now + 1, 2, "/usr/sbin/useradd", ["useradd", "a2"], pid=7002))
        wait_for(lambda: {r["event"]["process.pid"] for r in _spooled(m) if r["rule_id"] == USERADD_RULE}
                 == {7001, 7002})
        with open(audit, "w"):
            pass                                          # truncated under the watcher
        gap = wait_for(lambda: next((g for g in m.gaps["auditd"] if "truncated" in g["reason"]), None))
        assert gap["to"] >= gap["from"]
        write_audit(audit, audit_exec(now + 2, 3, "/usr/sbin/useradd", ["useradd", "a3"], pid=7003))
        wait_for(lambda: 7003 in {r["event"]["process.pid"] for r in _spooled(m)})
    finally:
        m.stop()


def test_spool_bound_drops_the_oldest_and_reports_it(tmp_path):
    sp = W.Spool(str(tmp_path / "spool.jsonl"), max_items=3, max_bytes=10**6)
    for i in range(1, 6):
        sp.add({"seq": i, "ts": 1000.0 + i, "rule_id": "R"})
    assert list(sp.items) == [3, 4, 5] and sp.dropped == 2
    assert sp.dropped_first == 1001.0 and sp.dropped_last == 1002.0
    sp.ack([3])
    again = W.Spool(str(tmp_path / "spool.jsonl"), max_items=3, max_bytes=10**6)
    assert list(again.items) == [4, 5]                    # survives a restart, acked ones gone
    assert [r["seq"] for r in again.due(time.time(), 10)] == [4, 5]
    again.mark_sent(4, time.time())
    assert [r["seq"] for r in again.due(time.time(), 10)] == [5]
    assert [r["seq"] for r in again.due(time.time() + W.RESEND_SECONDS + 1, 10)] == [4, 5]


def test_a_spool_overflow_while_the_link_is_down_is_a_gap(tmp_path):
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()], spool_max_detections=100, max_per_rule_minute=1000))
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        now = time.time()
        append(data, *[journal_entry(i, now, sudo_line("alice", f"/usr/bin/chattr -i /f{i}"), comm="sudo")
                       for i in range(1, 151)])
        wait_for(lambda: m.spool.dropped >= 50, timeout=20)
        gap = wait_for(lambda: next((g for g in m.gaps["journal"] if g.get("kind") == "spool"), None))
        assert "dropped" in gap["reason"]
        assert len(m.spool) == 100
    finally:
        m.stop()


def test_flood_is_capped_per_rule_per_minute_with_one_summary(tmp_path):
    m, data = _manager(tmp_path)
    m.apply(_config([_shipped()], max_per_rule_minute=20))
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        now = time.time()
        if now % 60 > 50:
            time.sleep(61 - now % 60)
            now = time.time()
        minute = (int(now) // 60) * 60.0
        append(data, *[journal_entry(i, now + (i % 50) / 1000, sudo_line("alice", f"/usr/bin/chattr -i /x{i}"),
                                     comm="sudo") for i in range(1, 2001)])
        wait_for(lambda: m.last_ts["journal"] is not None and m.queue.empty() and m.events["journal"]
                 and len(m.events["journal"]) >= 2000, timeout=60)
        m._minute_summaries(minute + 180)                 # the minute is over
        recs = [r for r in _spooled(m) if r["rule_id"] == CHATTR_RULE]
        single = [r for r in recs if "summary" not in r]
        summary = [r for r in recs if "summary" in r]
        assert len(single) == 20
        assert len(summary) == 1 and summary[0]["summary"]["suppressed"] == 1980
        # what goes over the link stays bounded: 21 messages for 2000 matching lines
        size = sum(len(json.dumps(r)) for r in recs)
        assert size < 21 * 4096
    finally:
        m.stop()


def test_cpu_budget_slows_a_catch_up_and_reports_it(tmp_path):
    m, data = _manager(tmp_path)
    now = time.time()
    append(data, *[journal_entry(i, now + 5 + i / 1000, failed_ssh("u", "198.51.100.9"), comm="sshd")
                   for i in range(1, 6001)])
    m.apply(_config([_shipped()], max_cpu_percent=5))
    try:
        wait_for(lambda: m.throttled_seconds > 0, timeout=60)
    finally:
        m.stop()


def test_a_clock_jump_back_on_the_machine_does_not_join_two_bursts(tmp_path):
    pack = D.load_pack(_counting_pack())
    ev = D.Evaluator(pack)
    base = 1_000_000.0

    def fail(i: int, ts: float) -> list:
        return ev.evaluate({"event.id": f"{i:032x}", "event.dataset": "kratos.auth", "event.provider": "sshd",
                            "event.action": "ssh_failed_login", "source.ip": "192.0.2.7"}, ts)

    assert not fail(1, base) and not fail(2, base + 1) and not fail(3, base + 2)
    # the clock jumps back an hour: three more failures must not complete the first burst
    assert not fail(4, base - 3600) and not fail(5, base - 3599)
    assert not fail(6, base - 3598)
    assert fail(7, base - 3597)                           # a real burst of four, after the jump


def test_pushes_are_validated_whole(tmp_path):
    good = _counting_pack(version=2)
    held = {"packs": W.pack_summary({"packs": [good]})}
    older = _counting_pack(version=1)
    with pytest.raises(W.WatchError, match="older"):
        W.validate_push({"enabled": True, "machine": MACHINE, "packs": [older]}, held)
    tampered = dict(good, rules=[dict(good["rules"][0], title="changed")])
    with pytest.raises(W.WatchError, match="refused"):
        W.validate_push({"enabled": True, "machine": MACHINE, "packs": [tampered]}, None)
    with pytest.raises(W.WatchError, match="unknown setting"):
        W.validate_push({"enabled": True, "machine": MACHINE, "packs": [good], "settings": {"run": 1}}, None)
    with pytest.raises(W.WatchError, match="rule id"):
        W.validate_push({"enabled": True, "machine": MACHINE, "packs": [good], "disabled": ["; rm -rf /"]}, None)
    with pytest.raises(W.WatchError, match="machine"):
        W.validate_push({"enabled": True, "machine": "A B", "packs": [good]}, None)
    cfg = W.validate_push({"enabled": True, "machine": MACHINE, "packs": [good],
                           "disabled": ["SIGMA-AB12CD34"]}, held)
    assert cfg["disabled"] == ["SIGMA-AB12CD34"]


def test_disabled_rules_are_not_evaluated_and_the_config_survives_a_restart(tmp_path):
    m, data = _manager(tmp_path)
    cfg = W.validate_push({"enabled": True, "machine": MACHINE, "packs": [_shipped()], "disabled": [CHATTR_RULE]},
                          None)
    m.apply(cfg)
    try:
        wait_for(lambda: m.state["journal"]["state"] == "watching")
        append(data, journal_entry(1, time.time(), sudo_line("alice", "/usr/bin/chattr -i /d"), comm="sudo"))
        wait_for(lambda: m.last_ts["journal"] is not None)
        time.sleep(0.3)
        assert not [r for r in _spooled(m) if r["rule_id"] == CHATTR_RULE]
    finally:
        m.stop()
    m2, _ = _manager(tmp_path)
    m2.load_saved()
    try:
        assert m2.enabled and m2.config["disabled"] == [CHATTR_RULE]
        assert (tmp_path / "state" / "watch_config.json").stat().st_mode & 0o077 == 0
    finally:
        m2.stop()


def test_journal_argv_is_fixed_and_refuses_a_bad_cursor():
    argv = W.journal_argv(None, None)
    assert argv[:5] == ["journalctl", "--no-pager", "--follow", "-o", "json"]
    assert "_COMM=sshd" in argv and "_PID=1" in argv and "_TRANSPORT=kernel" in argv
    with pytest.raises(ValueError):
        W.journal_argv("s=1;i=1; --output=export", None)


def test_a_stopped_auditd_is_not_watching_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "AUDITD_CHECK_SECONDS", 0.2)
    audit = tmp_path / "audit.log"
    audit.write_text("")
    m, _ = _manager(tmp_path, audit=audit)
    running = {"on": True}
    m.check_auditd = lambda: running["on"]
    m.apply(_config([_shipped()]))
    try:
        wait_for(lambda: m.state["auditd"]["state"] == "watching")
        running["on"] = False                      # auditd stopped: its log just stops growing
        wait_for(lambda: m.state["auditd"]["state"] == "error")
        assert "auditd isn't running" in m.state["auditd"]["error"]
        running["on"] = True
        wait_for(lambda: m.state["auditd"]["state"] == "watching")
    finally:
        m.stop()
