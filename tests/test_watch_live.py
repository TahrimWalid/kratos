"""Continuous detection, Kratos's side (C.2, kratos.detect.live): turning it on (people
only, trusted link, new enough agent), detections from an agent through the one
detection -> finding -> trigger -> notify path, de-duplication with the scheduled pass,
DETECT-002 health, and parity: an agent judges a line exactly as Kratos judges the
stored line."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from kratos import settings_store
from kratos.agent import triggers as T
from kratos.detect import live as L
from kratos.detect import run as R
from kratos.detect import store as ST
from kratos.detect.flat import flat
from kratos.events import assemble as A
from kratos.events.recording import events_for_log_read
from kratos.events.store import EventStore
from kratos.lifecycle.decide import Actor
from kratos.logsources.logread import LogRead, Record
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import detect as D
from kratos.subagent import watch as W

from tests._watch_fakes import audit_exec, cursor, failed_ssh, journal_entry, sudo_line

MACHINE = "198.51.100.30"
PERSON = Actor(user="alice", interface="cli")
CHATTR_RULE = "SIGMA-34979410"
USERADD_RULE = "SIGMA-759D0D51"
READ_CONTEXT = {"event.created", "kratos.transport", "kratos.read", "kratos.run_id", "kratos.window",
                "kratos.coverage"}


# ---------------------------------------------------------------------------- parity
def _journal_corpus(now: float) -> list[tuple[str, dict]]:
    return [
        ("auth", journal_entry(1, now, failed_ssh("bob", "192.0.2.7"), comm="sshd")),
        ("auth", journal_entry(2, now + 1, sudo_line("alice", "/usr/bin/chattr -i /etc/hostname"), comm="sudo")),
        ("auth", journal_entry(3, now + 2, "Accepted publickey for carol from 203.0.113.5 port 4022 ssh2: ED25519 "
                                           "SHA256:abc", comm="sshd-session")),
        ("auth", journal_entry(4, now + 3, sudo_line("alice", "/usr/bin/mysql -psecretpass db"), comm="sudo")),
        ("cron", journal_entry(5, now + 4, "(root) REPLACE (ubuntu)", ident="crontab", comm="crontab")),
        ("cron", journal_entry(6, now + 5, "(root) CMD (run-parts /etc/cron.hourly)", ident="CRON", comm="cron")),
        ("systemd_pid1", dict(journal_entry(7, now + 6, "Started Daily apt download activities.", ident="systemd",
                                            pid=1), UNIT="apt-daily.timer")),
        ("kernel", journal_entry(8, now + 7, "[UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=192.0.2.9 DST=198.51.100.30 LEN=60 "
                                             "PROTO=TCP SPT=40000 DPT=23 WINDOW=1 SYN", transport="kernel",
                                 ident="kernel")),
        ("auth", journal_entry(9, now + 8, "bad \udcff byte " + failed_ssh("eve", "192.0.2.8"), comm="sshd")),
    ]


def _core_flat(source: str, entries: list[dict]) -> list[dict]:
    read = LogRead(source={"auth": "auth", "cron": "cron", "systemd_pid1": "systemd", "kernel": "firewall"}[source],
                   via="agent", has_journal=True)
    read.records = [Record(kind="journal", ts=int(e["__REALTIME_TIMESTAMP"]) / 1e6, entry=e, match=source)
                    for e in entries]
    read.read_label = "log_sync"
    return [flat(ev) for ev in events_for_log_read(MACHINE, read)]


def _strip(d: dict) -> dict:
    return {k: v for k, v in d.items() if k not in READ_CONTEXT}


def test_agent_and_kratos_turn_the_same_journal_lines_into_the_same_events():
    now = 1_790_000_000.0
    for source, entry in _journal_corpus(now):
        agent = W.journal_values(entry, MACHINE)
        core = _core_flat(source, [entry])
        assert agent is not None and len(core) == 1, entry["MESSAGE"]
        assert _strip(A.flat(agent)) == _strip(core[0]), entry["MESSAGE"]


def test_agent_and_kratos_turn_the_same_audit_records_into_the_same_event():
    lines = audit_exec(1_790_000_100.0, 77, "/usr/bin/sshpass", ["sshpass", "-p", "hunter2x", "ssh", "x@y"])
    agent = W.audit_values(lines, "/var/log/audit/audit.log", MACHINE)
    read = LogRead(source="auditd", via="agent")
    read.records = [Record(kind="file", ts=1_790_000_100.0, text=t, path="/var/log/audit/audit.log")
                    for t in reversed(lines)]
    read.read_label = "log_sync"
    core = [flat(ev) for ev in events_for_log_read(MACHINE, read)]
    assert len(core) == 1
    assert _strip(A.flat(agent)) == _strip(core[0])
    assert "hunter2x" not in json.dumps(A.flat(agent))       # masked on the machine already


def test_the_same_lines_raise_the_same_matches_on_both_sides():
    from kratos.detect import pack as P

    pack = P.shipped().pack
    now = 1_790_000_000.0
    agent_ev, core_ev = D.Evaluator(pack), D.Evaluator(pack)
    for source, entry in _journal_corpus(now):
        a = [m.as_dict() for m in agent_ev.evaluate(A.flat(W.journal_values(entry, MACHINE)), now)]
        c = [m.as_dict() for m in core_ev.evaluate(_core_flat(source, [entry])[0], now)]
        assert a == c


# ---------------------------------------------------------------------------- turning it on
def _paired(tmp_path: Path, *, version: str = "0.9.0", link: str = "tls-pinned") -> tuple[SubAgentStore, str]:
    store = SubAgentStore(tmp_path / "kratos.db")
    code = store.create_pairing_code(name="db-01")
    res = store.redeem_pairing_code(code["code"], agent_id="a1", hostname="db-01", agent_version=version)
    tid = res["target_id"]
    store.record_link(tid, mode=link, pin_version=1 if link == "tls-pinned" else None)
    store.set_link(MACHINE, tid, "subagent")
    return store, tid


def test_turning_watching_on_is_for_people_with_a_new_agent_on_an_encrypted_link(tmp_path, monkeypatch):
    _store, tid = _paired(tmp_path)
    monkeypatch.setattr(settings_store, "in_tool_call", lambda: "run_linux_command")
    with pytest.raises(L.WatchSetupError, match="agent tools may not"):
        L.set_watching(tmp_path, tid, True, actor=PERSON)
    monkeypatch.undo()
    with pytest.raises(L.WatchSetupError, match="person"):
        L.set_watching(tmp_path, tid, True, actor=Actor(user="", interface="cli"))
    st = L.set_watching(tmp_path, tid, True, actor=PERSON)
    assert st["enabled"] and st["machine"] == MACHINE and st["changed_by"] == "alice via cli"
    version, cfg = L.sync_version(tmp_path, tid)
    assert version == 1 and cfg["enabled"] and cfg["packs"] and cfg["machine"] == MACHINE
    assert L.sync_version(tmp_path, tid)[0] == 1        # unchanged: same version
    ST.set_rule_enabled(tmp_path, CHATTR_RULE, False, target=MACHINE, reason="expected here", actor=PERSON)
    version, cfg = L.sync_version(tmp_path, tid)
    assert version == 2 and cfg["disabled"] == [CHATTR_RULE]
    L.set_watching(tmp_path, tid, False, actor=PERSON)
    version, cfg = L.sync_version(tmp_path, tid)
    assert version == 3 and cfg["enabled"] is False and cfg["packs"] == []


def test_an_old_agent_or_a_plaintext_link_cannot_be_turned_on(tmp_path):
    _store, old = _paired(tmp_path / "a", version="0.8.0")
    with pytest.raises(L.WatchSetupError, match=r"update the agent to watch continuously.*g"):
        L.set_watching(tmp_path / "a", old, True, actor=PERSON)
    _store, plain = _paired(tmp_path / "b", link="plaintext")
    with pytest.raises(L.WatchSetupError, match="encrypted"):
        L.set_watching(tmp_path / "b", plain, True, actor=PERSON)


# ---------------------------------------------------------------------------- detections
def _detection(entry: dict, *, seq: int = 1) -> dict:
    """What an agent sends for `entry` (built with the agent's own code)."""
    from kratos.detect import pack as P

    values = W.journal_values(entry, MACHINE)
    event = A.flat(values)
    ev = D.Evaluator(P.shipped().pack)
    m = ev.evaluate(event, values["timestamp"].timestamp())[0]
    rule = P.shipped().pack.by_id[m.rule_id].meta
    return {"type": "detection", "seq": seq, "rule_id": m.rule_id, "pack_id": "sigma-linux", "pack_version": 1,
            "ts": m.ts, "first_ts": m.first_ts, "source": "journal", "position": entry["__CURSOR"],
            "event": W.bounded_event(event, W._rule_fields(rule)), "group": m.group, "count": m.count,
            "event_ids": m.event_ids}


def _watching(tmp_path: Path) -> str:
    _store, tid = _paired(tmp_path)
    L.set_watching(tmp_path, tid, True, actor=PERSON)
    return tid


def test_a_detection_is_stored_once_and_the_scheduled_pass_does_not_store_it_again(tmp_path):
    tid = _watching(tmp_path)
    now = time.time() - 60
    entry = journal_entry(1, now, sudo_line("alice", "/usr/bin/chattr -i /etc/hostname"), comm="sudo")
    live = L.LiveDetections(tmp_path)
    assert live.handle_detection(tid, _detection(entry)) is True
    assert live.handle_detection(tid, _detection(entry)) is True        # sent again: acknowledged, not stored twice
    dets = EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=100)
    assert len(dets) == 1 and dets[0].rule_id == CHATTR_RULE and dets[0].read == "watch"
    assert live.stats["stored"] == 1 and live.stats["duplicates"] == 1
    # log sync brings the full line later; the scheduled pass over it finds the same match
    read = LogRead(source="auth", via="agent", has_journal=True)
    read.records = [Record(kind="journal", ts=int(entry["__REALTIME_TIMESTAMP"]) / 1e6, entry=entry, match="auth")]
    EventStore(tmp_path / "kratos.db").add(events_for_log_read(MACHINE, read))
    assert dets[0].detect_matched == tuple(e.event_id for e in events_for_log_read(MACHINE, read))
    R.run_pass(MACHINE, tmp_path)
    assert len(EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=100)) == 1


def test_malformed_or_unknown_detections_are_acknowledged_and_dropped(tmp_path):
    tid = _watching(tmp_path)
    live = L.LiveDetections(tmp_path)
    for bad in ({"rule_id": "SIGMA-00000000", "event": {}}, {"rule_id": "x; rm", "event": {}},
                {"rule_id": CHATTR_RULE, "event": {"event.id": "../../etc", "@timestamp": "now"}},
                {"rule_id": CHATTR_RULE, "event": "not a dict"}):
        assert live.handle_detection(tid, {"type": "detection", "seq": 1, "ts": time.time(), **bad}) is True
    assert EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=10) == []
    assert live.stats["dropped"] == 4


def test_a_detection_for_a_machine_no_longer_watched_is_dropped(tmp_path):
    tid = _watching(tmp_path)
    L.set_watching(tmp_path, tid, False, actor=PERSON)
    live = L.LiveDetections(tmp_path)
    entry = journal_entry(1, time.time(), sudo_line("alice", "/usr/bin/chattr -i /x"), comm="sudo")
    assert live.handle_detection(tid, _detection(entry)) is True
    assert EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=10) == []


class _Notifier:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def __call__(self, body: str, severity: str) -> dict:
        self.sent.append((body, severity))
        return {"status": "sent"}


def _trigger(tmp_path: Path, **kw) -> None:
    T.save_trigger(tmp_path, name=kw.pop("name", "live-high"), min_severity=kw.pop("min_severity", "medium"),
                   finding_id=kw.pop("finding_id", None), target=None, action=kw.pop("action", "notify"),
                   cooldown_minutes=kw.pop("cooldown_minutes", 15), only_new_or_reopened=kw.pop("only_new", True))


def test_one_burst_of_live_detections_is_one_alert_naming_the_rules_and_their_authors(tmp_path):
    tid = _watching(tmp_path)
    _trigger(tmp_path)
    live = L.LiveDetections(tmp_path)
    now = time.time() - 30
    for i, cmd in enumerate(("/usr/bin/chattr -i /a", "/usr/bin/chattr -i /b")):
        live.handle_detection(tid, _detection(journal_entry(i + 1, now + i, sudo_line("alice", cmd), comm="sudo"),
                                              seq=i + 1))
    settings_store.set("detect.alert_batch_seconds", 1, data_dir=tmp_path, actor="test")
    assert live.due() == []                      # still collecting the batch
    time.sleep(1.1)
    due = live.due()
    assert [m for m, _b in due] == [MACHINE]
    note = _Notifier()
    out = live.publish(MACHINE, due[0][1], notifier=note)
    assert len(note.sent) == 1
    body = note.sent[0][0]
    assert CHATTR_RULE in body and "rule by" in body and "(Sigma, DRL-1.1)" in body
    f = next(x for x in out["findings"] if x["id"] == CHATTR_RULE)
    assert any("Seen live" in e for e in f["evidence"]) and f["state"] == "open"
    # more matches of the same finding a minute later: still open, not news again
    live.handle_detection(tid, _detection(journal_entry(9, now + 9, sudo_line("alice", "/usr/bin/chattr -i /c"),
                                                        comm="sudo"), seq=9))
    time.sleep(1.1)
    machine, batch = live.due()[0]
    live.publish(machine, batch, notifier=note)
    assert len(note.sent) == 1


def test_an_investigate_trigger_from_a_live_alert_respects_the_budget_switch(tmp_path):
    tid = _watching(tmp_path)
    _trigger(tmp_path, action="investigate")
    from kratos.budget import guard

    guard.ensure_upgrade_migration(tmp_path)        # (an upgrade would carry an investigating trigger's choice over)
    settings_store.set("budget.trigger_investigations_allowed", False, data_dir=tmp_path, actor="test")
    live = L.LiveDetections(tmp_path)
    live.handle_detection(tid, _detection(journal_entry(1, time.time(), sudo_line("alice", "/usr/bin/chattr -i /a"),
                                                        comm="sudo")))
    calls: list = []
    note = _Notifier()
    L.publish(tmp_path, MACHINE, rules={CHATTR_RULE}, notifier=note,
              investigate_fn=lambda goal, d: calls.append(goal) or {"status": "done"})
    assert calls == [] and "may not start investigations" in note.sent[0][0]


# ---------------------------------------------------------------------------- health: DETECT-002
def _status(state: str = "watching", *, gaps: list | None = None, error: str | None = None) -> dict:
    return {"type": "watch_status", "enabled": True, "sources": [
        {"name": "journal", "state": state, "since": time.time() - 3600, "last_event_ts": time.time(),
         "events_per_min": 3, "matches": 0, "lag_seconds": 0, "dropped": 0, "skipped": 0, "gaps": gaps or [],
         "error": error},
        {"name": "auditd", "state": "watching", "since": time.time() - 3600, "last_event_ts": time.time(),
         "events_per_min": 1, "matches": 0, "lag_seconds": 0, "dropped": 0, "skipped": 0, "gaps": [], "error": None}]}


def _detect002(tmp_path: Path, live: dict | None = None) -> dict | None:
    out = L.publish(tmp_path, MACHINE, health_changed=True, live=live, notifier=_Notifier())
    return next((f for f in out["findings"] if f["id"] == "DETECT-002"), None)


def test_each_cause_opens_detect_002_and_it_closes_when_watching_resumes(tmp_path):
    tid = _watching(tmp_path)
    L.record_ack(tmp_path, tid, {"version": 1, "status": "ok"})
    handler = L.LiveDetections(tmp_path)
    up = {tid: (True, None)}
    handler.handle_status(tid, _status())
    assert _detect002(tmp_path, up) is None and L.health(tmp_path, tid, connected=True).healthy
    # 1. the watcher stopped
    handler.handle_status(tid, _status("error", error="journalctl: permission denied"))
    f = _detect002(tmp_path, up)
    assert f and f["severity"] == "medium" and "stopped:journal" in f["entities"]
    assert f["title"] == "Continuous detection isn't running on this machine"
    assert any("permission denied" in e for e in f["evidence"])
    # it closes by itself once the watcher reports watching again
    handler.handle_status(tid, _status())
    assert _detect002(tmp_path, up) is None
    from kratos.lifecycle import query as Q

    recs = [r for r in Q.list_findings(tmp_path, target=MACHINE, state="all") if r["rule_id"] == "DETECT-002"]
    assert recs and recs[0]["state"] == "mitigated"
    # 2. the link down longer than detect.watch.offline_minutes
    f = _detect002(tmp_path, {tid: (False, time.time() - 11 * 60)})
    assert f and "link_down" in f["entities"]
    assert _detect002(tmp_path, {tid: (False, time.time() - 60)}) is None      # not yet that long
    # 3. connected, but no watch status for over 3 minutes
    conn = ST._connect(tmp_path)
    conn.execute("UPDATE detect_pack_state SET last_status_at = ?", (time.time() - 400,))
    conn.commit()
    conn.close()
    f = _detect002(tmp_path, up)
    assert f and "no_status" in f["entities"]
    handler.handle_status(tid, _status())
    # 4. a stretch not watched (catch-up limit, vacuum, spool overflow)
    handler.handle_status(tid, _status(gaps=[{"from": time.time() - 9000, "to": time.time() - 3000,
                                              "reason": "older than the catch-up limit (1 h)", "kind": "watch"}]))
    f = _detect002(tmp_path, up)
    assert f and "gap:journal" in f["entities"] and any("catch-up limit" in e for e in f["evidence"])
    assert f["title"] == "Continuous detection missed part of this machine's logs"
    # 5. the agent refused the rules
    L.record_ack(tmp_path, tid, {"version": 2, "status": "refused", "reason": "a rule pack was refused: bad"})
    assert "rules_refused" in L.health(tmp_path, tid, connected=True).codes


def test_health_changes_are_noticed_once(tmp_path):
    tid = _watching(tmp_path)
    L.record_ack(tmp_path, tid, {"version": 1, "status": "ok"})
    L.LiveDetections(tmp_path).handle_status(tid, _status())
    assert L.health_changes(tmp_path, live={tid: (True, None)}) == []
    assert L.health_changes(tmp_path, live={tid: (False, time.time() - 3600)}) == [MACHINE]
    assert L.health_changes(tmp_path, live={tid: (False, time.time() - 3600)}) == []
    assert L.health_changes(tmp_path, live={tid: (True, None)}) == [MACHINE]


def test_a_watched_log_source_is_not_listed_as_unchecked(tmp_path):
    tid = _watching(tmp_path)
    L.LiveDetections(tmp_path).handle_status(tid, _status())
    out = L.publish(tmp_path, MACHINE, notifier=_Notifier())
    note = next((f for f in out["findings"] if f["id"] == "DETECT-001"), None)
    text = json.dumps(note or {})
    assert "audit log rules" not in text and "SSH server log rules" not in text
    doc = json.loads(Path(out["snapshot"]).read_text())
    assert doc["watch"]["enabled"] and doc["source"] == "live"


def test_a_spool_summary_counts_toward_the_findings_matches(tmp_path):
    tid = _watching(tmp_path)
    live = L.LiveDetections(tmp_path)
    now = time.time() - 30
    live.handle_detection(tid, _detection(journal_entry(1, now, sudo_line("a", "/usr/bin/chattr -i /a"),
                                                        comm="sudo")))
    live.handle_detection(tid, {"type": "detection", "seq": 2, "rule_id": CHATTR_RULE, "pack_id": "sigma-linux",
                                "pack_version": 1, "ts": now + 50, "first_ts": now + 1,
                                "summary": {"suppressed": 480, "minute": (now // 60) * 60}})
    out = L.publish(tmp_path, MACHINE, notifier=_Notifier())
    f = [x for x in out["findings"] if x["id"] == CHATTR_RULE]
    assert sum(x["detection_rule"]["matches"] for x in f) == 481


# ---------------------------------------------------------------------------- safety
def test_nothing_on_the_detection_path_can_execute_or_change_a_machine():
    """No route from a detection to the fix channel or a command: the live handler and the
    watcher name none of it, and the watcher starts exactly one kind of process."""
    import ast
    import inspect

    from kratos.detect import live as live_mod
    from kratos.subagent import watch as watch_mod

    forbidden = ("dispatch_action", "exec_dispatch", "push_whitelist", "dispatch_request", "run_linux_command",
                 "execute_tool_call",
                 "_run_argv", "os.system(", "os.kill", "shell=True")
    for mod in (live_mod, watch_mod):
        src = inspect.getsource(mod)
        for word in forbidden:
            assert word not in src, (mod.__name__, word)
    popen = [n for n in ast.walk(ast.parse(inspect.getsource(watch_mod)))
             if isinstance(n, ast.Call) and getattr(n.func, "attr", None) in ("Popen", "run", "call", "check_output")]
    assert len(popen) == 2      # journalctl --follow (journal_argv) and the oldest-entry query (fixed list)
    for call in popen:
        argv = call.args[0]
        assert isinstance(argv, ast.Name) and argv.id == "argv" or isinstance(argv, ast.List), ast.dump(argv)


def test_the_watch_api_needs_the_new_agent_version():
    from kratos.subagent import agent

    assert L.agent_can_watch(agent.AGENT_VERSION)
    assert not L.agent_can_watch("0.8.0") and not L.agent_can_watch("0.7.1") and not L.agent_can_watch(None)


def test_cursor_helper_is_a_valid_journal_cursor():
    from kratos.logsources.logread import valid_cursor

    assert valid_cursor(cursor(5, 1_790_000_000.0))


def test_a_reported_gap_is_published_once(tmp_path):
    tid = _watching(tmp_path)
    L.record_ack(tmp_path, tid, {"version": 1, "status": "ok"})
    live = L.LiveDetections(tmp_path)
    live.handle_status(tid, _status())
    live.handle_status(tid, _status(gaps=[{"from": time.time() - 300, "to": time.time() - 200,
                                          "reason": "journal entries were removed", "kind": "watch"}]))
    assert [m for m, _b in live.due()] == [MACHINE]                    # a health change goes out at once
    assert L.health_changes(tmp_path, live={tid: (True, None)}) == []  # ...and isn't published again
    live.handle_status(tid, _status(gaps=[{"from": time.time() - 300, "to": time.time() - 200,
                                          "reason": "journal entries were removed", "kind": "watch"}]))
    assert live.due() == []                                            # the same gap reported again: nothing new


def test_a_gap_the_agent_keeps_up_to_date_stays_one_gap(tmp_path):
    tid = _watching(tmp_path)
    live = L.LiveDetections(tmp_path)
    t = time.time()
    for n, end in ((10, t - 50), (40, t - 20), (90, t)):
        live.handle_status(tid, _status(gaps=[{"id": 7, "from": t - 60, "to": end, "kind": "spool",
                                              "reason": f"{n} detection(s) dropped: the link was down longer than "
                                                        "the spool holds"}]))
    gaps = {r["source"]: r["gaps"] for r in L.watch_rows(tmp_path, tid)}["journal"]
    assert len(gaps) == 1 and gaps[0]["reason"].startswith("90 ") and gaps[0]["to"] == pytest.approx(t)


def test_a_busy_watched_machine_never_hides_another_machines_detections(tmp_path):
    """Phase C audit: every live alert batch wrote a new timestamped snapshot, and the
    latest-snapshot lookup reads only the newest 100 files -- so within minutes one busy
    watched machine pushed every other machine's detection snapshot out of view (its SIGMA
    findings and coverage then vanished from answers, /detect and the lifecycle)."""
    from kratos.adapters.findings_engine import find_latest_inputs
    from kratos.detect.findings import RESULTS_DIR

    other = "198.51.100.31"
    R.run_pass(other, tmp_path)
    assert find_latest_inputs(tmp_path, other)["detections"] is not None
    for _ in range(120):
        L.publish(tmp_path, MACHINE, notifier=_Notifier())
    assert find_latest_inputs(tmp_path, other)["detections"] is not None
    assert find_latest_inputs(tmp_path, MACHINE)["detections"] is not None
    # and the live path keeps ONE current snapshot per machine, not one per batch
    live_files = [p for p in (tmp_path / RESULTS_DIR).glob("detections_*.json")
                  if json.loads(p.read_text())["source"] == "live"]
    assert len(live_files) == 1


def test_a_live_kratos_rule_finding_names_the_group_and_says_it_was_seen_watching(tmp_path):
    """Phase C audit: a new sudo account on a machine without auditd is caught live by
    Kratos's own rule; the finding names the account AND the group (group.name crosses the
    link), and its history says "watching", not "scheduled"."""
    from kratos.detect import pack as P
    from kratos.lifecycle import query as Q

    tid = _watching(tmp_path)
    own = P.kratos_pack()
    entry = journal_entry(1, time.time() - 30, "add 'carol' to group 'sudo'", comm="useradd")
    values = W.journal_values(entry, MACHINE)
    event = A.flat(values)
    [m] = D.Evaluator(own.pack).evaluate(event, values["timestamp"].timestamp())
    rule = own.pack.by_id[m.rule_id].meta
    det = {"type": "detection", "seq": 1, "rule_id": m.rule_id, "pack_id": own.pack_id, "pack_version": own.version,
           "ts": m.ts, "first_ts": m.first_ts, "source": "journal", "position": entry["__CURSOR"],
           "event": W.bounded_event(event, W._rule_fields(rule)), "group": m.group, "count": m.count,
           "event_ids": m.event_ids}
    assert det["event"].get("group.name") == "sudo"
    assert L.LiveDetections(tmp_path).handle_detection(tid, det) is True
    out = L.publish(tmp_path, MACHINE, notifier=_Notifier())
    [f] = [x for x in out["findings"] if x["id"] == "KRATOS-ACCOUNT-PRIVILEGED-GROUP"]
    assert {"carol", "sudo"} <= set(f["entities"]) and f["severity"] == "high"
    key = next(r["finding_key"] for r in Q.list_findings(tmp_path, target=MACHINE, state="all")
               if r["rule_id"] == "KRATOS-ACCOUNT-PRIVILEGED-GROUP")
    _rec, _latest, history = Q.get_finding(tmp_path, key)
    assert history and history[0]["interface"] == "watching"


def test_a_live_root_login_with_kratos_own_key_is_set_aside(tmp_path, monkeypatch):
    """Kratos's SSH user may be root: the root-login rule reads the "Accepted" line, so the
    live match carries the key fingerprint and Kratos sets its own login aside."""
    from kratos.detect import own as own_mod
    from kratos.detect import pack as P

    fp, other = "SHA256:" + "A" * 43, "SHA256:" + "B" * 43
    monkeypatch.setattr(own_mod, "kratos_fingerprint", lambda: fp)
    tid = _watching(tmp_path)
    own = P.kratos_pack()
    rule = own.pack.by_id["KRATOS-SSH-ROOT-LOGIN"].meta
    live = L.LiveDetections(tmp_path)
    for i, key in enumerate((fp, other)):
        line = f"Accepted publickey for root from 198.51.100.7 port 50022 ssh2: ED25519 {key}"
        entry = journal_entry(i + 1, time.time() - 30 + i, line, comm="sshd")
        values = W.journal_values(entry, MACHINE)
        event = A.flat(values)
        [m] = [x for x in D.Evaluator(own.pack).evaluate(event, values["timestamp"].timestamp())
               if x.rule_id == "KRATOS-SSH-ROOT-LOGIN"]
        bounded = W.bounded_event(event, W._rule_fields(rule))
        assert key in bounded["message"]
        assert live.handle_detection(tid, {
            "type": "detection", "seq": i + 1, "rule_id": m.rule_id, "pack_id": own.pack_id,
            "pack_version": own.version, "ts": m.ts, "first_ts": m.first_ts, "source": "journal",
            "position": entry["__CURSOR"], "event": bounded, "group": m.group, "count": m.count,
            "event_ids": m.event_ids}) is True
    assert live.stats["own"] == 1 and live.stats["stored"] == 1
