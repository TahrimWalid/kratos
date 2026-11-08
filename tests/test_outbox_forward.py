"""D.4 forwarding producers: findings changes (lifecycle events) and host events, each
by a per-channel cursor -- no gap and no duplicate across restarts, batch limits, the
backlog bound, filters, email digests, and two changes to one finding delivered in order."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from kratos import kratos_config as kc
from kratos.lifecycle import apply as LA, decide as LD
from kratos.lifecycle.coverage import Coverage
from kratos.outbox import config as C
from kratos.outbox import forward as FW
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.store import Outcome
from kratos.run_context import RunContext

ACTOR = LD.Actor(user="alice", interface="cli")
M1, M2 = "198.51.100.7", "198.51.100.8"
ALL = Coverage(inputs={k: None for k in ("nmap_parsed", "auth_stats", "auth_patterns", "system_context",
                                          "auth_trends", "file_integrity", "privileged_accounts", "vuln_scan")})


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    return tmp_path


def _run(target=M1):
    return RunContext(run_id=uuid.uuid4().hex, source="interactive", target=target, session_id=None,
                      started_at=1_000_000.0)


def _f(rid="CORR-SSH-001", severity="high", entities=("203.0.113.9",)):
    return {"id": rid, "title": f"{rid} title", "severity": severity, "evidence": ["x"], "subject": "",
            "entities": list(entities)}


def _apply(dd, findings, target=M1, now=1_000_000.0, run=None):
    return LA.apply_run(findings, target=target, coverage=ALL, run=run or _run(target), data_dir=dd, now=now)


def _ch(dd, name="siem", kind="webhook", scopes=("findings",), fmt="ocsf", **kw):
    cfg = {"url": "https://siem.example/in"} if kind == "webhook" else \
        {"host": "mail.example", "from": "k@example.com", "to": "o@example.com"}
    return C.add_channel(dd, name=name, kind=kind, config=cfg, scopes=list(scopes), format=fmt, actor=ACTOR, **kw)


def _msgs(dd, channel="siem"):
    with S.opened(dd) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM outbox WHERE channel = ? ORDER BY id", (channel,))]


def test_a_new_channel_starts_from_now_and_forwards_each_change_once(dd):
    _apply(dd, [_f()])                                   # before the channel existed: not forwarded
    _ch(dd)
    assert FW.produce_findings(dd) == 0
    _apply(dd, [_f(), _f("PKG-001", "medium", ("CVE-2024-0001",))], now=1_000_100.0)
    assert FW.produce_findings(dd) == 1                  # the still-open brute force is not a change
    assert FW.produce_findings(dd) == 0                  # a second pass adds nothing
    (m,) = _msgs(dd)
    body = json.loads(json.loads(m["payload"])["body"])
    assert m["kind"] == "finding" and m["message_id"].startswith("finding:") and body["class_uid"] == 2002
    assert m["order_key"] == body["finding_info"]["uid"]


def test_a_decision_and_a_fix_are_forwarded_as_changes(dd):
    _ch(dd, fmt="kratos")
    _, summary = _apply(dd, [_f()])
    key = summary["new"][0]
    LD.mark_false_positive(key, actor=ACTOR, reason="our scanner", data_dir=dd, now=1_000_050.0)
    FW.produce_findings(dd)
    types = [json.loads(json.loads(m["payload"])["body"])["type"] for m in _msgs(dd)]
    assert types == ["kratos.finding.new", "kratos.finding.decided"]
    decided = json.loads(json.loads(_msgs(dd)[1]["payload"])["body"])["data"]
    assert decided["decided_by"] == "alice" and decided["to_state"] == "false_positive"


def test_the_same_finding_changing_twice_before_delivery_goes_out_twice_in_order(dd, monkeypatch):
    _ch(dd, fmt="kratos")
    _apply(dd, [_f(severity="medium")])
    _apply(dd, [_f(severity="high")], now=1_000_100.0)
    sent = []
    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd_: sent.append(
        json.loads(d.payload["body"])["type"]) or Outcome(True, False))
    W.flush(dd, label="t")
    assert sent == ["kratos.finding.new", "kratos.finding.worse"]


@pytest.mark.parametrize("filters,expect", [
    ({"min_severity": "high"}, {"CORR-SSH-001"}),
    ({"rule_prefixes": ["pkg-"]}, {"PKG-001"}),
    ({"machines": [M2]}, {"NET-001"}),
    ({"only_new_or_worse": True}, {"CORR-SSH-001", "PKG-001", "NET-001"}),
])
def test_filters_are_respected(dd, filters, expect):
    _ch(dd, filters=filters)
    _apply(dd, [_f(), _f("PKG-001", "medium", ("CVE-2024-0001",))])
    _apply(dd, [_f("NET-001", "low", ("8080",))], target=M2)
    FW.produce_findings(dd)
    got = {json.loads(json.loads(m["payload"])["body"])["finding_info"]["types"][0] for m in _msgs(dd)}
    assert got == expect


def test_a_group_filter_follows_membership(dd):
    from kratos.fleet import groups as G

    G.create_group(dd, "web", ACTOR, members=[M2])
    _ch(dd, filters={"groups": ["web"]})
    _apply(dd, [_f()])
    _apply(dd, [_f("NET-001", "low", ("8080",))], target=M2)
    FW.produce_findings(dd)
    assert [json.loads(json.loads(m["payload"])["body"])["device"]["ip"] for m in _msgs(dd)] == [M2]


def test_email_gets_one_digest_per_run(dd):
    _ch(dd, name="mail", kind="email", fmt="text")
    _apply(dd, [_f(), _f("PKG-001", "medium", ("CVE-2024-0001",)), _f("NET-001", "low", ("8080",))])
    FW.produce_findings(dd)
    (m,) = _msgs(dd, "mail")
    p = json.loads(m["payload"])
    assert m["kind"] == "findings_digest" and "3 new or worse finding(s)" in p["subject"]


def test_a_crash_between_rendering_and_saving_loses_nothing_and_duplicates_nothing(dd, monkeypatch):
    _ch(dd)
    _apply(dd, [_f()])
    real = S.set_cursor

    def boom(*a, **k):
        raise RuntimeError("process killed")

    monkeypatch.setattr(S, "set_cursor", boom)
    FW.produce_findings(dd)                              # the transaction rolls back: nothing enqueued
    assert _msgs(dd) == []
    monkeypatch.setattr(S, "set_cursor", real)
    assert FW.produce_findings(dd) == 1 and FW.produce_findings(dd) == 0
    assert len(_msgs(dd)) == 1


# --- events ------------------------------------------------------------------------------
def _events(dd, n, target=M1, start=0):
    from kratos.adapters.auth_log_parse import classify_auth_message
    from kratos.events import converters as EC
    from kratos.events.store import EventStore

    created = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    ctx = EC.ReadContext(target=f"ubuntu@{target}", transport="ssh", read=EC.READ_JOURNAL_AUTH, created=created)
    evs = []
    for i in range(start, start + n):
        msg = f"Failed password for alice from 203.0.113.9 port {1000 + i % 60000} ssh2 #{i}"
        ts = datetime.fromtimestamp(created.timestamp() - 86400 + i, timezone.utc).isoformat()
        evs.append(EC.from_auth_event(classify_auth_message(ts, target, "sshd", msg, msg), ctx=ctx))
    return EventStore(dd / "kratos.db").add(evs)


def test_events_are_batched_and_survive_a_restart_with_no_gap_or_duplicate(dd, monkeypatch):
    _events(dd, 3)                                        # before the channel: not forwarded
    _ch(dd, scopes=("events",), fmt="ecs")
    _events(dd, 1203, start=10)
    FW.produce_events(dd)
    msgs = _msgs(dd)
    assert [len(json.loads(m["payload"])["ref"]["ids"]) for m in msgs] == [500, 500, 203]
    FW.produce_events(dd)                                 # a restarted producer adds nothing new
    assert len(_msgs(dd)) == 3
    _events(dd, 2, start=5000)
    FW.produce_events(dd)
    ids = [i for m in _msgs(dd) for i in json.loads(m["payload"])["ref"]["ids"]]
    assert len(ids) == len(set(ids)) == 1205 and ids == sorted(ids)
    sent: list[str] = []
    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd_: sent.extend(
        json.loads(d.payload["body"])) or Outcome(True, False))          # framing json: one array per batch
    W.flush(dd, label="t")
    assert len(sent) == 1205 and sent[0]["message"].endswith("#10") and sent[-1]["message"].endswith("#5001")


def test_the_events_cursor_waits_while_the_receiver_is_behind(dd):
    _ch(dd, scopes=("events",), fmt="ecs")
    _events(dd, FW.BATCH_EVENTS * (FW.MAX_EVENT_BACKLOG + 5))
    FW.produce_events(dd)
    assert len(_msgs(dd)) == FW.MAX_EVENT_BACKLOG
    ch = C.get_channel(dd, "siem")
    assert FW.events_waiting(dd, ch) == FW.BATCH_EVENTS * 5            # still stored, not dropped


def test_events_of_other_machines_are_not_forwarded_to_a_scoped_channel(dd):
    _ch(dd, scopes=("events",), fmt="ecs", filters={"machines": [M2]})
    _events(dd, 5, target=M1)
    _events(dd, 2, target=M2, start=100)
    FW.produce_events(dd)
    (m,) = _msgs(dd)
    assert json.loads(m["payload"])["ref"]["machines"] == [M2] and len(json.loads(m["payload"])["ref"]["ids"]) == 2
