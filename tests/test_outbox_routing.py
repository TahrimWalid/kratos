"""D.4: triggers and schedules choose channels by name; a scheduled run flushes its
messages before it exits and records what really happened (sent / queued / failed)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from kratos import kratos_config as kc
from kratos.agent import schedules as SCH
from kratos.agent import triggers as TR
from kratos.agent.trigger_eval import evaluate_triggers
from kratos.lifecycle.decide import Actor
from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.store import Outcome

ACTOR = Actor(user="tester", interface="cli")
HIGH = [{"id": "CORR-SSH-001", "title": "SSH brute force", "severity": "high", "evidence": ["x"]}]


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    for name in ("soc", "ops"):
        C.add_channel(tmp_path, name=name, kind="webhook", config={"url": f"https://{name}.example/in"},
                      scopes=["alerts"], actor=ACTOR)
    return tmp_path


def _queued(dd):
    with S.opened(dd) as conn:
        return sorted((r["channel"], r["kind"]) for r in conn.execute("SELECT channel, kind FROM outbox"))


def test_a_trigger_delivers_only_to_the_channels_it_names(dd):
    TR.save_trigger(dd, name="ssh", min_severity="high", deliver=["soc"])
    fired = evaluate_triggers(dd, HIGH, "198.51.100.7", now=datetime(2026, 11, 8, tzinfo=timezone.utc))
    assert fired[0]["queued"] and _queued(dd) == [("soc", "alert")]


def test_a_trigger_without_deliver_goes_to_every_alert_channel(dd):
    TR.save_trigger(dd, name="ssh", min_severity="high")
    evaluate_triggers(dd, HIGH, "198.51.100.7", now=datetime(2026, 11, 8, tzinfo=timezone.utc))
    assert _queued(dd) == [("ops", "alert"), ("soc", "alert")]


def test_an_unknown_or_non_alert_channel_is_refused_when_saving(dd):
    with pytest.raises(TR.TriggerError, match="no channel named 'nope'"):
        TR.save_trigger(dd, name="x", min_severity="high", deliver=["nope"])
    C.add_channel(dd, name="siem", kind="webhook", config={"url": "https://siem.example/in"}, scopes=["findings"],
                  format="ocsf", actor=ACTOR)
    with pytest.raises(SCH.ScheduleError, match="doesn't receive alerts"):
        SCH.save_schedule(dd, name="wk", kind="audit", deliver=["siem"])
    assert SCH.save_schedule(dd, name="wk", kind="audit").deliver == ["all"]
    assert SCH.save_schedule(dd, name="wk2", kind="audit", deliver=["ops", "ntfy"]).deliver == ["ops", "ntfy"]


def test_a_trigger_file_round_trips_its_channels(dd):
    t = TR.save_trigger(dd, name="ssh", min_severity="high", deliver=["soc", "ops"])
    assert t.deliver == ["soc", "ops"] and 'deliver = ["soc", "ops"]' in t.path.read_text()


def _sched_run(dd, monkeypatch, answer):
    from kratos.agent import scheduled_run as SR

    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd_: answer(ch))
    monkeypatch.setattr(SR, "_run_scheduled_body", None, raising=False)
    res = SR._schedule_notifier(SCH.save_schedule(dd, name="wk", kind="audit", deliver=["soc"]), dd)("report",
                                                                                                    "warning")
    SR.settle_delivery(dd, res)
    return res


def test_a_scheduled_run_records_sent_after_flushing(dd, monkeypatch):
    res = _sched_run(dd, monkeypatch, lambda ch: Outcome(True, False))
    assert res["status"] == "sent"


def test_a_scheduled_run_records_queued_with_the_reason_while_the_receiver_is_down(dd, monkeypatch):
    res = _sched_run(dd, monkeypatch, lambda ch: Outcome(False, True, "connection refused"))
    assert res["status"] == "queued" and "Kratos retries it (connection refused)" in res["observation"]


def test_a_scheduled_run_leaves_delivery_to_the_process_holding_the_lease(dd, monkeypatch):
    other = W.Worker(dd, label="the always-on listener")
    assert other.take_lease()
    calls = []
    res = _sched_run(dd, monkeypatch, lambda ch: calls.append(ch) or Outcome(True, False))
    assert calls == [] and res["status"] == "queued" and "the always-on listener delivers it" in res["observation"]


def test_a_receiver_refusing_the_message_records_failed(dd, monkeypatch):
    res = _sched_run(dd, monkeypatch, lambda ch: Outcome(False, False, "HTTP 400: nope", 400))
    assert res["status"] == "failed" and res["observation"] == "HTTP 400: nope"
