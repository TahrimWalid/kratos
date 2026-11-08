"""D.4 outbox core: enqueue, the delivery lease, per-message claims, the retry schedule,
rate caps, order per finding, outage notices, and that ntfy users get exactly the
notification they got before the outbox. No network: senders are replaced, or ntfy's
requests.post is."""
from __future__ import annotations

import random
import time

import pytest
import requests

from kratos import kratos_config as kc
from kratos.lifecycle.decide import Actor
from kratos.outbox import alerts as A
from kratos.outbox import config as C
from kratos.outbox import retry as R
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.store import Outcome

ACTOR = Actor(user="tester", interface="cli")


@pytest.fixture
def dd(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    return tmp_path


class FakeSenders:
    """Replaces the per-kind senders; records every call; answers from a script."""

    def __init__(self, monkeypatch):
        self.calls: list[tuple[str, str, dict]] = []
        self.answer = lambda channel, delivery: Outcome(True, False, "ok", 200)
        monkeypatch.setattr(W, "sender_for", lambda kind: self._send)

    def _send(self, delivery, channel, secrets, data_dir):
        self.calls.append((channel.name, delivery.message_id, delivery.payload))
        return self.answer(channel, delivery)


def _webhook(dd, name="hook", **kw):
    return C.add_channel(dd, name=name, kind="webhook", config={"url": "https://receiver.example/in"},
                         scopes=kw.pop("scopes", ["alerts"]), actor=ACTOR, **kw)


def test_enqueue_is_idempotent_per_channel_and_message_id(dd):
    with S.opened(dd) as conn:
        a = S.enqueue(conn, channel="x", kind="alert", message_id="m1", payload={"t": 1}, summary="s")
        b = S.enqueue(conn, channel="x", kind="alert", message_id="m1", payload={"t": 2}, summary="s")
        c = S.enqueue(conn, channel="y", kind="alert", message_id="m1", payload={"t": 1}, summary="s")
        assert a.created and not b.created and b.id == a.id and c.created and c.id != a.id
        assert conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 2


def test_producers_only_enqueue_and_never_block_on_a_slow_receiver(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    fakes.answer = lambda ch, d: (time.sleep(5), Outcome(True, False))[1]
    _webhook(dd)
    t0 = time.monotonic()
    res = A.enqueue_alert("hello", "warning", deliver=["hook"], data_dir=dd)
    assert time.monotonic() - t0 < 1.0 and res["status"] == "queued" and fakes.calls == []


def test_delivered_and_dead_messages_are_kept(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    A.enqueue_alert("one", deliver=["hook"], data_dir=dd)
    W.flush(dd, label="t")
    fakes.answer = lambda ch, d: Outcome(False, False, "HTTP 400: bad", 400)
    A.enqueue_alert("two", deliver=["hook"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        rows = {r["summary"]: r["status"] for r in S.listing(conn)}
    assert rows == {"one": "delivered", "two": "dead"}


def test_one_worker_holds_the_lease_and_a_dead_holders_lease_is_taken_over(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    a, b = W.Worker(dd, label="a"), W.Worker(dd, label="b")
    assert a.take_lease() and not b.take_lease()
    A.enqueue_alert("first", deliver=["hook"], data_dir=dd)
    a.cycle(wait=True)
    assert [c[2]["body"] for c in fakes.calls if "first" in c[2]["body"]]
    with S.opened(dd) as conn:                      # a dies: its lease simply runs out
        conn.execute("UPDATE outbox_lease SET expires_at = ?", (time.time() - 1,))
    assert b.take_lease() and not a.take_lease()
    b.cycle(wait=True)
    assert len(fakes.calls) == 1                    # the delivered message is never sent again


def test_a_message_whose_sender_died_is_sent_again_with_the_same_id(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    res = A.enqueue_alert("x", deliver=["hook"], data_dir=dd)
    oid = res["outbox_ids"][0]
    with S.opened(dd) as conn:                       # a worker claims it and dies before recording
        assert S.claim(conn, oid, holder="dead-worker", ttl=60) is not None
        assert S.due(conn, "hook") == []
        conn.execute("UPDATE outbox SET claimed_until = ? WHERE id = ?", (time.time() - 1, oid))
    W.flush(dd, label="t")
    assert [c[1] for c in fakes.calls] == [res["message_id"]]
    with S.opened(dd) as conn:
        row = S.get(conn, oid)
        assert row["status"] == "delivered" and row["attempts"] == 2
        atts = S.attempts_of(conn, oid)
        assert atts[0]["finished_at"] is None and atts[1]["ok"] == 1     # the lost attempt stays on record


def test_the_retry_schedule_with_jitter_then_dead(dd):
    rng = random.Random(7)
    with S.opened(dd) as conn:
        e = S.enqueue(conn, channel="x", kind="alert", message_id="m", payload={}, summary="s", now=0)
        now = 0.0
        delays = []
        for _ in range(R.MAX_ATTEMPTS):
            att = S.claim(conn, e.id, holder="w", ttl=60, now=now)
            assert att is not None
            st = S.finish(conn, e.id, att, holder="w", outcome=Outcome(False, True, "down"), now=now, rng=rng)
            row = S.get(conn, e.id)
            if st == "dead":
                break
            delays.append(row["next_attempt_at"] - now)
            now = row["next_attempt_at"]
        assert st == "dead" and row["attempts"] == R.MAX_ATTEMPTS
        assert len(delays) == len(R.SCHEDULE)
        for got, base in zip(delays, R.SCHEDULE):
            assert base * 0.9 - 1e-6 <= got <= base * 1.1 + 1e-6
        assert len({round(g / b, 6) for g, b in zip(delays, R.SCHEDULE)}) > 1    # jittered, not exact


@pytest.mark.parametrize("code,expect", [(400, "dead"), (401, "dead"), (404, "dead"), (410, "dead"),
                                         (408, "failed"), (429, "failed"), (500, "failed"), (503, "failed")])
def test_a_4xx_other_than_408_or_429_is_dead_at_once(dd, code, expect):
    with S.opened(dd) as conn:
        e = S.enqueue(conn, channel="x", kind="alert", message_id="m", payload={}, summary="s")
        att = S.claim(conn, e.id, holder="w", ttl=60)
        st = S.finish(conn, e.id, att, holder="w",
                      outcome=Outcome(False, R.http_retryable(code), f"HTTP {code}", code))
        assert st == expect


def test_retry_after_is_honoured(dd):
    with S.opened(dd) as conn:
        e = S.enqueue(conn, channel="x", kind="alert", message_id="m", payload={}, summary="s", now=0)
        att = S.claim(conn, e.id, holder="w", ttl=60, now=0)
        S.finish(conn, e.id, att, holder="w", outcome=Outcome(False, True, "busy", 429, retry_after=120), now=0)
        assert S.get(conn, e.id)["next_attempt_at"] >= 120


def test_a_flood_queues_at_the_rate_cap_and_nothing_is_dropped(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd, max_per_minute=5)
    for i in range(20):
        A.enqueue_alert(f"m{i}", deliver=["hook"], data_dir=dd)
    W.flush(dd, label="t", deadline_seconds=5)
    assert len(fakes.calls) == 5
    with S.opened(dd) as conn:
        assert S.backlog(conn, "hook") == 15
        assert S.counts(conn)["hook"] == {"delivered": 5, "pending": 15}


def test_messages_sharing_an_order_key_go_out_in_order(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    fail_first = {"n": 0}

    def answer(ch, d):
        if d.message_id == "f:1" and fail_first["n"] == 0:
            fail_first["n"] += 1
            return Outcome(False, True, "down")
        return Outcome(True, False)

    fakes.answer = answer
    with S.opened(dd) as conn:
        for mid in ("f:1", "f:2"):
            S.enqueue(conn, channel="hook", kind="finding", message_id=mid, payload={"body": mid}, summary=mid,
                      order_key="finding-A")
    W.flush(dd, label="t")
    assert [c[1] for c in fakes.calls] == ["f:1"]          # f:2 waits behind the failed f:1
    with S.opened(dd) as conn:
        conn.execute("UPDATE outbox SET next_attempt_at = 0 WHERE message_id = 'f:1'")
    W.flush(dd, label="t")
    assert [c[1] for c in fakes.calls] == ["f:1", "f:1", "f:2"]


def test_a_failing_channel_is_announced_once_through_the_others_and_once_on_recovery(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd, name="soc")
    _webhook(dd, name="ops")
    down = {"soc": True}
    fakes.answer = lambda ch, d: Outcome(False, True, "connection refused") if ch.name == "soc" and down["soc"] \
        else Outcome(True, False)
    A.enqueue_alert("alert", deliver=["soc"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:                        # it has been failing for 61 minutes
        conn.execute("UPDATE channels SET failing_since = ? WHERE name = 'soc'", (time.time() - 61 * 60,))
    W.flush(dd, label="t")
    W.flush(dd, label="t")
    notices = [c for c in fakes.calls if c[1].startswith("outage:")]
    assert len(notices) == 1 and notices[0][0] == "ops" and "can't reach soc" in notices[0][2]["body"]
    assert "connection refused" in notices[0][2]["body"]
    down["soc"] = False
    with S.opened(dd) as conn:
        conn.execute("UPDATE outbox SET next_attempt_at = 0 WHERE channel = 'soc'")
    W.flush(dd, label="t")
    W.flush(dd, label="t")
    rec = [c for c in fakes.calls if c[1].startswith("recovered:")]
    assert len(rec) == 1 and rec[0][0] == "ops" and "reaches soc again" in rec[0][2]["body"]


def test_existing_ntfy_users_get_the_identical_notification(dd, monkeypatch):
    """The built-in ntfy channel calls the old sender: same URL, body, title, priority, tags."""
    from kratos.agent import notify

    posts: list = []

    class _Resp:
        status_code = 200
        text = "ok"

    monkeypatch.setattr(requests, "post", lambda url, **kw: posts.append((url, kw)) or _Resp())
    monkeypatch.setattr(kc, "NTFY_TOPIC", "kratos-0123456789abcdef01234567")
    monkeypatch.setattr(kc, "NTFY_BASE_URL", "https://ntfy.example")
    monkeypatch.setattr(kc, "NTFY_TOKEN", "tok_" + "a" * 20)
    text = "HIGH on web-01: SSH brute force\nNext: open Kratos"
    notify.send_notification(text, "critical")
    direct = posts.pop()
    res = A.OutboxNotifier(["ntfy"], data_dir=dd)(text, "critical")
    assert res["status"] == "queued" and posts == []
    W.flush(dd, label="t")
    assert posts == [direct]


def test_ntfy_not_set_up_reads_as_before(dd):
    res = A.enqueue_alert("x", data_dir=dd)
    from kratos.agent.notify import NOT_CONFIGURED_HINT

    assert res["status"] == "not_configured" and res["observation"] == NOT_CONFIGURED_HINT
    with S.opened(dd) as conn:
        assert S.counts(conn) == {}


def test_a_turned_off_channel_keeps_its_messages_until_turned_on(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    A.enqueue_alert("x", deliver=["hook"], data_dir=dd)
    C.set_enabled(dd, "hook", False, actor=ACTOR)
    W.flush(dd, label="t")
    assert fakes.calls == []
    C.set_enabled(dd, "hook", True, actor=ACTOR)
    W.flush(dd, label="t")
    assert len(fakes.calls) == 1


def test_retry_now_brings_a_dead_message_back(dd, monkeypatch):
    fakes = FakeSenders(monkeypatch)
    _webhook(dd)
    fakes.answer = lambda ch, d: Outcome(False, False, "HTTP 400: missing field", 400)
    res = A.enqueue_alert("x", deliver=["hook"], data_dir=dd)
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        assert S.get(conn, res["outbox_ids"][0])["last_error"] == "HTTP 400: missing field"
    fakes.answer = lambda ch, d: Outcome(True, False)
    with S.opened(dd) as conn:
        assert S.retry_now(conn, ids=res["outbox_ids"]) == 1
    W.flush(dd, label="t")
    with S.opened(dd) as conn:
        assert S.get(conn, res["outbox_ids"][0])["status"] == "delivered"


def test_prune_only_takes_delivered_and_dead(dd):
    with S.opened(dd) as conn:
        with pytest.raises(ValueError):
            S.prune_candidates(conn, statuses_=("pending",), before=time.time())
