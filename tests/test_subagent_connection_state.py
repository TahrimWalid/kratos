"""Truthful sub-agent connection state (docs/subagent_connection_ux.md WS1 + WS10).

Three layers: the pure `status.assess` (every state, from recorded facts), the store's
listener/connection bookkeeping, and a REAL listener on a loopback socket with real and
hand-rolled agents -- including a zombie that answers pings but never sends telemetry."""
from __future__ import annotations

import asyncio
import contextlib
import socket
from datetime import datetime, timedelta, timezone

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import core_server as CS
from kratos.subagent import protocol as proto
from kratos.subagent import status as ST
from kratos.subagent.agent import SubAgent
from kratos.subagent.core_server import CoreServer

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def iso(seconds_ago: float) -> str:
    return (NOW - timedelta(seconds=seconds_ago)).isoformat(timespec="seconds")


TARGET = {"target_id": "tgt_1", "name": "web", "last_seen": iso(5), "revoked_at": None}


def _conn(**kw):
    base = {"connected_at": iso(300), "disconnected_at": None, "last_frame_at": iso(3),
            "last_telemetry_at": iso(20), "collect_interval": 30.0, "ping_interval": 10.0}
    base.update(kw)
    return base


def A(target=TARGET, conn=None, live=True, events=(), interval=30.0):
    return ST.assess(target, connection=conn, listener_live=live, events=list(events), collect_interval=interval, now=NOW)


# ---------------------------------------------------------------------------
# Pure assessment
# ---------------------------------------------------------------------------
def test_healthy_connection():
    st = A(conn=_conn())
    assert st.state == ST.STATE_CONNECTED and st.severity == "ok" and "last snapshot 20s ago" in st.reason


def test_zombie_answers_pings_but_sends_no_snapshots():
    st = A(conn=_conn(last_telemetry_at=iso(400)))
    assert st.state == ST.STATE_STALLED and "no snapshot for 400s" in st.reason and "every ~30s" in st.reason


def test_zombie_that_never_sent_a_snapshot():
    assert A(conn=_conn(last_telemetry_at=None, connected_at=iso(200))).state == ST.STATE_STALLED
    assert A(conn=_conn(last_telemetry_at=None, connected_at=iso(10))).state == ST.STATE_CONNECTED  # just connected


def test_stall_threshold_follows_the_agents_own_interval():
    assert A(conn=_conn(last_telemetry_at=iso(200)), interval=120).state == ST.STATE_CONNECTED  # 3x120 not reached
    assert A(conn=_conn(last_telemetry_at=iso(200)), interval=30).state == ST.STATE_STALLED


def test_open_socket_with_nothing_arriving_is_unresponsive():
    st = A(conn=_conn(last_frame_at=iso(40)))
    assert st.state == ST.STATE_UNRESPONSIVE and st.severity == "critical"


def test_recent_drop_is_reconnecting_then_offline():
    st = A(conn=_conn(disconnected_at=iso(20), disconnect_reason="connection lost"))
    assert st.state == ST.STATE_RECONNECTING and "connection lost" in st.reason
    st = A(target={**TARGET, "last_seen": iso(1000)}, conn=_conn(disconnected_at=iso(900), disconnect_reason="x"))
    assert st.state == ST.STATE_OFFLINE and st.severity == "critical" and "16 min ago" in st.reason


def test_no_listener_means_unknown_not_down():
    st = A(conn=_conn(), live=False)
    assert st.state == ST.STATE_NOT_WATCHED and "no Kratos listener" in st.reason


def test_flaky_link_is_called_out_even_when_connected():
    drops = [{"event": "disconnected", "at": iso(60 * i)} for i in range(1, 5)]
    st = A(conn=_conn(), events=drops)
    assert st.state == ST.STATE_CONNECTED and st.flaky and "4 drops in the last hour" in st.reason
    assert st.severity == "attention"


def test_revoked_quiet_vs_still_trying():
    revoked = {**TARGET, "revoked_at": iso(3600)}
    assert A(target=revoked).severity == "muted"
    st = A(target=revoked, events=[{"event": "rejected", "at": iso(30)}])
    assert st.state == ST.STATE_REVOKED and "still running" in st.reason and st.severity == "attention"


def test_never_connected_and_legacy_rows():
    assert A(target={**TARGET, "last_seen": None}).state == ST.STATE_NEVER
    assert A(conn=None).state == ST.STATE_CONNECTED  # recorded before tracking existed, recent
    assert A(target={**TARGET, "last_seen": iso(500)}, conn=None).state == ST.STATE_OFFLINE


def test_interval_estimate():
    assert ST.estimate_collect_interval({"collect_interval": 45}, []) == 45
    assert ST.estimate_collect_interval(None, [iso(0), iso(60), iso(120), iso(180)]) == 60
    assert ST.estimate_collect_interval(None, []) == ST.DEFAULT_COLLECT_INTERVAL


# ---------------------------------------------------------------------------
# Store bookkeeping
# ---------------------------------------------------------------------------
@pytest.fixture
def store(tmp_path):
    return SubAgentStore(tmp_path / "kratos.db")


def _pair(store, name="web"):
    code = store.create_pairing_code(name=name)["code"]
    return store.redeem_pairing_code(code, agent_id="a", hostname=name, agent_version="0.2.0")["target_id"]


def test_connection_rows_are_owned_by_their_listener(store):
    tid = _pair(store)
    store.register_listener("L1", pid=1, host="0.0.0.0", port=1, mode="service", build="b")
    store.record_connection_open(tid, listener_id="L1", peer="10.0.0.9", collect_interval=30, ping_interval=10)
    store.record_connection_closed(tid, listener_id="L-other", reason="x")  # a stranger can't close it
    assert store.get_connection(tid)["disconnected_at"] is None
    store.record_connection_closed(tid, listener_id="L1", reason="connection lost")
    c = store.get_connection(tid)
    assert c["disconnected_at"] and c["disconnect_reason"] == "connection lost"
    assert [e["event"] for e in store.recent_events(tid, 60)] == ["connected", "disconnected"]


def test_a_dead_listeners_connections_are_closed_by_the_next_one(store):
    tid = _pair(store)
    store.register_listener("L1", pid=1, host="h", port=1, mode="service", build="b")
    store.record_connection_open(tid, listener_id="L1", peer="p")
    store._write("UPDATE subagent_listeners SET heartbeat_at = ? WHERE listener_id = 'L1'", ("2020-01-01T00:00:00+00:00",))
    assert store.live_listeners(20) == []
    assert store.close_orphaned_connections(20) == 1
    assert "stopped unexpectedly" in store.get_connection(tid)["disconnect_reason"]


def test_stop_listener_closes_its_connections(store):
    tid = _pair(store)
    store.register_listener("L1", pid=1, host="h", port=1, mode="in_process", build="b")
    store.record_connection_open(tid, listener_id="L1", peer="p")
    store.stop_listener("L1")
    assert store.live_listeners(20) == [] and store.get_connection(tid)["disconnected_at"]


def test_event_retention_is_bounded(store, monkeypatch):
    from kratos.storage import subagent_store as SS

    monkeypatch.setattr(SS, "CONNECTION_EVENT_RETENTION_PER_TARGET", 5)
    tid = _pair(store)
    for i in range(12):
        store.record_connection_event(tid, "rejected", str(i))
    assert [e["detail"] for e in store.recent_events(tid, 60)] == ["7", "8", "9", "10", "11"]


def test_pairing_attempts_only_recorded_for_real_codes(store):
    code = store.create_pairing_code(name="x")["code"]
    store.record_pairing_attempt(code, "box (10.0.0.9)", "pairing code invalid, expired, or already used")
    store.record_pairing_attempt("NOPE-NOPE", "x", "y")
    assert store.get_pairing_code(code)["last_attempt_host"] == "box (10.0.0.9)"
    assert store.get_pairing_code("NOPE-NOPE") is None


# ---------------------------------------------------------------------------
# A real listener on a loopback socket
# ---------------------------------------------------------------------------
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _until(pred, timeout=6.0):
    for _ in range(int(timeout / 0.05)):
        v = pred()
        if v:
            return v
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met")


@contextlib.asynccontextmanager
async def _listener(store, monkeypatch, **kw):
    from kratos.subagent import collector

    # The real collector runs journalctl/ss on THIS machine every cycle; a fast
    # fake keeps these tests about the connection, not the host's log volume.
    monkeypatch.setattr(collector, "collect_snapshot", lambda **_: {"host": {"uptime_seconds": 1.0}})
    monkeypatch.setattr(CS, "LISTENER_HEARTBEAT_SECONDS", 0.1)
    server = CoreServer(store, host="127.0.0.1", port=_free_port(), mode="process", **kw)
    task = asyncio.create_task(server.serve_forever())
    await _until(lambda: store.live_listeners(20))
    try:
        yield server
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await server.close()


def _agent(store, port, tmp_path, name="a", **kw):
    code = store.create_pairing_code(name=name)["code"]
    return SubAgent("127.0.0.1", port, state_file=tmp_path / f"{name}.json", pairing_code=code,
                    collect_interval=kw.pop("collect_interval", 0.2), ping_interval=kw.pop("ping_interval", 0.2),
                    watch_files=[], services=[], local_allow_file=None, **kw)


def test_real_connect_disconnect_and_revoke_drops_the_live_socket(tmp_path, monkeypatch):
    store = SubAgentStore(tmp_path / "kratos.db")

    async def run():
        async with _listener(store, monkeypatch) as server:
            agent = _agent(store, server.port, tmp_path, collect_interval=1.0)
            task = asyncio.create_task(agent.run_forever())
            tid = await _until(lambda: agent.last_target_id)
            await _until(lambda: (store.get_connection(tid) or {}).get("last_telemetry_at"))
            c = store.get_connection(tid)
            assert c["listener_id"] == server.listener_id and c["collect_interval"] == 1.0  # announced by the agent
            [(_, st)] = ST.assess_all(store)
            assert st.state == ST.STATE_CONNECTED

            store.revoke_target(tid)  # from "another process"
            await _until(lambda: tid not in server.live_target_ids())
            assert store.get_connection(tid)["disconnect_reason"] == "unpaired in Kratos"
            # the agent keeps retrying with its now-revoked token -> recorded, and surfaced
            await _until(lambda: any(e["event"] == "rejected" for e in store.recent_events(tid, 60)), timeout=10)
            [(_, st)] = ST.assess_all(store)
            assert st.state == ST.STATE_REVOKED and "still running" in st.reason
            agent.stop()
            await asyncio.wait_for(task, 5)

    asyncio.run(run())


def test_listener_shutdown_is_recorded_and_status_says_not_watched(tmp_path, monkeypatch):
    store = SubAgentStore(tmp_path / "kratos.db")

    async def run():
        async with _listener(store, monkeypatch) as server:
            agent = _agent(store, server.port, tmp_path)
            task = asyncio.create_task(agent.run_forever())
            tid = await _until(lambda: agent.last_target_id)
            await _until(lambda: tid in server.live_target_ids())
        # listener closed
        assert "listener stopped" in store.get_connection(tid)["disconnect_reason"]
        [(_, st)] = ST.assess_all(store)
        assert st.state == ST.STATE_NOT_WATCHED
        agent.stop()
        await asyncio.wait_for(task, 5)

    asyncio.run(run())


def test_zombie_agent_is_reported_as_stalled(tmp_path, monkeypatch):
    """A hand-rolled agent that pairs and keeps pinging but never sends telemetry."""
    store = SubAgentStore(tmp_path / "kratos.db")
    monkeypatch.setattr(ST, "DEFAULT_COLLECT_INTERVAL", 0.1)

    async def run():
        async with _listener(store, monkeypatch) as server:
            code = store.create_pairing_code(name="z")["code"]
            r, w = await asyncio.open_connection("127.0.0.1", server.port)
            await proto.write_frame(w, proto.build_hello("zid", {"pairing_code": code}, "zombie", "0.2.0",
                                                         collect_interval=1.0, ping_interval=1.0))
            ack = await proto.read_frame(r)
            tid = ack["target_id"]
            now = datetime.now(timezone.utc)
            for _ in range(4):
                await proto.write_frame(w, proto.build_ping(1.0))
                await proto.read_frame(r)
                await asyncio.sleep(0.2)
            later = now + timedelta(seconds=120)  # judge it two minutes on, still pinging
            store.touch_last_seen(tid)
            conn = store.get_connection(tid)
            conn["last_frame_at"] = later.isoformat(timespec="seconds")
            st = ST.assess(store.get_target(tid), connection=conn, listener_live=True, events=[],
                           collect_interval=1.0, now=later)
            assert st.state == ST.STATE_STALLED
            w.close()

    asyncio.run(run())


def test_silent_session_is_replaced_but_an_active_duplicate_is_refused(tmp_path, monkeypatch):
    store = SubAgentStore(tmp_path / "kratos.db")
    monkeypatch.setattr(CS, "SILENT_SESSION_REPLACE_SECONDS", 0.5)

    async def run():
        async with _listener(store, monkeypatch) as server:
            code = store.create_pairing_code(name="d")["code"]
            r1, w1 = await asyncio.open_connection("127.0.0.1", server.port)
            await proto.write_frame(w1, proto.build_hello("did", {"pairing_code": code}, "d", "0.2.0"))
            ack = await proto.read_frame(r1)
            tid, token = ack["target_id"], ack["token"]

            async def hello2():
                r2, w2 = await asyncio.open_connection("127.0.0.1", server.port)
                await proto.write_frame(w2, proto.build_hello("did", {"token": token}, "d", "0.2.0"))
                return r2, w2, await proto.read_frame(r2)

            _, w2, reply = await hello2()  # the first session just spoke -> refused
            assert reply["type"] == proto.MSG_HELLO_REJECT
            w2.close()
            assert any("second connection" in (e["detail"] or "") for e in store.recent_events(tid, 60))
            await asyncio.sleep(0.7)  # first session goes silent (half-open)
            r3, w3, reply = await hello2()
            assert reply["type"] == proto.MSG_HELLO_ACK
            assert any(e["event"] == "replaced" for e in store.recent_events(tid, 60))
            w1.close()
            w3.close()

    asyncio.run(run())


def test_expired_code_attempt_is_recorded_and_guessing_is_throttled(tmp_path, monkeypatch):
    store = SubAgentStore(tmp_path / "kratos.db")
    monkeypatch.setattr(CS, "AUTH_FAILURE_LIMIT", 3)

    async def run():
        async with _listener(store, monkeypatch) as server:
            code = store.create_pairing_code(name="late")["code"]
            store._write("UPDATE subagent_pairing_codes SET expires_at = ? WHERE code = ?",
                         ("2020-01-01T00:00:00+00:00", code))

            async def try_code(c):
                r, w = await asyncio.open_connection("127.0.0.1", server.port)
                await proto.write_frame(w, proto.build_hello("x", {"pairing_code": c}, "late-box", "0.2.0"))
                reply = await proto.read_frame(r)
                w.close()
                return reply

            assert "expired" in (await try_code(code))["reason"]
            assert store.get_pairing_code(code)["last_attempt_host"].startswith("late-box")
            await try_code("AAAA-0000")
            await try_code("AAAA-0001")
            assert "too many" in (await try_code("AAAA-0002"))["reason"]  # throttled before any lookup

    asyncio.run(run())


def test_announced_intervals_are_sanity_checked():
    assert CS._interval(30) == 30.0 and CS._interval(0.2) is None and CS._interval(True) is None
    assert CS._interval("30") is None and CS._interval(99999) is None


def test_next_retry_follows_the_agents_backoff():
    from kratos.subagent import agent
    from kratos.subagent.status import next_agent_retry_in

    assert agent.BACKOFF_INITIAL_SECONDS == 2.0 and agent.BACKOFF_MAX_SECONDS == 60.0
    # attempts at 2, 6, 14, 30, 62, 122 ... seconds after the drop
    assert next_agent_retry_in(0) == 2
    assert next_agent_retry_in(5) == 1
    assert next_agent_retry_in(20) == 10
    assert next_agent_retry_in(62) == 60
    assert next_agent_retry_in(500) <= 60


def test_countdown_only_when_both_sides_saw_the_drop():
    from datetime import timedelta

    from kratos.subagent.status import SILENT_DROP_PREFIX, assess, utc_now

    now = utc_now()
    ago = (now - timedelta(seconds=5)).isoformat(timespec="seconds")
    target = {"target_id": "t", "last_seen": ago}
    clean = assess(target, connection={"connected_at": ago, "disconnected_at": ago,
                                       "disconnect_reason": "the agent closed the connection"},
                   listener_live=True, events=[], now=now)
    assert clean.state == "reconnecting" and "tries again in ~1s" in clean.reason
    silent = assess(target, connection={"connected_at": ago, "disconnected_at": ago,
                                        "disconnect_reason": f"{SILENT_DROP_PREFIX} for 30s"},
                    listener_live=True, events=[], now=now)
    assert "tries again in" not in silent.reason and "once it notices the silence" in silent.reason


def test_old_identity_needs_same_hostname_and_same_address():
    from kratos.subagent.status import ConnectionState, mark_superseded

    def st(state):
        return ConnectionState(state, state, "r", "critical", None)

    old = {"target_id": "old", "hostname": "web", "paired_at": "2026-09-01T00:00:00+00:00", "name": "web"}
    new = {"target_id": "new", "hostname": "web", "paired_at": "2026-09-02T00:00:00+00:00", "name": "web"}
    rows = [(old, st("offline")), (new, st("connected"))]
    assert [s.state for _, s in mark_superseded(rows, {"old": "10.0.0.5", "new": "10.0.0.5"})][0] == "superseded"
    # a different machine that merely shares a default hostname: a real outage, left as one
    assert mark_superseded(rows, {"old": "10.0.0.5", "new": "10.0.0.9"})[0][1].state == "offline"
    assert mark_superseded(rows, {"old": None, "new": "10.0.0.5"})[0][1].state == "offline"
    # an OLDER live pairing never marks a newer offline one
    assert mark_superseded([(new, st("offline")), (old, st("connected"))],
                           {"old": "10.0.0.5", "new": "10.0.0.5"})[0][1].state == "offline"
