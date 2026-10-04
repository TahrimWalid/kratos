"""The dead-man's switch and dispatch freshness are tied to the agent's OWN pings.

Security review (2026-10-05), finding 1: a correctly signed pong was accepted
whatever `ts` it echoed, and arming used the pong's arrival time -- so a stored
pong could be sent again to keep execution armed after core went silent, and a
dispatch held back in transit could still run much later. Now a pong counts only
if it echoes a ping this connection sent within the window, arming dates from
that ping's send time, and every dispatch must name such a ping."""
from __future__ import annotations

import asyncio
import time

from kratos.subagent import signing
from kratos.subagent.agent import DEAD_MANS_SWITCH_SECONDS, SubAgent

TOKEN = "t" * 32
NONCE = "n" * 32


def _agent(tmp_path) -> SubAgent:
    a = SubAgent("127.0.0.1", 1, state_file=tmp_path / "state.json", execution_enabled=True, local_allow_file=None)
    a.token = TOKEN
    a._session_nonce = NONCE
    a._peer_ip = "127.0.0.1"
    a._whitelist_version = 1
    return a


def _signed(msg: dict) -> dict:
    msg = dict(msg)
    msg["sig"] = signing.sign_envelope(signing.derive_signing_key(TOKEN), msg)
    return msg


def _pong(ts: float) -> dict:
    return _signed({"type": "pong", "ts": ts, "session_nonce": NONCE})


def _dispatch(heartbeat_ts=None, dispatch_id="d1") -> dict:
    msg = {"type": "exec_dispatch", "dispatch_id": dispatch_id, "action_id": "nope", "slot_values": {},
           "whitelist_version": 1, "session_nonce": NONCE}
    if heartbeat_ts is not None:
        msg["heartbeat_ts"] = heartbeat_ts
    return _signed(msg)


def test_a_signed_pong_counts_only_for_a_ping_this_connection_sent(tmp_path):
    a = _agent(tmp_path)
    sent = time.time()
    a._sent_pings.append(sent)
    assert a._pong_is_authentic(_pong(sent))
    assert not a._pong_is_authentic(_pong(sent - 1))           # never sent
    a._sent_pings.clear()                                       # a new connection
    assert not a._pong_is_authentic(_pong(sent))


def test_a_pong_for_an_old_ping_does_not_arm(tmp_path):
    a = _agent(tmp_path)
    old = time.time() - DEAD_MANS_SWITCH_SECONDS - 5
    a._sent_pings.append(old)
    assert not a._pong_is_authentic(_pong(old))
    assert not a._execution_armed()


def test_arming_dates_from_the_ping_not_the_pong(tmp_path):
    """Feeding the receive loop the same pong again later must not push the
    armed window past (ping send time + window)."""
    a = _agent(tmp_path)
    sent = time.time() - 10
    a._sent_pings.append(sent)

    class _Reader:
        def __init__(self, frames):
            self.frames = list(frames)

    async def go():
        from kratos.subagent import protocol as proto

        frames = [_pong(sent), _pong(sent)]

        async def fake_read(_reader):
            return frames.pop(0) if frames else None

        orig = proto.read_frame
        proto.read_frame = fake_read
        try:
            try:
                await a._receive_loop(_Reader(frames), None)
            except Exception:  # noqa: BLE001 -- ends with "core closed the connection"
                pass
        finally:
            proto.read_frame = orig

    asyncio.run(go())
    assert a._last_core_message_ts == sent


def _run(coro):
    return asyncio.run(coro)


def test_a_dispatch_must_name_a_recent_ping(tmp_path):
    a = _agent(tmp_path)
    now = time.time()
    a._sent_pings.append(now)
    a._last_core_message_ts = now

    missing = _run(a._process_exec_dispatch(_dispatch(None, "d1")))
    assert "heartbeat" in missing["reason"]
    unknown = _run(a._process_exec_dispatch(_dispatch(now - 3, "d2")))
    assert "heartbeat" in unknown["reason"]
    ok_so_far = _run(a._process_exec_dispatch(_dispatch(now, "d3")))
    assert "unknown action_id" in ok_so_far["reason"]          # passed the freshness gate


def test_a_dispatch_held_back_past_the_window_is_refused(tmp_path):
    a = _agent(tmp_path)
    old = time.time() - DEAD_MANS_SWITCH_SECONDS - 5
    a._sent_pings.append(old)
    fresh = time.time()
    a._sent_pings.append(fresh)
    a._last_core_message_ts = fresh                              # core is alive...
    late = _run(a._process_exec_dispatch(_dispatch(old, "d4")))  # ...but this dispatch is stale
    assert "heartbeat" in late["reason"]
