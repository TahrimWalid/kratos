"""The encrypted agent link over real loopback sockets (Phase C.4): a pinned
agent writes nothing before the server's key matched; it never falls back to
plaintext; the listener serves TLS and plaintext on one port by the first byte;
`subagent.tls.require` refuses plaintext; slow clients block nobody; pin-set
pushes go over pinned links only; rotation needs no re-pairing."""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from pathlib import Path

import pytest

from kratos import settings_store
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import core_server as CS
from kratos.subagent import pinning, protocol as proto, signing, tls
from kratos.subagent.agent import LINK_PLAIN, LINK_TLS, PinRefused, SubAgent
from kratos.subagent.core_server import CoreServer


def run(coro, timeout=60):
    return asyncio.run(asyncio.wait_for(coro, timeout=timeout))


class Harness:
    def __init__(self, tmp: Path):
        self.dir = tmp
        self.store = SubAgentStore(tmp / "kratos.db")
        self.core = CoreServer(self.store, host="127.0.0.1", port=0)
        self.tasks: list[asyncio.Task] = []
        self.agents: list[SubAgent] = []

    async def start(self) -> int:
        self.tasks.append(asyncio.create_task(self.core.serve_forever()))
        while self.core._server is None:
            await asyncio.sleep(0.02)
        return self.port

    @property
    def port(self) -> int:
        return self.core._server.sockets[0].getsockname()[1]

    def agent(self, name: str, *, pins: bool = True, run_it: bool = True, **kw) -> SubAgent:
        state = self.dir / f"{name}.json"
        kw.setdefault("pairing_code", None if state.exists() else self.store.create_pairing_code(name=name)["code"])
        if pins and "server_pins" not in kw:
            ks = tls.load_keys(self.dir)
            kw.update(server_pins=ks.pins(), server_pins_version=ks.version)
        a = SubAgent("127.0.0.1", self.port, state_file=state, local_allow_file=None, collect_interval=300, **kw)
        self.agents.append(a)
        if run_it:
            self.tasks.append(asyncio.create_task(a.run_forever()))
        return a

    async def wait(self, cond, what="condition", seconds=10.0):
        for _ in range(int(seconds / 0.05)):
            if cond():
                return
            await asyncio.sleep(0.05)
        raise AssertionError(f"timed out waiting for {what}")

    async def stop(self) -> None:
        for a in self.agents:
            a.stop()
        self.core.stop()
        await asyncio.sleep(0.1)
        await self.core.close()
        for t in self.tasks:
            t.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


def _target(store, name):
    return next(t for t in store.list_targets() if t["name"] == name)


# ---------------------------------------------------------------------------
def test_a_pinned_agent_pairs_over_tls_and_counts_as_a_trusted_transport(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start()
        a = h.agent("web")
        try:
            await h.wait(lambda: a.last_target_id and h.core._live, "pairing")
            assert a._link == LINK_TLS and a._transport_trusted()
            assert h.core._link[a.last_target_id] == tls.LINK_TLS
            t = _target(h.store, "web")
            assert (t["link_mode"], t["pin_version"]) == ("tls-pinned", 1)
            # the trust rule doesn't depend on the address once the link is pinned
            a._peer_ip, a._local_ip = "203.0.113.9", "198.51.100.4"
            assert a._transport_why_not() is None
            a._link = LINK_PLAIN
            assert "isn't an encrypted, pinned one" in a._transport_why_not()
        finally:
            await h.stop()
    run(go())


class _Recorder:
    """A TLS server with a key nobody pinned; records every byte it receives."""

    def __init__(self, tmp: Path, *, tls_on: bool = True):
        self.data = bytearray()
        self.tls_on = tls_on
        self.dir = tmp / "mitm"
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        ctx = None
        if self.tls_on:
            ctx = tls.server_context(tls.ensure_keys(self.dir))

        async def handle(reader, writer):
            try:
                while True:
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    self.data += chunk
            except (OSError, ssl.SSLError):
                pass
            finally:
                writer.close()

        self.server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
        return self.server.sockets[0].getsockname()[1]

    def close(self):
        self.server.close()


def test_a_server_with_another_key_gets_no_protocol_byte(tmp_path, caplog):
    """Man in the middle: the TLS handshake completes, then the agent closes
    without writing a single application byte -- no hello, no token, no code."""
    caplog.set_level(logging.ERROR, logger="kratos.subagent.agent")

    async def go():
        tls.ensure_keys(tmp_path)
        rec = _Recorder(tmp_path)
        port = await rec.start()
        ks = tls.load_keys(tmp_path)
        a = SubAgent("127.0.0.1", port, state_file=tmp_path / "a.json", pairing_code="1A2B-3C4D",
                     local_allow_file=None, server_pins=ks.pins())
        writes = []
        real = proto.write_frame

        async def spy(writer, message):
            writes.append(message)
            await real(writer, message)

        proto.write_frame = spy
        try:
            with pytest.raises(PinRefused, match="isn't the one this agent was given"):
                await a._connect_and_serve()
        finally:
            proto.write_frame = real
            await asyncio.sleep(0.1)
            rec.close()
        assert writes == []
        assert bytes(rec.data) == b""
        alerts = json.loads((tmp_path / "a.json").read_text())["link_alerts"]
        assert alerts["count"] == 1 and len(alerts["seen_key"]) == 16
        assert alerts["seen_key"] == tls.load_keys(tmp_path / "mitm").active_pin[:16]
    run(go())
    assert "nothing was sent to it" in caplog.text


def test_a_pinned_agent_never_falls_back_to_plaintext(tmp_path):
    """Downgrade: a server that only speaks plaintext sees a TLS ClientHello and
    nothing else -- never a Kratos frame, never the token."""
    async def go():
        tls.ensure_keys(tmp_path)
        rec = _Recorder(tmp_path, tls_on=False)
        port = await rec.start()
        ks = tls.load_keys(tmp_path)
        a = SubAgent("127.0.0.1", port, state_file=tmp_path / "a.json", local_allow_file=None,
                     server_pins=ks.pins())
        a.token = "secret-token-value"
        for _ in range(2):
            with pytest.raises((OSError, ssl.SSLError, asyncio.TimeoutError, proto.ProtocolError)):
                await asyncio.wait_for(a._connect_and_serve(), timeout=5)
        await asyncio.sleep(0.1)
        rec.close()
        data = bytes(rec.data)
        assert data and data[0] == proto.TLS_HANDSHAKE_FIRST_BYTE
        assert b"hello" not in data and b"secret-token-value" not in data and b'"type"' not in data
    run(go())


def test_saved_pins_that_are_unreadable_stop_the_agent_connecting_at_all(tmp_path):
    state = tmp_path / "a.json"
    state.write_text(json.dumps({"agent_id": "x", "token": "t", "server_pins": {"version": 2, "pins": ["zz"]}}))
    a = SubAgent("127.0.0.1", 1, state_file=state, local_allow_file=None)
    assert a.pinned and a._pins == []

    async def go():
        with pytest.raises(PinRefused, match="unreadable"):
            await a._connect_and_serve()
    run(go())


def test_an_old_agent_still_pairs_and_streams_over_plaintext_until_required(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start()
        old = h.agent("old", pins=False)
        try:
            await h.wait(lambda: old.last_target_id, "plaintext pairing")
            t = _target(h.store, "old")
            assert t["link_mode"] == "plaintext" and t["pin_version"] is None
            assert old._link == LINK_PLAIN
            settings_store.set(tls.REQUIRE, "on", data_dir=tmp_path, actor="test")
            # a fresh plaintext hello is now refused with the update message
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port)
            await proto.write_frame(writer, proto.build_hello("x", {"token": old.token}, "old", "0.7.1"))
            reply = await proto.read_frame(reader)
            writer.close()
            assert reply["type"] == proto.MSG_HELLO_REJECT and "update the agent" in reply["reason"]
            events = h.store.recent_events(old.last_target_id, 3600)
            assert any("update the agent" in (e.get("detail") or "") for e in events)
            # an encrypted agent still gets in
            new = h.agent("new")
            await h.wait(lambda: new.last_target_id, "encrypted pairing under require")
        finally:
            await h.stop()
    run(go())


def test_slow_and_silent_clients_dont_block_a_real_agent(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start()
        loop = asyncio.get_running_loop()
        hogs = []
        try:
            for i in range(60):
                s = socket.socket()
                s.setblocking(False)
                await loop.sock_connect(s, ("127.0.0.1", h.port))
                if i % 2:
                    # half a TLS ClientHello, then silence
                    await loop.sock_sendall(s, b"\x16\x03\x01\x02\x00\x01")
                hogs.append(s)
            a = h.agent("busy")
            await h.wait(lambda: a.last_target_id, "pairing among 60 stalled clients", seconds=8)
            plain = h.agent("plain", pins=False)
            await h.wait(lambda: plain.last_target_id, "plaintext pairing among stalled clients", seconds=8)
        finally:
            for s in hogs:
                s.close()
            await h.stop()
    run(go())


def test_past_the_pending_limit_new_connections_are_closed_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr(CS, "MAX_PENDING_HANDSHAKES", 3)
    monkeypatch.setattr(CS, "HELLO_TIMEOUT_SECONDS", 1.0)

    async def go():
        h = Harness(tmp_path)
        await h.start()
        loop = asyncio.get_running_loop()
        socks = []
        try:
            for _ in range(5):
                s = socket.socket()
                s.setblocking(False)
                await loop.sock_connect(s, ("127.0.0.1", h.port))
                socks.append(s)
            await asyncio.sleep(0.3)
            assert h.core._pending_handshakes == 3
            closed = 0
            for s in socks:
                try:
                    if await asyncio.wait_for(loop.sock_recv(s, 1), 0.2) == b"":
                        closed += 1
                except (asyncio.TimeoutError, OSError):
                    pass
            assert closed == 2
            await asyncio.sleep(1.2)  # the silent ones time out; the listener works again
            assert h.core._pending_handshakes == 0
            a = h.agent("after")
            await h.wait(lambda: a.last_target_id, "pairing after the flood")
        finally:
            for s in socks:
                s.close()
            await h.stop()
    run(go())


def test_a_liveness_check_that_sends_nothing_is_harmless(tmp_path):
    from kratos.subagent.core_listener import listener_running

    async def go():
        h = Harness(tmp_path)
        await h.start()
        try:
            for _ in range(5):
                assert await asyncio.to_thread(listener_running, h.port)
            await asyncio.sleep(0.1)
            assert h.core._pending_handshakes == 0
        finally:
            await h.stop()
    run(go())


# ---------------------------------------------------------------------------
# Pin-set push
# ---------------------------------------------------------------------------
class _Writer:
    def __init__(self):
        self.frames = []

    def write(self, data):
        self.frames.append(json.loads(data[4:]))

    async def drain(self):
        pass


def _push(agent: SubAgent, version, pins, *, nonce=None, token=None):
    env = proto.build_pin_set_push(version, pins, nonce or agent._session_nonce)
    env["sig"] = signing.sign_envelope(signing.derive_signing_key(token or agent.token), env)
    return env


def test_pin_pushes_are_only_taken_over_a_pinned_link_signed_newer_and_non_empty(tmp_path):
    ks = tls.ensure_keys(tmp_path)
    state = tmp_path / "a.json"
    a = SubAgent("127.0.0.1", 1, state_file=state, local_allow_file=None, server_pins=ks.pins())
    a.token, a._session_nonce = "tok", "ab" * 16
    new_pins = [ks.backup_pin, "cd" * 32]

    async def answer(msg):
        w = _Writer()
        await a._handle_pin_set_push(msg, w)
        return w.frames[-1]

    async def go():
        a._link = LINK_PLAIN
        r = await answer(_push(a, 2, new_pins))
        assert r["status"] == "refused" and "encrypted, pinned" in r["reason"]
        a._link = LINK_TLS
        assert (await answer(_push(a, 2, new_pins, nonce="cd" * 16)))["status"] == "refused"
        assert (await answer(_push(a, 2, new_pins, token="other")))["status"] == "refused"
        forged = _push(a, 2, new_pins)
        forged["pins"] = ["ee" * 32]
        assert (await answer(forged))["status"] == "refused"
        assert "can't be empty" in (await answer(_push(a, 2, [])))["reason"]
        assert (await answer(_push(a, 0, new_pins)))["status"] == "refused"
        assert a._pin_version == 1 and a._pins == ks.pins()
        ok = await answer(_push(a, 2, new_pins))
        assert ok == {"type": proto.MSG_PIN_SET_ACK, "version": 2, "status": "ok"}
        assert (await answer(_push(a, 2, new_pins)))["status"] == "ok"  # same again: idempotent
        assert "older" in (await answer(_push(a, 1, ks.pins())))["reason"]
        assert "different pin set" in (await answer(_push(a, 2, ks.pins())))["reason"]
    run(go())
    saved = json.loads(state.read_text())["server_pins"]
    assert saved == {"version": 2, "pins": new_pins}
    assert (state.stat().st_mode & 0o777) == 0o600
    # survives a restart, and the older set on the service's command line doesn't win
    b = SubAgent("127.0.0.1", 1, state_file=state, local_allow_file=None, server_pins=ks.pins(),
                 server_pins_version=1)
    assert (b._pins, b._pin_version) == (new_pins, 2)


def test_the_listener_never_pushes_pins_over_plaintext(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start()
        plain = h.agent("plain", pins=False)
        try:
            await h.wait(lambda: plain.last_target_id and plain.last_target_id in h.core._live, "pairing")
            assert await h.core.push_pin_set(plain.last_target_id) is False
            tls.rotate(tmp_path, actor="test")
            await asyncio.sleep(CS.TLS_WATCH_INTERVAL_SECONDS * 2)
            assert plain._pins == [] and plain.pinned is False
        finally:
            await h.stop()
    run(go())


def test_rotation_reaches_connected_and_offline_agents_without_re_pairing(tmp_path, monkeypatch):
    monkeypatch.setattr(CS, "TLS_WATCH_INTERVAL_SECONDS", 0.2)

    async def go():
        h = Harness(tmp_path)
        await h.start()
        online = h.agent("online")
        offline = h.agent("offline")
        try:
            await h.wait(lambda: online.last_target_id and offline.last_target_id
                         and len(h.core._live) == 2, "both paired")
            before = tls.load_keys(tmp_path)
            offline.stop()
            await h.wait(lambda: len(h.core._live) == 1, "offline agent gone")
            _, after = tls.rotate(tmp_path, actor="test")
            await h.wait(lambda: online._pin_version == after.version, "push to the connected agent")
            assert online._pins == after.pins()
            await h.wait(lambda: _target(h.store, "online")["pin_version"] == after.version, "recorded")
            # the offline agent still holds the old pair; the new active key was its backup
            assert offline._pins == before.pins() and after.active_pin == before.backup_pin
            back = h.agent("offline", pairing_code=None)
            await h.wait(lambda: back.last_target_id and back._link == LINK_TLS, "offline agent back")
            await h.wait(lambda: back._pin_version == after.version, "offline agent caught up")
            assert back.last_target_id == offline.last_target_id  # same pairing
            st = tls.status(tmp_path, h.store)
            assert {a["name"]: a["state"] for a in st["agents"]} == {"online": "encrypted",
                                                                       "offline": "encrypted"}
        finally:
            await h.stop()
    run(go())


def test_refused_servers_are_reported_on_the_next_good_connection(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start()
        a = h.agent("web")
        try:
            await h.wait(lambda: a.last_target_id, "pairing")
            a.stop()
            await h.wait(lambda: not h.core._live, "disconnected")
            a._note_pin_refusal("ab" * 32)
            a._note_pin_refusal("ab" * 32)
            back = h.agent("web", pairing_code=None)
            await h.wait(lambda: back.last_target_id, "reconnect")
            await asyncio.sleep(0.1)
            events = h.store.recent_events(back.last_target_id, 3600)
            alert = [e for e in events if e["event"] == "pin_refused"]
            assert alert and "refused 2 connection(s)" in alert[0]["detail"] and "abababab" in alert[0]["detail"]
            assert "link_alerts" not in json.loads((tmp_path / "web.json").read_text())
        finally:
            await h.stop()
    run(go())


def test_allow_untrusted_transport_is_ignored_once_pinned(tmp_path, caplog):
    ks = tls.ensure_keys(tmp_path)
    with caplog.at_level(logging.WARNING, logger="kratos.subagent.agent"):
        a = SubAgent("127.0.0.1", 1, state_file=tmp_path / "a.json", local_allow_file=None,
                     server_pins=ks.pins(), allow_untrusted_transport=True)
    assert a.allow_untrusted_transport is False and "ignored" in caplog.text
    a._link, a._peer_ip, a._local_ip = LINK_PLAIN, "203.0.113.9", "198.51.100.4"
    assert a._transport_why_not() is not None
    old = SubAgent("127.0.0.1", 1, state_file=tmp_path / "b.json", local_allow_file=None,
                   allow_untrusted_transport=True)
    old._link, old._peer_ip = LINK_PLAIN, "203.0.113.9"
    assert old._transport_why_not() is None  # still honoured for an agent without pins


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1_1 is deprecated:DeprecationWarning")
def test_tls_handshake_settings_with_the_listener(tmp_path):
    """What a real agent negotiates with the listener: TLS 1.3 (or 1.2 with an
    ECDHE suite) and the active key's certificate."""
    async def go():
        h = Harness(tmp_path)
        await h.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", h.port, ssl=pinning.client_context())
            obj = writer.get_extra_info("ssl_object")
            assert obj.version() in ("TLSv1.3", "TLSv1.2")
            if obj.version() == "TLSv1.2":
                assert "ECDHE" in obj.cipher()[0]
            assert pinning.check_server_pin(obj, tls.load_keys(tmp_path).pins())
            writer.close()
            ctx = pinning.client_context()
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with pytest.raises((ssl.SSLError, OSError)):
                await asyncio.open_connection("127.0.0.1", h.port, ssl=ctx)
        finally:
            await h.stop()
    run(go())
