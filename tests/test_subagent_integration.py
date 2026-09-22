"""
End-to-end (in-process, real localhost TCP sockets) tests for capability 1:
CoreServer <-> SubAgent talking the real wire protocol over real sockets, not
mocked. Exercises pairing, telemetry delivery, rejection paths, and
forced-disconnect reconnection using the saved token (no pairing code) --
the actual behaviors the design doc's transport rules (agent-initiated,
reconnect+backoff, app-level token auth) are meant to guarantee.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import socket

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import protocol as proto
from kratos.subagent.agent import SubAgent
from kratos.subagent.core_server import CoreServer


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _start_server(store: SubAgentStore, port: int) -> CoreServer:
    server = CoreServer(store, host="127.0.0.1", port=port)
    server._server = await asyncio.start_server(server._handle_connection, "127.0.0.1", port)
    return server


async def _wait_until(predicate, timeout: float = 5.0, interval: float = 0.05):
    elapsed = 0.0
    while elapsed < timeout:
        result = predicate()
        if result:
            return result
        await asyncio.sleep(interval)
        elapsed += interval
    raise AssertionError(f"condition not met within {timeout}s")


async def _stop_agent(agent: SubAgent, task: asyncio.Task) -> None:
    agent.stop()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def test_pairing_and_telemetry_flow(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            pairing = store.create_pairing_code(name="web-01")
            agent = SubAgent(
                core_host="127.0.0.1",
                core_port=port,
                state_file=tmp_path / "state.json",
                pairing_code=pairing["code"],
                collect_interval=0.1,
                ping_interval=5.0,
                watch_files=[],
                services=["definitely-not-a-real-service-xyz"],
            )
            task = asyncio.create_task(agent.run_forever())
            try:
                targets = await _wait_until(lambda: store.list_targets() or None)
                target_id = targets[0]["target_id"]
                latest = await _wait_until(lambda: store.get_latest_telemetry(target_id))

                assert "host" in latest["payload"]
                assert "services" in latest["payload"]
                assert target_id in server.live_target_ids()
                assert agent.token is not None
                assert agent.last_target_id == target_id

                saved = json.loads((tmp_path / "state.json").read_text())
                assert saved["token"] == agent.token
                assert saved["agent_id"] == agent.agent_id

                snapshot = server.status_snapshot()
                assert snapshot[0]["status"] == "connected"
                assert snapshot[0]["live_connection"] is True
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_unknown_token_is_rejected(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await proto.write_frame(writer, proto.build_hello("agent-x", {"token": "totally-bogus"}, "host-x", "0.1.0"))
            reply = await asyncio.wait_for(proto.read_frame(reader), timeout=5)
            assert reply["type"] == proto.MSG_HELLO_REJECT
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(run())


def test_unknown_pairing_code_is_rejected(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await proto.write_frame(writer, proto.build_hello("agent-x", {"pairing_code": "NOPE-0000"}, "host-x", "0.1.0"))
            reply = await asyncio.wait_for(proto.read_frame(reader), timeout=5)
            assert reply["type"] == proto.MSG_HELLO_REJECT
            assert "invalid" in reply["reason"] or "expired" in reply["reason"] or "used" in reply["reason"]
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(run())


def test_duplicate_live_connection_for_same_target_rejected(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            pairing = store.create_pairing_code()
            reader1, writer1 = await asyncio.open_connection("127.0.0.1", port)
            await proto.write_frame(writer1, proto.build_hello("agent-1", {"pairing_code": pairing["code"]}, "host-1", "0.1.0"))
            ack = await asyncio.wait_for(proto.read_frame(reader1), timeout=5)
            assert ack["type"] == proto.MSG_HELLO_ACK
            token = ack["token"]

            # A second connection presenting the SAME token while the first
            # is still live must be refused, not silently swap in.
            reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
            await proto.write_frame(writer2, proto.build_hello("agent-1", {"token": token}, "host-1", "0.1.0"))
            reply2 = await asyncio.wait_for(proto.read_frame(reader2), timeout=5)
            assert reply2["type"] == proto.MSG_HELLO_REJECT
            assert "already connected" in reply2["reason"]

            for w in (writer1, writer2):
                w.close()
                with contextlib.suppress(OSError):
                    await w.wait_closed()
        finally:
            await server.close()

    asyncio.run(run())


def test_agent_reconnects_and_reauthenticates_with_saved_token_after_forced_drop(tmp_path):
    """Simulates the connection dying (network blip / core hiccup) -- the
    agent must reconnect on its own AND must NOT need the pairing code again
    (it was single-use and is already spent); telemetry must resume flowing
    to the SAME target_id, not create a new one."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            pairing = store.create_pairing_code()
            agent = SubAgent(
                core_host="127.0.0.1",
                core_port=port,
                state_file=tmp_path / "state.json",
                pairing_code=pairing["code"],
                collect_interval=0.1,
                ping_interval=5.0,
                watch_files=[],
                services=[],
            )
            task = asyncio.create_task(agent.run_forever())
            try:
                target_id = (await _wait_until(lambda: store.list_targets() or None))[0]["target_id"]
                await _wait_until(lambda: store.get_latest_telemetry(target_id))
                assert agent.pairing_code is None  # spent after first successful handshake

                first_seq = store.get_latest_telemetry(target_id)["seq"]

                # Force the connection closed from the SERVER side -- the
                # agent must notice (EOF) and reconnect using its saved
                # token, not the (already-cleared) pairing code.
                server._live[target_id].close()

                def _reconnected_and_progressed():
                    latest = store.get_latest_telemetry(target_id)
                    if latest is None or latest["seq"] <= first_seq:
                        return False
                    return target_id in server.live_target_ids()

                await _wait_until(_reconnected_and_progressed, timeout=15.0)

                targets_after = store.list_targets()
                assert len(targets_after) == 1  # same target row reused, not a second pairing.
                assert targets_after[0]["target_id"] == target_id
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_agent_buffer_flushes_in_order_on_a_stub_writer(tmp_path):
    """Lower-level check of the 'small local buffer' rule (design doc,
    transport rule 4): queued frames are sent in the order they were
    collected, and the buffer drains completely."""

    class _StubWriter:
        def __init__(self):
            self.sent: list[bytes] = []

        def write(self, data: bytes) -> None:
            self.sent.append(data)

        async def drain(self) -> None:
            return None

    async def run():
        agent = SubAgent(core_host="127.0.0.1", core_port=1, state_file=tmp_path / "state.json")
        for i in range(5):
            agent._buffer.append({"seq": i, "collected_at": "ts", "payload": {"i": i}})
        writer = _StubWriter()
        await agent._flush_buffer(writer)
        assert len(agent._buffer) == 0
        # Decode what was actually written and check ordering/content.
        decoded_seqs = []
        for frame_bytes in writer.sent:
            length = proto._LENGTH.unpack(frame_bytes[:4])[0]
            msg = json.loads(frame_bytes[4 : 4 + length])
            decoded_seqs.append(msg["seq"])
        assert decoded_seqs == [0, 1, 2, 3, 4]

    asyncio.run(run())


def test_agent_buffer_is_bounded(tmp_path):
    from kratos.subagent.agent import BUFFER_MAX

    agent = SubAgent(core_host="127.0.0.1", core_port=1, state_file=tmp_path / "state.json")
    for i in range(BUFFER_MAX + 20):
        agent._buffer.append({"seq": i, "collected_at": "ts", "payload": {}})
    assert len(agent._buffer) == BUFFER_MAX
    # Oldest entries were dropped, not newest -- most recent state matters most for live monitoring.
    assert agent._buffer[-1]["seq"] == BUFFER_MAX + 19
