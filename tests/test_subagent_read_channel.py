"""Investigation reads over the real channel: a real CoreServer + a real agent
on loopback + the real local socket. Covers signing/replay, old agents,
unsupported probes, offline/disconnect, concurrency, timeouts and the socket's
own safety checks (docs/subagent_read_routing.md §5)."""
from __future__ import annotations

import asyncio
import os
import socket
import stat
import threading
import time
from pathlib import Path

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import local_reads, protocol as proto, reads, signing
from kratos.subagent.agent import SubAgent
from kratos.subagent.core_server import CoreServer


class Harness:
    def __init__(self, tmp: Path):
        self.dir = tmp
        self.store = SubAgentStore(tmp / "kratos.db")
        self.core = CoreServer(self.store, host="127.0.0.1", port=0, read_socket_path=local_reads.socket_path(tmp))
        self.agent: SubAgent | None = None
        self.tasks: list[asyncio.Task] = []

    async def start(self, *, agent: bool = True, **agent_kwargs) -> str | None:
        self.tasks.append(asyncio.create_task(self.core.serve_forever()))
        while self.core._server is None or self.core._local_reads is None:
            await asyncio.sleep(0.02)
        if not agent:
            return None
        return await self.start_agent(**agent_kwargs)

    async def start_agent(self, **kwargs) -> str:
        code = self.store.create_pairing_code(name="lab")["code"]
        port = self.core._server.sockets[0].getsockname()[1]
        self.agent = SubAgent("127.0.0.1", port, state_file=self.dir / f"agent{len(self.tasks)}.json",
                              pairing_code=code, local_allow_file=None, collect_interval=300, **kwargs)
        self.tasks.append(asyncio.create_task(self.agent.run_forever()))
        for _ in range(200):
            # Both ends done: core holds the connection AND the agent has
            # processed the hello_ack (saved its token). Core marks a target
            # live just before the agent reads that reply.
            if self.core._live and self.agent.token and self.agent.last_target_id:
                return next(iter(self.core._live))
            await asyncio.sleep(0.02)
        raise AssertionError("agent never connected")

    async def read(self, target_id: str, probe: str, params: dict | None = None) -> dict:
        return await asyncio.get_running_loop().run_in_executor(
            None, local_reads.request_read, self.dir, target_id, probe, params or {})

    async def stop(self) -> None:
        if self.agent:
            self.agent.stop()
        self.core.stop()
        await asyncio.sleep(0.1)
        await self.core.close()
        for t in self.tasks:
            t.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


def test_probes_answer_and_bad_requests_are_refused(tmp_path):
    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            clock = await h.read(tid, "clock")
            assert clock["status"] == "ok" and abs(float(clock["data"]["stdout"]) - time.time()) < 5
            hashes = await h.read(tid, "file_hashes")
            assert hashes["status"] == "ok" and "/etc/passwd" in hashes["data"]["stdout"]
            assert (await h.read(tid, "nope"))["status"] == "unsupported"
            bad = await h.read(tid, "open_files", {"pid": "1; id"})
            assert bad["status"] == "refused" and "pid" in bad["reason"]
            assert (await h.read(tid, "capabilities"))["data"]["checks"]
            priv = await h.read(tid, "privileged_accounts", {"since": time.time() - 86400})
            assert priv["status"] == "ok" and "PASSWD\troot\t0" in priv["data"]["stdout"]
        finally:
            await h.stop()
    run(go())


def test_socket_is_owner_only_and_stale_one_is_replaced(tmp_path):
    path = local_reads.socket_path(tmp_path)
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(path))
    stale.close()  # a socket file nobody serves (crashed listener)

    async def go():
        h = Harness(tmp_path)
        await h.start(agent=False)
        try:
            st = os.lstat(path)
            assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
            status = await asyncio.get_running_loop().run_in_executor(None, local_reads.listener_status, tmp_path)
            assert status and status["live"] == {}
        finally:
            await h.stop()
        assert not path.exists()  # removed on stop
    run(go())


def test_a_live_socket_is_never_stolen(tmp_path):
    async def go():
        a = Harness(tmp_path)
        await a.start(agent=False)
        b = CoreServer(a.store, host="127.0.0.1", port=0, read_socket_path=local_reads.socket_path(tmp_path))
        try:
            await b._start_local_reads()
            assert b._local_reads is None  # refused, logged; telemetry would carry on
            assert (await asyncio.get_running_loop().run_in_executor(
                None, local_reads.listener_status, tmp_path))["listener_id"] == a.core.listener_id
        finally:
            await a.stop()
    run(go())


def test_no_listener_and_loose_socket_are_clear_errors(tmp_path, monkeypatch):
    from kratos.subagent import core_listener

    monkeypatch.setattr(core_listener, "listener_running", lambda *a, **k: True)
    monkeypatch.setattr(core_listener, "service_scope", lambda *a, **k: "user")
    with pytest.raises(local_reads.LocalReadError, match="systemctl --user restart kratos-core-listener"):
        local_reads.request_read(tmp_path, "tgt_x", "clock", {})
    monkeypatch.setattr(core_listener, "service_scope", lambda *a, **k: "system")
    with pytest.raises(local_reads.LocalReadError, match="sudo systemctl restart kratos-core-listener"):
        local_reads.request_read(tmp_path, "tgt_x", "clock", {})
    monkeypatch.setattr(core_listener, "listener_running", lambda *a, **k: False)
    with pytest.raises(local_reads.LocalReadError, match="No Kratos listener") as e:
        local_reads.request_read(tmp_path, "tgt_x", "clock", {})
    assert e.value.kind == "no_listener"
    path = local_reads.socket_path(tmp_path)
    s = socket.socket(socket.AF_UNIX)
    s.bind(str(path))
    os.chmod(path, 0o666)
    try:
        with pytest.raises(local_reads.LocalReadError, match="readable by other users"):
            local_reads.request_read(tmp_path, "tgt_x", "clock", {})
    finally:
        s.close()
    os.chmod(path, 0o600)
    with pytest.raises(local_reads.LocalReadError) as e:  # nothing serves it: stale
        local_reads.request_read(tmp_path, "tgt_x", "clock", {})
    assert e.value.kind == "no_listener"


def test_long_data_dir_uses_a_private_runtime_socket(tmp_path):
    deep = tmp_path / ("x" * 120)
    p = local_reads.socket_path(deep)
    assert len(str(p)) < 108 and p.name.startswith("kratos-reads-")


def test_unknown_or_offline_target(tmp_path):
    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            h.core._started_monotonic -= 1000  # long-running listener: don't wait for a reconnect
            h.core._local_reads.started_monotonic -= 1000
            assert (await h.read("tgt_nobody", "clock"))["status"] == "offline"
            h.agent.stop()
            for _ in range(100):
                if not h.core._live:
                    break
                await asyncio.sleep(0.02)
            h.core._disconnected_at[tid] -= 1000
            out = await h.read(tid, "clock")
            assert out["status"] == "offline" and "isn't connected" in out["reason"]
        finally:
            await h.stop()
    run(go())


def test_listener_waits_for_an_agent_that_is_reconnecting(tmp_path):
    async def go():
        h = Harness(tmp_path)
        await h.start(agent=False)
        try:
            pending = asyncio.ensure_future(h.read("tgt_placeholder", "clock"))
            await asyncio.sleep(0.3)
            tid = await h.start_agent()
            # the request named a different id; a request for the real one connects fine
            assert (await pending)["status"] == "offline"
            h.agent.stop()
            for _ in range(100):
                if not h.core._live:
                    break
                await asyncio.sleep(0.02)
            agent2_task = asyncio.ensure_future(h.read(tid, "clock"))
            await asyncio.sleep(0.3)
            # same identity reconnects
            port = h.core._server.sockets[0].getsockname()[1]
            again = SubAgent("127.0.0.1", port, state_file=h.agent.state_file, local_allow_file=None,
                             collect_interval=300)
            h.tasks.append(asyncio.create_task(again.run_forever()))
            out = await agent2_task
            again.stop()
            assert out["status"] == "ok"
        finally:
            await h.stop()
    run(go())


def test_old_agent_without_reads_is_told_to_update(tmp_path, monkeypatch):
    real = proto.build_hello

    def old_hello(*a, **k):
        k.pop("read_probes", None)
        k.pop("read_api", None)
        msg = real(*a, **k)
        msg["agent_version"] = "0.2.0"
        return msg

    monkeypatch.setattr(proto, "build_hello", old_hello)

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            out = await h.read(tid, "clock")
            assert out["status"] == "old_agent" and "0.3.0" in out["reason"] and "/subagent" in out["reason"]
        finally:
            await h.stop()
    run(go())


def test_agent_refuses_unsigned_replayed_and_foreign_requests(tmp_path):
    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            a = h.agent
            key = signing.derive_signing_key(a.token)

            def req(seq, nonce=None, sign=True, probe="clock"):
                env = proto.build_read_request(f"r{seq}", probe, {}, seq, nonce or a._session_nonce)
                if sign:
                    env["sig"] = signing.sign_envelope(key, env)
                return env

            assert a._check_read_request(req(1000, sign=False)) == "invalid signature"
            assert "not for this connection" in a._check_read_request(req(1000, nonce="ab" * 16))
            assert a._check_read_request(req(1000)) is None
            assert "replay" in a._check_read_request(req(1000))      # same seq again
            assert "replay" in a._check_read_request(req(999))       # older seq
            forged = req(1001)
            forged["probe"] = "processes"                           # tampered after signing
            assert forged["sig"] and a._check_read_request(forged) == "invalid signature"
            a._peer_ip = "192.168.1.20"                              # plain LAN, no flag
            assert "not loopback or over a Tailscale interface" in a._check_read_request(req(1002))
            a.allow_untrusted_transport = True
            assert a._check_read_request(req(1003)) is None
            # the live channel still works after all that (core's own seq is independent)
            a._peer_ip = "127.0.0.1"
            a._last_read_seq = 0
            assert (await h.read(tid, "clock"))["status"] == "ok"
        finally:
            await h.stop()
    run(go())


def test_reads_never_touch_execution(tmp_path):
    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            assert h.agent.execution_enabled is False
            assert (await h.read(tid, "processes"))["status"] == "ok"
            assert h.agent.execution_enabled is False and h.agent._whitelist_specs == {}
        finally:
            await h.stop()
    run(go())


def test_concurrent_reads_are_served_one_at_a_time(tmp_path, monkeypatch):
    active = {"now": 0, "max": 0}
    lock = threading.Lock()
    real = reads._PROBES["clock"]

    def slow_clock(p):
        with lock:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        time.sleep(0.3)
        with lock:
            active["now"] -= 1
        return real(p)

    monkeypatch.setitem(reads._PROBES, "clock", slow_clock)

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            outs = await asyncio.gather(*(h.read(tid, "clock") for _ in range(4)))
            assert [o["status"] for o in outs] == ["ok"] * 4
            assert active["max"] == 1
        finally:
            await h.stop()
    run(go())


def test_disconnect_mid_read_answers_at_once(tmp_path, monkeypatch):
    monkeypatch.setitem(reads._PROBES, "processes", lambda p: time.sleep(2) or {})

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            pending = asyncio.ensure_future(h.read(tid, "processes"))
            await asyncio.sleep(0.4)
            t0 = time.monotonic()
            h.core._live[tid].close()  # the link drops while the box is working
            out = await pending
            assert out["status"] == "offline" and time.monotonic() - t0 < 3
        finally:
            await h.stop()
    run(go())


def test_probe_timeout_is_reported(tmp_path, monkeypatch):
    def hang(p):
        raise reads.ProbeTimeout("timed out after 30s")

    monkeypatch.setitem(reads._PROBES, "processes", hang)

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            out = await h.read(tid, "processes")
            assert out["status"] == "timed_out" and "processes" in out["reason"]
        finally:
            await h.stop()
    run(go())


def test_core_gives_up_on_a_silent_agent(tmp_path, monkeypatch):
    monkeypatch.setitem(reads._PROBES, "clock", lambda p: time.sleep(3) or {"returncode": 0, "stdout": "1", "stderr": ""})

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            out = await h.core.read_probe(tid, "clock", {}, timeout=0.5)
            assert out["status"] == "timed_out"
            assert (await h.read(tid, "file_hashes"))["status"] == "ok"  # the lock was released
        finally:
            await h.stop()
    run(go())


def test_oversized_result_is_an_error_not_a_dropped_connection(tmp_path, monkeypatch):
    monkeypatch.setitem(reads._PROBES, "processes",
                        lambda p: {"returncode": 0, "stdout": "x" * (proto.MAX_FRAME_BYTES + 10), "stderr": ""})

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            out = await h.read(tid, "processes")
            assert out["status"] == "error" and "too large" in out["reason"]
            assert (await h.read(tid, "clock"))["status"] == "ok"
        finally:
            await h.stop()
    run(go())
