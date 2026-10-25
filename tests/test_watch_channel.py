"""Continuous detection over the real agent link (C.2): a real listener and a real agent
on localhost, the agent following a fake journal. Turning watching on reaches the agent
as a signed push; a matching line becomes a stored detection, a finding and one alert;
detections made while the link is down arrive once after it is back; many agents at
once never stall the listener's pings; an old agent is never pushed to."""
from __future__ import annotations

import asyncio
import contextlib
import time

import pytest

from kratos.agent import scheduled_run
from kratos.agent import triggers as T
from kratos.detect import live as L
from kratos.events.store import EventStore
from kratos.lifecycle.decide import Actor
from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import core_server as CS
from kratos.subagent import protocol as proto
from kratos.subagent.agent import SubAgent
from kratos.subagent.core_server import CoreServer

from tests._watch_fakes import fake_journalctls, append, journal_entry, make_fake_journalctl, sudo_line
from tests.test_subagent_execution_channel import _free_port, _wait_until

PERSON = Actor(user="alice", interface="cli")
MACHINE = "db-01"
CHATTR_RULE = "SIGMA-34979410"


async def _server(tmp_path, port) -> CoreServer:
    store = SubAgentStore(tmp_path / "kratos.db")
    server = CoreServer(store, host="127.0.0.1", port=port, whitelist_store=WhitelistStore(tmp_path / "kratos.db"))
    server._server = await asyncio.start_server(server._handle_connection, "127.0.0.1", port)
    server._detect_task = asyncio.create_task(server._detect_loop())
    return server


async def _stop_server(server: CoreServer) -> None:
    await server.close()


@pytest.fixture(autouse=True)
def _no_leaked_journalctl(tmp_path):
    """Stopping the watcher never leaves its journalctl running."""
    yield
    deadline = time.monotonic() + 10
    while fake_journalctls(tmp_path) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert fake_journalctls(tmp_path) == []


def _agent(tmp_path, port, code=None) -> SubAgent:
    agent = SubAgent(core_host="127.0.0.1", core_port=port, state_file=tmp_path / "agent" / "state.json",
                     pairing_code=code, collect_interval=30, ping_interval=2.0, watch_files=[], services=[],
                     local_allow_file=None)
    exe, _data = make_fake_journalctl(tmp_path) if not (tmp_path / "journalctl").exists() else (
        tmp_path / "journalctl", tmp_path / "journal.jsonl")
    agent.watcher.journalctl = str(exe)
    agent.watcher.audit_path = str(tmp_path / "audit.log")
    return agent


@pytest.fixture
def notes(monkeypatch):
    sent: list[tuple[str, str, float]] = []

    def notifier(body: str, severity: str) -> dict:
        sent.append((body, severity, time.time()))
        return {"status": "sent"}

    monkeypatch.setattr(scheduled_run, "_default_notifier", notifier)
    return sent


def test_a_matching_line_reaches_the_phone_once_through_the_one_path(tmp_path, notes):
    T.save_trigger(tmp_path, name="live-high", min_severity="medium", action="notify", cooldown_minutes=15,
                   only_new_or_reopened=True)
    from kratos import settings_store

    settings_store.set("detect.alert_batch_seconds", 1, data_dir=tmp_path, actor="test")

    async def run():
        port = _free_port()
        server = await _server(tmp_path, port)
        store = server.store
        code = store.create_pairing_code(name=MACHINE)["code"]
        agent = _agent(tmp_path, port, code)
        task = asyncio.create_task(agent.run_forever())
        try:
            tid = await _wait_until(lambda: agent.last_target_id)
            await _wait_until(lambda: tid in server._agent_watch)
            L.set_watching(tmp_path, tid, True, actor=PERSON)
            await _wait_until(lambda: agent.watcher.state["journal"]["state"] == "watching", timeout=30)
            await _wait_until(lambda: (L.pack_state(tmp_path, tid) or {}).get("ack_status"), timeout=30)
            assert (L.pack_state(tmp_path, tid) or {}).get("ack_status") == "ok"
            sent_at = time.time()
            append(tmp_path / "journal.jsonl", journal_entry(1, sent_at, sudo_line("alice", "/usr/bin/chattr -i "
                                                                                   "/etc/hostname"), comm="sudo"))
            await _wait_until(lambda: notes, timeout=45)
            assert len(notes) == 1 and CHATTR_RULE in notes[0][0] and "rule by" in notes[0][0]
            assert notes[0][2] - sent_at < 45       # the measured end-to-end latency is a lab number
            dets = EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=10)
            assert [d.rule_id for d in dets] == [CHATTR_RULE]
            await _wait_until(lambda: len(agent.watcher.spool) == 0)      # acknowledged
            rows = {r["source"]: r for r in L.watch_rows(tmp_path, tid)}
            assert rows["journal"]["state"] == "watching" and rows["auditd"]["state"] == "not_available"
            # turned off: the agent stops following
            L.set_watching(tmp_path, tid, False, actor=PERSON)
            await _wait_until(lambda: not agent.watcher.enabled, timeout=15)
        finally:
            agent.stop()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            agent.watcher.stop()
            await _stop_server(server)

    asyncio.run(run())


def test_detections_made_while_the_link_is_down_arrive_once_after_it_is_back(tmp_path, notes):
    async def run():
        port = _free_port()
        server = await _server(tmp_path, port)
        code = server.store.create_pairing_code(name=MACHINE)["code"]
        agent = _agent(tmp_path, port, code)
        task = asyncio.create_task(agent.run_forever())
        try:
            tid = await _wait_until(lambda: agent.last_target_id)
            await _wait_until(lambda: tid in server._agent_watch)
            L.set_watching(tmp_path, tid, True, actor=PERSON)
            await _wait_until(lambda: agent.watcher.state["journal"]["state"] == "watching", timeout=15)
            await _stop_server(server)                     # the listener goes away
            now = time.time()
            append(tmp_path / "journal.jsonl", *[journal_entry(i, now + i / 10, sudo_line(
                "alice", f"/usr/bin/chattr -i /f{i}"), comm="sudo") for i in range(1, 4)])
            await _wait_until(lambda: len(agent.watcher.spool) == 3, timeout=15)
            server = await _server(tmp_path, port)       # back
            await _wait_until(lambda: len(agent.watcher.spool) == 0, timeout=60)
            dets = EventStore(tmp_path / "kratos.db").query(MACHINE, dataset="kratos.detect", limit=10)
            assert len(dets) == 3
        finally:
            agent.stop()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            agent.watcher.stop()
            await _stop_server(server)

    asyncio.run(run())


class _Raw:
    """A minimal agent speaking the protocol by hand (for load)."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    @classmethod
    async def pair(cls, port: int, code: str, *, watch: bool = True) -> "_Raw":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        hello = proto.build_hello("a" + code, {"pairing_code": code}, "host", "0.9.0", session_nonce="ab" * 16,
                                  watch={"enabled": False, "version": None, "packs": []} if watch else None)
        await proto.write_frame(writer, hello)
        ack = await proto.read_frame(reader)
        assert ack["type"] == proto.MSG_HELLO_ACK
        return cls(reader, writer)


def test_many_agents_sending_detections_at_once_never_stall_pings(tmp_path, monkeypatch):
    monkeypatch.setattr(CS, "DETECT_QUEUE_MAX", 40)
    monkeypatch.setattr(CS, "DETECT_PER_AGENT_MAX", 5)
    slow = []

    def handle_detection(self, target_id, msg):
        time.sleep(0.05)                                 # a slow database
        slow.append(1)
        return True

    monkeypatch.setattr(L.LiveDetections, "handle_detection", handle_detection)

    async def run():
        port = _free_port()
        server = await _server(tmp_path, port)
        try:
            senders = [await _Raw.pair(port, server.store.create_pairing_code(name=f"m{i}")["code"])
                       for i in range(30)]
            probe = await _Raw.pair(port, server.store.create_pairing_code(name="probe")["code"])
            peak = 0

            async def flood(raw: _Raw) -> None:
                for seq in range(1, 41):
                    await proto.write_frame(raw.writer, {"type": proto.MSG_DETECTION, "seq": seq, "rule_id": "X"})

            async def drain(raw: _Raw) -> None:
                with contextlib.suppress(Exception):
                    while await proto.read_frame(raw.reader) is not None:
                        pass

            drains = [asyncio.create_task(drain(r)) for r in senders]
            floods = asyncio.gather(*(flood(r) for r in senders))
            worst = 0.0
            for _ in range(20):
                peak = max(peak, server._detect_inflight)
                t0 = time.monotonic()
                await proto.write_frame(probe.writer, proto.build_ping(time.time()))
                while True:
                    msg = await asyncio.wait_for(proto.read_frame(probe.reader), timeout=5)
                    if msg["type"] == proto.MSG_PONG:
                        break
                worst = max(worst, time.monotonic() - t0)
                await asyncio.sleep(0.05)
            await floods
            assert worst < 0.5, worst                   # the listener answers while the workers are busy
            assert peak <= 40 and server.detect_backpressure > 0
            for t in drains:
                t.cancel()
        finally:
            await _stop_server(server)

    asyncio.run(run())


def test_an_old_agent_is_never_pushed_to_and_cannot_be_turned_on(tmp_path):
    async def run():
        port = _free_port()
        server = await _server(tmp_path, port)
        try:
            code = server.store.create_pairing_code(name="old")["code"]
            raw = await _Raw.pair(port, code, watch=False)
            tid = await _wait_until(lambda: next(iter(server._live), None))
            assert not server.watch_capable(tid)
            assert await server.push_detect_config(tid) is False
            conn = server.store
            conn._write("UPDATE subagent_targets SET agent_version = '0.8.0', link_mode = 'tls-pinned' "
                        "WHERE target_id = ?", (tid,))
            with pytest.raises(L.WatchSetupError, match="update the agent"):
                L.set_watching(tmp_path, tid, True, actor=PERSON)
            raw.writer.close()
        finally:
            await _stop_server(server)

    asyncio.run(run())
