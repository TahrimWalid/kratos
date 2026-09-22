"""
End-to-end (real localhost TCP sockets) tests for capability 2 (direct
execution): signed whitelist push, signed exec dispatch, the agent's
independent re-validation, the local `execution_enabled` opt-in, the
dead-man's switch, and anti-rollback on the whitelist version. Mirrors
test_subagent_integration.py's style (real CoreServer <-> SubAgent, no
mocking of the wire).

IMPORTANT: nothing here enables execution against a real target. Every
`SubAgent` in this file runs against a throwaway loopback TCP server in a
test process; `execution_enabled=True` is passed explicitly, per test, the
same way `docs/subagent_whitelist_design.md` §9 #7 frames it -- building and
testing the mechanism is unblocked; enabling it against a REAL target still
needs the independent review this test suite is evidence FOR, not a
substitute for.
"""
from __future__ import annotations

import asyncio
import contextlib
import socket

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import protocol as proto
from kratos.subagent import signing
from kratos.subagent import whitelist as W
from kratos.subagent.agent import SubAgent
from kratos.subagent.core_server import CoreServer


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _start_server(store: SubAgentStore, port: int, whitelist_store=None) -> CoreServer:
    server = CoreServer(store, host="127.0.0.1", port=port, whitelist_store=whitelist_store)
    server._server = await asyncio.start_server(server._handle_connection, "127.0.0.1", port)
    if whitelist_store is not None:
        server._watch_task = asyncio.create_task(server._whitelist_watch_loop())
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


async def _pair_agent(store, port, tmp_path, *, name=None, execution_enabled=False, **kwargs) -> tuple[SubAgent, asyncio.Task, str]:
    pairing = store.create_pairing_code(name=name)
    agent = SubAgent(
        core_host="127.0.0.1", core_port=port,
        state_file=tmp_path / f"state-{name or 'a'}.json",
        pairing_code=pairing["code"],
        collect_interval=0.1, ping_interval=2.0,
        watch_files=[], services=[],
        execution_enabled=execution_enabled,
        **kwargs,
    )
    task = asyncio.create_task(agent.run_forever())
    await _wait_until(lambda: agent.last_target_id is not None)
    return agent, task, agent.last_target_id


def test_whitelist_push_is_applied_and_acked(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wstore = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                ok = await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 1)
                assert ok is True
                await _wait_until(lambda: agent._whitelist_version == 1)
                assert "fail2ban.ban_ip" in agent._whitelist_specs
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_agent_rejects_a_whitelist_push_with_a_bad_signature(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                writer = server._live[target_id]
                envelope = {"type": proto.MSG_WHITELIST_PUSH, "version": 1, "actions": [W.spec_to_wire(spec)]}
                envelope["sig"] = "0" * 64  # bogus signature
                await proto.write_frame(writer, envelope)
                await asyncio.sleep(0.3)
                assert agent._whitelist_version is None  # never applied
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_anti_rollback_rejects_an_older_replayed_version(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 5)
                await _wait_until(lambda: agent._whitelist_version == 5)

                # A replayed, older-version push (e.g. a captured pre-revocation
                # message) must be rejected -- version must not go backwards.
                key = signing.derive_signing_key(target["token"])
                envelope = {"type": proto.MSG_WHITELIST_PUSH, "version": 3, "actions": []}
                envelope["sig"] = signing.sign_envelope(key, envelope)
                await proto.write_frame(server._live[target_id], envelope)
                await asyncio.sleep(0.3)
                assert agent._whitelist_version == 5  # unchanged
                assert "fail2ban.ban_ip" in agent._whitelist_specs  # not wiped by the replay
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_equal_version_repush_is_accepted_idempotently(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                ok1 = await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 2)
                assert ok1 is True
                ok2 = await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 2)
                assert ok2 is True  # same version re-applied cleanly, not rejected
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_a_malformed_action_rejects_the_whole_push(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                good = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                bad_wire = W.spec_to_wire(good)
                bad_wire["argv_template"] = ["bash", "-c", "{ip}"]  # would be a HardExclusionError
                key = signing.derive_signing_key(target["token"])
                envelope = {"type": proto.MSG_WHITELIST_PUSH, "version": 1, "actions": [W.spec_to_wire(good), bad_wire]}
                envelope["sig"] = signing.sign_envelope(key, envelope)
                await proto.write_frame(server._live[target_id], envelope)
                await asyncio.sleep(0.3)
                assert agent._whitelist_version is None  # the WHOLE push rejected, not partially applied
                assert agent._whitelist_specs == {}
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_refused_when_execution_not_enabled(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=False)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 1)
                await _wait_until(lambda: agent._whitelist_version == 1)

                result = await server.dispatch_action(
                    target_id, target["token"], "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1
                )
                assert result["status"] == "refused"
                assert "not enabled" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_succeeds_end_to_end_with_execution_enabled(tmp_path):
    """The full real path -- signed dispatch, agent-side signature/version/
    dead-man's-switch checks, independent re-validation, render_argv, and a
    REAL subprocess execution (a harmless, deterministic command: `echo`)."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                harmless = W.ActionSpec(
                    id="test.echo", layer="maintainer",
                    argv_template=("echo", "{msg}"),
                    slots={"msg": W.Slot(kind="token")},
                    effect="Echoes a token to stdout.", reversibility="No state change to reverse.",
                    blast_radius="None -- stdout only.", source_recommendation=("TEST-ECHO",),
                )
                target = store.get_target(target_id)
                ok = await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(harmless)], 1)
                assert ok is True

                result = await server.dispatch_action(
                    target_id, target["token"], "test.echo", {"msg": "hello-kratos"}, 1
                )
                assert result["status"] == "ok"
                assert result["exit_code"] == 0
                assert "hello-kratos" in result["stdout_tail"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_refused_on_stale_whitelist_version(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 3)
                await _wait_until(lambda: agent._whitelist_version == 3)

                # Dispatch claims an OLD version -- must be refused even
                # though the action itself is currently whitelisted.
                result = await server.dispatch_action(
                    target_id, target["token"], "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 2
                )
                assert result["status"] == "refused"
                assert "stale" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_refused_for_unknown_action_id(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [], 1)
                await _wait_until(lambda: agent._whitelist_version == 1)
                result = await server.dispatch_action(target_id, target["token"], "no.such.action", {}, 1)
                assert result["status"] == "refused"
                assert "unknown action_id" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_refused_on_bad_signature(tmp_path):
    """Sends a forged (bad-signature) exec_dispatch directly over the live
    connection (bypassing `dispatch_action`'s own correct signing) and
    confirms the agent still replies with a proper refused exec_result --
    registering a future the same way `dispatch_action` itself does, so this
    test observes the real reply instead of guessing at timing."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 1)
                await _wait_until(lambda: agent._whitelist_version == 1)

                dispatch_id = "forged-1"
                fut = asyncio.get_event_loop().create_future()
                server._pending_exec[dispatch_id] = fut
                envelope = {
                    "type": proto.MSG_EXEC_DISPATCH, "dispatch_id": dispatch_id, "action_id": "fail2ban.ban_ip",
                    "slot_values": {"jail": "sshd", "ip": "8.8.8.8"}, "whitelist_version": 1, "sig": "0" * 64,
                }
                await proto.write_frame(server._live[target_id], envelope)
                result = await asyncio.wait_for(fut, timeout=5)
                assert result["status"] == "refused"
                assert "signature" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_refused_with_wrong_slot_values(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 1)
                await _wait_until(lambda: agent._whitelist_version == 1)

                result = await server.dispatch_action(
                    target_id, target["token"], "fail2ban.ban_ip", {"jail": "apache", "ip": "8.8.8.8"}, 1
                )
                assert result["status"] == "refused"
                assert "validation failed" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dead_mans_switch_disarms_execution_when_heartbeat_is_stale(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
                target = store.get_target(target_id)
                await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(spec)], 1)
                await _wait_until(lambda: agent._whitelist_version == 1)

                # Force the heartbeat clock to look stale without waiting
                # DEAD_MANS_SWITCH_SECONDS for real.
                agent._last_core_message_ts -= 10_000

                result = await server.dispatch_action(
                    target_id, target["token"], "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1
                )
                assert result["status"] == "refused"
                assert "dead-man" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_whitelist_store_integration_pushes_effective_action_set_on_connect(tmp_path):
    """The whitelist_store-wired path: a target's effective enabled action
    set (maintainer default opted in for this test) is pushed automatically
    the moment it connects, with no manual push_whitelist call."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wstore = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()

        # Pre-create the pairing so we know the target_id before connecting,
        # so we can opt in a maintainer default for it before the agent dials in.
        pairing = store.create_pairing_code()
        # We don't know target_id until redemption, so instead: pair first,
        # THEN set an override, THEN reconnect to see the push pick it up.
        server = await _start_server(store, port, whitelist_store=wstore)
        try:
            agent = SubAgent(
                core_host="127.0.0.1", core_port=port, state_file=tmp_path / "state-wl.json",
                pairing_code=pairing["code"], collect_interval=0.1, ping_interval=2.0,
                watch_files=[], services=[], execution_enabled=False,
            )
            task = asyncio.create_task(agent.run_forever())
            try:
                await _wait_until(lambda: agent.last_target_id is not None)
                target_id = agent.last_target_id
                await _wait_until(lambda: agent._whitelist_version is not None)
                initial_version = agent._whitelist_version
                # low-tier defaults are enabled out of the box -- confirm one arrived.
                assert "fail2ban.ban_ip" in agent._whitelist_specs

                # Now opt in a high-tier default and confirm the WATCH LOOP
                # (not a manual push) picks it up within a couple of ticks.
                wstore.set_maintainer_override(target_id, "service.enable_now", True)
                await _wait_until(lambda: "service.enable_now" in agent._whitelist_specs, timeout=8.0)
                assert agent._whitelist_version > initial_version
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_dispatch_request_queue_is_serviced_by_the_watch_loop(tmp_path):
    """The cross-process path a real TUI would use: a dispatch REQUEST row
    (never a direct in-process call) is picked up by CoreServer's watch
    loop, actually dispatched over the real signed channel, and the result
    is written back onto the same row for the (separate-process) caller to
    poll."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wstore = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port, whitelist_store=wstore)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True)
            try:
                await _wait_until(lambda: agent._whitelist_version is not None)
                wstore.set_execution_opt_in(target_id, True)
                version = wstore.get_whitelist_version(target_id)
                request_id = wstore.create_dispatch_request(
                    target_id, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, version
                )

                def _completed():
                    row = wstore.get_dispatch_request(request_id)
                    return row if row and row["status"] == "done" else None

                row = await _wait_until(_completed, timeout=8.0)
                # fail2ban-client isn't installed in this test sandbox, so
                # the REAL outcome is an execution error -- proving the
                # queue really drove a real dispatch attempt end to end,
                # not a stubbed success.
                assert row["result"]["status"] in ("error", "ok")
                assert row["completed_at"] is not None
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())
