"""Agent-side hardening from the independent review (docs/subagent_execution_track.md §2):
replay (F4), persisted anti-rollback floor (F5), signed heartbeat (F6), guard-chain type
robustness (F7/F8), trusted transport (F9) -- plus the final run-time ceiling gate and
target-local exact commands.

Nothing here executes against a real target: agents talk to an in-process loopback core,
and the only real subprocess is `echo`."""
from __future__ import annotations

import asyncio
import json
import struct
import time

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import ceiling as C
from kratos.subagent import protocol as proto
from kratos.subagent import signing
from kratos.subagent import whitelist as W
from kratos.subagent.agent import SubAgent

from test_subagent_execution_channel import (
    ECHO_SPEC, TEST_CEILING, _free_port, _pair_agent, _start_server, _stop_agent, _wait_until,
)

TOKEN = "t" * 43


class FakeWriter:
    """Captures frames an agent writes, for unit-level handler tests."""

    def __init__(self) -> None:
        self.frames: list[dict] = []

    def write(self, data: bytes) -> None:
        (n,) = struct.unpack(">I", data[:4])
        self.frames.append(json.loads(data[4:4 + n]))

    async def drain(self) -> None:
        return None


def _agent(tmp_path, **kw) -> SubAgent:
    kw.setdefault("local_allow_file", None)
    kw.setdefault("ceiling", TEST_CEILING)
    a = SubAgent("127.0.0.1", 1, state_file=tmp_path / "state.json", **kw)
    a.token = TOKEN
    a._session_nonce = "ab" * 16
    a._peer_ip = "127.0.0.1"
    a._last_core_message_ts = time.time()
    a._sent_pings.append(a._last_core_message_ts)   # the ping that heartbeat answered
    return a


def _signed(msg: dict, token: str = TOKEN) -> dict:
    msg = dict(msg)
    msg["sig"] = signing.sign_envelope(signing.derive_signing_key(token), msg)
    return msg


def _push(version, actions) -> dict:
    return _signed({"type": proto.MSG_WHITELIST_PUSH, "version": version, "actions": actions})


def _dispatch(agent, **over) -> dict:
    msg = {"type": proto.MSG_EXEC_DISPATCH, "dispatch_id": over.pop("dispatch_id", "d1"),
           "action_id": "test.echo", "slot_values": {"msg": "hi"},
           "whitelist_version": agent._whitelist_version, "session_nonce": agent._session_nonce,
           "heartbeat_ts": agent._sent_pings[-1] if agent._sent_pings else None}
    msg.update(over)
    return _signed(msg)


async def _apply(agent, version=1, actions=None):
    w = FakeWriter()
    await agent._handle_whitelist_push(_push(version, actions or [W.spec_to_wire(ECHO_SPEC)]), w)
    return w


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# F4 -- replay
# ---------------------------------------------------------------------------
def test_a_dispatch_id_runs_once_per_connection(tmp_path):
    async def go():
        a = _agent(tmp_path, execution_enabled=True)
        await _apply(a)
        first = await a._process_exec_dispatch(_dispatch(a))
        again = await a._process_exec_dispatch(_dispatch(a))
        return first, again

    first, again = _run(go())
    assert first["status"] == "ok" and "hi" in first["stdout_tail"]
    assert again["status"] == "refused" and "duplicate" in again["reason"]


def test_a_dispatch_signed_for_another_connection_is_refused(tmp_path):
    async def go():
        a = _agent(tmp_path, execution_enabled=True)
        await _apply(a)
        return await a._process_exec_dispatch(_dispatch(a, session_nonce="cd" * 16))

    r = _run(go())
    assert r["status"] == "refused" and "not for this connection" in r["reason"]


def test_captured_dispatch_is_refused_after_reconnect_end_to_end(tmp_path):
    """Real sockets: a dispatch captured on connection 1 is replayed verbatim
    on connection 2 and refused."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path, execution_enabled=True,
                                                       ceiling=TEST_CEILING)
            try:
                target = store.get_target(target_id)
                assert await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(ECHO_SPEC)], 1)
                captured: list[dict] = []
                real_write = proto.write_frame

                async def spy(writer, msg):
                    if msg.get("type") == proto.MSG_EXEC_DISPATCH:
                        captured.append(dict(msg))
                    await real_write(writer, msg)

                proto.write_frame = spy
                try:
                    ok = await server.dispatch_action(target_id, target["token"], "test.echo", {"msg": "x"}, 1)
                finally:
                    proto.write_frame = real_write
                assert ok["status"] == "ok"

                old_nonce = agent._session_nonce
                server._live[target_id].close()  # drop the connection; the agent reconnects
                await _wait_until(lambda: agent._session_nonce not in (None, old_nonce) and target_id in server._live)
                await _wait_until(agent._execution_armed)
                assert await server.push_whitelist(target_id, target["token"], [W.spec_to_wire(ECHO_SPEC)], 1)
                result = await agent._process_exec_dispatch(captured[0])
                assert result["status"] == "refused" and "not for this connection" in result["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# F5 -- anti-rollback survives a restart
# ---------------------------------------------------------------------------
def test_version_floor_persists_across_restart(tmp_path):
    async def go():
        a = _agent(tmp_path)
        await _apply(a, version=5)
        b = _agent(tmp_path)  # fresh process, same state file and token
        assert b._whitelist_version is None and b._version_floor() == 5
        w = await _apply(b, version=3)
        # refused, not acked -- and core is told why and what this machine has
        assert b._whitelist_version is None
        assert [f["type"] for f in w.frames] == [proto.MSG_WHITELIST_PUSH_REFUSED]
        assert w.frames[0]["floor"] == 5 and "anti-rollback" in w.frames[0]["reason"]
        w = await _apply(b, version=5)
        assert b._whitelist_version == 5 and w.frames[0]["version"] == 5
        c = _agent(tmp_path)
        c.token = "u" * 43  # re-paired: a new core-side counter starts fresh
        await c._handle_whitelist_push(_push(1, [W.spec_to_wire(ECHO_SPEC)]) | {}, FakeWriter())
        return c

    c = _run(go())
    assert c._whitelist_version is None  # signed with the OLD token -> rejected on signature, as it should be


# ---------------------------------------------------------------------------
# F6 -- only a signed pong for this connection arms the dead-man's switch
# ---------------------------------------------------------------------------
def test_only_signed_pong_arms_execution(tmp_path):
    a = _agent(tmp_path)
    a._last_core_message_ts = None
    sent = a._sent_pings[-1]                       # a ping this connection really sent
    plain = {"type": proto.MSG_PONG, "ts": sent}
    assert not a._pong_is_authentic(plain)
    assert not a._pong_is_authentic(_signed({**plain, "session_nonce": "cd" * 16}))
    assert not a._pong_is_authentic(_signed({**plain, "session_nonce": a._session_nonce}, token="x" * 43))
    assert a._pong_is_authentic(_signed({**plain, "session_nonce": a._session_nonce}))


def test_unsigned_pong_and_telemetry_ack_do_not_arm_over_the_wire(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            try:
                agent._last_core_message_ts = None
                writer = server._live[target_id]
                await proto.write_frame(writer, proto.build_pong(time.time()))
                await proto.write_frame(writer, proto.build_telemetry_ack(1))
                await asyncio.sleep(0.2)
                assert agent._last_core_message_ts is None
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# F7 / F8 -- malformed values are refusals, never crashes or type confusion
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("override,needle", [
    ({"action_id": {"x": 1}}, "malformed"),
    ({"action_id": ["test.echo"]}, "malformed"),
    ({"slot_values": ["hi"]}, "malformed"),
    ({"whitelist_version": 1.0}, "malformed"),
    ({"whitelist_version": True}, "malformed"),
    ({"dispatch_id": 7}, "malformed"),
    ({"dispatch_id": "x" * 200}, "malformed"),
])
def test_malformed_dispatch_fields_are_refused(tmp_path, override, needle):
    async def go():
        a = _agent(tmp_path, execution_enabled=True)
        await _apply(a)
        w = FakeWriter()
        await a._handle_exec_dispatch(_dispatch(a, **override), w)
        return w.frames[0]

    frame = _run(go())
    assert frame["status"] == "refused" and needle in frame["reason"]


@pytest.mark.parametrize("version", [1.0, True, "1", -1, None, 2**31, 2**70])
def test_malformed_push_versions_are_refused(tmp_path, version):
    async def go():
        a = _agent(tmp_path)
        w = FakeWriter()
        await a._handle_whitelist_push(_push(version, [W.spec_to_wire(ECHO_SPEC)]), w)
        return a, w

    a, w = _run(go())
    assert a._whitelist_version is None and a._version_floor() is None  # nothing persisted
    assert [f["type"] for f in w.frames] == [proto.MSG_WHITELIST_PUSH_REFUSED]
    assert w.frames[0]["version"] is None


def test_a_huge_version_cannot_lock_out_later_pushes(tmp_path):
    """Review v2 F-3: a push with version 2**70 used to be applied and written to
    the persisted floor, so every later push (core counts from 1) was refused
    forever. Now the largest accepted version is the protocol bound."""
    async def go():
        a = _agent(tmp_path)
        await _apply(a, version=2**70)
        assert a._version_floor() is None
        w = await _apply(a, version=1)
        assert a._whitelist_version == 1 and w.frames[0]["type"] == proto.MSG_WHITELIST_PUSH_ACK
        w = await _apply(a, version=proto.MAX_WHITELIST_VERSION)
        assert a._version_floor() == proto.MAX_WHITELIST_VERSION

    _run(go())


def test_reset_whitelist_floor_clears_it_and_refuses_while_running(tmp_path, capsys):
    from kratos.subagent import agent as agent_mod

    async def go():
        a = _agent(tmp_path)
        await _apply(a, version=7)
        return a

    a = _run(go())
    state_file = a.state_file
    assert a._version_floor() == 7
    held = agent_mod._try_instance_lock(state_file)  # a running agent holds this
    try:
        assert agent_mod.main(["--state-file", str(state_file), "--reset-whitelist-floor"]) == 2
        assert "stop it first" in capsys.readouterr().err
    finally:
        held.close()
    assert agent_mod.main(["--state-file", str(state_file), "--reset-whitelist-floor"]) == 0
    saved = json.loads(state_file.read_text())
    assert "whitelist_version_floor" not in saved and saved["token"] == TOKEN  # identity kept
    assert _agent(tmp_path)._version_floor() is None
    assert agent_mod.main(["--state-file", str(state_file), "--reset-whitelist-floor"]) == 0
    assert "Nothing to reset" in capsys.readouterr().out


def test_a_second_agent_on_the_same_state_file_does_not_start(tmp_path, monkeypatch):
    from kratos.subagent import agent as agent_mod

    state_file = tmp_path / "state.json"
    held = agent_mod._try_instance_lock(state_file)
    monkeypatch.setattr(agent_mod, "INSTANCE_LOCK_WAIT_SECONDS", 0.6)
    try:
        assert agent_mod.main(["--core-host", "127.0.0.1", "--state-file", str(state_file)]) == 1
    finally:
        held.close()


def test_garbage_actions_in_a_push_are_reported_not_fatal(tmp_path):
    async def go():
        a = _agent(tmp_path)
        return a, await _apply(a, actions=[W.spec_to_wire(ECHO_SPEC), "junk", {"id": 5}, {"id": "x.y"}])

    a, w = _run(go())
    assert set(a._whitelist_specs) == {"test.echo"} and len(w.frames[0]["rejected"]) == 3


# ---------------------------------------------------------------------------
# F9 -- trusted transport
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("peer,trusted", [
    ("127.0.0.1", True), ("::1", True), ("100.64.0.10", True), ("fd7a:115c:a1e0::5", True),
    ("::ffff:127.0.0.1", True), ("10.136.28.1", False), ("192.168.1.10", False), ("203.0.113.9", False),
    (None, False), ("not-an-ip", False),
])
def test_transport_trust(tmp_path, peer, trusted):
    a = _agent(tmp_path)
    a._peer_ip = peer
    assert a._transport_trusted() is trusted
    a.allow_untrusted_transport = True
    assert a._transport_trusted() is True


def test_dispatch_over_untrusted_transport_is_refused(tmp_path):
    async def go():
        a = _agent(tmp_path, execution_enabled=True)
        await _apply(a)
        a._peer_ip = "10.136.28.1"
        return await a._process_exec_dispatch(_dispatch(a))

    r = _run(go())
    assert r["status"] == "refused" and "Tailscale" in r["reason"]


# ---------------------------------------------------------------------------
# The final gate is on the concrete argv, not just the pushed spec.
# ---------------------------------------------------------------------------
def test_a_value_the_slot_accepts_but_the_ceiling_denies_is_refused(tmp_path):
    """100.64.0.0/10 isn't "private" to the slot validator, but banning a
    tailnet address would cut core off -- the run-time ceiling check refuses."""

    async def go():
        a = _agent(tmp_path, execution_enabled=True)
        ban = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
        await _apply(a, actions=[W.spec_to_wire(ban)])
        return await a._process_exec_dispatch(_dispatch(
            a, action_id="fail2ban.ban_ip", slot_values={"jail": "sshd", "ip": "100.101.2.3"}))

    r = _run(go())
    assert r["status"] == "refused" and "ceiling" in r["reason"]


def test_ceiling_report_is_sent_in_hello_and_ack(tmp_path):
    async def go():
        a = _agent(tmp_path)
        return a, await _apply(a)

    a, w = _run(go())
    assert w.frames[0]["ceiling"]["fingerprint"] == TEST_CEILING.fingerprint()


# ---------------------------------------------------------------------------
# Target-local exact commands, end to end on the agent.
# ---------------------------------------------------------------------------
def test_exact_local_command_runs_and_is_revoked_by_removing_the_line(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    etc.chmod(0o755)  # a group-writable directory would (correctly) make the agent ignore the file
    allow = etc / "allowed-commands"
    allow.write_text("echo hello-local\n")
    allow.chmod(0o600)
    exact = W.ActionSpec(id="user.custom.e1", layer="user", argv_template=("echo", "hello-local"),
                         effect="Prints a line.", reversibility="Nothing to undo.", blast_radius="stdout only.")

    async def go():
        a = _agent(tmp_path, execution_enabled=True, ceiling=C.DEFAULT_CEILING, local_allow_file=str(allow))
        w = await _apply(a, actions=[W.spec_to_wire(exact)])
        assert w.frames[0]["rejected"] == [] and w.frames[0]["ceiling"]["local_commands"] == ["echo hello-local"]
        ran = await a._process_exec_dispatch(_dispatch(a, action_id="user.custom.e1", slot_values={}))
        allow.write_text("")  # the target admin removes the line
        revoked = await a._process_exec_dispatch(_dispatch(a, action_id="user.custom.e1", slot_values={},
                                                           dispatch_id="d2"))
        return ran, revoked

    ran, revoked = _run(go())
    assert ran["status"] == "ok" and "hello-local" in ran["stdout_tail"]
    assert revoked["status"] == "refused" and "ceiling" in revoked["reason"]


def test_exact_command_not_listed_on_the_target_is_refused_at_push(tmp_path):
    async def go():
        a = _agent(tmp_path, ceiling=C.DEFAULT_CEILING)
        exact = W.ActionSpec(id="user.custom.e2", layer="user", argv_template=("adduser", "alice"),
                             effect="e", reversibility="r", blast_radius="b")
        return a, await _apply(a, actions=[W.spec_to_wire(exact)])

    a, w = _run(go())
    assert a._whitelist_specs == {} and w.frames[0]["rejected"][0]["id"] == "user.custom.e2"


def test_stop_ends_a_live_connection_promptly(tmp_path):
    """stop() used to set a flag that a live connection never looked at, so
    `systemctl stop` hung until systemd's timeout SIGKILLed the agent."""

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, target_id = await _pair_agent(store, port, tmp_path)
            agent.stop()
            await asyncio.wait_for(task, timeout=2.0)  # returns on its own, no cancel needed
            assert task.done() and not task.cancelled()
        finally:
            await server.close()

    asyncio.run(run())


def test_the_agent_reports_its_execution_switch_and_transport(tmp_path):
    on = _agent(tmp_path, execution_enabled=True).ceiling_report()
    assert on["execution_enabled"] is True and on["transport_trusted"] is True     # loopback core
    off = _agent(tmp_path / "b", execution_enabled=False)
    off._peer_ip = "192.0.2.10"                                                     # plain network
    report = off.ceiling_report()
    assert report["execution_enabled"] is False and report["transport_trusted"] is False
