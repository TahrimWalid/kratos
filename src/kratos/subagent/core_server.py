"""
Kratos-core-side sub-agent server. Capability 1 (continuous, read-only
telemetry; docs/subagent_architecture.md) is always on for every paired
target, regardless of everything below.

Accepts OUTBOUND connections from paired sub-agents (the agent dials out and
holds the connection open; core never dials the agent -- see the design
doc's "Transport and connection direction" section) and:
  (a) authenticates each connection via the app-level pairing token/code,
      independent of the network layer;
  (b) receives a continuous stream of read-only telemetry snapshots and
      persists them (kratos.storage.subagent_store);
  (c) tracks per-target liveness from real connection state plus a
      keepalive ping, not guesswork.

**Capability 2 (direct execution)**: `push_whitelist`/`dispatch_action` are
the only two methods that ever originate a message TO an agent (every other
message here is a reply to something the agent itself sent first). Both
sign their envelope (`kratos.subagent.signing`) with a key derived from that
target's pairing token, and both are no-ops/errors if the target isn't
currently live-connected -- this module never dials out, queues, or retries
against an offline target (matching the transport's agent-initiated-
connection rule: core only ever writes onto a connection the agent opened).
If `whitelist_store` is supplied, a newly (re)connected target is
immediately pushed its current, authoritative whitelist (design doc §9 #4:
"the agent's whitelist copy is authoritative-from-core... not independently
authored on the target"), and `_whitelist_watch_loop` re-pushes on any
subsequent change -- a LOCAL SQLite version check on a short interval, not a
network poll of the agent (the agent is still only ever pushed to, never
polled, preserving the "core never dials the agent" transport invariant).
None of this makes an agent actually execute anything: that also requires
the agent's own local `execution_enabled` opt-in (see agent.py).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from typing import Any

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import protocol as proto
from kratos.subagent import signing
from kratos.subagent import whitelist as wl
from kratos.subagent.status import derive_status

logger = logging.getLogger("kratos.subagent.core_server")

DEFAULT_PORT = 8765
# No ping/telemetry at all within this long on an open socket -> treat the
# connection as dead and close it (the agent's own reconnect loop then takes
# over) rather than holding a silently-broken socket open forever.
PING_TIMEOUT_SECONDS = 30
HELLO_TIMEOUT_SECONDS = 10

# Capability 2 -- how long to wait for a whitelist_push_ack / exec_result
# before giving up on one in-flight request. An exec dispatch that never
# gets a reply within this window comes back as a genuine "outcome unknown"
# to the caller (matching the design canvas's own 11e state), not a hang.
WHITELIST_PUSH_ACK_TIMEOUT_SECONDS = 10.0
EXEC_RESULT_TIMEOUT_SECONDS = 35.0
# How often the (local, DB-only) watch loop checks whether any LIVE target's
# whitelist version has changed since it was last pushed -- design doc §9 #5
# wants "push immediately, don't poll [the agent]"; this polls the core's
# OWN local SQLite file, not the agent, and only ever results in a push over
# an already-open connection, never a new outbound dial to the agent.
WHITELIST_WATCH_INTERVAL_SECONDS = 2.0


class CoreServer:
    def __init__(
        self,
        store: SubAgentStore,
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        whitelist_store: Any | None = None,
    ) -> None:
        self.store = store
        self.host = host
        self.port = port
        self.whitelist_store = whitelist_store
        # target_id -> writer, for real live-connection status -- ground
        # truth ONLY within this running process (a separate CLI query has
        # no visibility into this and falls back to last_seen recency, see
        # status.py).
        self._live: dict[str, asyncio.StreamWriter] = {}
        self._server: asyncio.AbstractServer | None = None
        # Capability 2 in-flight request bookkeeping -- resolved by
        # _receive_loop when the matching reply arrives; left to time out
        # naturally (not force-resolved) if the connection drops mid-flight,
        # which is exactly the real "outcome unknown" case.
        self._pending_whitelist_ack: dict[str, asyncio.Future] = {}
        self._pending_exec: dict[str, asyncio.Future] = {}
        self._pushed_version: dict[str, int] = {}
        self._watch_task: asyncio.Task | None = None

    def live_target_ids(self) -> set[str]:
        return set(self._live.keys())

    def status_snapshot(self) -> list[dict[str, Any]]:
        """Every paired target with its derived status -- used by both the
        CLI (`subagent-status`) and, in-process, anything else that wants a
        live view without querying SQLite directly."""
        out = []
        for target in self.store.list_targets():
            live = target["target_id"] in self._live
            out.append(
                {
                    **target,
                    "status": derive_status(target["last_seen"], live=live),
                    "live_connection": live,
                }
            )
        return out

    async def serve_forever(self) -> None:
        self._server = await asyncio.start_server(self._handle_connection, self.host, self.port)
        sockets = self._server.sockets or []
        addrs = ", ".join(str(sock.getsockname()) for sock in sockets)
        logger.info("kratos subagent core server listening on %s", addrs)
        if self.whitelist_store is not None:
            self._watch_task = asyncio.create_task(self._whitelist_watch_loop())
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._watch_task is not None:
            self._watch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watch_task
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for writer in list(self._live.values()):
            writer.close()

    async def _whitelist_watch_loop(self) -> None:
        """Local-DB-only polling of `whitelist_version` AND the dispatch
        request queue for currently-live targets -- NOT a network poll of
        any agent (see this module's own docstring). Re-pushes the
        whitelist on any version change; services any pending dispatch
        request by actually calling `dispatch_action` and writing the
        result back. Leaves a transient failure to be retried on the next
        tick rather than raising out of the loop."""
        while True:
            await asyncio.sleep(WHITELIST_WATCH_INTERVAL_SECONDS)
            for target_id in list(self._live):
                try:
                    version = self.whitelist_store.get_whitelist_version(target_id)
                    if version != self._pushed_version.get(target_id):
                        await self._push_current_whitelist(target_id)
                    await self._service_pending_dispatch_requests(target_id)
                except Exception as e:  # noqa: BLE001 -- one target's failure must not stop the loop
                    logger.warning("whitelist watch loop: error servicing target %s: %s", target_id, e)

    async def _service_pending_dispatch_requests(self, target_id: str) -> None:
        pending = self.whitelist_store.list_pending_dispatch_requests(target_id)
        if not pending:
            return
        target = self.store.get_target(target_id)
        if target is None:
            return
        for req in pending:
            try:
                result = await self.dispatch_action(
                    target_id, target["token"], req["action_id"], req["slot_values"], req["whitelist_version"]
                )
            except RuntimeError as e:
                result = {"status": "error", "reason": str(e)}
            self.whitelist_store.complete_dispatch_request(req["request_id"], result)
            logger.info("serviced dispatch request %s for target %s: status=%s",
                        req["request_id"], target_id, result.get("status"))

    async def _push_current_whitelist(self, target_id: str) -> bool:
        """Reads this target's current effective (enabled) action set from
        `whitelist_store` and pushes it. Returns False (never raises) on any
        failure -- a push is best-effort-when-live, and the watch loop will
        retry on its next tick regardless."""
        if self.whitelist_store is None:
            return False
        target = self.store.get_target(target_id)
        if target is None or target.get("revoked_at"):
            return False
        version = self.whitelist_store.get_whitelist_version(target_id)
        actions = [wl.spec_to_wire(row["spec"]) for row in self.whitelist_store.effective_action_set(target_id)]
        ok = await self.push_whitelist(target_id, target["token"], actions, version)
        if ok:
            self._pushed_version[target_id] = version
        return ok

    async def push_whitelist(self, target_id: str, token: str, actions: list[dict], version: int) -> bool:
        """Sign + send a whitelist_push to a LIVE target and wait for its ack
        to confirm the SAME version. Returns False (never raises) if the
        target isn't connected or doesn't ack in time -- pushing only ever
        happens over a connection the agent itself opened (never dials out)."""
        writer = self._live.get(target_id)
        if writer is None:
            return False
        key = signing.derive_signing_key(token)
        envelope: dict[str, Any] = {"type": proto.MSG_WHITELIST_PUSH, "version": version, "actions": actions}
        envelope["sig"] = signing.sign_envelope(key, envelope)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_whitelist_ack[target_id] = fut
        try:
            await proto.write_frame(writer, envelope)
            ack = await asyncio.wait_for(fut, timeout=WHITELIST_PUSH_ACK_TIMEOUT_SECONDS)
            return ack.get("version") == version
        except (asyncio.TimeoutError, OSError, proto.ProtocolError):
            return False
        finally:
            self._pending_whitelist_ack.pop(target_id, None)

    async def dispatch_action(
        self, target_id: str, token: str, action_id: str, slot_values: dict[str, Any], whitelist_version: int
    ) -> dict[str, Any]:
        """Sign + send an exec_dispatch to a live target and wait for its
        exec_result. Raises RuntimeError if the target isn't connected --
        this is a real operational failure a caller (the future consent/
        approval UI) must surface, never silently swallow. A well-formed,
        correctly-signed dispatch is STILL subject to the agent's own
        independent re-validation, dead-man's switch, and local
        `execution_enabled` opt-in -- this method has no way to force any of
        those and doesn't try to."""
        writer = self._live.get(target_id)
        if writer is None:
            raise RuntimeError(f"target {target_id!r} is not currently connected")
        dispatch_id = uuid.uuid4().hex
        key = signing.derive_signing_key(token)
        envelope: dict[str, Any] = {
            "type": proto.MSG_EXEC_DISPATCH,
            "dispatch_id": dispatch_id,
            "action_id": action_id,
            "slot_values": slot_values,
            "whitelist_version": whitelist_version,
        }
        envelope["sig"] = signing.sign_envelope(key, envelope)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_exec[dispatch_id] = fut
        try:
            await proto.write_frame(writer, envelope)
            return await asyncio.wait_for(fut, timeout=EXEC_RESULT_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            # Genuinely unknown outcome -- e.g. the connection dropped
            # mid-execution. Matches the design canvas's own 11e state:
            # never silently reported as success or failure.
            return {"status": "unknown", "dispatch_id": dispatch_id, "reason": "no exec_result received before timeout"}
        finally:
            self._pending_exec.pop(dispatch_id, None)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        target_id: str | None = None
        try:
            hello = await asyncio.wait_for(proto.read_frame(reader), timeout=HELLO_TIMEOUT_SECONDS)
            if hello is None or hello.get("type") != proto.MSG_HELLO:
                await proto.write_frame(writer, proto.build_hello_reject("expected a hello message first"))
                return
            target_id, token, reject_reason = self._authenticate(hello)
            if reject_reason:
                logger.info("rejected connection from %s: %s", peer, reject_reason)
                await proto.write_frame(writer, proto.build_hello_reject(reject_reason))
                return
            assert target_id is not None and token is not None
            if target_id in self._live:
                # Two live sessions for one target would make "connected"
                # status and telemetry ordering ambiguous -- refuse the new
                # one rather than silently replacing the old.
                await proto.write_frame(writer, proto.build_hello_reject("already connected from another session"))
                return
            self._live[target_id] = writer
            self.store.record_connected(target_id, hostname=hello.get("hostname"), agent_version=hello.get("agent_version"))
            await proto.write_frame(writer, proto.build_hello_ack(target_id, token))
            logger.info("target %s connected from %s", target_id, peer)
            if self.whitelist_store is not None:
                # Every fresh connection gets the authoritative whitelist
                # re-synced immediately -- design doc §9 #4, and cheap
                # insurance against ever assuming a stale push cache is
                # still valid across a full disconnect/reconnect cycle.
                # MUST be fire-and-forget, not awaited here: push_whitelist's
                # ack can only ever be delivered by _receive_loop reading it
                # off this same connection, so awaiting the push before
                # starting _receive_loop below would deadlock until the
                # push's own ack timeout (a real bug, caught by this
                # module's own test suite) -- the two run concurrently instead.
                asyncio.create_task(self._push_current_whitelist(target_id))
            await self._receive_loop(reader, writer, target_id)
        except (asyncio.TimeoutError, proto.ProtocolError, ConnectionError, OSError) as e:
            logger.info("connection from %s (target=%s) ended: %s", peer, target_id, e)
        finally:
            if target_id is not None and self._live.get(target_id) is writer:
                del self._live[target_id]
                self._pushed_version.pop(target_id, None)
                logger.info("target %s disconnected", target_id)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    def _authenticate(self, hello: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
        auth = hello.get("auth") or {}
        token = auth.get("token")
        pairing_code = auth.get("pairing_code")
        if token:
            target = self.store.get_target_by_token(token)
            if target is None:
                return None, None, "unknown or revoked token"
            return target["target_id"], token, None
        if pairing_code:
            result = self.store.redeem_pairing_code(
                pairing_code,
                agent_id=hello.get("agent_id"),
                hostname=hello.get("hostname"),
                agent_version=hello.get("agent_version"),
            )
            if result is None:
                return None, None, "pairing code invalid, expired, or already used"
            return result["target_id"], result["token"], None
        return None, None, "no token or pairing code supplied"

    async def _receive_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target_id: str) -> None:
        while True:
            msg = await asyncio.wait_for(proto.read_frame(reader), timeout=PING_TIMEOUT_SECONDS)
            if msg is None:
                return  # clean EOF -- the agent closed deliberately.
            mtype = msg.get("type")
            if mtype == proto.MSG_TELEMETRY:
                self.store.record_telemetry(
                    target_id, msg.get("payload") or {}, seq=msg.get("seq"), collected_at=msg.get("collected_at")
                )
                await proto.write_frame(writer, proto.build_telemetry_ack(msg.get("seq")))
            elif mtype == proto.MSG_PING:
                self.store.touch_last_seen(target_id)
                await proto.write_frame(writer, proto.build_pong(msg.get("ts")))
            elif mtype == proto.MSG_WHITELIST_PUSH_ACK:
                fut = self._pending_whitelist_ack.get(target_id)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            elif mtype == proto.MSG_EXEC_RESULT:
                fut = self._pending_exec.get(msg.get("dispatch_id"))
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            else:
                logger.warning("ignoring unexpected message type %r from target %s", mtype, target_id)
