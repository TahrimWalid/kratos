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
the agent's own local `execution_enabled` opt-in (see agent.py), and whatever
core pushes is checked on the agent against the agent's OWN execution ceiling
(kratos.subagent.ceiling) -- core can narrow what a target allows, never widen
it. Each connection's `session_nonce` is carried in every signed dispatch and
pong so a captured message can't be replayed later (review findings F4/F6).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
import uuid
from collections import deque
from typing import Any

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import protocol as proto
from kratos.subagent import reads
from kratos.subagent import signing
from kratos.subagent import whitelist as wl
from kratos.subagent.status import (
    LISTENER_HEARTBEAT_SECONDS,
    LISTENER_STALE_AFTER_SECONDS,
    SILENT_DROP_PREFIX,
    derive_status,
)

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

_SESSION_NONCE_RE = re.compile(r"^[0-9a-f]{16,128}$")

# A new session for a target replaces an existing one only if the existing one
# has been silent this long -- the signature of a half-open TCP connection the
# agent already gave up on (NAT timeout, suspended laptop). An existing session
# that is still talking is kept, and the newcomer refused.
SILENT_SESSION_REPLACE_SECONDS = 15.0
# Failed pairing/auth attempts from one address within the window before
# further attempts are refused without a lookup (slows code guessing).
AUTH_FAILURE_LIMIT = 10
AUTH_FAILURE_WINDOW_SECONDS = 60.0

# Investigation reads (docs/subagent_read_routing.md): the first agent version
# that serves them, how long past a probe's own on-box timeout to wait for its
# reply, and how long a just-started listener / just-dropped agent is expected
# to (re)connect -- the agent's reconnect backoff tops out at 60s.
READ_MIN_AGENT_VERSION = (0, 3, 0)
READ_REPLY_MARGIN_SECONDS = 15.0
RECONNECT_EXPECTED_SECONDS = 90.0
_MAX_ADVERTISED_PROBES = 64


class CoreServer:
    def __init__(
        self,
        store: SubAgentStore,
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        whitelist_store: Any | None = None,
        mode: str | None = None,
        read_socket_path: Any | None = None,
    ) -> None:
        self.store = store
        self.host = host
        self.port = port
        self.whitelist_store = whitelist_store
        # How this listener runs, recorded so the UI can say whether telemetry
        # survives closing Kratos: "service" (under systemd), "in_process"
        # (inside a TUI), or "process" (a foreground `kratos subagent-serve`).
        self.mode = mode or ("service" if os.environ.get("INVOCATION_ID") else "process")
        self.listener_id = "lsn_" + uuid.uuid4().hex[:12]
        self._heartbeat_task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._last_frame: dict[str, float] = {}
        self._auth_failures: dict[str, deque] = {}
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
        # target_id -> the live connection's session nonce (absent for an
        # agent too old to send one -- such an agent gets telemetry only).
        self._session_nonce: dict[str, str] = {}
        # Why a connection is being closed from THIS side (recorded on close).
        self._close_reason: dict[str, str] = {}
        # Investigation reads: what each live agent says it can read, one read
        # at a time per target, a per-connection strictly increasing seq (the
        # agent's replay floor), and the replies being waited for.
        self.read_socket_path = read_socket_path
        self._local_reads: Any | None = None
        self._agent_reads: dict[str, dict[str, Any]] = {}
        self._read_locks: dict[str, asyncio.Lock] = {}
        self._read_seq: dict[str, int] = {}
        self._pending_reads: dict[str, tuple[str, asyncio.Future]] = {}
        self._disconnected_at: dict[str, float] = {}
        self._started_monotonic = time.monotonic()

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
        self._register()
        self._started_monotonic = time.monotonic()
        await self._start_local_reads()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        if self.whitelist_store is not None:
            self._watch_task = asyncio.create_task(self._whitelist_watch_loop())
        self._stop_event = asyncio.Event()
        try:
            # Deliberately NOT asyncio's Server.serve_forever(): on cancellation
            # it calls close() + wait_closed(), which (Python 3.12+) waits for
            # every open connection -- and those handlers are blocked reading
            # from agents, so a SIGTERM or TUI quit would hang forever.
            # start_server() is already accepting; just wait to be stopped.
            await self._stop_event.wait()
        finally:
            self._drop_live_connections()
            self._server.close()
            await self._stop_local_reads()

    def stop(self) -> None:
        """Ask serve_forever() to return (it then drops live connections)."""
        if self._stop_event is not None:
            self._stop_event.set()

    def _drop_live_connections(self) -> None:
        for target_id, writer in list(self._live.items()):
            self._close_reason.setdefault(target_id, "the Kratos listener stopped")
            writer.close()

    def _register(self) -> None:
        """Announce this listener (only once it has actually bound the port)
        and close connection rows left open by a listener that died."""
        from kratos.utils.build_info import RUNNING_BUILD

        try:
            self.store.close_orphaned_connections(LISTENER_STALE_AFTER_SECONDS)
            self.store.register_listener(self.listener_id, pid=os.getpid(), host=self.host, port=self.port,
                                         mode=self.mode, build=RUNNING_BUILD)
        except Exception as e:  # noqa: BLE001 -- bookkeeping must never stop the listener
            logger.warning("could not register listener: %s", e)

    async def _heartbeat_loop(self) -> None:
        """Keep this listener visibly alive, and enforce revocation on LIVE
        connections: a target unpaired from another process (the TUI) is
        disconnected here within one beat, not just refused next time."""
        while True:
            await asyncio.sleep(LISTENER_HEARTBEAT_SECONDS)
            try:
                self.store.heartbeat_listener(self.listener_id)
                for target_id in self.store.revoked_among(list(self._live)):
                    writer = self._live.get(target_id)
                    if writer is not None:
                        logger.info("target %s was unpaired -- closing its connection", target_id)
                        self._close_reason[target_id] = "unpaired in Kratos"
                        writer.close()
            except Exception as e:  # noqa: BLE001 -- one bad beat must not kill the loop
                logger.warning("listener heartbeat failed: %s", e)

    def _auth_blocked(self, peer_ip: str) -> bool:
        q = self._auth_failures.get(peer_ip)
        now = time.monotonic()
        while q and now - q[0] > AUTH_FAILURE_WINDOW_SECONDS:
            q.popleft()
        return bool(q) and len(q) >= AUTH_FAILURE_LIMIT

    def _note_auth_failure(self, peer_ip: str) -> None:
        if len(self._auth_failures) > 4096:  # bound memory under a spray from many addresses
            self._auth_failures.clear()
        self._auth_failures.setdefault(peer_ip, deque(maxlen=AUTH_FAILURE_LIMIT)).append(time.monotonic())

    async def close(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
        with contextlib.suppress(Exception):
            if self._server is not None:
                self.store.stop_listener(self.listener_id)
        if self._watch_task is not None:
            self._watch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watch_task
        await self._stop_local_reads()
        if self._server is not None:
            self._server.close()  # stop accepting new connections first
        # Close live connections BEFORE waiting: on Python 3.12+ wait_closed()
        # waits for every open connection's handler to finish, and those are
        # blocked reading from agents -- waiting first deadlocks (a systemctl
        # stop/restart would hang until systemd SIGKILLs the process).
        self._drop_live_connections()
        if self._server is not None:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)

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
            if ack.get("version") != version:
                return False
            rejected = ack.get("rejected") if isinstance(ack.get("rejected"), list) else []
            if rejected:
                logger.warning("target %s refused %d pushed action(s) as outside its ceiling: %s",
                               target_id, len(rejected), rejected)
            if self.whitelist_store is not None and hasattr(self.whitelist_store, "record_push_ack"):
                self.whitelist_store.record_push_ack(target_id, version, rejected, ack.get("ceiling"))
            return True
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
        session_nonce = self._session_nonce.get(target_id)
        if session_nonce is None:
            raise RuntimeError(
                f"target {target_id!r} runs a sub-agent too old for execution (no session nonce) -- update it"
            )
        dispatch_id = uuid.uuid4().hex
        key = signing.derive_signing_key(token)
        envelope: dict[str, Any] = {
            "type": proto.MSG_EXEC_DISPATCH,
            "dispatch_id": dispatch_id,
            "action_id": action_id,
            "slot_values": slot_values,
            "whitelist_version": whitelist_version,
            "session_nonce": session_nonce,
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
        peer_ip = peer[0] if isinstance(peer, tuple) and peer else "?"
        target_id: str | None = None
        owns_session = False
        close_reason = "connection closed"
        try:
            if self._auth_blocked(peer_ip):
                await proto.write_frame(writer, proto.build_hello_reject("too many failed attempts; try again later"))
                return
            hello = await asyncio.wait_for(proto.read_frame(reader), timeout=HELLO_TIMEOUT_SECONDS)
            if hello is None or hello.get("type") != proto.MSG_HELLO:
                await proto.write_frame(writer, proto.build_hello_reject("expected a hello message first"))
                return
            target_id, token, reject_reason = self._authenticate(hello)
            if reject_reason:
                logger.info("rejected connection from %s: %s", peer, reject_reason)
                self._note_auth_failure(peer_ip)
                self._record_rejection(hello, peer_ip, reject_reason)
                target_id = None
                await proto.write_frame(writer, proto.build_hello_reject(reject_reason))
                return
            assert target_id is not None and token is not None
            existing = self._live.get(target_id)
            if existing is not None:
                silent = time.monotonic() - self._last_frame.get(target_id, 0.0)
                if silent < SILENT_SESSION_REPLACE_SECONDS:
                    # Two live sessions for one target would make status and
                    # telemetry ordering ambiguous -- refuse the newcomer. If
                    # this keeps happening, one identity is running on two boxes.
                    self._safe(self.store.record_connection_event, target_id, "rejected",
                               f"a second connection from {peer_ip} while one is active "
                               "(is this agent's state file copied to another machine?)")
                    target_id = None
                    await proto.write_frame(writer, proto.build_hello_reject("already connected from another session"))
                    return
                # The old session went silent: the agent has already given up
                # on it (half-open TCP). Replace it instead of refusing.
                self._close_reason[target_id] = "replaced by a new connection from the agent"
                existing.close()
                self._safe(self.store.record_connection_event, target_id, "replaced",
                           f"previous session silent for {int(silent)}s; the agent reconnected from {peer_ip}")
            self._live[target_id] = writer
            owns_session = True
            self._last_frame[target_id] = time.monotonic()
            nonce = hello.get("session_nonce")
            if isinstance(nonce, str) and _SESSION_NONCE_RE.fullmatch(nonce):
                self._session_nonce[target_id] = nonce
            self._note_read_capability(target_id, hello)
            self.store.record_connected(target_id, hostname=hello.get("hostname"), agent_version=hello.get("agent_version"))
            self._safe(self.store.record_connection_open, target_id, listener_id=self.listener_id, peer=peer_ip,
                       collect_interval=_interval(hello.get("collect_interval")),
                       ping_interval=_interval(hello.get("ping_interval")))
            if self.whitelist_store is not None and hasattr(self.whitelist_store, "record_agent_hello"):
                self.whitelist_store.record_agent_hello(
                    target_id, agent_version=hello.get("agent_version"), ceiling=hello.get("ceiling")
                )
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
            close_reason = await self._receive_loop(reader, writer, target_id, token)
        except asyncio.TimeoutError:
            close_reason = f"{SILENT_DROP_PREFIX} for {PING_TIMEOUT_SECONDS}s"
            logger.info("connection from %s (target=%s) ended: timed out", peer, target_id)
        except (proto.ProtocolError, ConnectionError, OSError) as e:
            close_reason = f"connection lost ({type(e).__name__}: {e})" if str(e) else f"connection lost ({type(e).__name__})"
            logger.info("connection from %s (target=%s) ended: %s", peer, target_id, e)
        finally:
            if target_id is not None and owns_session:
                reason = self._close_reason.pop(target_id, None) or close_reason
                if self._live.get(target_id) is writer:
                    del self._live[target_id]
                    self._pushed_version.pop(target_id, None)
                    self._session_nonce.pop(target_id, None)
                    self._last_frame.pop(target_id, None)
                    self._agent_reads.pop(target_id, None)
                    self._disconnected_at[target_id] = time.monotonic()
                    self._fail_pending_reads(target_id, "the sub-agent disconnected before answering")
                    self._safe(self.store.record_connection_closed, target_id,
                               listener_id=self.listener_id, reason=reason)
                logger.info("target %s disconnected (%s)", target_id, reason)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    # ------------------------------------------------------------------
    # Investigation reads (docs/subagent_read_routing.md)
    # ------------------------------------------------------------------
    async def _start_local_reads(self) -> None:
        if self.read_socket_path is None:
            return
        from kratos.subagent.local_reads import LocalReadServer

        server = LocalReadServer(self, self.read_socket_path)
        try:
            await server.start()
        except Exception as e:  # noqa: BLE001 -- telemetry must keep working without it
            logger.warning("investigation reads through sub-agents are unavailable: %s", e)
            return
        self._local_reads = server

    async def _stop_local_reads(self) -> None:
        server, self._local_reads = self._local_reads, None
        if server is not None:
            await server.close()

    def _note_read_capability(self, target_id: str, hello: dict[str, Any]) -> None:
        self._read_seq[target_id] = 0  # the agent's replay floor resets with each connection
        probes = hello.get("read_probes")
        if not isinstance(probes, list):
            self._agent_reads.pop(target_id, None)
            return
        names = {p for p in probes[:_MAX_ADVERTISED_PROBES] if isinstance(p, str) and len(p) <= 64}
        self._agent_reads[target_id] = {"probes": names, "api": hello.get("read_api"),
                                        "version": hello.get("agent_version")}

    def is_live(self, target_id: str) -> bool:
        return target_id in self._live

    def expect_reconnect(self, target_id: str, since_monotonic: float | None = None) -> bool:
        """Is this target likely to (re)connect within seconds? True right after
        this listener started (agents are still finding it) or right after the
        target dropped (its own reconnect loop is running)."""
        now = time.monotonic()
        started = max(self._started_monotonic, since_monotonic or 0.0)
        if now - started < RECONNECT_EXPECTED_SECONDS:
            return self.store.get_target(target_id) is not None
        dropped = self._disconnected_at.get(target_id)
        return dropped is not None and now - dropped < RECONNECT_EXPECTED_SECONDS

    def offline_result(self, target_id: str) -> dict[str, Any]:
        target = self._safe(self.store.get_target, target_id)
        if not target or target.get("revoked_at"):
            return {"status": "offline", "reason": "this box is no longer paired with Kratos (it was unpaired) "
                                                   "-- pair it again from /subagent"}
        from kratos.subagent.status import _age, human_age, utc_now

        name = target.get("name") or target.get("hostname") or target_id
        last = human_age(_age(target.get("last_seen"), utc_now()))
        return {"status": "offline", "reason": (
            f"the sub-agent on {name} isn't connected to Kratos right now (last contact: {last}). "
            "It reconnects by itself once the box and the network are up -- see /subagent for why it dropped.")}

    def local_status(self) -> dict[str, Any]:
        return {
            "listener_id": self.listener_id,
            "mode": self.mode,
            "live": {tid: {"agent_version": info.get("version"), "read_probes": sorted(info.get("probes") or ()),
                           "reads": tid in self._agent_reads}
                     for tid in self._live for info in [self._agent_reads.get(tid, {})]},
        }

    def _fail_pending_reads(self, target_id: str, reason: str) -> None:
        for request_id, (tid, fut) in list(self._pending_reads.items()):
            if tid == target_id and not fut.done():
                fut.set_result({"status": "offline", "reason": reason, "request_id": request_id})

    async def read_probe(self, target_id: str, probe: str, params: dict[str, Any],
                         timeout: float | None = None) -> dict[str, Any]:
        """Send one signed read_request to a LIVE target and wait for its
        read_result. Returns {status, reason?, data?}; never raises for an
        operational failure (offline, old agent, timeout, dropped mid-read).
        The agent re-validates everything itself -- this side's checks only
        give a faster, clearer answer."""
        if target_id not in self._live:
            return self.offline_result(target_id)
        info = self._agent_reads.get(target_id)
        nonce = self._session_nonce.get(target_id)
        if info is None or nonce is None:
            version = self._safe(self.store.get_target, target_id) or {}
            return {"status": "old_agent", "reason": (
                f"this box runs sub-agent {version.get('agent_version') or 'of an older version'}; investigating "
                f"through it needs {'.'.join(map(str, READ_MIN_AGENT_VERSION))} or newer. Update it from "
                "/subagent (select it, press g) -- the box keeps its pairing.")}
        if probe not in info["probes"]:
            return {"status": "unsupported", "reason": (
                f"this box's sub-agent ({info.get('version') or '?'}) can't do the {probe!r} read -- update it from "
                "/subagent (select it, press g)"), "available": sorted(info["probes"])}
        target = self.store.get_target(target_id)
        if target is None or target.get("revoked_at"):
            return self.offline_result(target_id)
        budget = timeout or (reads.PROBE_TIMEOUT_SECONDS.get(probe, 30) + READ_REPLY_MARGIN_SECONDS)
        lock = self._read_locks.setdefault(target_id, asyncio.Lock())
        try:
            await asyncio.wait_for(lock.acquire(), timeout=budget)
        except asyncio.TimeoutError:
            return {"status": "busy", "reason": "another read on this box is still running -- try again shortly"}
        request_id = uuid.uuid4().hex
        try:
            writer = self._live.get(target_id)
            nonce = self._session_nonce.get(target_id)
            if writer is None or nonce is None:
                return self.offline_result(target_id)
            seq = self._read_seq.get(target_id, 0) + 1
            self._read_seq[target_id] = seq
            envelope = proto.build_read_request(request_id, probe, params, seq, nonce)
            envelope["sig"] = signing.sign_envelope(signing.derive_signing_key(target["token"]), envelope)
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            self._pending_reads[request_id] = (target_id, fut)
            await proto.write_frame(writer, envelope)
            reply = await asyncio.wait_for(fut, timeout=budget)
        except asyncio.TimeoutError:
            return {"status": "timed_out", "reason": f"the sub-agent didn't answer the {probe} read within {int(budget)}s"}
        except (OSError, ConnectionError, proto.ProtocolError) as e:
            return {"status": "offline", "reason": f"the connection to the sub-agent failed mid-read ({type(e).__name__})"}
        finally:
            self._pending_reads.pop(request_id, None)
            lock.release()
        out: dict[str, Any] = {"status": reply.get("status") if isinstance(reply.get("status"), str) else "error"}
        for key in ("reason", "data", "available"):
            if key in reply:
                out[key] = reply[key]
        return out

    def _record_rejection(self, hello: dict[str, Any], peer_ip: str, reason: str) -> None:
        """Remember WHY a known agent was turned away, so the UI can say "your
        unpaired agent is still running" or "that pairing code expired"."""
        auth = hello.get("auth") or {}
        who = f"{hello.get('hostname') or '?'} ({peer_ip})"
        token, code = auth.get("token"), auth.get("pairing_code")
        if isinstance(token, str) and token:
            t = self._safe(self.store.find_target_by_token_any, token)
            if t:
                self._safe(self.store.record_connection_event, t["target_id"], "rejected", f"{reason} -- from {who}")
        elif isinstance(code, str) and code:
            self._safe(self.store.record_pairing_attempt, code[:32], who, reason)

    @staticmethod
    def _safe(fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Connection bookkeeping must never take a live connection down."""
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            logger.warning("bookkeeping call %s failed: %s", getattr(fn, "__name__", fn), e)
            return None

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

    def _pong(self, target_id: str, token: str, ts: Any) -> dict[str, Any]:
        """A pong signed for this connection's session nonce -- the only thing
        that arms the agent's dead-man's switch (F6). An old agent without a
        nonce just gets the plain pong it always did."""
        pong = proto.build_pong(ts)
        nonce = self._session_nonce.get(target_id)
        if nonce is not None:
            pong["session_nonce"] = nonce
            pong["sig"] = signing.sign_envelope(signing.derive_signing_key(token), pong)
        return pong

    async def _receive_loop(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target_id: str, token: str
    ) -> str:
        while True:
            msg = await asyncio.wait_for(proto.read_frame(reader), timeout=PING_TIMEOUT_SECONDS)
            if msg is None:
                return "the agent closed the connection"  # clean EOF
            self._last_frame[target_id] = time.monotonic()
            mtype = msg.get("type")
            if mtype == proto.MSG_TELEMETRY:
                self.store.record_telemetry(
                    target_id, msg.get("payload") or {}, seq=msg.get("seq"), collected_at=msg.get("collected_at")
                )
                await proto.write_frame(writer, proto.build_telemetry_ack(msg.get("seq")))
            elif mtype == proto.MSG_PING:
                self.store.touch_last_seen(target_id)
                await proto.write_frame(writer, self._pong(target_id, token, msg.get("ts")))
            elif mtype == proto.MSG_WHITELIST_PUSH_ACK:
                fut = self._pending_whitelist_ack.get(target_id)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            elif mtype == proto.MSG_EXEC_RESULT:
                fut = self._pending_exec.get(msg.get("dispatch_id"))
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            elif mtype == proto.MSG_READ_RESULT:
                pending = self._pending_reads.get(msg.get("request_id"))
                # Only the target the request was sent to can answer it.
                if pending is not None and pending[0] == target_id and not pending[1].done():
                    pending[1].set_result(msg)
            else:
                logger.warning("ignoring unexpected message type %r from target %s", mtype, target_id)


def _interval(value: Any) -> float | None:
    """An agent-announced interval, if it's a sane number of seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if 1 <= value <= 3600 else None
