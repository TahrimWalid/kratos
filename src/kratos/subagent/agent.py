"""
Kratos sub-agent daemon. Runs on the monitored target, dials OUT to Kratos's
core, and continuously forwards read-only telemetry snapshots (capability 1;
docs/subagent_architecture.md) -- always on, regardless of everything below.

**Capability 2 (direct execution)**: this file also receives a signed,
versioned whitelist push and signed exec_dispatch messages from core (see
protocol.py's message shapes and signing.py's HMAC envelope), but a dispatch
only ever actually runs if ALL of the following hold, checked fresh on every
single dispatch, fail-closed on any failure:
  1. `execution_enabled=True` was passed at agent construction -- a LOCAL,
     explicit, target-operator opt-in. This defaults to False. Nothing in
     this codebase sets it True for a real target; it exists so the
     mechanism can be built and tested without requiring a real target to
     ever actually execute anything (see docs/subagent_whitelist_design.md
     and the architecture doc's "independent review gates ENABLING, not
     building" framing).
  2. The connection to core runs over a trusted transport: core's address is
     loopback or a Tailscale address, unless the operator explicitly passed
     --allow-untrusted-transport (review finding F9 -- this channel has no TLS
     of its own, so on a plain network the pairing token could be sniffed).
  3. The dispatch's signature verifies under this agent's OWN derived
     signing key (`signing.derive_signing_key(self.token)`) -- control 2 --
     and it carries this connection's `session_nonce` and a dispatch_id not
     already seen on it (F4: no replay across or within connections).
  4. The dead-man's switch is armed: a SIGNED pong carrying the current
     session nonce arrived within `DEAD_MANS_SWITCH_SECONDS` (design doc §9
     #5, F6) -- a severed, silent, or impersonated core disarms execution.
  5. The dispatch's `whitelist_version` matches this agent's CURRENTLY
     applied whitelist version exactly -- an old version can never be
     replayed to roll back a revocation (fail-closed on stale, §9 #5).
  6. The action_id is present in this agent's own whitelist copy and still
     fits the agent's own execution CEILING (kratos.subagent.ceiling --
     shipped as code here plus exact commands the target's admin listed in
     /etc/kratos-subagent/allowed-commands). Core can only ever narrow what
     the ceiling allows; it can't widen it (review findings F1/F2/F3).
  7. The concrete argv `render_argv` produced matches the ceiling AGAIN, and
     the binary resolves to an absolute path inside a trusted system
     directory -- the final check is on exactly what will run.
Only then is `subprocess.run(argv, shell=False, ...)` ever reached -- no
shell, no string concatenation, no $PATH lookup, a fixed minimal environment.
Every dispatch attempt (refused or executed) is logged locally via the
standard `logging` module (control 4: independent sub-agent-side logging).

Deploy by copying this file plus protocol.py, collector.py, signing.py,
whitelist.py, and ceiling.py onto the target as a `subagent/` package
directory (they must stay siblings -- all six are stdlib-only, confirmed by
import) and running,
from the parent of that directory:

    python3 -m subagent.agent --core-host <core-ip> --core-port 8765 --pair CODE-1234

On a successful pairing the agent saves its persistent token to
--state-file (default ~/.kratos_subagent/state.json); every later run reuses
it automatically and --pair is no longer needed (a used pairing code is
rejected by core if retried, per its own single-use design).

Transport rules (design doc, "Transport and connection direction"): this
process ALWAYS dials out and holds the connection open; it never listens for
or accepts an inbound connection from core. If the link drops for any reason
(core restart, network blip, a real WAN path once this ever runs against a
remote target), it reconnects with exponential backoff, and telemetry
collected while disconnected is queued in a small bounded in-memory buffer
and flushed in order on the next successful connection -- collection itself
never blocks waiting on the network.

Stdlib-only -- see protocol.py's module docstring for why.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import signal
import subprocess
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

try:  # `python3 -m subagent.agent` (preferred) -- real package-relative import.
    from . import ceiling as cl, collector, protocol as proto, signing, whitelist as wl
except ImportError:  # pragma: no cover -- fallback for `python3 subagent/agent.py` run directly.
    import ceiling as cl  # type: ignore[no-redef]
    import collector  # type: ignore[no-redef]
    import protocol as proto  # type: ignore[no-redef]
    import signing  # type: ignore[no-redef]
    import whitelist as wl  # type: ignore[no-redef]

logger = logging.getLogger("kratos.subagent.agent")

AGENT_VERSION = "0.2.0"
DEFAULT_CORE_PORT = 8765
DEFAULT_STATE_FILE = Path.home() / ".kratos_subagent" / "state.json"
DEFAULT_COLLECT_INTERVAL_SECONDS = 30.0
DEFAULT_PING_INTERVAL_SECONDS = 10.0
# "a small local buffer" per the transport doc's rule 4 -- bounded so a long
# outage can't grow memory without limit. For a live-monitoring stream, the
# most recent state matters far more than a long backlog of stale snapshots,
# so the buffer drops the OLDEST entry once full (deque(maxlen=...)) rather
# than refusing new collection.
BUFFER_MAX = 50
BACKOFF_INITIAL_SECONDS = 2.0
BACKOFF_MAX_SECONDS = 60.0
HANDSHAKE_TIMEOUT_SECONDS = 10.0

# Capability 2 -- design doc §9 #5: "the agent disarms execution if it hasn't
# had a fresh authenticated heartbeat within a bounded window." Comfortably
# above 3x the default ping interval (10s) so normal jitter never trips it,
# short enough that a genuinely severed/silent core disarms execution well
# before a human would still be assuming it's live.
DEAD_MANS_SWITCH_SECONDS = 45.0
EXEC_TIMEOUT_SECONDS = 30.0
OUTPUT_TAIL_MAX_CHARS = 4000
# Bound on dispatch ids remembered per connection for replay de-duplication.
SEEN_DISPATCH_IDS_MAX = 4096

# Transport check for execution (F9): core must be reached over loopback or a
# Tailscale/WireGuard tailnet address, since this channel has no TLS itself.
_TRUSTED_TRANSPORT_NETWORKS = tuple(
    ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48")
)


# The state file holds the pairing token, from which the channel's signing key
# is derived: anyone who can read it can pose as this agent (or sign as core).
# Owner read/write only -- never the default umask's world-readable 0644.
_STATE_MODE = 0o600


def _load_state(state_file: Path) -> dict[str, Any]:
    try:
        # Tighten a file an older agent wrote world-readable.
        if state_file.exists() and (state_file.stat().st_mode & 0o077):
            os.chmod(state_file, _STATE_MODE)
    except OSError:
        logger.warning("could not restrict %s to owner-only (0600) -- fix its permissions", state_file)
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(state_file: Path, state: dict[str, Any]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_file.with_suffix(".tmp")
    # Created 0600 from the first byte (no window where the token is readable).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _STATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(state))
    os.chmod(tmp, _STATE_MODE)  # O_CREAT ignores the mode when tmp already existed
    tmp.replace(state_file)  # atomic on POSIX -- same convention as self_write_loop.py's kept-tool metadata writes.


class SubAgent:
    def __init__(
        self,
        core_host: str,
        core_port: int,
        state_file: Path = DEFAULT_STATE_FILE,
        pairing_code: str | None = None,
        collect_interval: float = DEFAULT_COLLECT_INTERVAL_SECONDS,
        ping_interval: float = DEFAULT_PING_INTERVAL_SECONDS,
        watch_files: list[str] | None = None,
        services: list[str] | None = None,
        execution_enabled: bool = False,
        allow_untrusted_transport: bool = False,
        ceiling: "cl.Ceiling" = cl.DEFAULT_CEILING,
        local_allow_file: str | None = cl.LOCAL_ALLOW_FILE,
    ) -> None:
        self.core_host = core_host
        self.core_port = core_port
        self.state_file = state_file
        self.pairing_code = pairing_code
        self.collect_interval = collect_interval
        self.ping_interval = ping_interval
        self.watch_files = watch_files
        self.services = services
        # Capability 2, local opt-in only -- see this module's own docstring.
        # Defaults OFF; nothing in this codebase flips it on for a real target.
        self.execution_enabled = execution_enabled
        self.allow_untrusted_transport = allow_untrusted_transport
        # The shipped ceiling is code; tests may pass a different one. Nothing
        # received over the wire can ever replace it.
        self._base_ceiling = ceiling
        self._local_allow_file = local_allow_file

        self._state = _load_state(state_file)
        self.agent_id: str = self._state.get("agent_id") or uuid.uuid4().hex
        self.token: str | None = self._state.get("token")
        if not self._state.get("agent_id"):
            self._state["agent_id"] = self.agent_id
            self._persist_state()

        self._buffer: deque[dict[str, Any]] = deque(maxlen=BUFFER_MAX)
        self._seq = 0
        # Created inside run_forever(), not here: before Python 3.10 an
        # asyncio.Event binds to whatever loop exists at construction, and
        # main() builds the agent BEFORE its loop -- on 3.8/3.9 hosts (RHEL 9,
        # Debian 11) that crashed every start with "attached to a different loop".
        self._stop: asyncio.Event | None = None
        self._stop_requested = False
        # Set by _handshake on each successful connect -- exposed for tests/
        # observability, not required for correctness.
        self.last_target_id: str | None = None

        # Capability 2 execution-channel state. `_last_core_message_ts` is
        # stamped fresh on every successful handshake and on every message
        # received thereafter (_receive_loop) -- a reconnect must re-earn a
        # fresh heartbeat before the dead-man's switch re-arms. The
        # whitelist itself is NOT cleared on disconnect (core re-pushes it
        # after every fresh handshake anyway, per design; keeping the last-
        # known copy in the meantime just means "nothing to dispatch against
        # right now" rather than "forget everything"), but the dead-man's
        # switch check is what actually gates execution while disconnected.
        self._whitelist_specs: dict[str, "wl.ActionSpec"] = {}
        self._whitelist_version: int | None = None
        self._last_core_message_ts: float | None = None
        # Per-connection replay protection (F4) and the address core was
        # actually reached at (F9). Reset on every handshake.
        self._session_nonce: str | None = None
        self._seen_dispatch_ids: set[str] = set()
        self._peer_ip: str | None = None

    # ------------------------------------------------------------------
    # Persistent state
    # ------------------------------------------------------------------
    def _persist_state(self) -> None:
        self._state["agent_id"] = self.agent_id
        self._state["token"] = self.token
        _save_state(self.state_file, self._state)

    def _token_key(self) -> str:
        return hashlib.sha256((self.token or "").encode()).hexdigest()[:16]

    def _version_floor(self) -> int | None:
        """The newest whitelist version ever applied under the CURRENT token,
        persisted across restarts (F5): a fresh process must not accept an
        older push that a restart would otherwise let through. Keyed by token
        so re-pairing (a new token, a new core-side counter) starts fresh."""
        floors = self._state.get("whitelist_version_floor") or {}
        v = floors.get(self._token_key()) if isinstance(floors, dict) else None
        return v if type(v) is int else None

    def _record_version_floor(self, version: int) -> None:
        floors = self._state.get("whitelist_version_floor")
        if not isinstance(floors, dict):
            floors = {}
        floors[self._token_key()] = version
        self._state["whitelist_version_floor"] = floors
        self._persist_state()

    # ------------------------------------------------------------------
    # Ceiling
    # ------------------------------------------------------------------
    def _effective_ceiling(self) -> tuple["cl.Ceiling", list[str]]:
        """Shipped ceiling + the target admin's exact local commands, re-read
        every time so removing a line revokes it immediately."""
        if not self._local_allow_file:
            return self._base_ceiling, []
        shapes, problems = cl.load_local_commands(self._local_allow_file)
        return cl.with_local_commands(self._base_ceiling, shapes), problems

    def ceiling_report(self) -> dict[str, Any]:
        ceiling, problems = self._effective_ceiling()
        return {
            "version": ceiling.version,
            "fingerprint": ceiling.fingerprint(),
            "local_commands": [s.description for s in ceiling.shapes if s.local],
            "local_problems": problems,
        }

    def _transport_trusted(self) -> bool:
        if self.allow_untrusted_transport:
            return True
        try:
            addr = ipaddress.ip_address((self._peer_ip or "").split("%", 1)[0])
        except ValueError:
            return False
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        return any(addr in net for net in _TRUSTED_TRANSPORT_NETWORKS)

    def stop(self) -> None:
        self._stop_requested = True
        if self._stop is not None:
            self._stop.set()

    async def run_forever(self) -> None:
        backoff = BACKOFF_INITIAL_SECONDS
        self._stop = asyncio.Event()
        if self._stop_requested:
            self._stop.set()
        while not self._stop.is_set():
            try:
                await self._serve_until_stopped()
                backoff = BACKOFF_INITIAL_SECONDS  # a clean session (even a short one) means the link works -- don't keep penalizing it.
            except (OSError, asyncio.TimeoutError, proto.ProtocolError) as e:
                logger.warning("sub-agent connection ended (%s) -- retrying in %.0fs", e, backoff)
            if self._stop.is_set():
                break
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, BACKOFF_MAX_SECONDS)

    async def _serve_until_stopped(self) -> None:
        """One connection, torn down as soon as stop() is called -- otherwise a
        live connection would keep the process alive until systemd's stop
        timeout SIGKILLs it."""
        serve = asyncio.create_task(self._connect_and_serve())
        stopped = asyncio.create_task(self._stop.wait())
        try:
            await asyncio.wait({serve, stopped}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # asyncio.wait never raises the waited task's outcome, so this can't
            # swallow a cancellation of THIS task (no `return` in here either --
            # that would discard an in-flight CancelledError and leave the
            # reconnect loop running forever).
            stopped.cancel()
            if not serve.done():
                serve.cancel()
                await asyncio.wait({serve})
        if serve.cancelled():
            return  # stop() was called
        serve.result()  # re-raise a connection error for run_forever's backoff handling

    async def _connect_and_serve(self) -> None:
        reader, writer = await asyncio.open_connection(self.core_host, self.core_port)
        try:
            await self._handshake(reader, writer)
            await self._flush_buffer(writer)  # anything queued from a prior drop goes out immediately, not on the next collect tick.
            tasks = {
                asyncio.create_task(self._collect_loop(writer)),
                asyncio.create_task(self._ping_loop(writer)),
                asyncio.create_task(self._receive_loop(reader, writer)),
            }
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            finally:
                # Also runs when this coroutine itself is cancelled (stop()),
                # so no loop outlives its connection.
                for t in tasks:
                    t.cancel()
                await asyncio.wait(tasks)  # waits without re-raising their outcomes
            for t in done:
                if not t.cancelled() and t.exception() is not None:
                    raise t.exception()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.token:
            auth = {"token": self.token}
        elif self.pairing_code:
            auth = {"pairing_code": self.pairing_code}
        else:
            raise proto.ProtocolError("no saved token and no pairing code -- pair this agent first (--pair CODE)")
        self._session_nonce = secrets.token_hex(16)
        self._seen_dispatch_ids = set()
        self._last_core_message_ts = None  # only a signed pong on THIS connection re-arms execution
        peer = writer.get_extra_info("peername")
        self._peer_ip = peer[0] if isinstance(peer, tuple) and peer else None
        await proto.write_frame(writer, proto.build_hello(
            self.agent_id, auth, _hostname(), AGENT_VERSION,
            session_nonce=self._session_nonce, ceiling=self.ceiling_report(),
            collect_interval=self.collect_interval, ping_interval=self.ping_interval,
        ))
        reply = await asyncio.wait_for(proto.read_frame(reader), timeout=HANDSHAKE_TIMEOUT_SECONDS)
        if reply is None:
            raise proto.ProtocolError("core closed the connection during handshake")
        if reply.get("type") == proto.MSG_HELLO_REJECT:
            raise proto.ProtocolError(f"core rejected pairing: {reply.get('reason')}")
        if reply.get("type") != proto.MSG_HELLO_ACK:
            raise proto.ProtocolError(f"unexpected handshake reply type: {reply.get('type')!r}")
        new_token = reply.get("token")
        if new_token and new_token != self.token:
            self.token = new_token
            self._persist_state()
        self.last_target_id = reply.get("target_id")
        self.pairing_code = None  # single-use; never retried even if a later reconnect races with a core-side "already used" state.
        logger.info("paired -- target_id=%s", self.last_target_id)

    async def _collect_loop(self, writer: asyncio.StreamWriter) -> None:
        collect_fn = functools.partial(collector.collect_snapshot, watch_files=self.watch_files, services=self.services)
        loop = asyncio.get_event_loop()
        while True:
            snapshot = await loop.run_in_executor(None, collect_fn)
            self._seq += 1
            frame = {"seq": self._seq, "collected_at": _iso_now(), "payload": snapshot}
            self._buffer.append(frame)
            await self._flush_buffer(writer)
            await asyncio.sleep(self.collect_interval)

    async def _flush_buffer(self, writer: asyncio.StreamWriter) -> None:
        while self._buffer:
            frame = self._buffer[0]
            await proto.write_frame(writer, proto.build_telemetry(frame["seq"], frame["collected_at"], frame["payload"]))
            self._buffer.popleft()

    async def _ping_loop(self, writer: asyncio.StreamWriter) -> None:
        # First ping immediately, so a fresh connection earns its signed pong
        # (and an armed dead-man's switch) without waiting a full interval.
        while True:
            await proto.write_frame(writer, proto.build_ping(time.time()))
            await asyncio.sleep(self.ping_interval)

    async def _receive_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Drains telemetry_ack/pong frames so the peer's write buffer never
        # backs up, and is what notices a core-initiated close (EOF) or a
        # core that's gone silent (timeout) promptly -- not just on our next
        # write attempt. Also the ONLY place capability-2 messages (a signed
        # whitelist push, a signed exec dispatch) are ever received.
        timeout = max(self.ping_interval * 3, HANDSHAKE_TIMEOUT_SECONDS)
        while True:
            msg = await asyncio.wait_for(proto.read_frame(reader), timeout=timeout)
            if msg is None:
                raise proto.ProtocolError("core closed the connection")
            mtype = msg.get("type")
            if mtype == proto.MSG_TELEMETRY_ACK:
                continue
            if mtype == proto.MSG_PONG:
                # The ONLY thing that arms the dead-man's switch: a pong SIGNED
                # by core for this connection's session nonce (F6). An
                # unsigned pong/ack proves nothing about who is on the other
                # end. Deliberately not whitelist_push/exec_dispatch either --
                # a dispatch's own arrival must never be the heartbeat that
                # justifies running it.
                if self._pong_is_authentic(msg):
                    self._last_core_message_ts = time.time()
                continue
            try:
                if mtype == proto.MSG_WHITELIST_PUSH:
                    await self._handle_whitelist_push(msg, writer)
                elif mtype == proto.MSG_EXEC_DISPATCH:
                    await self._handle_exec_dispatch(msg, writer)
                else:
                    logger.warning("ignoring unexpected message type %r from core", mtype)
            except (OSError, proto.ProtocolError):
                raise
            except Exception:  # noqa: BLE001 -- a malformed message must never kill the connection (F7)
                logger.exception("error handling %r from core -- ignored", mtype)

    def _pong_is_authentic(self, msg: dict[str, Any]) -> bool:
        if not self.token or msg.get("session_nonce") != self._session_nonce:
            return False
        return signing.verify_envelope(signing.derive_signing_key(self.token), msg)

    async def _handle_whitelist_push(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        """Apply (or reject) a signed whitelist push.

        Every action is checked independently against this agent's OWN
        ceiling (never trusting that core already did). An action outside the
        ceiling is dropped and reported back in the ack; the rest are applied.
        That is safe because each surviving action is still bounded by the
        ceiling on its own, and it lets an older agent keep working when a
        newer core offers actions it doesn't know yet.

        Anti-rollback (design doc §9 #5, F5): a push older than the newest
        version ever applied under this token -- including across restarts --
        is refused outright. An EQUAL version is accepted idempotently (a
        reconnect re-syncing unchanged state)."""
        if not self.token:
            logger.warning("rejected whitelist_push: not paired")
            return
        key = signing.derive_signing_key(self.token)
        if not signing.verify_envelope(key, msg):
            logger.warning("rejected whitelist_push: invalid signature")
            return
        version = msg.get("version")
        if type(version) is not int or version < 0:  # F8: no bools, no floats
            logger.warning("rejected whitelist_push: version %r is not a non-negative integer", version)
            return
        floor = max((v for v in (self._whitelist_version, self._version_floor()) if v is not None), default=None)
        if floor is not None and version < floor:
            logger.warning("rejected whitelist_push: version %r is older than %r (anti-rollback)", version, floor)
            return
        actions = msg.get("actions")
        if not isinstance(actions, list):
            logger.warning("rejected whitelist_push: actions is not a list")
            return

        ceiling, _ = self._effective_ceiling()
        new_specs: dict[str, wl.ActionSpec] = {}
        rejected: list[dict[str, str]] = []
        for raw in actions:
            action_id = raw.get("id") if isinstance(raw, dict) else None
            label = action_id if isinstance(action_id, str) else "?"
            try:
                if not isinstance(raw, dict):
                    raise wl.ActionSpecError("action is not an object")
                spec = wl.spec_from_wire(raw)
                if spec.id in new_specs:
                    raise wl.ActionSpecError("duplicate action id")
                cl.check_spec(spec, ceiling)
            except (wl.ActionSpecError, cl.CeilingError, TypeError, ValueError) as e:
                rejected.append({"id": label, "reason": str(e)})
                continue
            new_specs[spec.id] = spec
        if rejected:
            logger.warning("whitelist_push v%s: refused %d action(s) outside this agent's ceiling: %s",
                           version, len(rejected), "; ".join(r["reason"] for r in rejected))
        self._whitelist_specs = new_specs
        self._whitelist_version = version
        self._record_version_floor(version)
        logger.info("applied whitelist_push: version=%s, %d action(s)", version, len(new_specs))
        await proto.write_frame(writer, proto.build_whitelist_push_ack(version, rejected, self.ceiling_report()))

    async def _handle_exec_dispatch(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        dispatch_id = msg.get("dispatch_id") if isinstance(msg.get("dispatch_id"), str) else ""
        try:
            result = await self._process_exec_dispatch(msg)
        except Exception as e:  # noqa: BLE001 -- "never raises" (F7): any surprise is a refusal, not a crash
            logger.exception("exec_dispatch %s: unexpected error", dispatch_id)
            result = {"status": "refused", "reason": f"internal error: {type(e).__name__}"}
        logger.info("exec_dispatch %s: action=%r status=%s reason=%s",
                    dispatch_id, msg.get("action_id"), result.get("status"), result.get("reason"))
        await proto.write_frame(writer, proto.build_exec_result(dispatch_id, ts=time.time(), **result))

    async def _process_exec_dispatch(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Every gate below is fail-closed and checked fresh, in order, on
        EVERY dispatch -- see this module's own docstring for the full list.
        Returns kwargs for `protocol.build_exec_result`."""
        if not self.execution_enabled:
            return {"status": "refused", "reason": "execution is not enabled on this agent (local opt-in required)"}
        if not self.token:
            return {"status": "refused", "reason": "not paired"}
        if not self._transport_trusted():
            return {"status": "refused", "reason": (
                f"core is reached at {self._peer_ip!r}, which is not loopback or a Tailscale address -- "
                "this channel has no encryption of its own; use Tailscale/WireGuard "
                "(or start the agent with --allow-untrusted-transport to accept the risk)")}
        dispatch_id, action_id = msg.get("dispatch_id"), msg.get("action_id")
        slot_values, version = msg.get("slot_values"), msg.get("whitelist_version")
        if not isinstance(dispatch_id, str) or not dispatch_id or len(dispatch_id) > 128:
            return {"status": "refused", "reason": "malformed dispatch_id"}
        if not isinstance(action_id, str) or not isinstance(slot_values, dict) or type(version) is not int:
            return {"status": "refused", "reason": "malformed dispatch (action_id/slot_values/whitelist_version types)"}
        key = signing.derive_signing_key(self.token)
        if not signing.verify_envelope(key, msg):
            return {"status": "refused", "reason": "invalid signature"}
        if msg.get("session_nonce") != self._session_nonce:
            return {"status": "refused", "reason": "dispatch is not for this connection (replay?)"}
        if dispatch_id in self._seen_dispatch_ids:
            return {"status": "refused", "reason": "duplicate dispatch_id (replay?)"}
        if len(self._seen_dispatch_ids) >= SEEN_DISPATCH_IDS_MAX:
            return {"status": "refused", "reason": "too many dispatches on this connection -- reconnect"}
        self._seen_dispatch_ids.add(dispatch_id)
        if not self._execution_armed():
            return {"status": "refused", "reason": "dead-man's switch: no fresh authenticated heartbeat from core"}
        if version != self._whitelist_version:
            return {
                "status": "refused",
                "reason": f"stale whitelist_version (dispatch={version!r}, agent has={self._whitelist_version!r})",
            }
        spec = self._whitelist_specs.get(action_id)
        if spec is None:
            return {"status": "refused", "reason": f"unknown action_id {action_id!r} in this agent's whitelist copy"}
        ceiling, _ = self._effective_ceiling()  # re-read: a removed local command is revoked immediately
        try:
            local = cl.uses_local_command(spec, ceiling)
            argv = wl.render_argv(spec, slot_values, hard_exclusions=not local)
            cl.match_argv(argv, ceiling)  # the final gate is on exactly what will run
        except (wl.ActionSpecError, wl.SlotValueError, cl.CeilingError) as e:
            return {"status": "refused", "reason": f"validation failed: {e}"}
        executable = cl.resolve_executable(argv[0])
        if executable is None:
            return {"status": "error", "reason": f"{argv[0]!r} is not installed in {', '.join(cl.TRUSTED_BIN_DIRS)}"}
        return await self._run_argv([executable, *argv[1:]])

    def _execution_armed(self) -> bool:
        if self._last_core_message_ts is None:
            return False
        return (time.time() - self._last_core_message_ts) <= DEAD_MANS_SWITCH_SECONDS

    async def _run_argv(self, argv: list[str]) -> dict[str, Any]:
        """The ONLY place this process ever executes anything -- always a
        plain argv list `render_argv` produced, `shell=False`, no string
        concatenation."""
        loop = asyncio.get_event_loop()
        try:
            proc = await loop.run_in_executor(
                None,
                functools.partial(subprocess.run, argv, shell=False, capture_output=True,
                                   timeout=EXEC_TIMEOUT_SECONDS, text=True, stdin=subprocess.DEVNULL,
                                   env=dict(cl.EXEC_ENV), cwd="/"),
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "reason": f"command timed out after {EXEC_TIMEOUT_SECONDS}s"}
        except OSError as e:
            return {"status": "error", "reason": f"failed to execute: {e}"}
        return {
            "status": "ok",
            "exit_code": proc.returncode,
            "stdout_tail": proc.stdout[-OUTPUT_TAIL_MAX_CHARS:],
            "stderr_tail": proc.stderr[-OUTPUT_TAIL_MAX_CHARS:],
        }


def _hostname() -> str:
    import socket

    return socket.gethostname()


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Kratos sub-agent -- telemetry (capability 1) + gated direct execution (capability 2)")
    p.add_argument("--core-host", required=True, help="Kratos core's reachable address")
    p.add_argument("--core-port", type=int, default=DEFAULT_CORE_PORT)
    p.add_argument("--pair", dest="pairing_code", default=None, help="One-time pairing code (only needed on first run)")
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    p.add_argument("--collect-interval", type=float, default=DEFAULT_COLLECT_INTERVAL_SECONDS)
    p.add_argument("--ping-interval", type=float, default=DEFAULT_PING_INTERVAL_SECONDS)
    p.add_argument("--log-level", default="INFO")
    p.add_argument(
        "--enable-execution", dest="execution_enabled", action="store_true", default=False,
        help=(
            "LOCAL, explicit opt-in for capability 2 (direct execution). Off by default. "
            "Do NOT pass this against a real target until the independent security review "
            "(docs/subagent_whitelist_design.md §9 #7) has passed for the code actually running here."
        ),
    )
    p.add_argument(
        "--allow-untrusted-transport", dest="allow_untrusted_transport", action="store_true", default=False,
        help=(
            "Allow execution even when core is not reached over loopback or Tailscale. The channel has no "
            "encryption of its own, so on a shared network the pairing token (and with it the signing key) "
            "can be sniffed. Leave off unless the network itself is trusted."
        ),
    )
    p.add_argument(
        "--local-allow-file", default=cl.LOCAL_ALLOW_FILE,
        help="Exact commands this target's admin allows Kratos to run, one per line (default: %(default)s).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    agent = SubAgent(
        core_host=args.core_host,
        core_port=args.core_port,
        state_file=args.state_file,
        pairing_code=args.pairing_code,
        collect_interval=args.collect_interval,
        ping_interval=args.ping_interval,
        execution_enabled=args.execution_enabled,
        allow_untrusted_transport=args.allow_untrusted_transport,
        local_allow_file=args.local_allow_file,
    )
    if args.execution_enabled:
        logger.warning(
            "direct execution is ENABLED on this agent (--enable-execution) -- "
            "confirm the independent security review has passed before pointing this at a real, "
            "in-use target (docs/subagent_whitelist_design.md §9 #7)"
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.add_signal_handler(signal.SIGINT, agent.stop)
        loop.add_signal_handler(signal.SIGTERM, agent.stop)
    except (NotImplementedError, AttributeError):
        pass  # e.g. no signal handling on this platform -- Ctrl+C still raises KeyboardInterrupt below.

    try:
        loop.run_until_complete(agent.run_forever())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
