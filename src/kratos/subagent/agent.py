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
  2. The dispatch's signature verifies under this agent's OWN derived
     signing key (`signing.derive_signing_key(self.token)`) -- control 2.
  3. The dead-man's switch is armed: this agent has had a fresh, real
     message from core within `DEAD_MANS_SWITCH_SECONDS` (design doc §9 #5)
     -- a severed or silently-dead core connection disarms execution.
  4. The dispatch's `whitelist_version` matches this agent's CURRENTLY
     applied whitelist version exactly -- an old version can never be
     replayed to roll back a revocation (fail-closed on stale, §9 #5).
  5. The action_id is present in this agent's own whitelist copy, and
     `whitelist.validate_spec()`/`render_argv()` (the SAME independent
     re-validation the design doc requires on the agent side, never trusting
     that core already validated) accept it.
Only then is `subprocess.run(argv, shell=False, ...)` ever reached -- no
shell, no string concatenation, the exact argv `render_argv` returned.
Every dispatch attempt (refused or executed) is logged locally via the
standard `logging` module (control 4: independent sub-agent-side logging).

Deploy by copying this file plus protocol.py, collector.py, signing.py, and
whitelist.py onto the target as a `subagent/` package directory (they must
stay siblings -- all five are stdlib-only, confirmed by import) and running,
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
import functools
import json
import logging
import signal
import subprocess
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

try:  # `python3 -m subagent.agent` (preferred) -- real package-relative import.
    from . import collector, protocol as proto, signing, whitelist as wl
except ImportError:  # pragma: no cover -- fallback for `python3 subagent/agent.py` run directly.
    import collector  # type: ignore[no-redef]
    import protocol as proto  # type: ignore[no-redef]
    import signing  # type: ignore[no-redef]
    import whitelist as wl  # type: ignore[no-redef]

logger = logging.getLogger("kratos.subagent.agent")

AGENT_VERSION = "0.1.0"
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


def _load_state(state_file: Path) -> dict[str, Any]:
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(state_file: Path, state: dict[str, Any]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
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

        state = _load_state(state_file)
        self.agent_id: str = state.get("agent_id") or uuid.uuid4().hex
        self.token: str | None = state.get("token")
        if not state.get("agent_id"):
            _save_state(state_file, {"agent_id": self.agent_id, "token": self.token})

        self._buffer: deque[dict[str, Any]] = deque(maxlen=BUFFER_MAX)
        self._seq = 0
        self._stop = asyncio.Event()
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

    def stop(self) -> None:
        self._stop.set()

    async def run_forever(self) -> None:
        backoff = BACKOFF_INITIAL_SECONDS
        while not self._stop.is_set():
            try:
                await self._connect_and_serve()
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

    async def _connect_and_serve(self) -> None:
        reader, writer = await asyncio.open_connection(self.core_host, self.core_port)
        try:
            await self._handshake(reader, writer)
            await self._flush_buffer(writer)  # anything queued from a prior drop goes out immediately, not on the next collect tick.
            collect_task = asyncio.create_task(self._collect_loop(writer))
            ping_task = asyncio.create_task(self._ping_loop(writer))
            receive_task = asyncio.create_task(self._receive_loop(reader, writer))
            done, pending = await asyncio.wait(
                {collect_task, ping_task, receive_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            for t in pending:
                try:
                    await t
                except asyncio.CancelledError:
                    pass
            for t in done:
                exc = t.exception()
                if exc is not None:
                    raise exc
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
        await proto.write_frame(writer, proto.build_hello(self.agent_id, auth, _hostname(), AGENT_VERSION))
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
            _save_state(self.state_file, {"agent_id": self.agent_id, "token": self.token})
        self.last_target_id = reply.get("target_id")
        self.pairing_code = None  # single-use; never retried even if a later reconnect races with a core-side "already used" state.
        self._last_core_message_ts = time.time()  # a fresh, real message from core -- (re-)arms the dead-man's switch
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
        while True:
            await asyncio.sleep(self.ping_interval)
            await proto.write_frame(writer, proto.build_ping(time.time()))

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
            if mtype in (proto.MSG_TELEMETRY_ACK, proto.MSG_PONG):
                # The dedicated, REGULAR liveness signals -- these are what
                # actually arm the dead-man's switch. Deliberately does NOT
                # include whitelist_push/exec_dispatch: an exec_dispatch's
                # own arrival must not be usable as the heartbeat that
                # justifies processing that same dispatch (that would make
                # the switch self-defeating for the one message it exists to
                # gate); a genuinely severed-then-recovered link re-arms via
                # the next real ping/pong exchange, which happens well
                # before any dispatch would normally follow it.
                self._last_core_message_ts = time.time()
                continue
            if mtype == proto.MSG_WHITELIST_PUSH:
                await self._handle_whitelist_push(msg, writer)
            elif mtype == proto.MSG_EXEC_DISPATCH:
                await self._handle_exec_dispatch(msg, writer)
            else:
                logger.warning("ignoring unexpected message type %r from core", mtype)

    async def _handle_whitelist_push(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        """Apply (or reject) a signed whitelist push -- design doc §9 #4/#5:
        the agent's whitelist is authoritative-FROM-core, but the agent still
        independently re-validates every action (never trusts that core
        already did), and rejects any push whose version doesn't strictly
        advance (anti-rollback -- a MITM replaying an old, pre-revocation
        push must not be able to resurrect a revoked action). A push with
        even ONE invalid action is rejected in full, never partially applied."""
        if not self.token:
            logger.warning("rejected whitelist_push: not paired")
            return
        key = signing.derive_signing_key(self.token)
        if not signing.verify_envelope(key, msg):
            logger.warning("rejected whitelist_push: invalid signature")
            return
        version = msg.get("version")
        if not isinstance(version, int) or (self._whitelist_version is not None and version < self._whitelist_version):
            # Strictly older than what we already have -> a real rollback
            # attempt, rejected (anti-rollback, design doc §9 #5). An EQUAL
            # version is accepted idempotently -- e.g. a fresh reconnect
            # re-pushing the same, unchanged whitelist is normal, not replay.
            logger.warning(
                "rejected whitelist_push: version %r is older than current %r (anti-rollback)",
                version, self._whitelist_version,
            )
            return
        new_specs: dict[str, wl.ActionSpec] = {}
        try:
            for raw in msg.get("actions") or []:
                spec = wl.spec_from_wire(raw)
                wl.validate_spec(spec)  # independent re-validation -- never trust core blindly
                new_specs[spec.id] = spec
        except wl.ActionSpecError as e:
            logger.warning("rejected whitelist_push: an action failed independent re-validation: %s", e)
            return
        self._whitelist_specs = new_specs
        self._whitelist_version = version
        logger.info("applied whitelist_push: version=%s, %d action(s)", version, len(new_specs))
        await proto.write_frame(writer, proto.build_whitelist_push_ack(version))

    async def _handle_exec_dispatch(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        dispatch_id = msg.get("dispatch_id") or ""
        action_id = msg.get("action_id")
        result = await self._process_exec_dispatch(msg)
        logger.info("exec_dispatch %s: action=%r status=%s reason=%s",
                    dispatch_id, action_id, result.get("status"), result.get("reason"))
        await proto.write_frame(writer, proto.build_exec_result(dispatch_id, ts=time.time(), **result))

    async def _process_exec_dispatch(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Every gate below is fail-closed and checked fresh, in order, on
        EVERY dispatch -- see this module's own docstring for the full list.
        Returns kwargs for `protocol.build_exec_result` (never raises)."""
        if not self.execution_enabled:
            return {"status": "refused", "reason": "execution is not enabled on this agent (local opt-in required)"}
        if not self.token:
            return {"status": "refused", "reason": "not paired"}
        key = signing.derive_signing_key(self.token)
        if not signing.verify_envelope(key, msg):
            return {"status": "refused", "reason": "invalid signature"}
        if not self._execution_armed():
            return {"status": "refused", "reason": "dead-man's switch: no fresh authenticated heartbeat from core"}
        version = msg.get("whitelist_version")
        if version != self._whitelist_version:
            return {
                "status": "refused",
                "reason": f"stale whitelist_version (dispatch={version!r}, agent has={self._whitelist_version!r})",
            }
        action_id = msg.get("action_id")
        spec = self._whitelist_specs.get(action_id)
        if spec is None:
            return {"status": "refused", "reason": f"unknown action_id {action_id!r} in this agent's whitelist copy"}
        try:
            wl.validate_spec(spec)  # re-validate the STORED spec itself, never just trust a past check
            argv = wl.render_argv(spec, msg.get("slot_values") or {})
        except (wl.ActionSpecError, wl.SlotValueError) as e:
            return {"status": "refused", "reason": f"validation failed: {e}"}
        return await self._run_argv(argv)

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
                                   timeout=EXEC_TIMEOUT_SECONDS, text=True),
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
