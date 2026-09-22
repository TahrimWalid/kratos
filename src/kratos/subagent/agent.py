"""
Kratos sub-agent daemon -- capability 1 (continuous, read-only telemetry;
docs/subagent_architecture.md) ONLY. Runs on the monitored target, dials OUT
to Kratos's core, and continuously forwards read-only telemetry snapshots.
There is no command-receiving code path anywhere in this file: it only ever
writes hello/telemetry/ping frames and reads hello_ack/hello_reject/
telemetry_ack/pong frames back (see protocol.py) -- capability 2 (direct
execution) is separate, not-yet-built, gated work and nothing here is a stub
or seam for it.

Deploy by copying this file plus protocol.py and collector.py onto the
target as a `subagent/` package directory (they must stay siblings) and
running, from the parent of that directory:

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
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

try:  # `python3 -m subagent.agent` (preferred) -- real package-relative import.
    from . import collector, protocol as proto
except ImportError:  # pragma: no cover -- fallback for `python3 subagent/agent.py` run directly.
    import collector  # type: ignore[no-redef]
    import protocol as proto  # type: ignore[no-redef]

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
    ) -> None:
        self.core_host = core_host
        self.core_port = core_port
        self.state_file = state_file
        self.pairing_code = pairing_code
        self.collect_interval = collect_interval
        self.ping_interval = ping_interval
        self.watch_files = watch_files
        self.services = services

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
            receive_task = asyncio.create_task(self._receive_loop(reader))
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

    async def _receive_loop(self, reader: asyncio.StreamReader) -> None:
        # Drains telemetry_ack/pong frames so the peer's write buffer never
        # backs up, and is what notices a core-initiated close (EOF) or a
        # core that's gone silent (timeout) promptly -- not just on our next
        # write attempt.
        timeout = max(self.ping_interval * 3, HANDSHAKE_TIMEOUT_SECONDS)
        while True:
            msg = await asyncio.wait_for(proto.read_frame(reader), timeout=timeout)
            if msg is None:
                raise proto.ProtocolError("core closed the connection")


def _hostname() -> str:
    import socket

    return socket.gethostname()


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Kratos sub-agent -- read-only telemetry forwarding (capability 1)")
    p.add_argument("--core-host", required=True, help="Kratos core's reachable address")
    p.add_argument("--core-port", type=int, default=DEFAULT_CORE_PORT)
    p.add_argument("--pair", dest="pairing_code", default=None, help="One-time pairing code (only needed on first run)")
    p.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    p.add_argument("--collect-interval", type=float, default=DEFAULT_COLLECT_INTERVAL_SECONDS)
    p.add_argument("--ping-interval", type=float, default=DEFAULT_PING_INTERVAL_SECONDS)
    p.add_argument("--log-level", default="INFO")
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
