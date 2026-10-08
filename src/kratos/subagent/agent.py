"""
Kratos sub-agent daemon. Runs on the monitored target, dials OUT to Kratos's
core, and continuously forwards read-only telemetry snapshots (capability 1;
docs/subagent_architecture.md) -- always on, regardless of everything below.

**Investigation reads** (docs/subagent_read_routing.md): core may also send a
signed `read_request` naming one probe from this agent's own closed set
(reads.py) with parameters this agent validates itself. No command text, path
list or rule text is accepted from core. A read is refused unless it is signed
for this connection's session nonce with a strictly increasing `seq` (no
replay) and core is reached over loopback/Tailscale (or the operator passed
--allow-untrusted-transport). Reads never change state and are unrelated to
execution: they don't need, and can't turn on, anything below.

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
     session nonce echoed one of THIS connection's own pings sent within
     `DEAD_MANS_SWITCH_SECONDS` (design doc §9 #5, F6) -- a severed, silent, or
     impersonated core disarms execution, and a replayed pong can't extend it.
     The dispatch itself must name such a recent ping (`heartbeat_ts`), so one
     held back in transit expires with the window.
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
import sys
import time
import uuid

try:
    import fcntl
except ImportError:  # pragma: no cover -- non-POSIX; the agent targets Linux
    fcntl = None  # type: ignore[assignment]
from collections import deque
from pathlib import Path
from typing import Any

try:  # `python3 -m subagent.agent` (preferred) -- real package-relative import.
    from . import ceiling as cl, collector, protocol as proto, reads, signing, whitelist as wl
except ImportError:  # pragma: no cover -- fallback for `python3 subagent/agent.py` run directly.
    import ceiling as cl  # type: ignore[no-redef]
    import collector  # type: ignore[no-redef]
    import protocol as proto  # type: ignore[no-redef]
    import reads  # type: ignore[no-redef]
    import signing  # type: ignore[no-redef]
    import whitelist as wl  # type: ignore[no-redef]

logger = logging.getLogger("kratos.subagent.agent")

AGENT_VERSION = "0.3.5"
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
# How long a starting agent waits for a previous one on the same state file
# to exit (a restart can briefly overlap the old process).
INSTANCE_LOCK_WAIT_SECONDS = 20.0

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
# Pings remembered per connection: a signed pong (and a dispatch) must name one of
# them. Comfortably more than DEAD_MANS_SWITCH_SECONDS / the shortest ping interval.
SENT_PINGS_MAX = 64
# Read probes run one at a time; at most this many may wait behind the running
# one before further requests are answered "busy" (core sends one at a time,
# so this only ever trips on a misbehaving peer).
READ_QUEUE_MAX = 4

# Transport check for execution and reads (F9): this channel has no
# encryption of its own, so core must be reached over loopback or over an
# interface that encrypts by itself. A tailnet-range address alone is not
# enough -- 100.64.0.0/10 is also carrier-grade NAT space, which ISPs use for
# plain internet (review v2 F-7) -- so this agent's own end of the connection
# must sit on a Tailscale interface (or one the operator names with
# --trusted-interface, e.g. their own WireGuard tunnel).
_LOOPBACK_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128"))
_TAILNET_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("100.64.0.0/10", "fd7a:115c:a1e0::/48"))
TAILSCALE_INTERFACE_PREFIX = "tailscale"  # tailscaled's TUN is tailscale0 unless --tun says otherwise
_SIOCGIFADDR = 0x8915


def _as_ip(text: Any) -> "ipaddress.IPv4Address | ipaddress.IPv6Address | None":
    try:
        addr = ipaddress.ip_address(str(text or "").split("%", 1)[0])
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def local_interface_of(addr: "ipaddress.IPv4Address | ipaddress.IPv6Address | None") -> str | None:
    """Name of the network interface this machine's address `addr` is assigned
    to, or None if it can't be told (non-Linux, an IPv4 alias, any error) --
    callers treat None as untrusted. Stdlib only: /proc/net/if_inet6 for IPv6,
    the SIOCGIFADDR ioctl (each interface's primary IPv4 address) for IPv4."""
    if addr is None:
        return None
    try:
        if addr.version == 6:
            want = addr.packed.hex()
            with open("/proc/net/if_inet6", encoding="ascii") as f:
                for line in f:
                    fields = line.split()
                    if len(fields) >= 6 and fields[0].lower() == want:
                        return fields[5]
            return None
        if fcntl is None:
            return None
        import socket
        import struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for _index, name in socket.if_nameindex():
                try:
                    raw = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, struct.pack("256s", name.encode()[:15]))
                except OSError:
                    continue  # no IPv4 address on this interface
                if raw[20:24] == addr.packed:
                    return name
    except (OSError, ValueError):
        return None
    return None


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
        trusted_interfaces: "tuple[str, ...] | list[str]" = (),
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
        # Interfaces the operator says encrypt by themselves (their own
        # WireGuard tunnel, or a Tailscale TUN with a custom name).
        self.trusted_interfaces = frozenset(str(n) for n in trusted_interfaces)
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
        self._local_ip: str | None = None  # this agent's own end of the connection (F-7)
        # Send times of this connection's own pings. A signed pong arms execution
        # only by echoing one of them, and only from THAT ping's send time, so a
        # replayed pong can't extend the dead-man's switch; every dispatch must
        # name a recent one, so a dispatch held back in transit expires.
        self._sent_pings: deque[float] = deque(maxlen=SENT_PINGS_MAX)
        # Read probes (docs/subagent_read_routing.md): per-connection replay
        # floor, a one-at-a-time lock (made per connection, on the running
        # loop), and the tasks to cancel when the connection ends.
        self._last_read_seq = 0
        self._read_lock: asyncio.Lock | None = None
        self._read_tasks: set[asyncio.Task] = set()

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
        previous = self._state.get("whitelist_version_floor")
        floors = dict(previous) if isinstance(previous, dict) else {}
        floors[self._token_key()] = version
        self._state["whitelist_version_floor"] = floors
        try:
            self._persist_state()
        except OSError:
            self._state["whitelist_version_floor"] = previous  # memory never runs ahead of the file
            raise

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
            # So Kratos can say up front that a run will be refused, instead of
            # asking for typed EXECUTE first (seen in the fix-channel recording).
            "execution_enabled": bool(self.execution_enabled),
            "transport_trusted": self._transport_trusted(),
        }

    def _transport_trusted(self) -> bool:
        return self._transport_why_not() is None

    def _transport_why_not(self) -> str | None:
        """None when this connection to core may carry execution and reads;
        otherwise a plain reason, used in refusals."""
        if self.allow_untrusted_transport:
            return None
        peer = _as_ip(self._peer_ip)
        if peer is None:
            return "core's address on this connection is unknown"
        if any(peer in net for net in _LOOPBACK_NETWORKS):
            return None
        iface = local_interface_of(_as_ip(self._local_ip))
        if iface is not None and iface in self.trusted_interfaces:
            return None
        if iface is not None and iface.startswith(TAILSCALE_INTERFACE_PREFIX) \
                and any(peer in net for net in _TAILNET_NETWORKS):
            return None
        if any(peer in net for net in _TAILNET_NETWORKS):
            return (f"core is reached at {self._peer_ip!r}, a tailnet-range address, but not over a Tailscale "
                    f"interface (this end is on {iface or 'an unknown interface'}) -- 100.64.0.0/10 is also "
                    "carrier-grade NAT space, so it isn't treated as encrypted")
        return f"core is reached at {self._peer_ip!r}, which is not loopback or over a Tailscale interface"

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
                # so no loop (or read in flight) outlives its connection.
                pending_reads = set(self._read_tasks)
                for t in tasks | pending_reads:
                    t.cancel()
                await asyncio.wait(tasks | pending_reads)  # waits without re-raising their outcomes
                self._read_tasks.clear()
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
        self._sent_pings = deque(maxlen=SENT_PINGS_MAX)
        self._last_read_seq = 0
        self._read_lock = asyncio.Lock()
        self._last_core_message_ts = None  # only a signed pong on THIS connection re-arms execution
        peer = writer.get_extra_info("peername")
        self._peer_ip = peer[0] if isinstance(peer, tuple) and peer else None
        local = writer.get_extra_info("sockname")
        self._local_ip = local[0] if isinstance(local, tuple) and local else None
        await proto.write_frame(writer, proto.build_hello(
            self.agent_id, auth, _hostname(), AGENT_VERSION,
            session_nonce=self._session_nonce, ceiling=self.ceiling_report(),
            collect_interval=self.collect_interval, ping_interval=self.ping_interval,
            read_probes=reads.READ_PROBES, read_api=reads.READ_API_VERSION,
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
            ts = time.time()
            self._sent_pings.append(ts)
            await proto.write_frame(writer, proto.build_ping(ts))
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
                    # armed from when OUR ping left, not when the pong arrived:
                    # a delayed or replayed pong can't stretch the window
                    self._last_core_message_ts = max(self._last_core_message_ts or 0.0, float(msg["ts"]))
                continue
            try:
                if mtype == proto.MSG_WHITELIST_PUSH:
                    await self._handle_whitelist_push(msg, writer)
                elif mtype == proto.MSG_EXEC_DISPATCH:
                    await self._handle_exec_dispatch(msg, writer)
                elif mtype == proto.MSG_READ_REQUEST:
                    # Never awaited here: a 3-minute YARA scan must not stop
                    # this loop reading pongs and other messages.
                    self._start_read(msg, writer)
                else:
                    logger.warning("ignoring unexpected message type %r from core", mtype)
            except (OSError, proto.ProtocolError):
                raise
            except Exception:  # noqa: BLE001 -- a malformed message must never kill the connection (F7)
                logger.exception("error handling %r from core -- ignored", mtype)

    def _pong_is_authentic(self, msg: dict[str, Any]) -> bool:
        if not self.token or msg.get("session_nonce") != self._session_nonce:
            return False
        if not self._is_own_recent_ping(msg.get("ts")):
            return False
        return signing.verify_envelope(signing.derive_signing_key(self.token), msg)

    def _is_own_recent_ping(self, ts: Any) -> bool:
        """`ts` is the send time of a ping THIS connection sent, within the
        dead-man's window."""
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts not in self._sent_pings:
            return False
        return 0 <= time.time() - ts <= DEAD_MANS_SWITCH_SECONDS

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
        floor = max((v for v in (self._whitelist_version, self._version_floor()) if v is not None), default=None)
        # F8: no bools, no floats. Review v2 F-3: bounded above, so one push
        # can't raise the persisted floor beyond anything core will ever send.
        if type(version) is not int or not 0 <= version <= proto.MAX_WHITELIST_VERSION:
            await self._refuse_push(writer, None, f"version {version!r} is not an integer from 0 to "
                                                  f"{proto.MAX_WHITELIST_VERSION}", floor)
            return
        if floor is not None and version < floor:
            await self._refuse_push(writer, version, f"version {version} is older than {floor}, the newest this "
                                                     "machine has applied (anti-rollback)", floor)
            return
        actions = msg.get("actions")
        if not isinstance(actions, list):
            await self._refuse_push(writer, version, "actions is not a list", floor)
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
            except Exception as e:  # noqa: BLE001 -- review v2 F-4: one odd action is refused, never the whole push
                logger.exception("whitelist_push v%s: unexpected error checking action %r", version, label)
                rejected.append({"id": label, "reason": f"could not be checked ({type(e).__name__})"})
                continue
            new_specs[spec.id] = spec
        if rejected:
            logger.warning("whitelist_push v%s: refused %d action(s) outside this agent's ceiling: %s",
                           version, len(rejected), "; ".join(r["reason"] for r in rejected))
        try:
            # Recorded BEFORE applying: a version this machine can't remember
            # across a restart would weaken anti-rollback, so it isn't used.
            self._record_version_floor(version)
        except OSError as e:
            await self._refuse_push(writer, version, f"could not save the version on this machine ({e.strerror or e}); "
                                                     "is its disk full or read-only?", floor)
            return
        self._whitelist_specs = new_specs
        self._whitelist_version = version
        logger.info("applied whitelist_push: version=%s, %d action(s)", version, len(new_specs))
        await proto.write_frame(writer, proto.build_whitelist_push_ack(version, rejected, self.ceiling_report()))

    async def _refuse_push(self, writer: asyncio.StreamWriter, version: int | None, reason: str,
                           floor: int | None) -> None:
        """Answer a signed push that is refused as a whole, instead of staying
        silent: core would otherwise wait out its ack timeout and push the
        same thing again every few seconds, never learning why."""
        logger.warning("rejected whitelist_push: %s", reason)
        await proto.write_frame(writer, proto.build_whitelist_push_refused(version, reason, floor))

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
        why_not = self._transport_why_not()
        if why_not is not None:
            return {"status": "refused", "reason": (
                f"{why_not} -- this channel has no encryption of its own; use Tailscale/WireGuard "
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
        if not self._is_own_recent_ping(msg.get("heartbeat_ts")):
            # The dispatch names the latest ping core had seen when it was sent;
            # one held back in transit longer than the window is refused.
            return {"status": "refused", "reason": "dispatch is not tied to a recent heartbeat (delayed or replayed?)"}
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

    # ------------------------------------------------------------------
    # Read probes -- separate from execution; see reads.py
    # ------------------------------------------------------------------
    def _check_read_request(self, msg: dict[str, Any]) -> str | None:
        """Every gate, fail-closed, in order. Returns a refusal reason or None.
        The signature is checked before anything that changes state, so an
        unsigned message can't move the replay floor."""
        if not self.token:
            return "not paired"
        why_not = self._transport_why_not()
        if why_not is not None:
            return (f"{why_not} -- this channel has no encryption of its own, so investigation reads are "
                    "refused on it. "
                    "Reach Kratos over Tailscale/WireGuard, or reinstall the agent with "
                    "--allow-untrusted-transport if this network is trusted")
        request_id, probe, params, seq = msg.get("request_id"), msg.get("probe"), msg.get("params"), msg.get("seq")
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            return "malformed request_id"
        if not isinstance(probe, str) or not isinstance(params, dict) or type(seq) is not int:
            return "malformed read request (probe/params/seq types)"
        if not signing.verify_envelope(signing.derive_signing_key(self.token), msg):
            return "invalid signature"
        if msg.get("session_nonce") != self._session_nonce:
            return "read request is not for this connection (replay?)"
        if seq <= self._last_read_seq:
            return "read request is out of order or repeated (replay?)"
        self._last_read_seq = seq
        return None

    def _start_read(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        request_id = msg.get("request_id") if isinstance(msg.get("request_id"), str) else ""
        reason = self._check_read_request(msg)
        if reason is None and len(self._read_tasks) > READ_QUEUE_MAX:
            reply = proto.build_read_result(request_id, "busy", reason="too many reads waiting on this agent")
        elif reason is not None:
            logger.warning("read_request refused: %s", reason)
            reply = proto.build_read_result(request_id, "refused", reason=reason)
        else:
            task = asyncio.ensure_future(self._serve_read(msg, writer))
            self._read_tasks.add(task)
            task.add_done_callback(self._read_tasks.discard)
            return
        task = asyncio.ensure_future(self._send_read_reply(writer, reply))
        self._read_tasks.add(task)
        task.add_done_callback(self._read_tasks.discard)

    async def _serve_read(self, msg: dict[str, Any], writer: asyncio.StreamWriter) -> None:
        request_id, probe = msg["request_id"], msg["probe"]
        lock = self._read_lock or asyncio.Lock()
        async with lock:
            loop = asyncio.get_event_loop()
            started = time.monotonic()
            try:
                body = await loop.run_in_executor(None, reads.run_probe, probe, msg["params"])
            except Exception as e:  # noqa: BLE001 -- run_probe never raises; belt and braces
                body = {"status": "error", "reason": f"{type(e).__name__}"}
        logger.info("read %s: probe=%s status=%s (%.1fs)", request_id, probe, body.get("status"),
                    time.monotonic() - started)
        await self._send_read_reply(writer, proto.build_read_result(
            request_id, body["status"], reason=body.get("reason"), data=body.get("data"),
            available=body.get("available")))

    async def _send_read_reply(self, writer: asyncio.StreamWriter, reply: dict[str, Any]) -> None:
        try:
            await proto.write_frame(writer, reply)
        except proto.FrameTooLargeError:
            await proto.write_frame(writer, proto.build_read_result(
                reply["request_id"], "error", reason="the result was too large to send -- narrow the request"))
        except (OSError, ConnectionError):
            pass  # the connection is going away; the receive loop handles that

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
    p.add_argument("--core-host", default=None, help="Kratos core's reachable address (required to run)")
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
            "Allow execution and investigation reads even when core is not reached over loopback or "
            "Tailscale. The channel has no "
            "encryption of its own, so on a shared network the pairing token (and with it the signing key) "
            "can be sniffed. Leave off unless the network itself is trusted."
        ),
    )
    p.add_argument(
        "--trusted-interface", dest="trusted_interfaces", action="append", default=[], metavar="NAME",
        help=("A network interface that encrypts traffic by itself (e.g. your own WireGuard tunnel wg0, or a "
              "Tailscale TUN with a custom name). Core reached over it counts as a trusted transport. "
              "Repeatable. Interfaces named tailscale* are recognised without this."),
    )
    p.add_argument(
        "--local-allow-file", default=cl.LOCAL_ALLOW_FILE,
        help="Exact commands this target's admin allows Kratos to run, one per line (default: %(default)s).",
    )
    p.add_argument(
        "--reset-whitelist-floor", action="store_true", default=False,
        help=("Forget the newest whitelist version this machine has applied, then exit. Use when Kratos "
              "reports this machine refuses its pushes as too old; stop the agent first."),
    )
    return p


def _instance_lock_path(state_file: Path) -> Path:
    return state_file.with_name(state_file.name + ".lock")


def _try_instance_lock(state_file: Path) -> Any | None:
    """Take the one-agent-per-state-file lock without waiting. Returns the
    open lock file (keep it open to hold the lock), or None if another agent
    holds it. Two agents on one state file would share an identity and
    overwrite each other's state; the reset below must not race a live one."""
    if fcntl is None:
        return open(os.devnull)  # nothing to lock with; behave as before
    path = _instance_lock_path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT, _STATE_MODE), "r+")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def _acquire_instance_lock(state_file: Path, wait_seconds: float) -> Any | None:
    # A restart (or the installer's stop-then-start) can briefly overlap the
    # old process's exit, so wait a little before giving up.
    deadline = time.monotonic() + wait_seconds
    while True:
        lock = _try_instance_lock(state_file)
        if lock is not None or time.monotonic() >= deadline:
            return lock
        time.sleep(0.5)


def reset_whitelist_floor(state_file: Path) -> int:
    """Forget the newest whitelist version this machine has applied, so Kratos
    can push from its own count again. For when Kratos's database was restored
    from an older copy, or something holding this pairing pushed a version
    Kratos will never reach. Run by the target's admin with the agent stopped;
    refuses while it runs (it would write the old value straight back)."""
    lock = _try_instance_lock(state_file)
    if lock is None:
        print("The agent is running with this state file -- stop it first, then run this again.", file=sys.stderr)
        return 2
    try:
        state = _load_state(state_file)
        floors = state.pop("whitelist_version_floor", None)
        if not floors:
            print(f"Nothing to reset: {state_file} has no whitelist version recorded.")
            return 0
        _save_state(state_file, state)
        print(f"Cleared the recorded whitelist version in {state_file}. Start the agent again; "
              "Kratos will push its current allowlist when it reconnects.")
        return 0
    finally:
        lock.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.reset_whitelist_floor:
        return reset_whitelist_floor(args.state_file)
    if not args.core_host:
        parser.error("--core-host is required")
    instance_lock = _acquire_instance_lock(args.state_file, INSTANCE_LOCK_WAIT_SECONDS)
    if instance_lock is None:
        logger.error("another agent is already running with %s -- not starting a second one", args.state_file)
        return 1

    agent = SubAgent(
        core_host=args.core_host,
        core_port=args.core_port,
        state_file=args.state_file,
        pairing_code=args.pairing_code,
        collect_interval=args.collect_interval,
        ping_interval=args.ping_interval,
        execution_enabled=args.execution_enabled,
        allow_untrusted_transport=args.allow_untrusted_transport,
        trusted_interfaces=args.trusted_interfaces,
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
        instance_lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
