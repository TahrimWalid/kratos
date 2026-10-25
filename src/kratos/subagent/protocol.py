"""
Wire protocol for the Kratos sub-agent <-> core telemetry channel
(capability 1 -- docs/subagent_architecture.md).

Stdlib-only, no kratos-internal imports -- this module is deployed as a
sibling file alongside agent.py and collector.py directly onto a monitored
target and must run there with nothing but a system python3 (see agent.py's
module docstring). It is also imported normally as kratos.subagent.protocol
by the core-side server, which does not have that constraint -- one file,
both roles, so the two sides can never drift out of sync with each other.

Transport rules this protocol is built around (see the design doc's
"Transport and connection direction" section, added during capability 1's
build phase): the sub-agent dials OUT to core and holds the connection open;
core never dials the agent. This module has no opinion on who connects to
whom -- it only defines the framing and message shapes exchanged once a
connection exists.

Framing: each message is a 4-byte big-endian length prefix followed by that
many bytes of UTF-8 JSON. MAX_FRAME_BYTES bounds how much a single frame can
claim to be, so a corrupt or hostile peer can't exhaust memory by sending a
huge length prefix.

Message shapes (every message has a "type" field):
  hello              {type, version, agent_id, auth: {token} | {pairing_code},
                      hostname, agent_version, session_nonce?, ceiling?,
                      collect_interval?, ping_interval?}
  hello_ack          {type, target_id, token}
  hello_reject       {type, reason}
  telemetry          {type, seq, collected_at, payload}
  telemetry_ack      {type, seq}
  ping               {type, ts}
  pong               {type, ts, session_nonce?, sig?}  -- echoes the ping's ts;
                      signed when the agent sent a session_nonce (only a
                      verified pong arms the agent's dead-man's switch)

Capability 2 (direct execution) messages -- see kratos.subagent.signing for
the HMAC envelope these carry, kratos.subagent.whitelist for the ActionSpec
shape serialized in `actions`, and core_server.py/agent.py's own module
docstrings for the fail-closed/dead-man's-switch/anti-rollback behavior
built around them (design doc §9 #4/#5). Building this channel does NOT
enable execution against any real target -- see agent.py's own
`execution_enabled` flag, which defaults OFF and is the one thing that must
be explicitly, locally set on the target for a dispatch to ever actually run.
  whitelist_push      {type, version, actions: [ActionSpec-as-dict, ...], sig}
  whitelist_push_ack  {type, version, rejected: [{id, reason}], ceiling}
  exec_dispatch       {type, dispatch_id, action_id, slot_values,
                       whitelist_version, session_nonce, sig}

`session_nonce` is fresh random per agent connection; the agent refuses any
signed dispatch/pong that doesn't carry the current one, so a captured
message can't be replayed on a later connection (and dispatch ids are
de-duplicated within one). `ceiling` describes the agent's own execution
ceiling (kratos.subagent.ceiling): {version, fingerprint, local_commands,
local_problems} -- what this target will actually run, reported so core can
show it, never something core can change.
  exec_result         {type, dispatch_id, status: "ok"|"refused"|"error",
                       reason, exit_code, stdout_tail, stderr_tail, ts}

Read probes (docs/subagent_read_routing.md) -- separate from execution, never
gated by it, never able to change state. Core names a probe from the agent's
closed set (kratos.subagent.reads) and passes parameters the agent validates;
no command text crosses the wire. Signed like a dispatch, bound to the
connection's session_nonce, and `seq` must strictly increase per connection
(core sends one read at a time), so a captured request can't be replayed.
  read_request        {type, request_id, probe, params, seq, session_nonce, sig}
  read_result         {type, request_id, status: "ok"|"refused"|"unsupported"|
                       "not_installed"|"timed_out"|"error"|"busy", reason?, data?}
A hello from an agent that serves reads adds `read_api` (int) and
`read_probes` (the names it has).

Encrypted link (Phase C.4): the framing above is unchanged; an agent that holds
server-key pins speaks it inside TLS and writes nothing before the server's key
matched a pin (kratos.subagent.pinning). Its hello adds `link`
("tls-pinned" | "plaintext"), `pin_version` (the pin set it holds) and, after
it refused a server whose key didn't match, `link_alerts` {count, first_at,
last_at, seen_key} (reported on the next good connection -- it can't be sent to
the server it refused). Core may then replace the pin set over that pinned link:
  pin_set_push        {type, version, pins: [hex sha256, ...], session_nonce, sig}
  pin_set_ack         {type, version, status: "ok"|"refused", reason?}
The agent accepts a push only over a pinned TLS link, signed for this
connection's session nonce, with a version newer than the one it holds (equal
and identical is acknowledged), and never an empty set.

Continuous detection (Phase C.2, kratos.subagent.watch). A hello from an agent
that can watch adds `watch_api` (int) and `watch` {enabled, version, packs:
[{pack_id, pack_version, sha256}]}. Core pushes the rule packs as signed,
versioned DATA -- rules in the evaluator's closed format, never code:
  detect_pack_push    {type, version, enabled, machine, packs: [pack, ...],
                       disabled: [rule id, ...], settings: {...}, session_nonce, sig}
  detect_pack_ack     {type, version, status: "ok"|"refused", reason?, packs?}
Turning watching on is accepted only over a trusted link (pinned TLS, or the
older trusted-transport rule) -- matched log content crosses it. A push with a
lower `version` than the agent has applied is refused (anti-rollback, kept across
restarts); a pack is validated whole and refused whole.
The agent sends what it matched, and acknowledged detections leave its spool:
  detection           {type, seq, rule_id, pack_id, pack_version, ts, first_ts,
                       detected_at, sent_at (the agent's clock), source, position,
                       event: {bounded ECS fields}, group?,
                       count?, event_ids?}   -- or, past the per-rule rate limit,
                      {..., summary: {suppressed, minute}} instead of an event
  detection_ack       {type, seqs: [int, ...]}
  watch_status        {type, enabled, watch_since, sources: [{name, state, since,
                       last_event_ts, events_per_min, matches, lag_seconds,
                       dropped, skipped, gaps, error}], packs, spooled, queued,
                       cpu_seconds, throttled_seconds, rss, seq}
"""
from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

PROTOCOL_VERSION = 1
# 8 MiB: a read result (e.g. a few thousand journal entries) is capped on the
# agent at 4 MiB of output, which JSON-escaping can grow; still bounded.
MAX_FRAME_BYTES = 8 * 1024 * 1024
_LENGTH = struct.Struct(">I")

MSG_HELLO = "hello"
MSG_HELLO_ACK = "hello_ack"
MSG_HELLO_REJECT = "hello_reject"
MSG_TELEMETRY = "telemetry"
MSG_TELEMETRY_ACK = "telemetry_ack"
MSG_PING = "ping"
MSG_PONG = "pong"

MSG_WHITELIST_PUSH = "whitelist_push"
MSG_WHITELIST_PUSH_ACK = "whitelist_push_ack"
MSG_WHITELIST_PUSH_REFUSED = "whitelist_push_refused"
MSG_EXEC_DISPATCH = "exec_dispatch"
MSG_EXEC_RESULT = "exec_result"
MSG_READ_REQUEST = "read_request"
MSG_READ_RESULT = "read_result"
MSG_PIN_SET_PUSH = "pin_set_push"
MSG_PIN_SET_ACK = "pin_set_ack"
MSG_DETECT_PACK_PUSH = "detect_pack_push"
MSG_DETECT_PACK_ACK = "detect_pack_ack"
MSG_DETECTION = "detection"
MSG_DETECTION_ACK = "detection_ack"
MSG_WATCH_STATUS = "watch_status"
# Bounds on what an agent may send about watching (core refuses anything bigger).
MAX_DETECTION_ACK_SEQS = 1000
MAX_DETECT_PUSH_VERSION = 2**31 - 1

# The two first bytes the listener tells apart without consuming them: a TLS
# record starts with its content type (22 = handshake), a Kratos frame with the
# high byte of its length, which MAX_FRAME_BYTES (8 MiB < 16 MiB) keeps at 0.
TLS_HANDSHAKE_FIRST_BYTE = 0x16
PLAIN_FRAME_FIRST_BYTE = 0x00

# Whitelist versions are counted up by core from 1. Bounded so that one push
# can't set the agent's persisted anti-rollback floor to a number core never
# reaches (review v2 F-3); far above any real count of edits.
MAX_WHITELIST_VERSION = 2**31 - 1


class ProtocolError(ValueError):
    """The peer sent something that doesn't parse as a valid frame/message."""


class FrameTooLargeError(ProtocolError):
    """A frame's declared or actual size exceeds MAX_FRAME_BYTES."""


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------
def encode_frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FrameTooLargeError(f"encoded frame is {len(body)} bytes, over the {MAX_FRAME_BYTES}-byte limit")
    return _LENGTH.pack(len(body)) + body


async def write_frame(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    writer.write(encode_frame(message))
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read one length-prefixed JSON frame. Returns None on a clean EOF that
    lands exactly on a frame boundary (the peer closed deliberately, not
    mid-message) -- callers treat that as "connection ended", not an error."""
    try:
        header = await reader.readexactly(_LENGTH.size)
    except asyncio.IncompleteReadError as e:
        if e.partial == b"":
            return None
        raise ProtocolError(f"connection closed mid-frame-header ({len(e.partial)} of {_LENGTH.size} bytes)") from e
    (length,) = _LENGTH.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise FrameTooLargeError(f"peer declared a {length}-byte frame, over the {MAX_FRAME_BYTES}-byte limit")
    if length == 0:
        raise ProtocolError("zero-length frame")
    try:
        body = await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise ProtocolError(f"connection closed mid-frame-body ({len(e.partial)} of {length} bytes)") from e
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"malformed frame body: {e}") from e
    if not isinstance(parsed, dict) or "type" not in parsed:
        raise ProtocolError("frame body is not a JSON object with a 'type' field")
    return parsed


# ---------------------------------------------------------------------------
# Message builders -- both sides use these so the shape is defined exactly
# once, not re-typed (and potentially drifted) at every call site.
# ---------------------------------------------------------------------------
def build_hello(
    agent_id: str, auth: dict[str, str], hostname: str, agent_version: str,
    session_nonce: str | None = None, ceiling: dict[str, Any] | None = None,
    collect_interval: float | None = None, ping_interval: float | None = None,
    read_probes: list[str] | tuple[str, ...] | None = None, read_api: int = 1,
    link: str | None = None, pin_version: int | None = None,
    link_alerts: dict[str, Any] | None = None,
    watch: dict[str, Any] | None = None, watch_api: int = 1,
) -> dict[str, Any]:
    msg = {
        "type": MSG_HELLO,
        "version": PROTOCOL_VERSION,
        "agent_id": agent_id,
        "auth": auth,
        "hostname": hostname,
        "agent_version": agent_version,
    }
    if session_nonce is not None:
        msg["session_nonce"] = session_nonce
    if ceiling is not None:
        msg["ceiling"] = ceiling
    # How often this agent sends snapshots/pings, so core can tell "quiet on
    # schedule" from "stalled" without guessing.
    if collect_interval is not None:
        msg["collect_interval"] = collect_interval
    if ping_interval is not None:
        msg["ping_interval"] = ping_interval
    if read_probes is not None:
        msg["read_api"] = read_api
        msg["read_probes"] = list(read_probes)
    if link is not None:
        msg["link"] = link
    if pin_version is not None:
        msg["pin_version"] = pin_version
    if link_alerts:
        msg["link_alerts"] = link_alerts
    if watch is not None:
        msg["watch_api"] = watch_api
        msg["watch"] = watch
    return msg


def build_hello_ack(target_id: str, token: str) -> dict[str, Any]:
    return {"type": MSG_HELLO_ACK, "target_id": target_id, "token": token}


def build_hello_reject(reason: str) -> dict[str, Any]:
    return {"type": MSG_HELLO_REJECT, "reason": reason}


def build_telemetry(seq: int, collected_at: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"type": MSG_TELEMETRY, "seq": seq, "collected_at": collected_at, "payload": payload}


def build_telemetry_ack(seq: int) -> dict[str, Any]:
    return {"type": MSG_TELEMETRY_ACK, "seq": seq}


def build_ping(ts: float) -> dict[str, Any]:
    return {"type": MSG_PING, "ts": ts}


def build_pong(ts: float) -> dict[str, Any]:
    return {"type": MSG_PONG, "ts": ts}


def build_whitelist_push(version: int, actions: list[dict[str, Any]], sig: str) -> dict[str, Any]:
    return {"type": MSG_WHITELIST_PUSH, "version": version, "actions": actions, "sig": sig}


def build_whitelist_push_ack(
    version: int, rejected: list[dict[str, str]] | None = None, ceiling: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {"type": MSG_WHITELIST_PUSH_ACK, "version": version, "rejected": rejected or [], "ceiling": ceiling}


def build_whitelist_push_refused(version: int | None, reason: str, floor: int | None) -> dict[str, Any]:
    """The agent refused a whole push (too old, out of range, malformed). Sent
    instead of silence so core stops re-pushing and can show why; `floor` is
    the newest version the agent has already applied under this pairing."""
    return {"type": MSG_WHITELIST_PUSH_REFUSED, "version": version, "reason": reason, "floor": floor}


def build_exec_dispatch(
    dispatch_id: str, action_id: str, slot_values: dict[str, Any], whitelist_version: int,
    session_nonce: str, sig: str,
) -> dict[str, Any]:
    return {
        "type": MSG_EXEC_DISPATCH,
        "dispatch_id": dispatch_id,
        "action_id": action_id,
        "slot_values": slot_values,
        "whitelist_version": whitelist_version,
        "session_nonce": session_nonce,
        "sig": sig,
    }


def build_exec_result(
    dispatch_id: str,
    status: str,
    *,
    reason: str | None = None,
    exit_code: int | None = None,
    stdout_tail: str = "",
    stderr_tail: str = "",
    ts: float | None = None,
) -> dict[str, Any]:
    return {
        "type": MSG_EXEC_RESULT,
        "dispatch_id": dispatch_id,
        "status": status,
        "reason": reason,
        "exit_code": exit_code,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "ts": ts,
    }


def build_read_request(request_id: str, probe: str, params: dict[str, Any], seq: int, session_nonce: str) -> dict[str, Any]:
    """Unsigned envelope -- the caller adds `sig` (signing.sign_envelope)."""
    return {"type": MSG_READ_REQUEST, "request_id": request_id, "probe": probe, "params": params,
            "seq": seq, "session_nonce": session_nonce}


def build_read_result(request_id: str, status: str, *, reason: str | None = None,
                      data: dict[str, Any] | None = None, available: list[str] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"type": MSG_READ_RESULT, "request_id": request_id, "status": status}
    if reason is not None:
        msg["reason"] = reason
    if data is not None:
        msg["data"] = data
    if available is not None:
        msg["available"] = available
    return msg


def build_pin_set_push(version: int, pins: list[str], session_nonce: str) -> dict[str, Any]:
    """Unsigned envelope -- the caller adds `sig` (signing.sign_envelope)."""
    return {"type": MSG_PIN_SET_PUSH, "version": version, "pins": list(pins), "session_nonce": session_nonce}


def build_pin_set_ack(version: Any, status: str, reason: str | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"type": MSG_PIN_SET_ACK, "version": version, "status": status}
    if reason is not None:
        msg["reason"] = reason
    return msg


def build_detect_pack_push(version: int, enabled: bool, machine: str, packs: list[dict[str, Any]],
                           disabled: list[str], settings: dict[str, Any], session_nonce: str) -> dict[str, Any]:
    """Unsigned envelope -- the caller adds `sig` (signing.sign_envelope)."""
    return {"type": MSG_DETECT_PACK_PUSH, "version": version, "enabled": enabled, "machine": machine,
            "packs": packs, "disabled": list(disabled), "settings": dict(settings), "session_nonce": session_nonce}


def build_detect_pack_ack(version: Any, status: str, reason: str | None = None,
                          packs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"type": MSG_DETECT_PACK_ACK, "version": version, "status": status}
    if reason is not None:
        msg["reason"] = reason
    if packs is not None:
        msg["packs"] = packs
    return msg


def build_detection_ack(seqs: list[int]) -> dict[str, Any]:
    return {"type": MSG_DETECTION_ACK, "seqs": list(seqs)}


# ---------------------------------------------------------------------------
# Blocking framing, for the local socket between an investigating process and
# the listener (kratos.subagent.local_reads). Same frame format.
# ---------------------------------------------------------------------------
def _recv_exactly(sock: Any, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            if not buf:
                raise EOFError("peer closed the connection")
            raise ProtocolError(f"connection closed mid-frame ({len(buf)} of {n} bytes)")
        buf += chunk
    return bytes(buf)


def send_frame_sync(sock: Any, message: dict[str, Any]) -> None:
    sock.sendall(encode_frame(message))


def recv_frame_sync(sock: Any) -> dict[str, Any]:
    (length,) = _LENGTH.unpack(_recv_exactly(sock, _LENGTH.size))
    if length > MAX_FRAME_BYTES:
        raise FrameTooLargeError(f"peer declared a {length}-byte frame, over the {MAX_FRAME_BYTES}-byte limit")
    if length == 0:
        raise ProtocolError("zero-length frame")
    body = _recv_exactly(sock, length)
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"malformed frame body: {e}") from e
    if not isinstance(parsed, dict) or "type" not in parsed:
        raise ProtocolError("frame body is not a JSON object with a 'type' field")
    return parsed
