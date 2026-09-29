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
"""
from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1024 * 1024  # 1 MiB -- generous for one telemetry snapshot, bounded against abuse.
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
MSG_EXEC_DISPATCH = "exec_dispatch"
MSG_EXEC_RESULT = "exec_result"


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
