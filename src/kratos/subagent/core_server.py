"""
Kratos-core-side sub-agent telemetry server -- capability 1 ONLY (continuous,
read-only telemetry; docs/subagent_architecture.md).

Accepts OUTBOUND connections from paired sub-agents (the agent dials out and
holds the connection open; core never dials the agent -- see the design
doc's "Transport and connection direction" section) and:
  (a) authenticates each connection via the app-level pairing token/code,
      independent of the network layer;
  (b) receives a continuous stream of read-only telemetry snapshots and
      persists them (kratos.storage.subagent_store);
  (c) tracks per-target liveness from real connection state plus a
      keepalive ping, not guesswork.

This module cannot send a command TO an agent -- there is no message type,
method, or code path anywhere here that originates a request to the far end
beyond a telemetry_ack/pong reply to something the agent itself sent.
Capability 2 (direct execution) is separate, gated on an independently
reviewed whitelist, and not implemented here or anywhere else in the
codebase.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import protocol as proto
from kratos.subagent.status import derive_status

logger = logging.getLogger("kratos.subagent.core_server")

DEFAULT_PORT = 8765
# No ping/telemetry at all within this long on an open socket -> treat the
# connection as dead and close it (the agent's own reconnect loop then takes
# over) rather than holding a silently-broken socket open forever.
PING_TIMEOUT_SECONDS = 30
HELLO_TIMEOUT_SECONDS = 10


class CoreServer:
    def __init__(self, store: SubAgentStore, host: str = "0.0.0.0", port: int = DEFAULT_PORT) -> None:
        self.store = store
        self.host = host
        self.port = port
        # target_id -> writer, for real live-connection status -- ground
        # truth ONLY within this running process (a separate CLI query has
        # no visibility into this and falls back to last_seen recency, see
        # status.py).
        self._live: dict[str, asyncio.StreamWriter] = {}
        self._server: asyncio.AbstractServer | None = None

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
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for writer in list(self._live.values()):
            writer.close()

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
            await self._receive_loop(reader, writer, target_id)
        except (asyncio.TimeoutError, proto.ProtocolError, ConnectionError, OSError) as e:
            logger.info("connection from %s (target=%s) ended: %s", peer, target_id, e)
        finally:
            if target_id is not None and self._live.get(target_id) is writer:
                del self._live[target_id]
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
            else:
                logger.warning("ignoring unexpected message type %r from target %s", mtype, target_id)
