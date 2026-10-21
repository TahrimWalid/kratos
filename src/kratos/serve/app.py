"""`kratos serve` -- the chat-client server (docs/phaseB/B.3).

Two doors on one local HTTP server:

* the OpenAI-compatible door (`/v1/models`, `/v1/chat/completions`): a chat client adds
  Kratos as a connection and picks a model named after a machine (`kratos/web-01`); the
  reply is Kratos's CHECKED answer, never the model's raw draft;
* MCP over Streamable HTTP (`/mcp`): an agent host starts an investigation and polls it.

Every request passes one gate (`KratosGate`, pure ASGI so streaming is untouched), in
this order: the Host header must be one this server answers to (DNS-rebinding defence --
a web page on another site can't reach a localhost server through a name it controls),
any Origin header is refused unless allowed (no browser talks to this server directly),
the body must be small, and the bearer token must be a live Kratos client token. A source
that keeps presenting wrong tokens is throttled. No CORS headers, no cookies, no pages.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from kratos.serve import auth as _auth
from kratos.serve import settings as _settings  # noqa: F401 -- registers serve.* settings
from kratos.serve import store as _store

logger = logging.getLogger(__name__)

_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")


def _json_error(status: int, message: str, *, kind: str, code: str | None = None) -> tuple[int, bytes]:
    body = {"error": {"message": message, "type": kind, "param": None, "code": code}}
    return status, json.dumps(body).encode("utf-8")


class ServeState:
    """Everything one server process shares between requests -- built once at startup."""

    def __init__(self, data_dir: Path, *, bind_host: str, port: int) -> None:
        from kratos.serve.runs import RunSlots
        from kratos.subagent.core_server import AuthFailureLimiter

        self.data_dir = Path(data_dir)
        self.bind_host = bind_host
        self.port = int(port)
        self.slots = RunSlots(self.data_dir)
        self.limiter = AuthFailureLimiter()
        self.started_at = time.time()
        self._verified: dict[str, tuple[str, float]] = {}   # sha256(token) -> (token_id, when)
        self.investigations: Any = None                      # mcp_http.Investigations, set by create_app
        self._metered_lock = threading.Lock()
        self._in_flight: dict[str, int] = {}                 # token id -> metered requests not yet audited

    def reserve_metered(self, token_id: str, limit: int) -> bool:
        """Take one of this token's hourly model-using requests, or False when the hour's
        limit is used. Counts the audit log's metered rows AND the requests of this process
        still running (their row is written when they end), under one lock -- so requests
        arriving together can't all pass the same check. Pair with release_metered."""
        since = time.time() - 3600
        with self._metered_lock:
            used = _store.metered_requests_since(self.data_dir, token_id, since) + self._in_flight.get(token_id, 0)
            if used >= limit:
                return False
            self._in_flight[token_id] = self._in_flight.get(token_id, 0) + 1
            return True

    def release_metered(self, token_id: str) -> None:
        """The request's metered audit row is written (or it never used the model)."""
        with self._metered_lock:
            left = self._in_flight.get(token_id, 0) - 1
            if left > 0:
                self._in_flight[token_id] = left
            else:
                self._in_flight.pop(token_id, None)

    def note_runs(self, *, running: bool = True) -> None:
        """Refresh the status file (`kratos serve status`, /doctor read it)."""
        from kratos.serve import status as _status

        _status.write(self.data_dir, running=running, host=self.bind_host, port=self.port,
                      started_at=self.started_at, active=self.slots.active, waiting=self.slots.waiting)

    # -- hosts
    def allowed_hosts(self) -> set[str]:
        from kratos import settings_store

        names = set(_LOOPBACK_NAMES) | {self.bind_host.lower(), f"[{self.bind_host.lower()}]"}
        out = {n for n in names} | {f"{n}:{self.port}" for n in names}
        try:
            extra = settings_store.get(_settings.ALLOWED_HOSTS, data_dir=self.data_dir) or []
        except Exception:  # noqa: BLE001
            extra = []
        out |= {str(h).lower() for h in extra}
        return out

    # -- tokens
    def verify(self, presented: str | None) -> _auth.Client | None:
        """Verify a bearer token. The scrypt check runs once per token per process; later
        requests re-read the row (so a revoke applies on the next request) and compare a
        SHA-256 of the presented token in constant time."""
        import hashlib
        import hmac

        if not presented:
            return None
        digest = hashlib.sha256(presented.encode("utf-8", "replace")).hexdigest()
        hit = None
        for known, (token_id, _when) in list(self._verified.items()):
            if hmac.compare_digest(known, digest):
                hit = token_id
        if hit is not None:
            row = _store.get_token(self.data_dir, hit)
            if row is None or row.get("revoked_at"):
                self._verified.pop(digest, None)
                return None
            return _auth.Client(token_id=hit, name=row["name"], targets=tuple(row["targets"]),
                                doors=tuple(d for d in row["doors"] if d in _auth.DOORS))
        client = _auth.verify(self.data_dir, presented)
        if client is not None:
            if len(self._verified) > 256:
                self._verified.clear()
            self._verified[digest] = (client.token_id, time.time())
        return client


class KratosGate:
    """Host/Origin check, body-size limit and bearer-token auth for every request."""

    def __init__(self, app: Any, state: ServeState) -> None:
        self.app = app
        self.state = state

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self._respond(send, *_json_error(404, "not found", kind="invalid_request_error"))
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        path = scope.get("path") or ""
        door = "mcp" if path == "/mcp" or path.startswith("/mcp/") else "openai"
        peer = (scope.get("client") or ("", 0))[0] or ""
        host = headers.get("host", "").strip().lower()
        if host not in self.state.allowed_hosts():
            await self._refuse(send, 421, "this server does not answer to that host name", door, path, peer,
                               "host header not allowed")
            return
        if "origin" in headers:
            await self._refuse(send, 403, "requests from a web page are not accepted", door, path, peer,
                               "origin header present")
            return
        limit = self._max_body()
        try:
            if int(headers.get("content-length") or 0) > limit:
                await self._refuse(send, 413, "the request is too large", door, path, peer, "body too large")
                return
        except ValueError:
            await self._refuse(send, 400, "bad content-length", door, path, peer, "bad content-length")
            return
        if self.state.limiter.source_blocked(peer):
            await self._refuse(send, 429, "too many failed attempts from this address; try again later",
                               door, path, peer, "auth throttled", kind="rate_limit_exceeded")
            return
        presented = _auth.bearer_from(headers.get("authorization"))
        client = await asyncio.to_thread(self.state.verify, presented)
        if client is None:
            self.state.limiter.note_failure(peer)
            await self._refuse(send, 401, "a valid Kratos token is needed (kratos serve token create)", door, path,
                               peer, "no or wrong token", status_word="unauthorized", kind="invalid_request_error",
                               code="invalid_api_key", extra_headers=[(b"www-authenticate", b"Bearer")])
            return
        if not client.may_use(door):
            await self._refuse(send, 403, f"this token may not use the {door} door", door, path, peer,
                               "door not allowed for token", token_id=client.token_id)
            return
        scope.setdefault("state", {})
        scope["state"]["kratos_client"] = client
        scope["kratos.client"] = client
        if door != "mcp":
            await self.app(scope, self._limited(receive, limit), send)   # the OpenAI routes audit themselves
            return
        # MCP: one audit row per request, written when the response has gone out.
        started, seen = time.monotonic(), {"status": 500, "bytes": 0}

        async def counting_send(message: dict) -> None:
            if message.get("type") == "http.response.start":
                seen["status"] = int(message.get("status") or 500)
            elif message.get("type") == "http.response.body":
                seen["bytes"] += len(message.get("body") or b"")
            await send(message)

        try:
            await self.app(scope, self._limited(receive, limit), counting_send)
        finally:
            word = "ok" if seen["status"] < 400 else ("refused" if seen["status"] < 500 else "error")
            try:
                await asyncio.to_thread(_store.audit, self.state.data_dir, door="mcp", endpoint=path, status=word,
                                        token_id=client.token_id, client_addr=peer,
                                        duration=time.monotonic() - started, bytes_out=seen["bytes"])
            except Exception:  # noqa: BLE001
                logger.debug("serve: audit failed", exc_info=True)

    def _max_body(self) -> int:
        from kratos import settings_store

        try:
            return int(settings_store.get(_settings.MAX_BODY_BYTES, data_dir=self.state.data_dir))
        except Exception:  # noqa: BLE001
            return 1_000_000

    @staticmethod
    def _limited(receive: Any, limit: int) -> Any:
        seen = 0

        async def wrapped() -> dict:
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body") or b"")
                if seen > limit:
                    raise _BodyTooLarge()
            return message

        return wrapped

    async def _refuse(self, send: Any, status: int, message: str, door: str, path: str, peer: str, detail: str,
                      *, status_word: str = "refused", kind: str = "invalid_request_error", code: str | None = None,
                      token_id: str | None = None, extra_headers: list | None = None) -> None:
        _status, body = _json_error(status, message, kind=kind, code=code)
        try:
            await asyncio.to_thread(_store.audit, self.state.data_dir, door=door, endpoint=path, status=status_word,
                                    token_id=token_id, client_addr=peer, detail=detail, bytes_out=len(body))
        except Exception:  # noqa: BLE001 -- an audit write never changes the answer
            logger.debug("serve: audit failed", exc_info=True)
        await self._respond(send, status, body, extra_headers=extra_headers)

    @staticmethod
    async def _respond(send: Any, status: int, body: bytes, *, extra_headers: list | None = None) -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())] + list(extra_headers or [])})
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass


def create_app(data_dir: Path, *, bind_host: str = "127.0.0.1", port: int = 8770) -> Any:
    """The ASGI app: the gate around one Starlette app holding the OpenAI routes and the
    MCP endpoint."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse

    from kratos.serve import mcp_http, openai_routes

    state = ServeState(data_dir, bind_host=bind_host, port=port)
    mcp_app, session_manager = mcp_http.build(state)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Any):
        state.note_runs(running=True)
        try:
            async with session_manager.run():
                yield
        finally:
            state.note_runs(running=False)

    async def too_large(request: Any, exc: Exception) -> Any:
        status, body = _json_error(413, "the request is too large", kind="invalid_request_error")
        return JSONResponse(json.loads(body), status_code=status)

    async def not_found(request: Any, exc: Exception) -> Any:
        status, body = _json_error(404, "not found", kind="invalid_request_error")
        return JSONResponse(json.loads(body), status_code=getattr(exc, "status_code", 404))

    api = Starlette(routes=openai_routes.routes(state) + list(mcp_app.routes), lifespan=lifespan,
                    exception_handlers={_BodyTooLarge: too_large, 404: not_found, 405: not_found})
    api.state.kratos = state
    return KratosGate(api, state)
