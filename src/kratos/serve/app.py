"""`kratos serve` -- the chat-client server (docs/phaseB/B.3).

Two doors on one local HTTP server:

* the OpenAI-compatible door (`/v1/models`, `/v1/chat/completions`): a chat client adds
  Kratos as a connection and picks a model named after a machine (`kratos/web-01`); the
  reply is Kratos's CHECKED answer, never the model's raw draft;
* MCP over Streamable HTTP (`/mcp`): an agent host starts an investigation and polls it;
* the agent doors (E.5, off until a person turns them on): A2A 1.0 (`/.well-known/agent-card.json`,
  `/a2a/v1/...`) for another agent delegating a task, and AG-UI (`/ag-ui/run`) for an agent
  front end -- person tokens with the `agents` door only, never a shared gateway token.

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
# Chat turns open at once (running + waiting for a slot): beyond this a new message is
# answered "busy" (429) instead of piling up threads. Each turn holds one thread of the
# server's own pool, never the shared pool request handling needs. A2A tasks and AG-UI
# runs take the same turns.
MAX_OPEN_TURNS = 16
# E.5: the agent doors and the token door they need; their requests are small.
AGENT_DOORS = ("a2a", "agui")
AGENT_MAX_BODY = 256 * 1024


def door_of(path: str) -> str:
    """Which door a request path belongs to."""
    from kratos.serve.a2a.card import API_PREFIX, WELL_KNOWN_PATH
    from kratos.serve.agui import PATH as AGUI_PATH

    if path == "/mcp" or path.startswith("/mcp/"):
        return "mcp"
    if path == WELL_KNOWN_PATH or path == API_PREFIX or path.startswith(API_PREFIX + "/"):
        return "a2a"
    if path == AGUI_PATH or path.startswith("/ag-ui/"):
        return "agui"
    return "openai"


def door_enabled(data_dir: Path, door: str) -> bool:
    if door not in AGENT_DOORS:
        return True
    from kratos import settings_store
    from kratos.serve.a2a import settings as AS

    try:
        return bool(settings_store.get(AS.A2A_ENABLED if door == "a2a" else AS.AGUI_ENABLED, data_dir=data_dir))
    except Exception:  # noqa: BLE001 -- a setting that can't be read keeps the door shut
        return False


def _public(door: str, path: str, method: str) -> bool:
    """The two A2A resources served without a token: the public card and the signing keys."""
    from kratos.serve.a2a.card import KEYS_PATH, WELL_KNOWN_PATH

    return door == "a2a" and method == "GET" and path in (WELL_KNOWN_PATH, KEYS_PATH)


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
        from concurrent.futures import ThreadPoolExecutor

        self.max_open_turns = MAX_OPEN_TURNS
        self.turn_pool = ThreadPoolExecutor(max_workers=MAX_OPEN_TURNS, thread_name_prefix="kratos-turn")
        self._turns_lock = threading.Lock()
        self._open_turns = 0
        self._handles: set[Any] = set()
        from kratos.serve.a2a.tasks import Tasks

        self.a2a_tasks = Tasks(self.data_dir)              # E.5: A2A tasks and AG-UI runs of this process
        self.a2a_open_lock = threading.Lock()

    # -- chat turns
    def open_turn(self) -> bool:
        """Admit one more chat turn, or False when MAX_OPEN_TURNS are already open."""
        with self._turns_lock:
            if self._open_turns >= self.max_open_turns:
                return False
            self._open_turns += 1
            return True

    def close_turn(self) -> None:
        with self._turns_lock:
            self._open_turns = max(0, self._open_turns - 1)

    @property
    def open_turns(self) -> int:
        return self._open_turns

    def track_turn(self, handle: Any) -> None:
        with self._turns_lock:
            self._handles.add(handle)

    def untrack_turn(self, handle: Any) -> None:
        with self._turns_lock:
            self._handles.discard(handle)

    def shutdown_turns(self, timeout: float = 10.0) -> int:
        """The server is stopping: tell every open chat turn to stop (its run ends before
        the next model call or tool dispatch) and wait for them, up to `timeout`. Returns
        how many were still open."""
        with self._turns_lock:
            handles = list(self._handles)
        for h in handles:
            h.stop.set()
        deadline = time.monotonic() + timeout
        while self._open_turns and time.monotonic() < deadline:
            time.sleep(0.1)
        self.turn_pool.shutdown(wait=False, cancel_futures=True)
        return self._open_turns

    @staticmethod
    def meter_key(token_id: str, user_id: str | None = None) -> str:
        """What the hourly limit counts against: the token -- and, for a shared gateway
        token, the person behind it (one person must not use up everyone's hour)."""
        return f"{token_id}/{user_id}" if user_id else token_id

    def reserve_metered(self, token_id: str, limit: int, user_id: str | None = None) -> bool:
        """Take one of this token's hourly model-using requests, or False when the hour's
        limit is used. Counts the audit log's metered rows AND the requests of this process
        still running (their row is written when they end), under one lock -- so requests
        arriving together can't all pass the same check. Pair with release_metered.
        `user_id`: count per person (gateway tokens)."""
        since = time.time() - 3600
        key = self.meter_key(token_id, user_id)
        with self._metered_lock:
            used = _store.metered_requests_since(self.data_dir, token_id, since, user_id) + self._in_flight.get(key, 0)
            if used >= limit:
                return False
            self._in_flight[key] = self._in_flight.get(key, 0) + 1
            return True

    def release_metered(self, token_id: str, user_id: str | None = None) -> None:
        """The request's metered audit row is written (or it never used the model)."""
        key = self.meter_key(token_id, user_id)
        with self._metered_lock:
            left = self._in_flight.get(key, 0) - 1
            if left > 0:
                self._in_flight[key] = left
            else:
                self._in_flight.pop(key, None)

    # -- who is calling (D.7)
    def resolve_actor(self, client: _auth.Client, headers: dict[str, str],
                      door: str = "openai") -> tuple[Any, str | None]:
        """(the Actor for this request, None) or (None, the plain reason it is refused).

        A person token is its user. A gateway token (a shared Open WebUI) carries no person
        itself: the person is Open WebUI's SIGNED forwarded identity (an HS256 JWT checked
        with the gateway's secret), mapped by the owner to a Kratos user. Unsigned
        X-OpenWebUI-User-* headers are never trusted. Disabled users, unknown users and
        expired tokens are refused (fail closed)."""
        from kratos import authz
        from kratos.authz import openwebui
        from kratos.authz import users as U
        from kratos.lifecycle.decide import Actor

        try:
            if client.kind == "gateway":
                secret = openwebui.read_secret(self.data_dir, client.token_id)
                try:
                    fwd = openwebui.verify(headers.get(openwebui.HEADER), secret or "")
                except openwebui.JWTError as e:
                    return None, f"{e} -- the shared Open WebUI must send a signed identity"
                m = U.mapping_for(self.data_dir, "openwebui", fwd.sub)
                if m is None:
                    who = fwd.email or fwd.name or fwd.sub
                    return None, (f"the Open WebUI user {who} is not a Kratos user -- ask the Kratos owner to add you "
                                  f"(kratos users map openwebui {fwd.sub} <user>)")
                actor = Actor(user=m.user_name, interface="serve", user_id=m.user_id,
                              credential=f"gateway:{client.token_id}+openwebui:{fwd.sub}")
            else:
                user = U.get(self.data_dir, client.user_id)
                if user is None:
                    return None, "this token's Kratos user no longer exists"
                # The door is part of the credential the audit trail shows (token:<id>+a2a).
                suffix = f"+{door}" if door in AGENT_DOORS else ""
                actor = Actor(user=user.name, interface="serve", user_id=user.user_id,
                              credential=f"token:{client.token_id}{suffix}")
            authz.principal_of(actor, data_dir=self.data_dir)
        except authz.Denied as e:
            return None, e.reason
        except Exception as e:  # noqa: BLE001 -- fail closed with the reason
            logger.warning("serve: could not resolve the caller", exc_info=True)
            return None, f"Kratos could not work out who is calling ({type(e).__name__})"
        return actor, None

    def note_runs(self, *, running: bool = True) -> None:
        """Refresh the status file (`kratos serve status`, /doctor read it)."""
        from kratos.serve import status as _status

        from kratos.utils.build_info import RUNNING_BUILD

        _status.write(self.data_dir, running=running, host=self.bind_host, port=self.port,
                      started_at=self.started_at, active=self.slots.active, waiting=self.slots.waiting,
                      build=RUNNING_BUILD)

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
    def live_token_id(self, presented: str | None) -> bool:
        """Whether a presented token NAMES a live (unrevoked) token -- a cheap row lookup,
        no secret check. Used only to let such a request past the failed-auth throttle;
        the secret is still checked in full afterwards."""
        m = _auth._TOKEN_RE.match(str(presented or "").strip())
        if not m:
            return False
        row = _store.get_token(self.data_dir, m.group(1))
        return bool(row) and not row.get("revoked_at")

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
            return _auth.client_from_row(row)
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
        door = door_of(path)
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
        if door in AGENT_DOORS and not await asyncio.to_thread(door_enabled, self.state.data_dir, door):
            # Off (the default): as if the door didn't exist -- no card, no route.
            await self._respond(send, *_json_error(404, "not found", kind="invalid_request_error"))
            return
        if _public(door, path, scope.get("method", "GET")):
            await self.app(scope, receive, send)
            return
        limit = self._max_body() if door not in AGENT_DOORS else min(self._max_body(), AGENT_MAX_BODY)
        try:
            if int(headers.get("content-length") or 0) > limit:
                await self._refuse(send, 413, "the request is too large", door, path, peer, "body too large")
                return
        except ValueError:
            await self._refuse(send, 400, "bad content-length", door, path, peer, "bad content-length")
            return
        presented = _auth.bearer_from(headers.get("authorization"))
        if self.state.limiter.source_blocked(peer) and not await asyncio.to_thread(self.state.live_token_id,
                                                                                    presented):
            # A throttled address is refused without the (slow) secret check -- unless the
            # token names a live token: behind a reverse proxy every client shares one
            # address, and a stranger's wrong tokens must not lock the owner out.
            await self._refuse(send, 429, "too many failed attempts from this address; try again later",
                               door, path, peer, "auth throttled", kind="rate_limit_exceeded")
            return
        client = await asyncio.to_thread(self.state.verify, presented)
        if client is None:
            self.state.limiter.note_failure(peer)
            await self._refuse(send, 401, "a valid Kratos token is needed (kratos serve token create)", door, path,
                               peer, "no or wrong token", status_word="unauthorized", kind="invalid_request_error",
                               code="invalid_api_key", extra_headers=[(b"www-authenticate", b"Bearer")])
            return
        if client.expired:
            await self._refuse(send, 401, client.expired_text + " -- ask the Kratos owner for a new one "
                               "(kratos tokens rotate)", door, path, peer, "token expired",
                               status_word="unauthorized", token_id=client.token_id, code="invalid_api_key",
                               authz_reason=client.expired_text, client=client)
            return
        if door in AGENT_DOORS and client.kind == "gateway":
            # A2A and AG-UI carry no signed per-person identity: a shared Open WebUI's token
            # would be every mapped person at once.
            why = "these doors take a person token -- a shared Open WebUI's gateway token can't be used here"
            await self._refuse(send, 403, why, door, path, peer, "gateway token on an agent door",
                               token_id=client.token_id, authz_reason=why, client=client)
            return
        token_door = "agents" if door in AGENT_DOORS else door
        if not client.may_use(token_door):
            hint = (" -- the owner makes one with: kratos tokens create --user <you> --agents"
                    if token_door == "agents" else "")
            await self._refuse(send, 403, f"this token may not use the {token_door} door{hint}", door, path, peer,
                               "door not allowed for token", token_id=client.token_id,
                               authz_reason=f"this token may not use the {token_door} door" if token_door == "agents"
                               else None, client=client)
            return
        actor, why = await asyncio.to_thread(self.state.resolve_actor, client, headers, door)
        if actor is None:
            if client.kind == "gateway" and door == "openai" and path == "/v1/models" and \
                    scope.get("method", "GET") == "GET":
                # A shared Open WebUI shows its LAST good model list to a user whose list
                # request failed (even an empty list) -- another person's machines. One
                # placeholder model stops that; choosing it is refused like everything else.
                await self._refuse(send, 200, why or "refused", door, path, peer, (why or "refused")[:200],
                                   token_id=client.token_id, authz_reason=why, client=client,
                                   body=_placeholder_models(self.state.started_at))
                return
            await self._refuse(send, 403, why or "refused", door, path, peer, (why or "refused")[:200],
                               token_id=client.token_id, authz_reason=why, client=client)
            return
        scope.setdefault("state", {})
        scope["state"]["kratos_client"] = client
        scope["kratos.client"] = client
        scope["kratos.actor"] = actor
        from kratos import authz

        if door == "openai":
            with authz.acting_as(actor):
                await self.app(scope, self._limited(receive, limit), send)   # the OpenAI routes audit themselves
            return
        # MCP and the agent doors: one audit row per request, written when the response has gone out.
        started, seen = time.monotonic(), {"status": 500, "bytes": 0}

        async def counting_send(message: dict) -> None:
            if message.get("type") == "http.response.start":
                seen["status"] = int(message.get("status") or 500)
            elif message.get("type") == "http.response.body":
                seen["bytes"] += len(message.get("body") or b"")
            await send(message)

        try:
            with authz.acting_as(actor):
                await self.app(scope, self._limited(receive, limit), counting_send)
        finally:
            word = "ok" if seen["status"] < 400 else ("refused" if seen["status"] < 500 else "error")
            try:
                await asyncio.to_thread(_store.audit, self.state.data_dir, door=door, endpoint=path, status=word,
                                        token_id=client.token_id, client_addr=peer, user_id=actor.user_id,
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
                      token_id: str | None = None, extra_headers: list | None = None,
                      authz_reason: str | None = None, client: Any = None, body: bytes | None = None) -> None:
        if body is None:
            _status, body = _json_error(status, message, kind=kind, code=code)
        try:
            await asyncio.to_thread(_store.audit, self.state.data_dir, door=door, endpoint=path, status=status_word,
                                    token_id=token_id, client_addr=peer, detail=detail, bytes_out=len(body))
        except Exception:  # noqa: BLE001 -- an audit write never changes the answer
            logger.debug("serve: audit failed", exc_info=True)
        if authz_reason is not None:
            # A token that verified but whose person is refused (expired, unmapped, disabled,
            # unsigned identity): the one audit trail records it with the credential.
            from kratos.authz import audit as _aa

            cred = (f"gateway:{token_id}" if getattr(client, "kind", "") == "gateway" else f"token:{token_id}")
            if door in AGENT_DOORS:
                cred += f"+{door}"
            try:
                await asyncio.to_thread(_aa.record, self.state.data_dir, interface="serve", action="read",
                                        result="refused", user_id=getattr(client, "user_id", None)
                                        if getattr(client, "kind", "") != "gateway" else None,
                                        credential=cred, obj=f"{door} {path}"[:120], reason=authz_reason)
            except Exception:  # noqa: BLE001
                logger.warning("serve: could not record a refusal in the audit trail", exc_info=True)
        await self._respond(send, status, body, extra_headers=extra_headers)

    @staticmethod
    async def _respond(send: Any, status: int, body: bytes, *, extra_headers: list | None = None) -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())] + list(extra_headers or [])})
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass


NO_ACCESS_MODEL = "kratos-no-access"


def _placeholder_models(started_at: float) -> bytes:
    return json.dumps({"object": "list", "data": [{"id": NO_ACCESS_MODEL, "object": "model",
                                                   "created": int(started_at), "owned_by": "kratos"}]}).encode()


def create_app(data_dir: Path, *, bind_host: str = "127.0.0.1", port: int = 8770) -> Any:
    """The ASGI app: the gate around one Starlette app holding the OpenAI routes and the
    MCP endpoint."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse

    from kratos.serve import agui, mcp_http, openai_routes
    from kratos.serve.a2a import routes as a2a_routes
    from kratos.serve.a2a import store as a2a_store
    from kratos.serve.a2a import tasks as a2a_tasks

    state = ServeState(data_dir, bind_host=bind_host, port=port)
    mcp_app, session_manager = mcp_http.build(state)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Any):
        state.note_runs(running=True)
        try:   # E.5: a task an earlier server process left unfinished can't still be running
            await asyncio.to_thread(a2a_store.fail_unfinished, data_dir, a2a_tasks.RESTARTED)
        except Exception:  # noqa: BLE001 -- history only
            logger.warning("serve: could not close the tasks of an earlier run", exc_info=True)
        from kratos.outbox import worker as _outbox_worker

        delivery = _outbox_worker.start_background(data_dir, label="kratos serve")
        try:
            async with session_manager.run():
                yield
        finally:
            if delivery is not None:
                await asyncio.to_thread(delivery.stop, 5)
            # Stopping: running MCP investigations are told to stop and waited for (off the
            # event loop), so nothing keeps reading a machine after the server is gone.
            await asyncio.to_thread(state.investigations.shutdown)
            await asyncio.to_thread(state.a2a_tasks.shutdown)
            await asyncio.to_thread(state.shutdown_turns)
            state.note_runs(running=False)

    async def too_large(request: Any, exc: Exception) -> Any:
        status, body = _json_error(413, "the request is too large", kind="invalid_request_error")
        return JSONResponse(json.loads(body), status_code=status)

    async def not_found(request: Any, exc: Exception) -> Any:
        status, body = _json_error(404, "not found", kind="invalid_request_error")
        return JSONResponse(json.loads(body), status_code=getattr(exc, "status_code", 404))

    api = Starlette(routes=openai_routes.routes(state) + list(mcp_app.routes) + a2a_routes.routes(state)
                    + agui.routes(state), lifespan=lifespan,
                    exception_handlers={_BodyTooLarge: too_large, 404: not_found, 405: not_found})
    api.state.kratos = state
    return KratosGate(api, state)
