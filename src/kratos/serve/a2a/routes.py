"""The A2A 1.0 HTTP+JSON/REST binding (spec §11) inside `kratos serve`.

  GET  /.well-known/agent-card.json      the public, signed card (no token needed)
  GET  /a2a/v1/keys.json                 the signing keys (JWK set: active + retired)
  GET  /a2a/v1/extendedAgentCard         the caller's card (their machines and groups)
  POST /a2a/v1/message:send              start a task (waits for it unless returnImmediately)
  POST /a2a/v1/message:stream            start a task and stream it (SSE)
  GET  /a2a/v1/tasks                     this person's tasks
  GET  /a2a/v1/tasks/{id}                one task
  POST /a2a/v1/tasks/{id}:cancel         cancel it
  POST /a2a/v1/tasks/{id}:subscribe      stream an unfinished task (SSE)
  *    /a2a/v1/tasks/{id}/pushNotificationConfigs...   "not supported" -- always

Everything except the first two needs a person token with the `agents` door, checked by
KratosGate (serve.app) before a route runs; these routes then check the person's role and
machines for each action (D.7). Errors are A2A's `google.rpc.Status` shape (code, status,
message, an ErrorInfo detail with the A2A reason), so the reference SDK maps them.

A task id belongs to the person who started it: another person's id is "not found".
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
from typing import Any

from starlette.requests import Request

from kratos.serve.a2a import card as C
from kratos.serve.a2a import skills as K
from kratos.serve.a2a import tasks as TK

logger = logging.getLogger(__name__)

VERSION_HEADER = "a2a-version"
SUPPORTED_VERSION = "1.0"
KEEPALIVE_SECONDS = 10.0
SEND_WAIT_SECONDS = 600.0
MAX_JSON_DEPTH = 32
_ERRORS = {   # reason -> (HTTP code, gRPC status)
    "TASK_NOT_FOUND": (404, "NOT_FOUND"),
    "TASK_NOT_CANCELABLE": (400, "FAILED_PRECONDITION"),
    "PUSH_NOTIFICATION_NOT_SUPPORTED": (400, "FAILED_PRECONDITION"),
    "UNSUPPORTED_OPERATION": (400, "FAILED_PRECONDITION"),
    "CONTENT_TYPE_NOT_SUPPORTED": (400, "INVALID_ARGUMENT"),
    "VERSION_NOT_SUPPORTED": (400, "FAILED_PRECONDITION"),
    "INVALID_PARAMS": (400, "INVALID_ARGUMENT"),
    "INVALID_REQUEST": (400, "INVALID_ARGUMENT"),
    "METHOD_NOT_FOUND": (404, "NOT_FOUND"),
    "PERMISSION_DENIED": (403, "PERMISSION_DENIED"),
    "INTERNAL_ERROR": (500, "INTERNAL"),
}
PUSH_REFUSAL = ("Kratos doesn't send push notifications: it never calls a URL another agent names. Poll the task "
                "(GetTask) or stream it (message:stream / :subscribe); alerts to people go through Kratos's own "
                "channels, set up by a person.")


def a2a_error(reason: str, message: str, *, metadata: dict[str, Any] | None = None) -> Any:
    from starlette.responses import JSONResponse

    code, status = _ERRORS.get(reason, (500, "INTERNAL"))
    body = {"error": {"code": code, "status": status, "message": message,
                      "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason,
                                   "domain": "a2a-protocol.org", "metadata": metadata or {}}]}}
    return JSONResponse(body, status_code=code)


def _depth_ok(value: Any) -> bool:
    stack = [(value, 1)]
    while stack:
        v, d = stack.pop()
        if d > MAX_JSON_DEPTH:
            return False
        if isinstance(v, dict):
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, d + 1) for x in v)
    return True


async def read_json(request: Request) -> Any:
    """The body as JSON -- or raises ValueError with a plain reason (a body that grows past
    the size limit raises the gate's _BodyTooLarge, answered 413)."""
    from kratos.serve.app import _BodyTooLarge

    try:
        raw = await request.body()
    except _BodyTooLarge:
        raise
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("the request body must be JSON") from None
    if not _depth_ok(value):
        raise ValueError(f"the request body is nested deeper than {MAX_JSON_DEPTH} levels")
    return value


def version_problem(request: Request) -> Any:
    """None when the caller speaks A2A 1.0 (header or query parameter), else the error."""
    value = (request.headers.get(VERSION_HEADER) or request.query_params.get("A2A-Version") or "").strip()
    major_minor = ".".join(value.split(".")[:2]) if value else "0.3"     # §3.6: absent means 0.3
    if major_minor == SUPPORTED_VERSION:
        return None
    return a2a_error("VERSION_NOT_SUPPORTED", f"Kratos speaks A2A {SUPPORTED_VERSION}; this request asked for "
                     f"{major_minor} (send the header A2A-Version: {SUPPORTED_VERSION})",
                     metadata={"supportedVersions": SUPPORTED_VERSION})


def _host(request: Request) -> str:
    return (request.headers.get("host") or "127.0.0.1").strip()


def _sse(obj: dict[str, Any]) -> str:
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


async def stream_task(t: TK.TaskRun, q: Any, request: Request, *, first: dict[str, Any] | None = None):
    """SSE: the task as it is now, then each change until it has finished. A client that
    goes away only stops listening -- the task keeps running and GetTask has its result."""
    try:
        snap = TK.snapshot(t)
        yield _sse({"task": TK.task_json(snap)} if first is None else first)
        if t.finished:
            return
        last = time.monotonic()
        while True:
            try:
                kind, value = await asyncio.wait_for(q.get(), 1.0)
            except asyncio.TimeoutError:
                if await request.is_disconnected():
                    return
                if time.monotonic() - last >= KEEPALIVE_SECONDS:
                    last = time.monotonic()
                    yield ": keep-alive\n\n"
                continue
            last = time.monotonic()
            snap = TK.snapshot(t)
            if kind == "result":
                yield _sse({"artifactUpdate": {"taskId": t.task_id, "contextId": t.context_id,
                                               "artifact": TK.artifact_json(t.task_id, value), "lastChunk": True}})
                continue
            if kind == "progress":
                status = TK.status_json(task_id=t.task_id, context_id=t.context_id, state=TK.WORKING,
                                        updated=snap["updated"], reason=None, progress=value)
            else:
                status = TK.status_json(task_id=t.task_id, context_id=t.context_id, state=value,
                                        updated=snap["updated"], reason=snap["reason"], progress=snap["progress"])
            yield _sse({"statusUpdate": {"taskId": t.task_id, "contextId": t.context_id, "status": status}})
            if kind == "state" and value in TK.S.TERMINAL:
                return
    finally:
        t.unsubscribe(q)


def routes(state: Any) -> list[Any]:
    from starlette.routing import Route

    h = _handlers(state)
    return [Route(C.WELL_KNOWN_PATH, h["public_card"], methods=["GET"]),
            Route(C.KEYS_PATH, h["keys"], methods=["GET"]),
            Route(C.API_PREFIX + "/{rest:path}", h["api"], methods=["GET", "POST", "DELETE", "PUT", "PATCH"])]


def _handlers(state: Any) -> dict[str, Any]:
    from starlette.responses import JSONResponse, StreamingResponse

    def _me(request: Request) -> tuple[Any, Any]:
        return request.scope["kratos.client"], request.scope["kratos.actor"]

    async def public_card(request: Request) -> Any:
        body = await asyncio.to_thread(C.card_for, state.data_dir, C.base_url(state.data_dir, _host(request)))
        return JSONResponse(body, headers={"cache-control": "max-age=300"})

    async def keys(request: Request) -> Any:
        return JSONResponse(await asyncio.to_thread(C.key_set, state.data_dir))

    async def extended_card(request: Request) -> Any:
        from kratos import authz
        from kratos.serve.openai_routes import group_models_for, scope_machines

        client, actor = _me(request)
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.READ, data_dir=state.data_dir, audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))

        def build() -> Any:
            machines = scope_machines(client, state.data_dir)
            groups = [t for _m, t in group_models_for(client, state.data_dir)]
            return C.card_for(state.data_dir, C.base_url(state.data_dir, _host(request)), machines=machines,
                              groups=groups)

        return JSONResponse(await asyncio.to_thread(contextvars.copy_context().run, build))

    async def send(request: Request, *, streaming: bool) -> Any:
        from kratos import authz

        client, actor = _me(request)
        try:      # a person is attached at all (each skill is checked again, with its own action)
            await asyncio.to_thread(authz.require, actor, authz.P.READ, data_dir=state.data_dir, audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        problem = version_problem(request)
        if problem is not None:
            return problem
        try:
            body = await read_json(request)
        except ValueError as e:
            return a2a_error("INVALID_REQUEST", str(e))
        if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
            return a2a_error("INVALID_PARAMS", "SendMessageRequest needs a message")
        cfg = body.get("configuration") or {}
        if not isinstance(cfg, dict):
            return a2a_error("INVALID_PARAMS", "configuration must be an object")
        if cfg.get("taskPushNotificationConfig"):
            # Refused before anything is stored or started: Kratos makes no request to a
            # URL another agent names.
            return a2a_error("PUSH_NOTIFICATION_NOT_SUPPORTED", PUSH_REFUSAL)
        message = body["message"]
        tid = message.get("taskId")
        if tid:
            row = await asyncio.to_thread(state.a2a_tasks.view, str(tid), actor.user_id)
            if row is None:
                return a2a_error("TASK_NOT_FOUND", "no task with that id")
            return a2a_error("UNSUPPORTED_OPERATION",
                             "a Kratos task takes one message and never asks for more -- start a new task "
                             f"(this one is {str(row['state']).replace('TASK_STATE_', '').lower()})")

        def single() -> str | None:
            from kratos.serve.openai_routes import scope_machines

            mine = scope_machines(client, state.data_dir)
            return mine[0] if len(mine) == 1 else None

        one = await asyncio.to_thread(contextvars.copy_context().run, single)
        try:
            call = K.parse(message, single_machine=one)
        except K.InputError as e:
            await asyncio.to_thread(authz.record_refusal, actor, authz.P.A2A_USE, f"bad message: {e}"[:200],
                                    obj="a2a message", data_dir=state.data_dir)
            return a2a_error(e.reason, str(e))
        loop = asyncio.get_running_loop()
        started = await asyncio.to_thread(contextvars.copy_context().run, TK.start_task, state, actor=actor,
                                          client=client, door="a2a", call=call, loop=loop)
        t, q = started.task, started.queue
        if streaming:
            return StreamingResponse(stream_task(t, q, request), media_type="text/event-stream",
                                     headers={"cache-control": "no-cache", "x-accel-buffering": "no"})
        t.unsubscribe(q)
        if not cfg.get("returnImmediately"):
            deadline = time.monotonic() + SEND_WAIT_SECONDS
            while not t.finished and time.monotonic() < deadline:
                if await request.is_disconnected():
                    break                    # the task keeps running; GetTask has its result
                await asyncio.sleep(0.25)
        return JSONResponse({"task": TK.task_json(TK.snapshot(t))})

    async def get_task(request: Request, task_id: str) -> Any:
        from kratos import authz

        client, actor = _me(request)
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.SESSIONS_OWN, data_dir=state.data_dir,
                                    audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        row = await asyncio.to_thread(state.a2a_tasks.view, task_id, actor.user_id)
        if row is None:
            return a2a_error("TASK_NOT_FOUND", "no task with that id")
        return JSONResponse(TK.task_json(row))

    async def list_tasks(request: Request) -> Any:
        from kratos import authz
        from kratos.serve.a2a import store as S

        client, actor = _me(request)
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.SESSIONS_OWN, data_dir=state.data_dir,
                                    audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        qp = request.query_params
        try:
            size = max(1, min(int(qp.get("pageSize") or 50), 100))
            offset = max(0, int(qp.get("pageToken") or 0))
        except ValueError:
            return a2a_error("INVALID_PARAMS", "pageSize and pageToken are whole numbers")
        state_f = qp.get("status") or None
        if state_f is not None and state_f not in S.STATES:
            return a2a_error("INVALID_PARAMS", "unknown status")
        ctx = qp.get("contextId") or None
        if ctx is not None and not K.valid_id(ctx):
            return a2a_error("INVALID_PARAMS", "bad contextId")
        rows, total = await asyncio.to_thread(S.list_for, state.data_dir, actor.user_id, context_id=ctx,
                                              state=state_f, limit=size, offset=offset)
        live = []
        for r in rows:
            t = state.a2a_tasks.live(r["task_id"], actor.user_id)
            live.append(TK.task_json(TK.snapshot(t) if t is not None else r))
        nxt = str(offset + size) if offset + size < total else ""
        return JSONResponse({"tasks": live, "nextPageToken": nxt, "pageSize": size, "totalSize": total})

    async def cancel(request: Request, task_id: str) -> Any:
        from kratos import authz

        client, actor = _me(request)
        problem = version_problem(request)
        if problem is not None:
            return problem
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.SESSIONS_OWN, data_dir=state.data_dir,
                                    obj=f"a2a cancel {task_id[:60]}")
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        try:
            snap = await asyncio.to_thread(TK.cancel_task, state, task_id, actor.user_id)
        except TK.NotFound:
            return a2a_error("TASK_NOT_FOUND", "no task with that id")
        except TK.NotCancelable as e:
            return a2a_error("TASK_NOT_CANCELABLE", "the task has already finished "
                             f"({str(e).replace('TASK_STATE_', '').lower()}); nothing was restarted")
        return JSONResponse(TK.task_json(snap))

    async def subscribe(request: Request, task_id: str) -> Any:
        from kratos import authz

        client, actor = _me(request)
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.SESSIONS_OWN, data_dir=state.data_dir,
                                    audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        problem = version_problem(request)
        if problem is not None:
            return problem
        t = state.a2a_tasks.live(task_id, actor.user_id)
        if t is None:
            row = await asyncio.to_thread(state.a2a_tasks.view, task_id, actor.user_id)
            if row is None:
                return a2a_error("TASK_NOT_FOUND", "no task with that id")
            return a2a_error("UNSUPPORTED_OPERATION", "the task has finished -- read it with GetTask")
        q = t.subscribe(asyncio.get_running_loop())
        if t.finished:
            t.unsubscribe(q)
            return a2a_error("UNSUPPORTED_OPERATION", "the task has finished -- read it with GetTask")
        return StreamingResponse(stream_task(t, q, request), media_type="text/event-stream",
                                 headers={"cache-control": "no-cache", "x-accel-buffering": "no"})

    async def api(request: Request) -> Any:
        """One route for the binding's paths (`tasks/{id}:cancel` doesn't fit a path pattern)."""
        rest = str(request.path_params.get("rest") or "")
        method = request.method
        if rest == "extendedAgentCard" and method == "GET":
            return await extended_card(request)
        if rest == "message:send" and method == "POST":
            return await send(request, streaming=False)
        if rest == "message:stream" and method == "POST":
            return await send(request, streaming=True)
        if rest == "tasks" and method == "GET":
            return await list_tasks(request)
        if rest.startswith("tasks/"):
            tail = rest[len("tasks/"):]
            if "/pushNotificationConfigs" in tail or tail.endswith("/pushNotificationConfigs"):
                return a2a_error("PUSH_NOTIFICATION_NOT_SUPPORTED", PUSH_REFUSAL)
            if "/" not in tail:
                if tail.endswith(":cancel") and method == "POST":
                    return await cancel(request, tail[:-len(":cancel")])
                if tail.endswith(":subscribe") and method in ("POST", "GET"):
                    return await subscribe(request, tail[:-len(":subscribe")])
                if ":" not in tail and method == "GET":
                    return await get_task(request, tail)
        return a2a_error("METHOD_NOT_FOUND", "not an A2A method Kratos offers")

    return {"public_card": public_card, "keys": keys, "api": api}
