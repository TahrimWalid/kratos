"""The AG-UI door of `kratos serve` (docs/phaseE/E.5 §3.8): `POST /ag-ui/run`.

An AG-UI front end posts a RunAgentInput (thread id, run id, the conversation); Kratos
answers with one Server-Sent Events stream for that run:

  RUN_STARTED
  STEP_STARTED / STEP_FINISHED   one pair per collection check and per tool read -- the
                                 check or tool NAME from Kratos's own registries and a
                                 fixed status word; never text from the machine or model
  TEXT_MESSAGE_START / _CONTENT / _END   the checked answer, as the chat door renders it --
                                 sent only once the run and every answer check finished,
                                 so the stream never shows an unchecked draft
  CUSTOM "kratos.findings"       the findings as data (the same payload as A2A's data part)
  RUN_FINISHED                   (outcome "cancelled" when the run was stopped)
  RUN_ERROR                      refused (role, machine, limits, busy) or failed

The run is an A2A task with door "agui" (tasks.start_task): the same person token (with the
`agents` door), the same D.7 checks, slots, hourly limit and budget, the same engine and
answer checks. Which machine: `forwardedProps.kratos.machine` ("@group" for a group
question), or the caller's only machine. Tool-call events are never sent -- the front end
can't call Kratos's tools -- and tools the front end offers are ignored: Kratos never
calls back. `resume` (answering an interrupt) is refused: Kratos never interrupts to ask.
A front end that disconnects stops the run before its next read (AG-UI has no way to
pick the result up again).
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import re
import time
from typing import Any

from starlette.requests import Request

PATH = "/ag-ui/run"
MAX_DELTA = 4000
KEEPALIVE_SECONDS = 10.0
FINDINGS_EVENT = "kratos.findings"
_CHECKED_RE = re.compile(r"^checked ([a-z0-9_]{1,40}): ([a-z][a-z _-]{0,30})$")
_RUNNING_RE = re.compile(r"^running ([A-Za-z0-9_]{1,64})$")


def _event(kind: str, **fields: Any) -> str:
    body = {"type": kind, "timestamp": int(time.time() * 1000), **{k: v for k, v in fields.items() if v is not None}}
    return "data: " + json.dumps(body, ensure_ascii=False) + "\n\n"


def _known_checks() -> set[str]:
    try:
        from kratos.collect import checks as _register  # noqa: F401 -- registers the checks
        from kratos.collect import registry

        return {c.name for c in registry.checks()}
    except Exception:  # noqa: BLE001
        return set()


def _known_tools() -> set[str]:
    from kratos.agent.tools import TOOL_REGISTRY

    return set(TOOL_REGISTRY)


def step_of(line: str, checks: set[str], tools: set[str]) -> tuple[str, str, str | None] | None:
    """(kind "check"|"tool", name, status) for a Kratos progress line naming a known check
    or tool; None for anything else (it is not shown as a step)."""
    m = _CHECKED_RE.match(line or "")
    if m and m.group(1) in checks:
        return "check", m.group(1), m.group(2).strip()
    m = _RUNNING_RE.match(line or "")
    if m and m.group(1) in tools:
        return "tool", m.group(1), None
    return None


def question_of(body: dict[str, Any]) -> str:
    """The last user message's text (strings or text parts)."""
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        raise ValueError("messages must be a non-empty list")
    for m in reversed(msgs):
        if not isinstance(m, dict) or m.get("role") != "user":
            continue
        content = m.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "\n".join(str(p.get("text") or "") for p in content
                             if isinstance(p, dict) and p.get("type") == "text")
        else:
            text = ""
        if text.strip():
            return text.strip()
    raise ValueError("there is no user message to answer")


def machine_of(body: dict[str, Any]) -> str | None:
    fp = body.get("forwardedProps")
    k = fp.get("kratos") if isinstance(fp, dict) else None
    m = k.get("machine") if isinstance(k, dict) else None
    if m is None:
        return None
    if not isinstance(m, str) or not m.strip() or len(m) > 255:
        raise ValueError("forwardedProps.kratos.machine must be a machine name or '@group'")
    return m.strip()


def routes(state: Any) -> list[Any]:
    from starlette.routing import Route

    return [Route(PATH, _handler(state), methods=["POST"])]


def _handler(state: Any) -> Any:
    from starlette.responses import StreamingResponse

    async def run(request: Request) -> Any:
        from kratos import authz
        from kratos.serve.a2a import skills as K
        from kratos.serve.a2a import tasks as TK
        from kratos.serve.a2a.card import MAX_QUESTION
        from kratos.serve.a2a.routes import a2a_error, read_json

        client, actor = request.scope["kratos.client"], request.scope["kratos.actor"]
        try:
            await asyncio.to_thread(authz.require, actor, authz.P.READ, data_dir=state.data_dir, audit_allowed=False)
        except authz.Denied as e:
            return a2a_error("PERMISSION_DENIED", str(e))
        try:
            body = await read_json(request)
            if not isinstance(body, dict):
                raise ValueError("the body must be a RunAgentInput object")
            thread_id, run_id = body.get("threadId"), body.get("runId")
            if not (K.valid_id(thread_id) and K.valid_id(run_id)):
                raise ValueError("threadId and runId are required (1-128 letters, digits, '_', '.', ':' or '-')")
            if body.get("resume"):
                raise ValueError("Kratos never interrupts a run to ask anything, so there is nothing to resume")
            question = question_of(body)
            if len(question) > MAX_QUESTION:
                raise ValueError(f"the question is longer than {MAX_QUESTION} characters")
            machine = machine_of(body)
        except ValueError as e:
            await asyncio.to_thread(authz.record_refusal, actor, authz.P.AGUI_USE, f"bad input: {e}"[:200],
                                    obj="ag-ui run", data_dir=state.data_dir)
            return a2a_error("INVALID_PARAMS", str(e))

        def single() -> str | None:
            from kratos.serve.openai_routes import scope_machines

            mine = scope_machines(client, state.data_dir)
            return mine[0] if len(mine) == 1 else None

        if machine is None:
            machine = await asyncio.to_thread(contextvars.copy_context().run, single)
        if machine is None:
            data = None
        elif machine.startswith("@"):
            data = {"skill": "ask_group", "group": machine, "question": question}
        else:
            data = {"skill": "investigate_machine", "machine": machine, "question": question}
        loop = asyncio.get_running_loop()

        def begin() -> Any:
            if data is None:
                raise K.InputError("name the machine in forwardedProps.kratos.machine (you may use several, or none)")
            call = K.parse({"messageId": run_id, "role": "ROLE_USER", "parts": [{"data": data}]})
            return TK.start_task(state, actor=actor, client=client, door="agui", call=call, loop=loop)

        try:
            started = await asyncio.to_thread(contextvars.copy_context().run, begin)
        except K.InputError as e:
            await asyncio.to_thread(authz.record_refusal, actor, authz.P.AGUI_USE, str(e)[:200], obj="ag-ui run",
                                    data_dir=state.data_dir)
            return a2a_error(e.reason, str(e))
        checks, tools = await asyncio.to_thread(lambda: (_known_checks(), _known_tools()))
        return StreamingResponse(_stream(state, started.task, started.queue, request, thread_id, run_id, checks,
                                         tools),
                                 media_type="text/event-stream",
                                 headers={"cache-control": "no-cache", "x-accel-buffering": "no"})

    return run


async def _stream(state: Any, t: Any, q: Any, request: Request, thread_id: str, run_id: str,
                  checks: set[str], tools: set[str]):
    from kratos.serve.a2a import tasks as TK

    open_tool: list[str] = []
    meta = {"kratos": {"taskId": t.task_id}}
    done = False

    def close_tool() -> list[str]:
        out = [_event("STEP_FINISHED", stepName=f"tool {n}") for n in open_tool]
        open_tool.clear()
        return out

    try:
        yield _event("RUN_STARTED", threadId=thread_id, runId=run_id, metadata=meta)
        last = time.monotonic()
        while True:
            snap = TK.snapshot(t)
            if snap["state"] in TK.S.TERMINAL and q.empty():
                break
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
            if kind == "progress":
                step = step_of(value, checks, tools)
                if step is None:
                    continue
                kind_, name, status = step
                if kind_ == "tool":
                    for e in close_tool():
                        yield e
                    open_tool.append(name)
                    yield _event("STEP_STARTED", stepName=f"tool {name}")
                else:
                    yield _event("STEP_STARTED", stepName=f"check {name}")
                    yield _event("STEP_FINISHED", stepName=f"check {name}", metadata={"kratos": {"status": status}})
            elif kind == "state" and value in TK.S.TERMINAL:
                break
        for e in close_tool():
            yield e
        snap = TK.snapshot(t)
        if snap["state"] == TK.COMPLETED and snap["result"]:
            text = str(snap["result"].get("text") or "")
            mid = f"{t.task_id}-answer"
            yield _event("TEXT_MESSAGE_START", messageId=mid, role="assistant")
            for i in range(0, len(text), MAX_DELTA):
                yield _event("TEXT_MESSAGE_CONTENT", messageId=mid, delta=text[i:i + MAX_DELTA])
            yield _event("TEXT_MESSAGE_END", messageId=mid)
            if isinstance(snap["result"].get("data"), dict):
                yield _event("CUSTOM", name=FINDINGS_EVENT, value=snap["result"]["data"])
            yield _event("RUN_FINISHED", threadId=thread_id, runId=run_id, metadata=meta)
        elif snap["state"] == TK.CANCELED:
            yield _event("RUN_FINISHED", threadId=thread_id, runId=run_id, outcome={"type": "cancelled"},
                         metadata=meta)
        else:
            code = "rejected" if snap["state"] == TK.REJECTED else "failed"
            yield _event("RUN_ERROR", message=str(snap["reason"] or code), code=code, metadata=meta)
        done = True
    finally:
        t.unsubscribe(q)
        if not done and not t.finished:
            # The front end went away mid-run: stop before the next read. No awaiting here
            # (this may run inside a cancellation): the cancel runs on its own.
            def _cancel() -> None:
                try:
                    TK.cancel_task(state, t.task_id, t.user_id, t.token_id)
                except (TK.NotFound, TK.NotCancelable):
                    pass

            t.stop.set()
            asyncio.get_running_loop().create_task(asyncio.to_thread(_cancel))
