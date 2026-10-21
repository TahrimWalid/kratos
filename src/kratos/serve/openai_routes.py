"""The OpenAI-compatible door: `GET /v1/models`, `POST /v1/chat/completions`.

Kratos is "the model". The client picks `kratos/<machine>` (or `kratos` for the default
machine); the last user message is the request; the reply is Kratos's checked answer.
While an investigation runs, Kratos-written progress lines stream in the reasoning field
(`reasoning_content`, which Open WebUI shows as "thinking") and SSE keep-alive comments
keep the connection open; the answer is sent only when the run has finished and every
answer check has had its say -- the model's own tokens are never streamed.
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

from starlette.requests import Request

from kratos.serve import render as _render
from kratos.serve import store as _store

logger = logging.getLogger(__name__)

# The path this server SERVES (Kratos is the model here). The model-request scan
# (tests/test_budget_choke_point.py) allows this one assignment and nothing else.
COMPLETIONS_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"
KEEPALIVE_SECONDS = 10.0
HISTORY_MESSAGES = 8              # earlier messages kept as context, newest last
HISTORY_CHARS = 6000
MODEL_PREFIX = "kratos"
_CHAT_ID_HEADER = "x-openwebui-chat-id"
_USER_HEADERS = ("x-openwebui-user-name", "x-openwebui-user-email", "x-openwebui-user-id")

HELP_TEXT = """Kratos, from a chat client. Ask in plain words -- "has anyone been trying to log in?",
"check this machine for anything suspicious" -- and Kratos investigates the machine named by
the model you picked (kratos/<machine>), with the same checks, answer checks, masking and
spending limits as the Kratos app.

Commands that work here (no model call):
  /findings          the open findings Kratos remembers for this machine
  /usage             today's model use and the limits
  /retest <key>      re-collect what a finding depends on and re-check it
  /help              this text

Not available from a chat client -- use the Kratos app: /evolve, /whitelist, /run-fix,
accepting or dismissing findings, settings, target setup, presets.

Text Kratos quotes from a machine is shown inert: no image loads, no link is clickable.
Your OWN messages are drawn by the chat app itself -- an image link you type there is
loaded by the app, not by Kratos."""

_ALLOWED_COMMANDS = ("/findings", "/usage", "/retest", "/help")


# --------------------------------------------------------------------------- helpers
def _error(status: int, message: str, *, kind: str = "invalid_request_error", code: str | None = None) -> Any:
    from starlette.responses import JSONResponse

    return JSONResponse({"error": {"message": message, "type": kind, "param": None, "code": code}},
                        status_code=status)


def default_target() -> str:
    from kratos import kratos_config

    return kratos_config.process_target().rsplit("@", 1)[-1].strip().strip("[]").lower()


def models_for(client: Any) -> list[tuple[str, str]]:
    """(model id, target) for each machine this token may investigate. `kratos` is the
    default machine when the token may reach it."""
    out: list[tuple[str, str]] = []
    default = default_target()
    scope = list(client.targets) or ([default] if default else [])
    if default and default in scope:
        out.append((MODEL_PREFIX, default))
    for t in scope:
        out.append((f"{MODEL_PREFIX}/{t}", t))
    return out


def target_for_model(client: Any, model: str) -> str | None:
    """The machine a model name stands for, if this token may reach it. The machine comes
    from the model name only -- never from the message."""
    wanted = str(model or "").strip().lower()
    for mid, target in models_for(client):
        if mid == wanted:
            return target
    return None


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and p.get("type") in ("text", "input_text") and isinstance(p.get("text"), str):
                parts.append(p["text"])
        return "\n".join(parts)
    return ""


def split_messages(messages: Any) -> tuple[str, list[tuple[str, str]]]:
    """(the last user message, earlier (role, text) pairs). System messages from the
    client are ignored: Kratos has its own instructions, and a client's system prompt is
    not the person's request."""
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty list")
    convo = [(str(m.get("role") or ""), _text_of(m.get("content"))) for m in messages if isinstance(m, dict)]
    convo = [(r, t) for r, t in convo if r in ("user", "assistant")]
    last_user = max((i for i, (r, _t) in enumerate(convo) if r == "user"), default=None)
    if last_user is None or not convo[last_user][1].strip():
        raise ValueError("there is no user message to answer")
    return convo[last_user][1].strip(), convo[:last_user]


def history_text(earlier: list[tuple[str, str]]) -> str:
    """Earlier messages as 'You: … / Kratos: …' lines, newest kept, capped like a TUI
    resume. The caller frames it as data before any model sees it."""
    lines = [("You: " if r == "user" else "Kratos: ") + t.strip() for r, t in earlier[-HISTORY_MESSAGES:] if t.strip()]
    text = "\n\n".join(lines)
    if len(text) > HISTORY_CHARS:
        text = "[…earlier conversation trimmed…]\n" + text[-HISTORY_CHARS:]
    return text


def chat_key(headers: dict[str, str], token_id: str, model: str, convo: list[tuple[str, str]], first_user: str) -> str:
    chat_id = (headers.get(_CHAT_ID_HEADER) or "").strip()
    if chat_id and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", chat_id):
        return "chat:" + chat_id
    first = next((t for r, t in convo if r == "user"), first_user)
    digest = hashlib.sha256("\x1f".join([token_id, model, first.strip()]).encode("utf-8", "replace")).hexdigest()
    return "hash:" + digest[:32]


# --------------------------------------------------------------------------- client tasks
_TASK_RE = re.compile(r"^\s*###\s*Task:", re.IGNORECASE)


def client_task_reply(text: str) -> str | None:
    """Open WebUI (and similar clients) send their own background prompts -- a title, tags,
    follow-up suggestions -- to the selected model. Those aren't questions about a machine:
    Kratos answers them itself, without a model call or an investigation."""
    if not _TASK_RE.match(text or "") or "<chat_history>" not in text:
        return None
    if '"title"' in text:
        return json.dumps({"title": "Kratos chat"})
    if '"tags"' in text:
        return json.dumps({"tags": ["Security"]})
    if '"follow_ups"' in text:
        return json.dumps({"follow_ups": []})
    if '"queries"' in text:
        return json.dumps({"queries": []})
    return "{}"


# --------------------------------------------------------------------------- commands
def command_reply(text: str, *, target: str, data_dir: Path) -> str | None:
    """A chat-safe command's reply (Markdown), or the 'not available here' reply; None
    when the message isn't a command."""
    word = text.split(maxsplit=1)[0].lower() if text.startswith("/") else ""
    if not word:
        return None
    if word not in _ALLOWED_COMMANDS:
        return ("`" + re.sub(r"[^a-z0-9/_-]", "", word)[:30] + "` is not available from a chat client -- "
                "use the Kratos app. Type /help for what works here.")
    if word == "/help":
        return _render.kratos_text_markdown(HELP_TEXT)
    if word == "/usage":
        from kratos.budget import report as _br

        return _render.kratos_text_markdown(_usage_text(_br, data_dir))
    if word == "/findings":
        return _render.kratos_text_markdown(_findings_text(target, data_dir))
    if word == "/retest":
        return None          # it reads the machine: a turn of its own (slots, hourly limit) -- _serve_turn
    return None


def is_retest(text: str) -> bool:
    return bool(text) and text.split(maxsplit=1)[0].lower() == "/retest"


def _usage_text(br: Any, data_dir: Path) -> str:
    try:
        return br.today_text(data_dir) if hasattr(br, "today_text") else json.dumps(br.today(data_dir), default=str)
    except Exception as e:  # noqa: BLE001
        return f"Could not read the usage: {type(e).__name__}"


def _findings_text(target: str, data_dir: Path) -> str:
    from kratos.lifecycle import migrate as _lc_migrate
    from kratos.lifecycle import query as Q
    from kratos.lifecycle.keys import short
    from kratos.triage.run import enrich_rows

    _lc_migrate.ensure_imported(data_dir)
    rows = Q.list_findings(data_dir, target=target, state="open_verified", limit=50)
    enrich_rows(rows, data_dir)
    if not rows:
        return f"No open findings for {target}."
    lines = [f"Open findings for {target} ({len(rows)}):"]
    for r in rows:
        v = r.get("verdict") or {}
        tag = f"  [{v.get('tag')}]" if isinstance(v, dict) and v.get("tag") else ""
        lines.append(f"- {short(r['finding_key'])}  {str(r.get('severity') or '').upper():<8} {r.get('rule_id')}  "
                     f"{str(r.get('title') or '')[:100]}{tag}")
    lines.append("Re-check one: /retest <key>. Decide on one (accept, false positive): in the Kratos app.")
    return "\n".join(lines)


def _retest_text(key: str, target: str, data_dir: Path) -> str:
    from kratos.lifecycle import store as _lc
    from kratos.target_key import target_key
    from kratos.triage.run import retest

    if not re.fullmatch(r"[0-9a-f]{6,64}", key or ""):
        return "Usage: /retest <finding key> (the short key /findings shows)."
    try:
        with _lc.opened(data_dir) as conn:
            full = _lc.resolve_key(conn, key)
            rec = _lc.get_record(conn, full)
    except Exception:  # noqa: BLE001
        return f"No finding {key}."
    if target_key(rec["target"]) != target_key(target):
        return f"No finding {key} on {target}."
    from kratos.run_context import run_scope

    with run_scope("web", target=target):
        out = retest(full, data_dir=data_dir, target=target)
    lines = [f"Retest of {out['rule_id']} on {out['target']}: {out['before_state']} -> {out['after_state']}",
             f"verdict: {out['verdict']['tag']} -- {out['verdict']['sentence']}"]
    if out.get("incomplete"):
        lines.append(f"left open: the re-collection was incomplete ({out['incomplete']})")
    return "\n".join(lines)


# --------------------------------------------------------------------------- the turn
class TurnHandle:
    """One chat turn running on a worker thread: its progress events, stop flag, result.

    Made on the event loop; the worker thread hands events back with
    call_soon_threadsafe, so a stream waiting for the next line holds no thread (it used to
    block one pool thread per open chat in queue.get -- with a few chats open the shared
    pool ran dry and the server stopped answering anything, even /v1/models)."""

    def __init__(self, loop: "asyncio.AbstractEventLoop | None" = None) -> None:
        self._loop = loop or asyncio.get_running_loop()
        self.events: "asyncio.Queue[tuple[str, Any]]" = asyncio.Queue()
        self.stop = threading.Event()
        self.result: dict[str, Any] | None = None

    def _put(self, item: tuple[str, Any]) -> None:
        try:
            self._loop.call_soon_threadsafe(self.events.put_nowait, item)
        except RuntimeError:          # the loop is closed: the server stopped, nobody is reading
            pass

    def progress(self, line: str) -> None:
        self._put(("progress", line))

    def finish(self, result: dict[str, Any]) -> None:
        self.result = result
        self._put(("done", result))


def serve_turn(handle: TurnHandle, **kw: Any) -> None:
    """Route the message and answer it, on a worker thread. Whatever happens, `handle`
    is finished -- a failure becomes a plain-words reply, never a hung stream."""
    try:
        _serve_turn(handle, **kw)
    except Exception as e:  # noqa: BLE001
        logger.warning("serve: turn failed", exc_info=True)
        if handle.result is None:
            handle.finish({"status": "error", "content": f"Kratos hit an error answering this ({type(e).__name__})."})


def _serve_turn(handle: TurnHandle, *, state: Any, client: Any, target: str, model: str, message: str,
                earlier: list[tuple[str, str]], session_id: str) -> None:
    """Route the message (the same router as the TUI) and answer it: a chat reply, or an
    investigation in a bounded slot. Fills `handle`."""
    from kratos import settings_store, untrusted
    from kratos.run_context import run_scope
    from kratos.serve import settings as _s
    from kratos.serve.runs import RunRequest, run_investigation
    from kratos.tui_mk2.command_intent import route_message

    link_hosts = settings_store.get(_s.LINK_HOSTS, data_dir=state.data_dir) or []
    if is_retest(message):
        # A retest re-collects from the machine like an investigation does: it waits for a
        # slot, so chat clients can't put more load on a machine than serve.max_parallel.
        if not state.slots.acquire(should_stop=handle.stop.is_set,
                                   on_wait=lambda: handle.progress("waiting for another investigation to finish…")):
            handle.finish({"status": "stopped", "content": "Stopped before the retest started."})
            return
        try:
            arg = message.split(maxsplit=1)[1].strip() if len(message.split(maxsplit=1)) > 1 else ""
            handle.progress("re-collecting what the finding depends on…")
            text = _retest_text(arg, target, state.data_dir)
        finally:
            state.slots.release()
        handle.finish({"status": "ok", "content": _render.kratos_text_markdown(text)})
        return
    history = history_text(earlier)
    try:
        # The same router as the TUI (one model call, masked, metered under source "web").
        # route_message frames the earlier conversation as data itself.
        with run_scope("web", target=target, session_id=session_id):
            route = route_message(message, history, capture_stderr=False)
    except Exception as e:  # noqa: BLE001
        from kratos.budget.guard import BudgetExceeded

        if isinstance(e, BudgetExceeded):
            handle.finish({"status": "budget", "content": _render.kratos_note_markdown(e.user_message())})
            return
        logger.warning("serve: routing failed", exc_info=True)
        handle.finish({"status": "error", "content": "Kratos could not reach its model to read the message."})
        return
    kind = route.kind
    if kind == "failed":
        handle.finish({"status": "error", "content": "Kratos could not reach its model: "
                       + untrusted.md_code(route.reason or "no detail", max_len=200)})
        return
    if kind == "chat":
        reply = str(route.reply or "")
        _record_chat_turn(state.data_dir, session_id, message, reply)
        handle.finish({"status": "ok", "content": _render.chat_markdown(reply, link_hosts=link_hosts)})
        return
    if kind != "investigate" and kind != "clarify_host":
        # investigate_host (Kratos's own machine), app controls (model, target, rename, ...),
        # presets: not from a chat client. "This machine" in a served chat is the model's
        # machine -- clarify_host is investigated as that.
        if route.command in ("help",):
            text = _render.kratos_text_markdown(HELP_TEXT)
        elif route.command == "report":
            text = _render.kratos_text_markdown(_findings_text(target, state.data_dir))
        elif kind == "investigate_host":
            text = ("From a chat client Kratos investigates the machine named by the model you picked ("
                    + untrusted.md_code(target) + "), not the machine Kratos runs on. Use the Kratos app for that.")
        else:
            text = "That is not available from a chat client -- use the Kratos app. Type /help for what works here."
        _record_chat_turn(state.data_dir, session_id, message, text)
        handle.finish({"status": "ok", "content": text})
        return

    if not state.slots.acquire(should_stop=handle.stop.is_set,
                               on_wait=lambda: handle.progress("waiting for another investigation to finish…")):
        handle.finish({"status": "stopped", "content": "Stopped before the investigation started."})
        return
    try:
        state.note_runs()
        outcome = run_investigation(RunRequest(goal=message, target=target, data_dir=state.data_dir, source="web",
                                               session_id=session_id, prior_context=history or None,
                                               should_stop=handle.stop.is_set, on_progress=handle.progress))
    finally:
        state.slots.release()
        state.note_runs()
    status = {"refused_by_budget": "budget", "stopped_by_budget": "budget", "stopped": "stopped",
              "error": "error"}.get(outcome.status, "ok")
    content = _render.answer_markdown(outcome.final_answer, outcome.answer_parts, outcome.recommended_commands,
                                      link_hosts=link_hosts)
    handle.finish({"status": status, "content": content, "run_id": outcome.run_id, "usage": outcome.token_usage})


# --------------------------------------------------------------------------- routes
def routes(state: Any) -> list[Any]:
    """The OpenAI-door routes (Starlette -- no extra web framework on top of what the MCP
    SDK already brings)."""
    from starlette.routing import Route

    handlers = _handlers(state)
    return [Route(MODELS_PATH, handlers["models"], methods=["GET"]),
            Route(COMPLETIONS_PATH, handlers["chat"], methods=["POST"])]


def _handlers(state: Any) -> dict[str, Any]:
    from starlette.responses import JSONResponse, StreamingResponse

    async def list_models(request: Request) -> Any:
        client = request.scope["kratos.client"]
        now = int(state.started_at)
        data = [{"id": mid, "object": "model", "created": now, "owned_by": "kratos"} for mid, _t in models_for(client)]
        body = {"object": "list", "data": data}
        await asyncio.to_thread(_store.audit, state.data_dir, door="openai", endpoint=MODELS_PATH, status="ok",
                                token_id=client.token_id, client_addr=_peer(request), bytes_out=len(json.dumps(body)))
        return JSONResponse(body)

    async def chat_completions(request: Request) -> Any:
        client = request.scope["kratos.client"]
        started = time.monotonic()
        peer = _peer(request)
        headers = {k.lower(): v for k, v in request.headers.items()}
        user = next((headers[h] for h in _USER_HEADERS if headers.get(h)), None)

        def audit(status: str, *, model: str | None = None, target: str | None = None, run_id: str | None = None,
                  metered: bool = False, bytes_out: int = 0, detail: str | None = None) -> None:
            try:
                _store.audit(state.data_dir, door="openai", endpoint=COMPLETIONS_PATH, status=status,
                             token_id=client.token_id, model=model, target=target, client_addr=peer,
                             client_user=user, run_id=run_id, metered=metered,
                             duration=time.monotonic() - started, bytes_out=bytes_out, detail=detail)
            except Exception:  # noqa: BLE001
                logger.debug("serve: audit failed", exc_info=True)

        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            await asyncio.to_thread(audit, "refused", detail="body is not JSON")
            return _error(400, "the request body must be JSON")
        if not isinstance(body, dict):
            return _error(400, "the request body must be a JSON object")
        model = str(body.get("model") or "")
        stream = bool(body.get("stream"))
        target = target_for_model(client, model)
        if target is None:
            await asyncio.to_thread(audit, "refused", model=model[:200], detail="model not in this token's scope")
            return _error(404, f"The model {model[:80]!r} does not exist or this token may not use it.",
                          code="model_not_found")
        try:
            message, earlier = split_messages(body.get("messages"))
        except ValueError as e:
            await asyncio.to_thread(audit, "refused", model=model, target=target, detail=str(e))
            return _error(400, str(e))

        task = client_task_reply(message)
        if task is not None:
            await asyncio.to_thread(audit, "task", model=model, target=target, bytes_out=len(task))
            return _respond_text(task, model=model, stream=stream, reasoning=False)
        cmd = await asyncio.to_thread(command_reply, message, target=target, data_dir=state.data_dir) \
            if message.startswith("/") else None
        if cmd is not None:
            await asyncio.to_thread(audit, "ok", model=model, target=target, detail="command", bytes_out=len(cmd))
            return _respond_text(cmd, model=model, stream=stream)

        if not state.open_turn():
            await asyncio.to_thread(audit, "refused", model=model, target=target, detail="too many open turns")
            return _error(429, f"Kratos is already answering {state.max_open_turns} messages; try again shortly.",
                          kind="rate_limit_exceeded", code="server_busy")
        try:
            limit = await asyncio.to_thread(_hourly_limit, state.data_dir)
        except BaseException:
            state.close_turn()
            raise
        if not await asyncio.to_thread(state.reserve_metered, client.token_id, limit):
            state.close_turn()
            await asyncio.to_thread(audit, "refused", model=model, target=target, detail="hourly limit")
            return _error(429, f"This token has used its {limit} messages for this hour (serve.requests_per_hour).",
                          kind="rate_limit_exceeded", code="rate_limit_exceeded")
        # From here the request holds one of the hour's slots: it is given back once the
        # metered audit row is written, or at once if the request ends before using the model.
        try:
            # A retest makes no model call: the spending limits don't stop it.
            refusal = None if is_retest(message) else await asyncio.to_thread(_precheck, target, state.data_dir)
            if refusal is not None:
                await asyncio.to_thread(audit, "budget", model=model, target=target, detail="budget refused")
                state.release_metered(client.token_id)
                state.close_turn()
                return _respond_text(_render.kratos_note_markdown(refusal), model=model, stream=stream)
            convo = [*earlier, ("user", message)]
            key = chat_key(headers, client.token_id, model, convo, message)
            session_id = await asyncio.to_thread(_session_for, state, client.token_id, key, target)
        except BaseException:
            state.release_metered(client.token_id)
            state.close_turn()
            raise
        handle = TurnHandle()
        # The turn runs on the server's own bounded pool (state.turn_pool), never the shared
        # default pool the request handling itself needs; the context is copied like to_thread.
        call = functools.partial(contextvars.copy_context().run, serve_turn, handle, state=state, client=client,
                                 target=target, model=model, message=message, earlier=earlier,
                                 session_id=session_id)
        state.track_turn(handle)
        try:
            worker = asyncio.get_running_loop().run_in_executor(state.turn_pool, call)
        except BaseException:
            state.untrack_turn(handle)
            state.release_metered(client.token_id)
            state.close_turn()
            raise
        worker.add_done_callback(lambda _f: (state.untrack_turn(handle), state.close_turn()))

        def finished(result: dict[str, Any], sent: int) -> None:
            try:
                audit(result.get("status") or "error", model=model, target=target, run_id=result.get("run_id"),
                      metered=True, bytes_out=sent)
            finally:
                state.release_metered(client.token_id)

        if stream:
            return StreamingResponse(_sse(handle, worker, model=model, on_done=finished, request=request),
                                     media_type="text/event-stream",
                                     headers={"cache-control": "no-cache", "x-accel-buffering": "no"})
        return await _complete(handle, worker, request, model=model, on_done=finished)

    return {"models": list_models, "chat": chat_completions}

def _record_chat_turn(data_dir: Path, session_id: str, message: str, reply: str) -> None:
    """A turn that answered without investigating, saved like the TUI's chat turns."""
    from kratos.storage.session_store import SessionStore

    store = SessionStore(data_dir / "kratos.db")
    turn_id = store.start_turn(session_id, message)
    d = data_dir / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{session_id}_turn{turn_id}.json"
    path.write_text(json.dumps([{"final_answer": reply}], indent=2), encoding="utf-8")
    store.complete_turn(turn_id, "chat_reply", transcript_ref=str(path))


def _peer(request: Any) -> str:
    return (request.client.host if request.client else "") or ""


def _hourly_limit(data_dir: Path) -> int:
    from kratos import settings_store
    from kratos.serve import settings as _s

    return int(settings_store.get(_s.REQUESTS_PER_HOUR, data_dir=data_dir))


def _precheck(target: str, data_dir: Path) -> str | None:
    from kratos.budget import guard as _guard
    from kratos.run_context import run_scope

    with run_scope("web", target=target):
        refusal = _guard.precheck("web", data_dir_=data_dir)
    return refusal.user_message() if refusal is not None else None


def _session_for(state: Any, token_id: str, key: str, target: str) -> str:
    from kratos.llm_config import get_active_llm_model
    from kratos.storage.session_store import SessionStore

    found = _store.session_for(state.data_dir, token_id, key, target)
    if found:
        store = SessionStore(state.data_dir / "kratos.db")
        if store.get_session(found) is not None:
            return found
    store = SessionStore(state.data_dir / "kratos.db")
    new = store.create_session([target], get_active_llm_model())
    return _store.remember_session(state.data_dir, token_id, key, target, new)


def _completion_id() -> str:
    return "chatcmpl-" + secrets.token_hex(12)


def _usage_block(usage: Any) -> dict[str, int]:
    u = usage if isinstance(usage, dict) else {}
    p, c = int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": int(u.get("total_tokens") or (p + c))}


def _chunk(cid: str, created: int, model: str, delta: dict[str, Any], finish: str | None = None,
           usage: Any = None) -> str:
    obj: dict[str, Any] = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
                           "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    if usage is not None:
        obj["usage"] = _usage_block(usage)
    return "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"


def _respond_text(text: str, *, model: str, stream: bool, reasoning: bool = True) -> Any:
    from starlette.responses import JSONResponse, StreamingResponse

    cid, created = _completion_id(), int(time.time())
    if not stream:
        return JSONResponse(_completion_body(cid, created, model, text, None))

    async def gen():
        yield _chunk(cid, created, model, {"role": "assistant", "content": ""})
        yield _chunk(cid, created, model, {"content": text})
        yield _chunk(cid, created, model, {}, finish="stop")
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"cache-control": "no-cache"})


def _completion_body(cid: str, created: int, model: str, text: str, usage: Any) -> dict[str, Any]:
    return {"id": cid, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": _usage_block(usage)}


async def _next_event(handle: TurnHandle, timeout: float) -> tuple[str, Any] | None:
    try:
        return await asyncio.wait_for(handle.events.get(), timeout)
    except asyncio.TimeoutError:
        return None


async def _sse(handle: TurnHandle, worker: "asyncio.Future[Any]", *, model: str,
               on_done: Callable[[dict[str, Any], int], None], request: Any):
    """The stream: role chunk, progress in `reasoning_content`, keep-alive comments every
    KEEPALIVE_SECONDS of silence, then the whole checked answer as content, then [DONE].
    A client that goes away (the generator is cancelled or closed, or the request reports
    a disconnect) sets the stop flag: the run ends before its next model call or tool
    dispatch, and the turn is audited as stopped once the worker has wound down."""
    cid, created = _completion_id(), int(time.time())
    sent = 0
    result: dict[str, Any] | None = None
    try:
        first = _chunk(cid, created, model, {"role": "assistant", "content": ""})
        sent += len(first)
        yield first
        last = time.monotonic()
        while result is None:
            event = await _next_event(handle, 1.0)
            if event is None:
                if await request.is_disconnected():
                    return
                if time.monotonic() - last >= KEEPALIVE_SECONDS:
                    last = time.monotonic()
                    yield ": keep-alive\n\n"
                continue
            kind, value = event
            if kind == "progress":
                line = _chunk(cid, created, model, {"reasoning_content": _render.progress_markdown(value)})
                last = time.monotonic()
                sent += len(line)
                yield line
            else:
                result = value
        content = str(result.get("content") or "")
        for piece in (_chunk(cid, created, model, {"content": content}),
                      _chunk(cid, created, model, {}, finish="stop", usage=result.get("usage")),
                      "data: [DONE]\n\n"):
            sent += len(piece)
            yield piece
    finally:
        # No awaiting here: on a disconnect this runs inside a cancellation.
        if result is None:
            handle.stop.set()
            asyncio.get_running_loop().create_task(_audit_when_done(handle, worker, on_done, sent))
        else:
            asyncio.get_running_loop().create_task(asyncio.to_thread(on_done, result, sent))


async def _audit_when_done(handle: TurnHandle, worker: "asyncio.Future[Any]",
                           on_done: Callable[[dict[str, Any], int], None], sent: int) -> None:
    try:
        await worker
    except Exception:  # noqa: BLE001
        pass
    result = handle.result or {"status": "stopped"}
    if result.get("status") == "ok":
        result = {**result, "status": "stopped"}      # the client never got it
    await asyncio.to_thread(on_done, result, sent)


async def _complete(handle: TurnHandle, worker: "asyncio.Future[Any]", request: Any, *, model: str,
                    on_done: Callable[[dict[str, Any], int], None]) -> Any:
    from starlette.responses import JSONResponse

    while not worker.done():
        if await request.is_disconnected():
            handle.stop.set()
            asyncio.get_running_loop().create_task(_audit_when_done(handle, worker, on_done, 0))
            return JSONResponse({"error": {"message": "client went away", "type": "stopped"}}, status_code=499)
        await asyncio.wait({worker}, timeout=1.0)
    try:
        await worker
    except Exception:  # noqa: BLE001
        logger.warning("serve: turn failed", exc_info=True)
    result = handle.result or {"status": "error", "content": "The request failed inside Kratos."}
    body = _completion_body(_completion_id(), int(time.time()), model, str(result.get("content") or ""),
                            result.get("usage"))
    await asyncio.to_thread(on_done, result, len(json.dumps(body)))
    return JSONResponse(body)
