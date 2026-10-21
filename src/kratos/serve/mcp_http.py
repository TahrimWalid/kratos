"""MCP over Streamable HTTP, stateless, start-then-poll (docs/phaseB/B.3 §3.2).

An investigation takes seconds to minutes; an MCP tool call should not hang on it. So
`kratos_start_investigation(goal, target)` returns an investigation id and the run goes
on in the background; `kratos_get_investigation(id)` reports its progress lines and, when
it has finished, the checked answer and the findings. Both take an optional
`wait_seconds` (up to 120): they return as soon as the run is done, or when the wait is
up -- a host that makes one tool call per turn gets the answer in that call. Without an
id, `kratos_get_investigation` reports this token's newest investigation (hosts that
lose the id between turns -- seen with Open WebUI's prompt-based tool calling). The id is
random and bound to the token that started it -- another token asking for it is told it
does not exist. Each investigation is also recorded in `serve_sessions`
(`mcp:<id>` -> its session), so after a restart it is still found: its state is rebuilt
from the session's turn and transcript ("interrupted" if the server stopped mid-run). Works with clients on MCP 2025-11-25 (the SDK's newest) and with the stateless
2026-07-28 model: no server-side MCP session, nothing to resume.

Read tools (`kratos_get_findings`, `kratos_list_sessions`, `kratos_finding_states`) are
the stdio server's, limited to the machines the token may reach. Nothing reachable here
asks for approval, changes a finding, or touches the fix channel.
"""
from __future__ import annotations

import collections
import contextvars
import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import Context  # module level: FastMCP evaluates tool annotations here

logger = logging.getLogger(__name__)

MAX_KEPT = 200
PROGRESS_KEPT = 60
MAX_WAIT_SECONDS = 120
_KEY_PREFIX = "mcp:"


@dataclass
class Job:
    investigation_id: str
    token_id: str
    target: str
    goal_chars: int
    created: float = field(default_factory=time.time)
    status: str = "waiting"                      # waiting | running | done | stopped | error | refused
    progress: "collections.deque[str]" = field(default_factory=lambda: collections.deque(maxlen=PROGRESS_KEPT))
    outcome: dict[str, Any] | None = None
    finished: float | None = None
    stop: threading.Event = field(default_factory=threading.Event)
    session_id: str | None = None
    thread: threading.Thread | None = None

    def view(self) -> dict[str, Any]:
        out: dict[str, Any] = {"investigation_id": self.investigation_id, "status": self.status,
                               "target": self.target, "progress": list(self.progress),
                               "session_id": self.session_id}
        if self.outcome is not None:
            out.update({k: self.outcome.get(k) for k in ("final_answer", "findings", "recommended_commands",
                                                         "session_id", "run_id", "token_usage", "budget")})
        return out


class Investigations:
    """The investigations started over MCP in this process (in memory; the sessions and
    transcripts they write are in kratos.db as usual)."""

    def __init__(self) -> None:
        self._jobs: "collections.OrderedDict[str, Job]" = collections.OrderedDict()
        self._lock = threading.Lock()

    def new(self, token_id: str, target: str, goal: str) -> Job:
        job = Job(investigation_id="inv_" + secrets.token_urlsafe(18), token_id=token_id, target=target,
                  goal_chars=len(goal))
        with self._lock:
            self._jobs[job.investigation_id] = job
            while len(self._jobs) > MAX_KEPT:
                victim = next((k for k, j in self._jobs.items() if j.finished is not None), None)
                if victim is None:
                    break
                del self._jobs[victim]
        return job

    def get(self, token_id: str, investigation_id: str) -> Job | None:
        import hmac

        with self._lock:
            job = self._jobs.get(str(investigation_id or ""))
        if job is None or not hmac.compare_digest(job.token_id, token_id):
            return None
        return job

    def newest(self, token_id: str) -> Job | None:
        with self._lock:
            mine = [j for j in self._jobs.values() if j.token_id == token_id]
        return max(mine, key=lambda j: j.created) if mine else None

    def running(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.finished is None)

    def shutdown(self, timeout: float = 10.0) -> int:
        """The server is stopping: ask every running investigation to stop (it ends before
        its next model call or tool dispatch) and wait for its thread, up to `timeout` in
        all. Returns how many were still running afterwards (their turn then reads
        `interrupted` after the restart)."""
        with self._lock:
            live = [j for j in self._jobs.values() if j.finished is None]
        for job in live:
            job.stop.set()
        deadline = time.monotonic() + timeout
        for job in live:
            if job.thread is not None:
                job.thread.join(max(0.0, deadline - time.monotonic()))
        return sum(1 for j in live if j.thread is not None and j.thread.is_alive())


_TURN_STATUS = {"final_answer": "done", "max_iters_reached": "done", "stopped_by_budget": "done",
                "cancelled": "stopped", "error": "error"}


def view_from_store(data_dir: Any, token_id: str, investigation_id: str | None) -> dict[str, Any] | None:
    """An investigation this token started, rebuilt from kratos.db and its transcript (after
    a restart, or once it left the in-memory list). `investigation_id` None = the newest."""
    import json
    from pathlib import Path

    from kratos.serve import store as _store
    from kratos.serve.runs import extract_findings
    from kratos.storage.session_store import SessionStore

    rows = _store.sessions_with_prefix(data_dir, token_id, _KEY_PREFIX)
    if investigation_id:
        rows = [r for r in rows if r["client_chat_key"] == _KEY_PREFIX + investigation_id]
    if not rows:
        return None
    row = rows[0]                                   # newest first
    inv = row["client_chat_key"][len(_KEY_PREFIX):]
    out: dict[str, Any] = {"investigation_id": inv, "target": row["target"], "session_id": row["session_id"],
                           "progress": [], "status": "interrupted"}
    turns = SessionStore(Path(data_dir) / "kratos.db").get_goal_history(row["session_id"])
    if not turns:
        return out
    turn = turns[-1]
    status = turn.get("status")
    if turn.get("completed_at") is None or status in (None, "", "in_progress"):
        out["status"] = "interrupted"               # the server stopped while it ran
        return out
    out["status"] = _TURN_STATUS.get(str(status), "done")
    ref = turn.get("transcript_ref")
    try:
        transcript = json.loads(Path(ref).read_text(encoding="utf-8")) if ref else []
    except (OSError, ValueError):
        transcript = []
    final = next((e for e in reversed(transcript) if isinstance(e, dict) and e.get("final_answer")), {})
    out.update({"final_answer": final.get("final_answer"), "findings": extract_findings(transcript),
                "recommended_commands": final.get("recommended_commands") or [],
                "run_id": next((e.get("run_id") for e in transcript if isinstance(e, dict) and e.get("run_id")), None)})
    return out


async def _wait_for(job: Job, wait_seconds: Any) -> None:
    import asyncio

    try:
        wait = max(0.0, min(float(wait_seconds or 0), float(MAX_WAIT_SECONDS)))
    except (TypeError, ValueError):
        raise ValueError(f"wait_seconds must be a number from 0 to {MAX_WAIT_SECONDS}") from None
    deadline = time.monotonic() + wait
    while job.finished is None and time.monotonic() < deadline:
        await asyncio.sleep(0.25)


def _client(ctx: Any) -> Any:
    request = getattr(getattr(ctx, "request_context", None), "request", None)
    client = request.scope.get("kratos.client") if request is not None else None
    if client is None:
        raise PermissionError("no Kratos token on this request")
    return client


def _scope_targets(client: Any) -> list[str]:
    from kratos.serve.openai_routes import default_target

    return list(client.targets) or ([default_target()] if default_target() else [])


def _resolve_target(client: Any, target: str) -> str:
    from kratos.serve.openai_routes import MODEL_PREFIX, target_for_model

    t = str(target or "").strip().lower()
    if not t:
        raise ValueError("target is required")
    model = t if t == MODEL_PREFIX or t.startswith(MODEL_PREFIX + "/") else f"{MODEL_PREFIX}/{t}"
    resolved = target_for_model(client, model)
    if resolved is None:
        raise ValueError(f"this token may not investigate {t!r}")
    return resolved


def build(state: Any) -> tuple[Any, Any]:
    """(the MCP Starlette app with its /mcp route, its session manager)."""
    from mcp.server.fastmcp import FastMCP
    from mcp.server.transport_security import TransportSecuritySettings

    from kratos import mcp_server as _stdio
    from kratos import untrusted
    from kratos.serve.runs import RunRequest, run_investigation

    state.investigations = Investigations()
    hosts = sorted(state.allowed_hosts())
    mcp = FastMCP(name="kratos", stateless_http=True, json_response=True, streamable_http_path="/mcp",
                  transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                               allowed_hosts=hosts, allowed_origins=[]))

    def _run(job: Job, goal: str) -> None:
        try:
            if not state.slots.acquire(should_stop=job.stop.is_set,
                                       on_wait=lambda: job.progress.append("waiting for another investigation to finish…")):
                job.status, job.finished = "stopped", time.time()
                return
            try:
                job.status = "running"
                state.note_runs()
                outcome = run_investigation(RunRequest(goal=goal, target=job.target, data_dir=state.data_dir,
                                                       source="mcp", should_stop=job.stop.is_set,
                                                       on_progress=job.progress.append,
                                                       on_session=lambda sid: _remember(state, job, sid)))
            finally:
                state.slots.release()
                state.note_runs()
            job.outcome = outcome.as_dict()
            job.status = {"refused_by_budget": "refused", "stopped": "stopped", "error": "error"}.get(
                outcome.status, "done")
        except Exception as e:  # noqa: BLE001
            logger.warning("serve: MCP investigation failed", exc_info=True)
            job.status, job.outcome = "error", {"final_answer": f"The investigation failed: {type(e).__name__}"}
        finally:
            job.finished = job.finished or time.time()
            _audit(state, job)

    @mcp.tool()
    async def kratos_start_investigation(goal: str, target: str, ctx: Context,
                                         wait_seconds: float = 0) -> dict[str, Any]:
        """Starts a Kratos investigation of `target` (a machine this token may reach -- an
        address or name, or a model id like "kratos/web-01") for `goal`, and returns its
        `investigation_id`. With `wait_seconds` (0-120) it waits that long for the result and
        returns it as soon as it is done (most investigations take 5-30 s); otherwise poll
        kratos_get_investigation. Kratos's own agent picks which checks run; read-only --
        nothing reachable here changes the machine. When done, `final_answer` is Kratos's
        checked answer: show it as it is, it already says what Kratos found."""
        import asyncio

        client = _client(ctx)
        if not goal or not goal.strip():
            raise ValueError("goal is required")
        resolved = _resolve_target(client, target)
        from kratos.serve.openai_routes import _hourly_limit

        limit = await asyncio.to_thread(_hourly_limit, state.data_dir)
        if not await asyncio.to_thread(state.reserve_metered, client.token_id, limit):
            raise ValueError(f"this token has used its {limit} investigations for this hour (serve.requests_per_hour)")
        try:
            job = state.investigations.new(client.token_id, resolved, goal)
            job.thread = threading.Thread(target=contextvars.copy_context().run, args=(_run, job, goal.strip()),
                                          name=f"serve-mcp-{job.investigation_id[:12]}", daemon=True)
            job.thread.start()
        except BaseException:
            state.release_metered(client.token_id)
            raise
        await _wait_for(job, wait_seconds)
        return untrusted.for_model(job.view(), field_cap=None)

    @mcp.tool()
    async def kratos_get_investigation(ctx: Context, investigation_id: str = "",
                                       wait_seconds: float = 0) -> dict[str, Any]:
        """The state of an investigation this token started (its newest one if
        `investigation_id` is empty): `status` (waiting, running, done, stopped, refused,
        error, or interrupted when Kratos restarted while it ran), recent `progress` lines,
        and when done the checked `final_answer` (Kratos's findings block, its notes, then
        the model's analysis), `findings` and `recommended_commands` (for a person -- never
        run them automatically). `wait_seconds` (0-120) waits for the result first."""
        import asyncio

        client = _client(ctx)
        inv = str(investigation_id or "").strip()
        job = state.investigations.get(client.token_id, inv) if inv else state.investigations.newest(client.token_id)
        if job is not None:
            await _wait_for(job, wait_seconds)
            return untrusted.for_model(job.view(), field_cap=None)
        stored = await asyncio.to_thread(view_from_store, state.data_dir, client.token_id, inv or None)
        if stored is None:
            raise ValueError("no investigation with that id" if inv else "this token has started no investigation")
        return untrusted.for_model(stored, field_cap=None)

    @mcp.tool()
    def kratos_get_findings(ctx: Context, session_id: str | None = None) -> dict[str, Any]:
        """Findings from a Kratos session on a machine this token may reach (the most recent
        such session if `session_id` is omitted), grouped by the goal that produced them."""
        client = _client(ctx)
        allowed = set(_scope_targets(client))
        from kratos.storage.session_store import SessionStore

        store = SessionStore(state.data_dir / "kratos.db")
        if session_id:
            session = store.get_session(session_id)
            if session is None or not set(t.lower() for t in session["targets"]) <= allowed:
                raise ValueError("no session with that id")
        else:
            session = next((s for s in store.list_recent_sessions(limit=200)
                            if s["targets"] and set(t.lower() for t in s["targets"]) <= allowed), None)
            if session is None:
                return {"session_id": None, "target": [], "turns": []}
        turns = _stdio._load_session_turns(store, session["session_id"])
        return untrusted.for_model({"session_id": session["session_id"], "target": session["targets"],
                                    "turns": turns}, field_cap=None)

    @mcp.tool()
    def kratos_list_sessions(ctx: Context, limit: int = 10) -> list[dict[str, Any]]:
        """Recent Kratos sessions on machines this token may reach, most recent first."""
        client = _client(ctx)
        allowed = set(_scope_targets(client))
        from kratos.storage.session_store import SessionStore

        store = SessionStore(state.data_dir / "kratos.db")
        limit = max(1, min(int(limit or 10), 100))
        rows = [s for s in store.list_recent_sessions(limit=500)
                if s["targets"] and set(t.lower() for t in s["targets"]) <= allowed][:limit]
        return untrusted.for_model([{"session_id": s["session_id"], "name": s.get("name"), "targets": s["targets"],
                                     "last_goal": s.get("latest_goal"), "last_active_at": s["last_active_at"]}
                                    for s in rows], field_cap=None)

    @mcp.tool()
    def kratos_finding_states(ctx: Context, target: str | None = None, state_filter: str | None = None,
                              limit: int = 100) -> dict[str, Any]:
        """Read-only: the findings Kratos remembers for a machine this token may reach (or
        all of them), with each one's state and latest verdict. Changing a finding's state
        is a person-only action -- there is no tool for it."""
        client = _client(ctx)
        targets = [_resolve_target(client, target)] if target else _scope_targets(client)
        rows: list[dict[str, Any]] = []
        for t in targets:
            rows.extend(_stdio._finding_states_for(state.data_dir, t, state_filter, limit))
        return untrusted.for_model({"targets": targets, "count": len(rows), "findings": rows[:limit]},
                                   field_cap=None)

    app = mcp.streamable_http_app()
    return app, mcp.session_manager


def _remember(state: Any, job: Job, session_id: str) -> None:
    """Record mcp:<id> -> session, so the investigation is still found after a restart."""
    from kratos.serve import store as _store

    job.session_id = session_id
    _store.remember_session(state.data_dir, job.token_id, _KEY_PREFIX + job.investigation_id, job.target, session_id)


def _audit(state: Any, job: Job) -> None:
    from kratos.serve import store as _store

    try:
        _store.audit(state.data_dir, door="mcp", endpoint="kratos_start_investigation",
                     status={"done": "ok", "refused": "budget"}.get(job.status, job.status
                                                                     if job.status in ("stopped", "error") else "ok"),
                     token_id=job.token_id, target=job.target,
                     run_id=(job.outcome or {}).get("run_id"), metered=True,
                     duration=(job.finished or time.time()) - job.created)
    except Exception:  # noqa: BLE001
        logger.debug("serve: audit failed", exc_info=True)
    finally:
        state.release_metered(job.token_id)
