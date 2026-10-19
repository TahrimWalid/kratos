"""MCP over Streamable HTTP, stateless, start-then-poll (docs/phaseB/B.3 §3.2).

An investigation takes minutes; an MCP tool call should not. So
`kratos_start_investigation(goal, target)` returns an investigation id at once and the
run goes on in the background; `kratos_get_investigation(id)` reports its progress lines
and, when it has finished, the checked answer and the findings. The id is random and
bound to the token that started it -- another token asking for it is told it does not
exist. Works with clients on MCP 2025-11-25 (the SDK's newest) and with the stateless
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

    def running(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.finished is None)


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
                                                       on_progress=job.progress.append))
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
    def kratos_start_investigation(goal: str, target: str, ctx: Context) -> dict[str, Any]:
        """Starts a Kratos investigation of `target` (a machine this token may reach -- an
        address or name, or a model id like "kratos/web-01") for `goal`, and returns at once
        with an `investigation_id`. Poll kratos_get_investigation for progress and, when it
        has finished, the checked answer and findings. Kratos's own agent picks which checks
        run; read-only -- nothing reachable here changes the machine."""
        client = _client(ctx)
        if not goal or not goal.strip():
            raise ValueError("goal is required")
        resolved = _resolve_target(client, target)
        from kratos.serve import store as _store
        from kratos.serve.openai_routes import _hourly_limit

        limit = _hourly_limit(state.data_dir)
        if _store.metered_requests_since(state.data_dir, client.token_id, time.time() - 3600) >= limit:
            raise ValueError(f"this token has used its {limit} investigations for this hour (serve.requests_per_hour)")
        job = state.investigations.new(client.token_id, resolved, goal)
        threading.Thread(target=contextvars.copy_context().run, args=(_run, job, goal.strip()),
                         name=f"serve-mcp-{job.investigation_id[:12]}", daemon=True).start()
        return {"investigation_id": job.investigation_id, "status": job.status, "target": resolved}

    @mcp.tool()
    def kratos_get_investigation(investigation_id: str, ctx: Context) -> dict[str, Any]:
        """The state of an investigation this token started: `status` (waiting, running,
        done, stopped, refused, error), recent `progress` lines, and when done the checked
        `final_answer` (Kratos's findings block, its notes, then the model's analysis),
        `findings` and `recommended_commands` (for a person -- never run them automatically)."""
        client = _client(ctx)
        job = state.investigations.get(client.token_id, investigation_id)
        if job is None:
            raise ValueError("no investigation with that id")
        out: dict[str, Any] = {"investigation_id": job.investigation_id, "status": job.status,
                               "target": job.target, "progress": list(job.progress)}
        if job.outcome is not None:
            out.update({k: job.outcome.get(k) for k in ("final_answer", "findings", "recommended_commands",
                                                         "session_id", "run_id", "token_usage", "budget")})
        return untrusted.for_model(out, field_cap=None)

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
