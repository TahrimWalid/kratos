"""The one way a headless door runs an investigation (docs/phaseB/B.3 §5.1).

Used by the chat server (OpenAI door), MCP over HTTP, and `kratos mcp-serve` (stdio).
Everything a run needs is set for THAT run only -- never a process global -- because the
chat server runs several at once:

* tools: `run_agent(tool_filter=headless_tool_filter)` -- no tool that could stop to ask a
  person (approval-gated, or one that may prompt from inside) is offered or dispatched;
  `TOOL_REGISTRY` itself is never touched;
* machine: `kratos_config.pinned_target(target)` (a contextvar; every thread the run
  starts copies it), and the dispatch target guard holds the model to it;
* approval and clarify: `approval_provider_scope(deny)` and `clarify_provider_scope(None)`
  -- if anything still asked, the answer is no, and the model is told nobody is there;
* budget: `budget.guard.precheck(source)` refuses before anything starts; the run's model
  calls are metered under its run scope (source `web` / `mcp`, unattended caps).

A run executes on the calling thread; the servers call it via `asyncio.to_thread`, which
copies the context. `RunSlots` bounds how many run at once (`serve.max_parallel`).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)

TRANSCRIPTS_DIRNAME = "sessions"


def headless_tool_filter(name: str) -> bool:
    """True for a tool a headless run may use: anything that could pause for a person's
    approval is left out (tool_reaches_approval -- the registry flag OR a request_approval
    call in the handler; fails safe on an unknown tool)."""
    from kratos.agent.tools import TOOL_REGISTRY, tool_reaches_approval

    return not tool_reaches_approval(TOOL_REGISTRY.get(name))


def _deny_approval(tool_name: str, details: dict[str, Any]) -> bool:
    return False


@dataclass
class RunRequest:
    goal: str
    target: str
    data_dir: Path
    source: str                                   # "mcp" | "web"
    session_id: str | None = None                 # append to this session (else a new one)
    prior_context: str | None = None              # earlier messages, already framed as data
    max_iters: int = 10
    timezone: str | None = None
    should_stop: Callable[[], bool] | None = None
    on_progress: Callable[[str], None] | None = None
    on_session: Callable[[str], None] | None = None   # told the session id as soon as it exists


@dataclass
class RunOutcome:
    status: str                                   # final_answer | stopped | refused_by_budget | stopped_by_budget | error | ...
    session_id: str | None
    run_id: str | None = None
    final_answer: str = ""
    answer_parts: dict[str, str] | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    recommended_commands: list[dict[str, Any]] = field(default_factory=list)
    token_usage: dict[str, Any] | None = None
    time: dict[str, Any] | None = None
    budget: dict[str, Any] | None = None
    error: str | None = None
    duration: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "status": self.status, "run_id": self.run_id,
                "final_answer": self.final_answer, "findings": self.findings,
                "recommended_commands": self.recommended_commands, "token_usage": self.token_usage,
                "time": self.time, "budget": self.budget}


def extract_findings(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every correlate_findings result in a transcript, in order (shared with mcp_server)."""
    findings: list[dict[str, Any]] = []
    for step in transcript or []:
        if step.get("tool") != "correlate_findings":
            continue
        obs = step.get("observation")
        if isinstance(obs, dict) and str(obs.get("status", "")).lower() != "error":
            inner = obs.get("result")
            obs = inner if isinstance(inner, dict) else obs
        if isinstance(obs, dict) and obs.get("findings"):
            findings.extend(obs["findings"])
    return findings


def _progress_for_step(step: dict[str, Any]) -> str | None:
    """A Kratos-written progress line for one transcript entry -- tool names and fixed
    words only, never text from the machine or the model."""
    tool = step.get("tool")
    if step.get("status") == "final_answer_rejected":
        return "checking the answer against what Kratos found…"
    if tool and step.get("collected"):
        return f"Kratos re-ran {tool} because new data arrived"
    if tool:
        return f"running {tool}"
    if step.get("tool_proposal"):
        return "the model noted a missing capability"
    return None


def run_investigation(req: RunRequest) -> RunOutcome:
    """Run one investigation for a headless door. Never raises for an ordinary failure:
    the outcome says what happened in plain words."""
    from kratos import kratos_config
    from kratos.agent.loop import InvestigationStopped, clarify_provider_scope, run_agent as _run_agent
    from kratos.agent.tools import approval_provider_scope
    from kratos.budget import breaker as _breaker
    from kratos.budget import guard as _guard
    from kratos.llm_config import get_active_llm_model
    from kratos.run_context import run_scope
    from kratos.storage.session_store import SessionStore

    started = time.monotonic()
    data_dir = Path(req.data_dir)
    target = req.target.strip()

    def progress(line: str) -> None:
        if req.on_progress is not None:
            try:
                req.on_progress(line)
            except Exception:  # noqa: BLE001 -- a progress reader never breaks the run
                logger.debug("progress callback failed", exc_info=True)

    with run_scope(req.source, target=target, session_id=req.session_id):
        refusal = _guard.precheck(req.source, data_dir_=data_dir)
    if refusal is not None:
        return RunOutcome(status="refused_by_budget", session_id=req.session_id,
                          final_answer=refusal.user_message(), budget=refusal.as_dict(),
                          duration=time.monotonic() - started)

    store = SessionStore(data_dir / "kratos.db")
    session_id = req.session_id or store.create_session([target], get_active_llm_model())
    turn_id = store.start_turn(session_id, req.goal)
    if req.on_session is not None:
        try:
            req.on_session(session_id)
        except Exception:  # noqa: BLE001 -- bookkeeping never stops the run
            logger.debug("on_session callback failed", exc_info=True)

    def on_step(step: dict[str, Any]) -> None:
        line = _progress_for_step(step)
        if line:
            progress(line)

    status, result, error = "error", None, None
    with kratos_config.pinned_target(target), approval_provider_scope(_deny_approval), \
            clarify_provider_scope(None), run_scope(req.source, target=target, session_id=session_id):
        try:
            result = _run_agent(req.goal, data_dir, max_iters=req.max_iters, on_step=on_step,
                               prior_context=req.prior_context, timezone=req.timezone,
                               session_id=session_id, should_stop=req.should_stop,
                               tool_filter=headless_tool_filter, on_progress=progress)
            status = str(result.get("status") or "error")
        except InvestigationStopped:
            status = "stopped"
        except Exception as e:  # noqa: BLE001 -- reported in plain words, recorded below
            logger.warning("headless investigation failed", exc_info=True)
            status, error = "error", f"{type(e).__name__}: {str(e)[:200]}"
            _breaker.record_outcome(data_dir, req.source, failure=f"the run raised {type(e).__name__}")
    if result is not None and status != "stopped_by_budget":
        _breaker.record_outcome(data_dir, req.source, failure=_breaker.run_failure_reason(result))

    transcript = (result or {}).get("transcript") or []
    transcripts_dir = data_dir / TRANSCRIPTS_DIRNAME
    transcripts_dir.mkdir(parents=True, exist_ok=True)
    transcript_path = transcripts_dir / f"{session_id}_turn{turn_id}.json"
    transcript_path.write_text(json.dumps(transcript, indent=2, default=str), encoding="utf-8")
    store.complete_turn(turn_id, status if status != "stopped" else "cancelled", transcript_ref=str(transcript_path))

    r = result or {}
    final = r.get("final_answer") or ""
    if status == "stopped":
        final = "Stopped: the investigation was stopped before it finished, so this is no answer."
    elif status == "error" and not final:
        final = "The investigation could not finish: " + (error or "an unexpected error")
    return RunOutcome(status=status, session_id=session_id, run_id=r.get("run_id"), final_answer=final,
                      answer_parts=r.get("answer_parts"), findings=extract_findings(transcript),
                      recommended_commands=list(r.get("recommended_commands") or []),
                      token_usage=r.get("token_usage"), time=r.get("time"), budget=r.get("budget"),
                      error=error, duration=time.monotonic() - started)


class RunSlots:
    """At most `serve.max_parallel` investigations at once (read fresh on every wait, so
    a change applies without a restart); the rest wait their turn, in order."""

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = Path(data_dir)
        self._cond = threading.Condition()
        self._active = 0
        self._queue: list[object] = []

    def _limit(self) -> int:
        from kratos import settings_store
        from kratos.serve import settings as _s

        try:
            return int(settings_store.get(_s.MAX_PARALLEL, data_dir=self._data_dir))
        except Exception:  # noqa: BLE001
            return 2

    @property
    def active(self) -> int:
        return self._active

    @property
    def waiting(self) -> int:
        return len(self._queue)

    def acquire(self, *, should_stop: Callable[[], bool] | None = None,
                on_wait: Callable[[], None] | None = None) -> bool:
        """Take a slot; False if `should_stop` turned true while waiting."""
        me = object()
        with self._cond:
            self._queue.append(me)
            told = False
            try:
                while self._queue[0] is not me or self._active >= self._limit():
                    if should_stop is not None and should_stop():
                        return False
                    if not told and on_wait is not None:
                        told = True
                        on_wait()
                    self._cond.wait(0.5)
                self._active += 1
                return True
            finally:
                self._queue.remove(me)
                self._cond.notify_all()

    def release(self) -> None:
        with self._cond:
            self._active = max(0, self._active - 1)
            self._cond.notify_all()
