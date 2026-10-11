"""Who is running what -- readable from anywhere in the call stack.

Every entry point that starts work (a TUI turn, `kratos investigate`, a scheduled
run, a trigger, an MCP call, `/evolve`, ...) opens a `run_scope`. Code deep in the
stack -- the model interface, the event store -- reads `current()` to attribute
what it does to that run: which run, started how, about which machine, in which
session. A scope opened inside another gets its own `run_id` and records the
outer one as `parent_run_id` (a trigger investigation inside a scheduled run).

A ContextVar does not flow into a new thread. Every worker thread (Textual
`@work(thread=True)`, `threading.Thread`, an executor) opens its own `run_scope`
inside the thread, or runs its target through `contextvars.copy_context().run`
(`asyncio.to_thread` already does). `tests/test_run_context.py` checks every
entry point.
"""
from __future__ import annotations

import contextlib
import contextvars
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TypeVar

from kratos.target_key import target_key

SOURCES = ("interactive", "schedule", "trigger", "pipeline", "mcp", "web", "evolve", "cli")
# Runs with no person watching: 0.4's hard spending caps apply to these.
UNATTENDED = frozenset({"schedule", "trigger", "mcp", "web"})


@dataclass(frozen=True)
class RunContext:
    run_id: str                  # uuid4 hex, new per run
    source: str                  # one of SOURCES
    target: str | None           # target_key(...) of the machine under investigation
    session_id: str | None       # TUI/REPL session, if any
    started_at: float            # epoch seconds, UTC
    parent_run_id: str | None = None

    @property
    def unattended(self) -> bool:
        return self.source in UNATTENDED


_CURRENT: contextvars.ContextVar[RunContext | None] = contextvars.ContextVar("kratos_run_context", default=None)


def current() -> RunContext | None:
    return _CURRENT.get()


def current_run_id() -> str | None:
    ctx = _CURRENT.get()
    return ctx.run_id if ctx else None


def _active_target_key() -> str | None:
    from kratos import kratos_config

    active = kratos_config.get_active_target()
    return target_key(active) if active else None


@contextlib.contextmanager
def run_scope(source: str, *, target: str | None = None,
              session_id: str | None = None) -> Iterator[RunContext]:
    """Open a run. `target` defaults to the enclosing run's target, else the
    active target; `session_id` defaults to the enclosing run's."""
    if source not in SOURCES:
        raise ValueError(f"unknown run source {source!r}; expected one of {SOURCES}")
    parent = _CURRENT.get()
    if target is not None:
        key: str | None = target_key(target) or None
    elif parent is not None:
        key = parent.target
    else:
        key = _active_target_key()
    ctx = RunContext(
        run_id=uuid.uuid4().hex,
        source=source,
        target=key,
        session_id=session_id if session_id is not None else (parent.session_id if parent else None),
        started_at=time.time(),
        parent_run_id=parent.run_id if parent else None,
    )
    token = _CURRENT.set(ctx)
    try:
        yield ctx
    finally:
        _CURRENT.reset(token)


T = TypeVar("T")


def bind(fn: Callable[..., T]) -> Callable[..., T]:
    """`fn` wrapped to run in a copy of the CURRENT context -- for handing work to
    a plain thread or executor, which would otherwise start with no run."""
    ctx = contextvars.copy_context()

    def runner(*args: Any, **kwargs: Any) -> T:
        return ctx.run(fn, *args, **kwargs)

    return runner
