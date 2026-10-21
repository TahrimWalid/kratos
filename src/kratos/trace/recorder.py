"""Run records: one local JSON trace per run (docs/phaseB/B.5 §5.4).

Every investigation, standard audit, pipeline, scheduled run and trigger opens
`run_trace(...)`. Inside it, the hooks record spans into the CURRENT trace:

  * `model_call`        -- llm_interface._metered_call (the one model choke point)
  * `tool_call`         -- agent.loop.execute_tool_call (every tool dispatch)
  * `collection_check`  -- collect.runner.prepare (each check, reused or run)
  * `guard` / `answer`  -- agent.loop (guard rejections/NOTEs, how the answer was built)
  * `collection` / `collection_settled` -- agent.loop (the collected report the model started
                          from, and checks folded in before the answer; what evals/replay replays)
  * `run`               -- the run itself, and a nested run kind (an audit inside a schedule)

The trace being built lives in a ContextVar, never a module global: parallel runs in
separate threads each record into their own, and a worker thread started with a copy
of the context (collection checks, `asyncio.to_thread`) records into its run's trace.
A run opened inside another run (a trigger's investigation inside a scheduled run --
a new `run_context` scope) gets its own trace that names the parent.

The file is written once when the run ends -- `data_dir/traces/<YYYY-MM-DD>/<run_id>.json`,
atomically, owner-only. While the run is going, a `.partial` copy is refreshed every few
seconds, so a crash (or a run that raises) leaves a readable record. A span that ends
after its run finished (a check still running in the background) rewrites the file.

Tool results are kept in full up to `trace.max_result_bytes`; a larger one keeps its
head and the sha256 of the whole. Prompts are kept only with `trace.store_prompts`.
Nothing here may fail a run: every hook swallows its own errors.
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from kratos import paths, run_context

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
TRACES_DIR = "traces"
PARTIAL_SUFFIX = ".partial"
PARTIAL_FLUSH_SECONDS = 3.0
KINDS = ("run", "model_call", "tool_call", "collection_check", "collection", "collection_settled", "guard", "answer",
         "child_run")

_TRACE: contextvars.ContextVar["Trace | None"] = contextvars.ContextVar("kratos_trace", default=None)
_SPAN: contextvars.ContextVar["Span | None"] = contextvars.ContextVar("kratos_trace_span", default=None)
_LAST_TOOL: contextvars.ContextVar["Span | None"] = contextvars.ContextVar("kratos_trace_last_tool", default=None)


def _now_iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="milliseconds")


def _new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def cap_value(value: Any, max_bytes: int) -> Any:
    """`value` as stored in a trace: itself when its JSON is at most `max_bytes`, else
    {"truncated": true, "bytes": N, "sha256": <of the whole JSON>, "head": <first part>}."""
    try:
        text = json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        text = json.dumps(str(value), ensure_ascii=False)
    raw = text.encode("utf-8", "surrogatepass")
    if len(raw) <= max_bytes:
        return value if isinstance(value, (dict, list, str, int, float, bool, type(None))) else json.loads(text)
    return {"truncated": True, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "head": raw[:max_bytes].decode("utf-8", "replace")}


@dataclass
class Span:
    trace: "Trace"
    id: str
    parent_id: str | None
    kind: str
    name: str
    start: float
    start_mono: float
    attrs: dict[str, Any] = field(default_factory=dict)
    end: float | None = None
    end_mono: float | None = None
    status: str | None = None

    def set(self, **attrs: Any) -> "Span":
        with self.trace.lock:
            self.attrs.update(attrs)
        return self

    def finish(self, status: str = "ok", **attrs: Any) -> None:
        late = False
        with self.trace.lock:
            if self.end is not None:
                self.attrs.update(attrs)
                return
            self.attrs.update(attrs)
            self.end, self.end_mono = time.time(), time.monotonic()
            self.status = status
            late = self.trace.finished
        if late:
            self.trace.rewrite()
        else:
            self.trace.maybe_flush()

    @property
    def duration_ms(self) -> float | None:
        return None if self.end_mono is None else round((self.end_mono - self.start_mono) * 1000, 1)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "parent_id": self.parent_id, "kind": self.kind, "name": self.name,
                "start": _now_iso(self.start), "end": _now_iso(self.end) if self.end is not None else None,
                "duration_ms": self.duration_ms, "status": self.status or "unfinished", "attrs": self.attrs}


class _NoSpan:
    """What the hooks get when no trace is being recorded."""
    id = None

    def set(self, **attrs: Any) -> "_NoSpan":
        return self

    def finish(self, status: str = "ok", **attrs: Any) -> None:
        return None


NO_SPAN = _NoSpan()


class Trace:
    def __init__(self, *, run_id: str, trace_id: str, kind: str, name: str, data_dir: Path,
                 ctx: run_context.RunContext | None, max_result_bytes: int, store_prompts: bool,
                 otel_export: bool) -> None:
        self.run_id = run_id
        self.trace_id = trace_id
        self.kind = kind
        self.name = name
        self.data_dir = Path(data_dir)
        self.source = ctx.source if ctx else None
        # the scope's machine; else the one active when the run started (`kratos run --target`
        # sets it after main() opened the CLI's scope)
        self.target = (ctx.target if ctx and ctx.target else None) or _safe_active_target()
        self.session_id = ctx.session_id if ctx else None
        self.parent_run_id = ctx.parent_run_id if ctx else None
        self.has_context = ctx is not None
        self.max_result_bytes = max_result_bytes
        self.store_prompts = store_prompts
        self.otel_export = otel_export
        self.lock = threading.RLock()
        self.spans: list[Span] = []
        self.started = time.time()
        self.status = "running"
        self.finished = False
        self.result: dict[str, Any] = {}
        self._last_flush = 0.0
        day = datetime.fromtimestamp(self.started, timezone.utc).strftime("%Y-%m-%d")
        self.path = self.data_dir / TRACES_DIR / day / f"{trace_id}.json"

    # --- spans ---
    def open_span(self, kind: str, name: str, parent: Span | None, attrs: dict[str, Any]) -> Span:
        sp = Span(self, _new_span_id(), parent.id if parent is not None else None, kind, name,
                  time.time(), time.monotonic(), dict(attrs))
        with self.lock:
            self.spans.append(sp)
        return sp

    @property
    def root(self) -> Span:
        return self.spans[0]

    # --- file ---
    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            spans = [s.to_dict() for s in self.spans]
            totals = _totals(self.spans)
            return {
                "format": FORMAT_VERSION, "run_id": self.run_id, "trace_id": self.trace_id, "kind": self.kind,
                "name": self.name, "source": self.source, "target": self.target, "session_id": self.session_id,
                "parent_run_id": self.parent_run_id, "started": _now_iso(self.started),
                "finished": _now_iso(self.root.end) if self.finished and self.root.end else None,
                "status": self.status, "result": dict(self.result), "totals": totals,
                "settings": {"max_result_bytes": self.max_result_bytes, "store_prompts": self.store_prompts},
                "spans": spans,
            }

    def _write(self, path: Path) -> None:
        paths.ensure_private_dir(path.parent)
        paths.ensure_private_dir(self.data_dir / TRACES_DIR)
        # ASCII-escaped: every character (a lone surrogate from a log line too) survives exactly
        body = json.dumps(self.to_dict(), default=str, ensure_ascii=True, indent=1)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)  # the temp file this write just created
            raise

    @property
    def partial_path(self) -> Path:
        return self.path.with_name(self.path.name + PARTIAL_SUFFIX)

    def maybe_flush(self, force: bool = False) -> None:
        if self.finished:
            return
        now = time.monotonic()
        with self.lock:
            if not force and now - self._last_flush < PARTIAL_FLUSH_SECONDS:
                return
            self._last_flush = now
        try:
            self._write(self.partial_path)
        except Exception:  # noqa: BLE001 -- a record must never fail its run
            logger.debug("trace: partial write failed", exc_info=True)

    def finish(self, status: str, *, crashed: bool = False) -> None:
        with self.lock:
            self.status = status
            root = self.root
            if root.end is None:
                root.end, root.end_mono, root.status = time.time(), time.monotonic(), status
            self.finished = True
        try:
            if crashed:
                self._write(self.partial_path)   # a run that raised: the .partial is its record
                return
            self._write(self.path)
            with contextlib.suppress(OSError):
                self.partial_path.unlink()  # the partial copy this trace wrote while running
        except Exception:  # noqa: BLE001
            logger.warning("could not write the run record %s", self.path, exc_info=True)
            return
        if self.otel_export:
            _export_otel(self)

    def rewrite(self) -> None:
        """A span ended after the run finished: bring the written file up to date."""
        try:
            target = self.path if self.path.exists() else self.partial_path
            self._write(target)
        except Exception:  # noqa: BLE001
            logger.debug("trace: late rewrite failed", exc_info=True)


def _safe_active_target() -> str | None:
    try:
        return run_context._active_target_key()
    except Exception:  # noqa: BLE001
        return None


def _totals(spans: list[Span]) -> dict[str, Any]:
    t: dict[str, Any] = {"model_calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
                         "cost_usd": 0.0, "tool_calls": 0, "collection_checks": 0, "guards": 0}
    for s in spans:
        if s.kind == "model_call":
            t["model_calls"] += 1
            for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
                t[k] += int(s.attrs.get(k) or 0)
            t["cost_usd"] += float(s.attrs.get("cost_usd") or 0.0)
        elif s.kind == "tool_call":
            t["tool_calls"] += 1
        elif s.kind == "collection_check":
            t["collection_checks"] += 1
        elif s.kind == "guard":
            t["guards"] += 1
    t["cost_usd"] = round(t["cost_usd"], 6)
    root = spans[0] if spans else None
    if root is not None and root.end_mono is not None:
        t["duration_ms"] = round((root.end_mono - root.start_mono) * 1000, 1)
    return t


_otel_missing_said = threading.Event()   # logging only: say "extra missing" once per process


def _export_otel(tr: Trace) -> None:
    try:
        from kratos.trace import otel
    except Exception:  # noqa: BLE001 -- the extra isn't installed
        if not _otel_missing_said.is_set():
            _otel_missing_said.set()
            logger.warning("trace.otel_export is on but the OpenTelemetry extra is not installed "
                           "(pip install 'kratos[otel]'); run records stay local only")
        return
    try:
        otel.export_in_background(tr.to_dict())
    except Exception:  # noqa: BLE001 -- never affects the run
        logger.warning("could not start the OpenTelemetry export", exc_info=True)


# --- the public API --------------------------------------------------------

def current() -> Trace | None:
    return _TRACE.get()


def current_trace_id() -> str | None:
    tr = _TRACE.get()
    return tr.trace_id if tr is not None else None


def _settings(data_dir: Path) -> tuple[bool, int, bool, bool]:
    from kratos import settings_store
    from kratos.trace import settings as S

    try:
        return (bool(settings_store.get(S.ENABLED, data_dir=data_dir)),
                int(settings_store.get(S.MAX_RESULT_BYTES, data_dir=data_dir)),
                bool(settings_store.get(S.STORE_PROMPTS, data_dir=data_dir)),
                bool(settings_store.get(S.OTEL_EXPORT, data_dir=data_dir)))
    except Exception:  # noqa: BLE001 -- unreadable settings: record with the defaults
        logger.debug("trace: settings unreadable", exc_info=True)
        return True, 256 * 1024, False, False


def _unique_id(data_dir: Path, run_id: str, day: str) -> str:
    """The run's id -- or `<run_id>-2`, `-3`, ... when one run scope holds several
    traced runs (two investigations started from one TUI turn)."""
    folder = Path(data_dir) / TRACES_DIR / day
    candidate, n = run_id, 1
    while (folder / f"{candidate}.json").exists() or (folder / f"{candidate}.json{PARTIAL_SUFFIX}").exists() \
            or candidate in _IN_FLIGHT:
        n += 1
        candidate = f"{run_id}-{n}"
    return candidate


_IN_FLIGHT: set[str] = set()   # trace ids being written by this process (guards _unique_id races)
_IN_FLIGHT_LOCK = threading.Lock()


@contextlib.contextmanager
def run_trace(kind: str, data_dir: Path | str | None, *, name: str = "", _file_suffix: str | None = None,
              **attrs: Any) -> Iterator[Trace | None]:
    """Record a run. Inside a trace of the same run it is a nested `run` span; inside a
    different run (a child scope) it starts the child's own trace and notes it in the
    parent's. Yields the Trace (None when recording is off or impossible)."""
    ctx = run_context.current()
    active = _TRACE.get()
    if active is not None and not active.finished and (
            (ctx is None and not active.has_context) or (ctx is not None and ctx.run_id == active.run_id)):
        sp = start_span("run", name or kind, run_kind=kind, **attrs)
        token = _SPAN.set(sp) if isinstance(sp, Span) else None
        status = "ok"
        try:
            yield active
        except BaseException as e:
            status = "error"
            sp.set(error=f"{type(e).__name__}: {str(e)[:300]}")
            raise
        finally:
            if token is not None:
                _SPAN.reset(token)
            sp.finish(status)
        return
    if data_dir is None:
        from kratos import kratos_config
        data_dir = kratos_config.get_active_data_dir()
    tr: Trace | None = None
    if data_dir is not None:
        try:
            enabled, max_bytes, store_prompts, otel_export = _settings(Path(data_dir))
            if enabled:
                run_id = ctx.run_id if ctx is not None else uuid.uuid4().hex
                day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                with _IN_FLIGHT_LOCK:
                    trace_id = _unique_id(Path(data_dir), f"{run_id}-{_file_suffix}" if _file_suffix else run_id, day)
                    _IN_FLIGHT.add(trace_id)
                tr = Trace(run_id=run_id, trace_id=trace_id, kind=kind, name=name or kind, data_dir=Path(data_dir),
                           ctx=ctx, max_result_bytes=max_bytes, store_prompts=store_prompts, otel_export=otel_export)
                tr.open_span("run", name or kind, None, {"run_kind": kind, **attrs})
        except Exception:  # noqa: BLE001
            logger.warning("could not start a run record", exc_info=True)
            tr = None
    if tr is None:
        yield None
        return
    if active is not None and not active.finished:
        event("child_run", kind, child_run_id=tr.run_id, child_trace_id=tr.trace_id)
    t_token = _TRACE.set(tr)
    s_token = _SPAN.set(tr.root)
    tr.maybe_flush(force=True)
    crashed = False
    ended_as: str | None = None
    try:
        yield tr
    except BaseException as e:
        # A run the person deliberately stopped (agent.loop.InvestigationStopped says so
        # with `trace_status`) is a finished record with status "stopped", not a crash.
        ended_as = getattr(e, "trace_status", None)
        crashed = ended_as is None
        tr.root.set(error=f"{type(e).__name__}: {str(e)[:300]}") if crashed else tr.root.set(stopped=True)
        raise
    finally:
        _SPAN.reset(s_token)
        _TRACE.reset(t_token)
        try:
            tr.finish(ended_as or ("error" if crashed else (tr.status if tr.status != "running" else "ok")),
                      crashed=crashed)
        finally:
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT.discard(tr.trace_id)


def set_result(**result: Any) -> None:
    """The run's outcome (status, counts) -- stored on the trace."""
    tr = _TRACE.get()
    if tr is None:
        return
    with tr.lock:
        if "status" in result and result["status"]:
            tr.status = str(result["status"])
        tr.result.update(result)


def start_span(kind: str, name: str, *, parent: Span | None = None, **attrs: Any) -> Span | _NoSpan:
    """A span in the current trace, child of the current span (or `parent`). It is NOT
    made current: use `span()` for that, or `use_span()` from another thread."""
    tr = _TRACE.get()
    if tr is None:
        return NO_SPAN
    try:
        return tr.open_span(kind, name, parent if parent is not None else _SPAN.get(), attrs)
    except Exception:  # noqa: BLE001
        logger.debug("trace: span failed", exc_info=True)
        return NO_SPAN


@contextlib.contextmanager
def use_span(sp: Span | _NoSpan) -> Iterator[None]:
    """Make `sp` the parent of spans opened inside (e.g. a check's tool calls)."""
    if not isinstance(sp, Span):
        yield
        return
    t1 = _TRACE.set(sp.trace)
    t2 = _SPAN.set(sp)
    try:
        yield
    finally:
        _SPAN.reset(t2)
        _TRACE.reset(t1)


@contextlib.contextmanager
def span(kind: str, name: str, **attrs: Any) -> Iterator[Span | _NoSpan]:
    """A span around a block; an exception marks it `error` (and propagates)."""
    sp = start_span(kind, name, **attrs)
    if not isinstance(sp, Span):
        yield sp
        return
    token = _SPAN.set(sp)
    status = "ok"
    try:
        yield sp
    except BaseException as e:
        status = "error"
        sp.set(error=f"{type(e).__name__}: {str(e)[:300]}")
        raise
    finally:
        _SPAN.reset(token)
        sp.finish(status)   # no-op when the block already finished it with its own status


def event(kind: str, name: str, **attrs: Any) -> None:
    """A zero-length span (a guard firing, the answer's composition)."""
    sp = start_span(kind, name, **attrs)
    sp.finish("ok")


def note_last_tool(sp: Span | _NoSpan) -> None:
    _LAST_TOOL.set(sp if isinstance(sp, Span) else None)


def annotate_last_tool(*, expect_name: str | None = None, **attrs: Any) -> None:
    """Add to the tool span this context's last `execute_tool_call` recorded (the
    envelope call id is chosen after the call returns). Once: a call refused before
    dispatch has no span, and must not annotate the previous one."""
    sp = _LAST_TOOL.get()
    if sp is None or sp.trace is not _TRACE.get() or (expect_name and sp.name != expect_name):
        return
    sp.set(**attrs)
    _LAST_TOOL.set(None)


# What a model request outside any run record is for ("route" for the message router);
# names the small record such a request gets (standalone_record).
_PURPOSE: contextvars.ContextVar["str | None"] = contextvars.ContextVar("kratos_trace_purpose", default=None)


@contextlib.contextmanager
def purpose(label: str) -> Iterator[None]:
    """Name the model requests made inside this block, for the record they get when no
    run record is open (`kratos trace list` shows it)."""
    token = _PURPOSE.set(label)
    try:
        yield
    finally:
        _PURPOSE.reset(token)


@contextlib.contextmanager
def standalone_record(data_dir: Path | str | None) -> Iterator[Trace | None]:
    """A record for ONE model request made outside any run record -- the message router,
    a plain chat reply, a pipeline draft, compaction, `kratos chat`. Every request to the
    model then leaves a record, so `kratos trace show --sent` can show what it sent
    (Phase B audit: the router's request, which carries the conversation, left none). It
    belongs to the enclosing run (budget rows, per-run caps and masking are unchanged); only
    its FILE gets a suffix (`<run>-route.json`), so it never takes the name of the
    investigation record that may follow in the same run."""
    label = _PURPOSE.get() or "model call"
    kind = label.split()[0]
    with run_trace(kind, data_dir, name=label, _file_suffix=kind) as tr:
        yield tr


def result_for_trace(value: Any) -> Any:
    """A tool result, capped per this trace's setting."""
    tr = _TRACE.get()
    return cap_value(value, tr.max_result_bytes if tr is not None else 256 * 1024)


def prompts_enabled() -> bool:
    tr = _TRACE.get()
    return bool(tr is not None and tr.store_prompts)


def bind(fn):  # noqa: ANN001, ANN201
    """`fn` run in a copy of the current context (trace and run) -- for a plain thread."""
    ctx = contextvars.copy_context()

    def runner(*args: Any, **kwargs: Any) -> Any:
        return ctx.run(fn, *args, **kwargs)

    return runner
