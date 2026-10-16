"""A second copy of a run record for the person's own OpenTelemetry collector
(docs/phaseB/B.5 §5.5). Imported only when the `otel` extra is installed AND the
person turned on `trace.otel_export`; the local JSON record is always written first.

What leaves: span names, timings, statuses, token counts, cost, model and tool
names, guard names, finding ids. Never tool arguments or results, prompts, the
goal, the machine's name or the session -- those stay in the local file.

Where it goes: only to `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT`
(OTLP over HTTP/protobuf, the standard env vars, headers included). With neither
set nothing is sent -- the exporter's own default (localhost) is never used.

Span names follow the OpenTelemetry GenAI semantic conventions (development status,
checked 2026-10-16 against open-telemetry/semantic-conventions-genai, links at
semconv v1.44): the investigation is `invoke_agent kratos`, a model call
`chat {gen_ai.request.model}` (CLIENT) with gen_ai.operation.name, gen_ai.provider.name,
gen_ai.request.model, gen_ai.request.max_tokens, gen_ai.usage.input_tokens,
gen_ai.usage.output_tokens, error.type; a tool call `execute_tool {gen_ai.tool.name}`
with gen_ai.tool.name, gen_ai.tool.call.id, gen_ai.tool.type. Kratos's own spans use a
`kratos.` prefix. The OTel trace id is the run id (both are 128 bits), so a run can be
found in Jaeger/Grafana by its `kratos trace show` id.

Export runs on its own (non-daemon) thread with a short timeout: a slow or dead
collector delays nothing in the run, and a failure is logged once per endpoint.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime
from typing import Any

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.trace import SpanKind, Status, StatusCode, set_span_in_context

logger = logging.getLogger(__name__)

EXPORT_TIMEOUT_SECONDS = 5.0
ENDPOINT_VARS = ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT")

_warned: set[str] = set()          # endpoints already reported as failing (logging only, no run state)
_warned_lock = threading.Lock()


def configured_endpoint() -> str | None:
    for var in ENDPOINT_VARS:
        value = os.environ.get(var, "").strip()
        if value:
            return value
    return None


def _ns(iso: Any) -> int | None:
    if not iso:
        return None
    try:
        return int(datetime.fromisoformat(str(iso)).timestamp() * 1_000_000_000)
    except ValueError:
        return None


def _hex_id(text: str, bits: int) -> int:
    """`text` as an id of `bits` bits: itself when it is that much hex, else its sha256."""
    s = str(text or "")
    n = bits // 4
    if len(s) == n and all(c in "0123456789abcdef" for c in s):
        value = int(s, 16)
    else:
        value = int(hashlib.sha256(s.encode()).hexdigest()[:n], 16)
    return value or 1


class _FixedIds(IdGenerator):
    """Hands out the ids Kratos already chose (the run id, each span's id)."""

    def __init__(self, trace_id: int) -> None:
        self.trace_id = trace_id
        self.next_span_id = 1

    def generate_trace_id(self) -> int:
        return self.trace_id

    def generate_span_id(self) -> int:
        return self.next_span_id


class _Collect(SpanProcessor):
    def __init__(self) -> None:
        self.spans: list[ReadableSpan] = []

    def on_end(self, span: ReadableSpan) -> None:
        self.spans.append(span)


_PROVIDERS = (("gemini", "gcp.gemini"), ("gpt", "openai"), ("o1", "openai"), ("o3", "openai"),
              ("claude", "anthropic"), ("mistral", "mistral"), ("deepseek", "deepseek"), ("grok", "x_ai"))


def provider_name(model: str, local: bool) -> str:
    m = (model or "").lower()
    for needle, name in _PROVIDERS:
        if needle in m:
            return name
    return "kratos.local" if local else "kratos.openai_compatible"


def _clean(attrs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in attrs.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            v = [str(x) for x in v]
        elif not isinstance(v, (str, bool, int, float)):
            v = str(v)
        out[k] = v
    return out


def _describe(span: dict[str, Any], root: bool, trace: dict[str, Any]) -> tuple[str, SpanKind, dict[str, Any]]:
    """(name, kind, attributes) for one recorded span -- the export allowlist."""
    kind = span.get("kind")
    a = span.get("attrs") or {}
    status = span.get("status")
    base = {"kratos.span.kind": kind, "kratos.status": status}
    if root:
        run_kind = trace.get("kind") or a.get("run_kind")
        attrs = {**base, "kratos.run_id": trace.get("run_id"), "kratos.trace_id": trace.get("trace_id"),
                 "kratos.run.kind": run_kind, "kratos.run.source": trace.get("source"),
                 "kratos.parent_run_id": trace.get("parent_run_id")}
        for k in ("model_calls", "tool_calls", "prompt_tokens", "completion_tokens", "cost_usd"):
            attrs[f"kratos.total.{k}"] = (trace.get("totals") or {}).get(k)
        if run_kind == "investigation":
            attrs.update({"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "kratos"})
            return "invoke_agent kratos", SpanKind.INTERNAL, attrs
        return f"kratos.run {run_kind}", SpanKind.INTERNAL, attrs
    if kind == "model_call":
        model = str(a.get("model") or "")
        attrs = {**base, "gen_ai.operation.name": "chat",
                 "gen_ai.provider.name": provider_name(model, bool(a.get("local"))),
                 "gen_ai.request.model": model, "gen_ai.request.max_tokens": a.get("max_tokens"),
                 "gen_ai.usage.input_tokens": a.get("prompt_tokens"),
                 "gen_ai.usage.output_tokens": a.get("completion_tokens"),
                 "kratos.cost_usd": a.get("cost_usd"), "kratos.ledger_row_id": a.get("ledger_row_id"),
                 "kratos.model.local": bool(a.get("local"))}
        if status not in ("ok", None):
            attrs["error.type"] = status
        return f"chat {model}", SpanKind.CLIENT, attrs
    if kind == "tool_call":
        tool = str(a.get("tool") or span.get("name") or "")
        attrs = {**base, "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": tool,
                 "gen_ai.tool.type": "function", "gen_ai.tool.call.id": a.get("envelope_id"),
                 "kratos.approval_asked": a.get("approval_asked"), "kratos.approval_answer": a.get("approval_answer"),
                 "kratos.skipped": a.get("skipped")}
        if status not in ("ok", None):
            attrs["error.type"] = status
        return f"execute_tool {tool}", SpanKind.INTERNAL, attrs
    if kind == "collection_check":
        return (f"kratos.collection_check {span.get('name')}", SpanKind.INTERNAL,
                {**base, "kratos.check": span.get("name"), "kratos.check.source": a.get("source"),
                 "kratos.transport": a.get("transport"), "kratos.check.outcome": a.get("outcome"),
                 "kratos.check.still_running_at_start_budget": a.get("still_running_at_start_budget"),
                 "kratos.check.settled_later": a.get("settled_later")})
    if kind == "guard":
        return (f"kratos.guard {span.get('name')}", SpanKind.INTERNAL,
                {**base, "kratos.guard": span.get("name"), "kratos.guard.action": a.get("action")})
    if kind == "answer":
        return ("kratos.answer", SpanKind.INTERNAL,
                {**base, "kratos.answer.block_finding_ids": a.get("block_finding_ids"),
                 "kratos.answer.note_count": a.get("note_count"),
                 "kratos.answer.model_text_chars": a.get("model_text_chars")})
    if kind == "child_run":
        return ("kratos.child_run", SpanKind.INTERNAL, {**base, "kratos.child_run_id": a.get("child_run_id")})
    if kind == "run":
        return (f"kratos.run {a.get('run_kind')}", SpanKind.INTERNAL, {**base, "kratos.run.kind": a.get("run_kind")})
    return f"kratos.{kind}", SpanKind.INTERNAL, base


def build_spans(trace: dict[str, Any]) -> list[ReadableSpan]:
    """The recorded run as finished OTel spans (not exported)."""
    ids = _FixedIds(_hex_id(trace.get("run_id") or trace.get("trace_id") or "", 128))
    collect = _Collect()
    # Resource(...) directly, not Resource.create(): create() runs resource detectors on a
    # thread pool, which fails once a short CLI process is shutting down (seen live).
    provider = TracerProvider(resource=Resource({"service.name": os.environ.get("OTEL_SERVICE_NAME") or "kratos"}),
                              id_generator=ids, shutdown_on_exit=False)
    provider.add_span_processor(collect)
    tracer = provider.get_tracer("kratos.trace")
    spans = [s for s in trace.get("spans") or [] if isinstance(s, dict)]
    live: dict[str, Any] = {}
    end_of_run = _ns(trace.get("finished")) or _ns(spans[0].get("end")) if spans else None
    for n, s in enumerate(spans):
        name, kind, attrs = _describe(s, n == 0, trace)
        parent = live.get(s.get("parent_id"))
        ids.next_span_id = _hex_id(s.get("id") or str(n), 64)
        start = _ns(s.get("start"))
        otel_span = tracer.start_span(name, context=set_span_in_context(parent) if parent is not None else None,
                                      kind=kind, attributes=_clean(attrs), start_time=start)
        if s.get("status") in ("error", "tool_error", "refused_by_budget", "not_approved"):
            otel_span.set_status(Status(StatusCode.ERROR, str(s.get("status"))))
        live[s.get("id")] = otel_span
    for s in reversed(spans):                       # children end before their parents
        otel_span = live.get(s.get("id"))
        if otel_span is not None:
            otel_span.end(end_time=_ns(s.get("end")) or end_of_run or _ns(s.get("start")))
    provider.shutdown()
    return list(collect.spans)


def _new_exporter(timeout: float) -> SpanExporter:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    return OTLPSpanExporter(timeout=timeout)


def _send(spans: list[ReadableSpan], exporter: SpanExporter, endpoint: str, own: bool) -> bool:
    try:
        result = exporter.export(spans)
        ok = result == SpanExportResult.SUCCESS
        if not ok:
            _warn_once(endpoint, f"could not send run records to the OpenTelemetry collector at {endpoint}; "
                                 "they stay in the local file (this is logged once)")
        return ok
    except Exception as e:  # noqa: BLE001 -- the export never affects a run
        _warn_once(endpoint, f"could not send run records to the OpenTelemetry collector at {endpoint} "
                             f"({type(e).__name__}); they stay in the local file (this is logged once)")
        return False
    finally:
        if own:
            try:
                exporter.shutdown()
            except Exception:  # noqa: BLE001
                pass


def _prepare(trace: dict[str, Any], exporter: SpanExporter | None,
             timeout: float) -> tuple[list[ReadableSpan], SpanExporter, str, bool] | None:
    """Spans and exporter, built on the caller's thread (no network)."""
    own = exporter is None
    endpoint = "test exporter" if exporter is not None else configured_endpoint()
    if endpoint is None:
        _warn_once("no endpoint", "trace.otel_export is on but OTEL_EXPORTER_OTLP_ENDPOINT is not set; "
                                  "run records stay local only")
        return None
    try:
        spans = build_spans(trace)
        return spans, (exporter if exporter is not None else _new_exporter(timeout)), endpoint, own
    except Exception as e:  # noqa: BLE001
        _warn_once(endpoint, f"could not prepare run records for the OpenTelemetry collector at {endpoint} "
                             f"({type(e).__name__}); they stay in the local file (this is logged once)")
        return None


def export(trace: dict[str, Any], *, exporter: SpanExporter | None = None,
           timeout: float = EXPORT_TIMEOUT_SECONDS) -> bool:
    """Send one run, on this thread. True when the collector accepted it. Never raises."""
    ready = _prepare(trace, exporter, timeout)
    return _send(*ready) if ready is not None else False


def _warn_once(key: str, message: str) -> None:
    with _warned_lock:
        if key in _warned:
            return
        _warned.add(key)
    logger.warning(message)


def export_in_background(trace: dict[str, Any]) -> threading.Thread | None:
    """Build the spans here (cheap, no network), send them on their own thread. Not a
    daemon: a short-lived `kratos investigate` waits at most the export timeout at exit
    instead of dropping the copy."""
    ready = _prepare(trace, None, EXPORT_TIMEOUT_SECONDS)
    if ready is None:
        return None
    t = threading.Thread(target=_send, args=ready, name="kratos-otel-export", daemon=False)
    t.start()
    return t
