"""The optional OpenTelemetry copy of a run record (kratos.trace.otel, docs/phaseB/B.5 §5.5):
the span tree and names, nothing sensitive exported, a failing collector never
affects the run, and without the extra nothing is imported."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time

import pytest

pytest.importorskip("opentelemetry.sdk")

from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402
from opentelemetry.trace import SpanKind  # noqa: E402

from kratos import kratos_config, settings_store  # noqa: E402
from kratos.agent import loop as agent_loop  # noqa: E402
from kratos.run_context import run_scope  # noqa: E402
from kratos.trace import otel, recorder  # noqa: E402
from kratos.trace import settings as TS  # noqa: E402
from tests.test_trace import DISMISSIVE, GOOD, MeteredScript, _final, _tool, dd  # noqa: E402,F401

SECRET_GOAL = "check db-01 for user alice-secret-goal"
SECRET_RESULT = "process-list-secret-result"


def _recorded_run(dd, monkeypatch):
    from kratos.agent.tools import TOOL_REGISTRY

    settings_store.set(TS.STORE_PROMPTS, True, data_dir=dd, actor="test")   # even then, prompts stay local
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler",
                        lambda **kw: {"status": "ok", "processes": [SECRET_RESULT]})
    monkeypatch.setattr(agent_loop, "agent_chat",
                        MeteredScript([_tool("list_processes", {"user": "alice-arg"}), _tool("correlate_findings"),
                                       _final(DISMISSIVE), _final(GOOD)]))
    with run_scope("interactive", target="db-01.example") as ctx:
        result = agent_loop.run_agent(SECRET_GOAL, dd, max_iters=6)
    from kratos.trace import store

    return ctx, store.find(dd, result["run_id"]).data


def test_the_span_tree_names_and_attributes(dd, monkeypatch):
    ctx, data = _recorded_run(dd, monkeypatch)
    mem = InMemorySpanExporter()
    assert otel.export(data, exporter=mem) is True
    spans = mem.get_finished_spans()
    assert len(spans) == len(data["spans"])
    by_name = {}
    for s in spans:
        by_name.setdefault(s.name, []).append(s)
    root = by_name["invoke_agent kratos"][0]
    assert root.parent is None
    assert format(root.context.trace_id, "032x") == ctx.run_id           # OTel trace id = the run id
    assert {format(s.context.trace_id, "032x") for s in spans} == {ctx.run_id}
    assert root.attributes["gen_ai.operation.name"] == "invoke_agent"
    assert root.attributes["kratos.run_id"] == ctx.run_id
    chats = by_name["chat priced-model"]
    assert len(chats) == 4 and all(c.kind == SpanKind.CLIENT for c in chats)
    a = chats[0].attributes
    assert a["gen_ai.operation.name"] == "chat" and a["gen_ai.request.model"] == "priced-model"
    assert a["gen_ai.usage.input_tokens"] == 1000 and a["gen_ai.usage.output_tokens"] == 100
    assert "gen_ai.provider.name" in a
    tool = by_name["execute_tool list_processes"][0]
    assert tool.attributes["gen_ai.tool.name"] == "list_processes" and tool.attributes["gen_ai.tool.call.id"]
    assert tool.parent.span_id == root.context.span_id
    assert "kratos.guard dismissive_verdict_contradiction" in by_name
    ans = by_name["kratos.answer"][0].attributes
    assert list(ans["kratos.answer.block_finding_ids"]) == ["CORR-SSH-001"]
    for s in spans:                                                     # times survive
        assert s.start_time and s.end_time and s.end_time >= s.start_time


def test_no_tool_result_prompt_goal_or_machine_name_is_exported(dd, monkeypatch):
    _, data = _recorded_run(dd, monkeypatch)
    raw = json.dumps(data)
    assert SECRET_RESULT in raw and SECRET_GOAL in raw and "alice-arg" in raw   # the local file has them
    mem = InMemorySpanExporter()
    otel.export(data, exporter=mem)
    exported = json.dumps([{"name": s.name, "attrs": dict(s.attributes), "events": [e.name for e in s.events],
                            "resource": dict(s.resource.attributes)} for s in mem.get_finished_spans()],
                          default=str)
    for secret in (SECRET_RESULT, SECRET_GOAL, "alice", "db-01", "check the box", "CORR-SSH-001: SSH exposed",
                   "No suspicious activity", data["session_id"] or "no-session-xyz"):
        assert secret not in exported, secret


class _Failing(SpanExporter):
    def __init__(self):
        self.calls = 0

    def export(self, spans):
        self.calls += 1
        raise ConnectionError("collector is down")

    def shutdown(self):
        pass


def test_a_failing_collector_is_logged_once_and_never_fails(dd, monkeypatch, caplog):
    _, data = _recorded_run(dd, monkeypatch)
    otel._warned.clear()
    caplog.set_level("WARNING", logger="kratos.trace.otel")
    fail = _Failing()
    assert otel.export(data, exporter=fail) is False
    assert otel.export(data, exporter=fail) is False
    msgs = [r.message for r in caplog.records if "collector" in r.message]
    assert len(msgs) == 1 and fail.calls == 2


def test_a_dead_endpoint_does_not_slow_or_fail_the_run(dd, monkeypatch, caplog):
    """Export on: the run ends on time, its file is written, the copy fails off-thread."""
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()                                                         # nothing listens there
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", f"http://127.0.0.1:{port}")
    settings_store.set(TS.OTEL_EXPORT, True, data_dir=dd, actor="test")
    otel._warned.clear()
    started = []
    real = otel.export_in_background
    monkeypatch.setattr(otel, "export_in_background", lambda tr: started.append(real(tr)) or started[-1])
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    t0 = time.monotonic()
    with run_scope("cli"):
        result = agent_loop.run_agent("check", dd, max_iters=4)
    assert time.monotonic() - t0 < 3.0
    assert result["status"] == "final_answer"
    from kratos.trace import store

    assert store.find(dd, result["run_id"]).partial is False
    (thread,) = started
    thread.join(15)
    assert not thread.is_alive()
    assert any("could not send run records" in r.message for r in caplog.records)


def test_no_endpoint_means_nothing_is_sent(dd, monkeypatch, caplog):
    for var in otel.ENDPOINT_VARS:
        monkeypatch.delenv(var, raising=False)
    otel._warned.clear()
    caplog.set_level("WARNING", logger="kratos.trace.otel")
    with run_scope("cli"):
        with recorder.run_trace("pipeline", dd) as tr:
            pass
    assert otel.export(tr.to_dict()) is False
    assert any("OTEL_EXPORTER_OTLP_ENDPOINT is not set" in r.message for r in caplog.records)


def test_export_off_by_default_never_imports_otel(dd, monkeypatch):
    calls = []
    monkeypatch.setattr(recorder, "_export_otel", lambda tr: calls.append(tr))
    with run_scope("cli"):
        with recorder.run_trace("pipeline", dd):
            pass
    assert calls == []


def test_without_the_extra_nothing_imports_opentelemetry(tmp_path):
    """A run with export turned on, in a process where opentelemetry cannot be imported."""
    code = f"""
import sys, builtins, json
real = builtins.__import__
def guard(name, *a, **k):
    if name.startswith('opentelemetry'):
        raise ImportError('not installed: ' + name)
    return real(name, *a, **k)
builtins.__import__ = guard
from kratos import settings_store, run_context
from kratos.trace import recorder, settings as TS
settings_store.set(TS.OTEL_EXPORT, True, data_dir={str(tmp_path)!r}, actor='t')
with run_context.run_scope('cli'):
    with recorder.run_trace('pipeline', {str(tmp_path)!r}) as tr:
        pass
print(json.dumps({{'written': tr.path.exists(), 'otel': [m for m in sys.modules if m.startswith('opentelemetry')]}}))
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res == {"written": True, "otel": []}
    assert "otel" in out.stderr and "not installed" in out.stderr


def test_provider_names():
    assert otel.provider_name("gemini-3.1-flash-lite", False) == "gcp.gemini"
    assert otel.provider_name("qwen2.5:7b", True) == "kratos.local"
    assert otel.provider_name("some-model", False) == "kratos.openai_compatible"
