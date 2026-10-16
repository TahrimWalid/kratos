"""Run records (kratos.trace, docs/phaseB/B.5 §5.4, §7): one trace per run with every
model call, tool call, collection check, guard and the answer's composition; parallel
runs never mix; a child run links to its parent; big results are capped; a run that
raises leaves a readable .partial; hostile text is shown safely."""
from __future__ import annotations

import json
import re
import threading
import time
from argparse import Namespace
from pathlib import Path

import pytest

from kratos import kratos_config, llm_interface, settings_store
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.collect import checks as _register_checks  # noqa: F401 -- real checks registered before patching
from kratos.collect import registry
from kratos.collect import settings as collect_settings
from kratos.collect.registry import Check, CheckResult
from kratos.run_context import run_scope
from kratos.trace import recorder, store, view
from kratos.trace import settings as TS

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
TARGET = "10.0.0.5"
HIGH = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst activity observed",
        "severity": "high", "evidence": ["burst from 10.0.0.66"], "recommendation": ["restrict ssh"]}
DISMISSIVE = "No suspicious activity was detected on this system; overall the system appears secure."
GOOD = ("A HIGH-severity finding (CORR-SSH-001: SSH exposed with failed-login burst activity) was identified "
        "and requires attention. Recommend restricting SSH access.")


def _tool(name: str, args: dict | None = None) -> str:
    return json.dumps({"reasoning": "next", "tool": name, "args": args or {}})


def _final(text: str) -> str:
    return json.dumps({"reasoning": "done", "final_answer": text})


class MeteredScript:
    """Scripted replies that go through the REAL model choke point (_metered_call)."""

    def __init__(self, replies: list[str], *, delay: float = 0.0) -> None:
        self.replies, self.delay = list(replies), delay
        self.lock = threading.Lock()

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        with self.lock:
            reply = self.replies.pop(0)
        time.sleep(self.delay)

        def send() -> dict:
            return {"choices": [{"message": {"content": reply}}],
                    "usage": {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100}}

        body = llm_interface._metered_call(send, system_prompt=system_prompt, prompt=user_prompt,
                                           max_tokens=max_tokens or 512, model="priced-model", local=False)
        return body["choices"][0]["message"]["content"]


@pytest.fixture
def dd(tmp_path, monkeypatch):
    from kratos.budget import pricing

    d = tmp_path / "data"
    d.mkdir()
    kratos_config.set_active_data_dir(d)
    kratos_config.set_active_target(TARGET)
    pricing.set_rate(d, "priced-model", 1.0, 2.0, actor="test")
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [HIGH], "count": 1, "staleness_warning": None,
                                      "missing_inputs": [], "input_errors": {}, "inputs_used": {}})
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler",
                        lambda **kw: {"status": "ok", "processes": [{"pid": 1, "cmd": "init"}]})
    return d


def _spans(data: dict, kind: str) -> list[dict]:
    return [s for s in data["spans"] if s["kind"] == kind]


def _only_trace(d: Path) -> dict:
    files = [p for p in store.trace_files(d) if not p.name.endswith(".partial")]
    assert len(files) == 1, files
    return json.loads(files[0].read_text())


# ------------------------------------------------------------------------------ completeness
@pytest.fixture
def with_collection(dd, monkeypatch):
    """The real collection runner with two fake checks: one quick, one still running
    at the start budget that finishes in the background."""
    monkeypatch.delenv("KRATOS_COLLECT", raising=False)
    monkeypatch.setattr(registry, "_CHECKS", {})
    monkeypatch.setattr(settings_store, "_REGISTRY", dict(settings_store._REGISTRY))
    monkeypatch.setattr("kratos.collect.runner._warm_ssh", lambda host: None)
    settings_store.set(collect_settings.START_BUDGET, 1, data_dir=dd, actor="test")

    def quick(ctx):
        ctx.dispatch("list_processes", {}, ctx.data_dir)
        return CheckResult("ok", "1 process", tools=["list_processes"])

    def slow(ctx):
        time.sleep(1.6)
        return CheckResult("ok", "slow but fine")

    for name, run, order in (("t_quick", quick, 1), ("t_slow", slow, 2)):
        registry.register(Check(name=name, cost="quick", ttl_setting=f"collect.ttl.{name}_minutes",
                                default_ttl_minutes=60, run=run, inputs=(), transports=frozenset({"ssh", "agent"}),
                                budget_seconds=20.0, label=name, order=order))
    return dd


def test_a_scripted_investigation_records_everything_under_its_run(with_collection, monkeypatch):
    dd = with_collection
    monkeypatch.setattr(agent_loop, "agent_chat",
                        MeteredScript([_tool("list_processes"), _final(DISMISSIVE), _final(GOOD)]))
    with run_scope("interactive") as ctx:
        result = agent_loop.run_agent("check the box", dd, max_iters=6)
    assert result["status"] == "final_answer"
    data = _only_trace(dd)
    assert data["run_id"] == ctx.run_id == result["run_id"]
    assert data["kind"] == "investigation" and data["source"] == "interactive" and data["target"] == TARGET
    assert data["status"] == "final_answer"
    # every model call, with tokens, cost and the budget ledger row
    calls = _spans(data, "model_call")
    assert len(calls) == 3
    from kratos.budget.ledger import BudgetLedger

    rows = {r["id"]: r for r in BudgetLedger(dd).rows()}
    for c in calls:
        a = c["attrs"]
        assert a["prompt_tokens"] == 1000 and a["completion_tokens"] == 100 and a["model"] == "priced-model"
        assert rows[a["ledger_row_id"]]["run_id"] == ctx.run_id
        assert a["cost_usd"] == pytest.approx(rows[a["ledger_row_id"]]["cost_usd"])
        assert "prompt" not in a and a["prompt_chars"] > 0          # sizes only by default
    assert data["totals"]["model_calls"] == 3 and data["totals"]["prompt_tokens"] == 3000
    # every tool call: the collection check's (nested under it), the model's, correlations
    tools = _spans(data, "tool_call")
    by_id = {s["id"]: s for s in data["spans"]}
    names = [t["name"] for t in tools]
    assert names.count("list_processes") == 2 and "correlate_findings" in names
    model_call = [t for t in tools if t["name"] == "list_processes"
                  and by_id[t["parent_id"]]["kind"] == "run"]
    assert len(model_call) == 1 and model_call[0]["attrs"]["envelope_id"]
    assert model_call[0]["attrs"]["args"] == {}
    assert model_call[0]["attrs"]["result"]["result"]["processes"][0]["cmd"] == "init"
    # collection checks, including the one that finished in the background
    checks = {s["name"]: s for s in _spans(data, "collection_check")}
    assert set(checks) == {"t_quick", "t_slow"}
    in_check = [t for t in tools if by_id[t["parent_id"]]["name"] == "t_quick"]
    assert [t["name"] for t in in_check] == ["list_processes"]
    slow = checks["t_slow"]["attrs"]
    assert slow["still_running_at_start_budget"] is True and slow["settled_later"] is True
    assert checks["t_slow"]["status"] == "ok"
    # the guard that sent the dismissive answer back, and the answer's composition
    guards = _spans(data, "guard")
    assert any(g["attrs"]["guard"] == "dismissive_verdict_contradiction" and g["attrs"]["action"] == "rejected" for g in guards)
    (answer,) = _spans(data, "answer")
    assert answer["attrs"]["block_finding_ids"] == ["CORR-SSH-001"]
    assert result["final_answer"].startswith("Kratos found")
    assert "CORR-SSH-001" in result["final_answer"].split("\n\n")[0]
    # every span belongs to this run's tree
    root = data["spans"][0]
    assert root["kind"] == "run" and root["parent_id"] is None
    assert all(s["parent_id"] in by_id for s in data["spans"][1:])
    # the transcript links each step to the record
    assert all(e.get("run_id") == data["trace_id"] for e in result["transcript"])
    assert not any(p.name.endswith(".partial") for p in store.trace_files(dd))


def test_the_record_holds_the_collection_the_model_started_from(with_collection, monkeypatch):
    """B.4: the collected report (checks, correlation) and the checks folded in before the
    answer are in the record -- what evals/replay needs to replay a run without the machine."""
    dd = with_collection
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("list_processes"), _final(GOOD)]))
    with run_scope("interactive"):
        agent_loop.run_agent("check the box", dd, max_iters=6)
    data = _only_trace(dd)
    (start,) = _spans(data, "collection")
    rep = start["attrs"]["report"]
    assert [c["name"] for c in rep["checks"]] == ["t_quick", "t_slow"]
    assert rep["still_running"] == ["t_slow"] and rep["target"] == TARGET
    assert rep["correlation"]["findings"][0]["id"] == "CORR-SSH-001"
    quick = rep["checks"][0]
    assert quick["status"] == "ok" and quick["summary"] == "1 process" and quick["tools"] == ["list_processes"]
    assert isinstance(quick["steps"], list)   # the tool calls a real check made (its ctx.call), for the transcript
    (settled,) = _spans(data, "collection_settled")
    assert settled["attrs"]["checks"]["t_slow"]["summary"] == "slow but fine"
    lines = view.tree_lines(store.load([p for p in store.trace_files(dd) if p.suffix == ".json"][0]))
    assert any("collected before the model · 2 check(s), still running: t_slow" in ln for ln in lines)
    assert any("finished in the background before the answer: t_slow" in ln for ln in lines)


def test_the_trace_file_is_private(dd, monkeypatch):
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    with run_scope("cli"):
        agent_loop.run_agent("check", dd, max_iters=4)
    (p,) = store.trace_files(dd)
    assert p.stat().st_mode & 0o777 == 0o600
    assert (dd / "traces").stat().st_mode & 0o777 == 0o700
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", p.parent.name)


def test_recording_off_writes_nothing_and_changes_nothing(dd, monkeypatch):
    settings_store.set(TS.ENABLED, False, data_dir=dd, actor="test")
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    result = agent_loop.run_agent("check", dd, max_iters=4)
    assert result["status"] == "final_answer" and "run_id" not in result
    assert store.trace_files(dd) == []


def test_store_prompts_keeps_the_text(dd, monkeypatch):
    settings_store.set(TS.STORE_PROMPTS, True, data_dir=dd, actor="test")
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    agent_loop.run_agent("check the box", dd, max_iters=4)
    calls = _spans(_only_trace(dd), "model_call")
    assert "check the box" in calls[0]["attrs"]["prompt"]


def test_a_budget_refused_call_is_recorded(dd, monkeypatch):
    from kratos.budget import limits as L

    settings_store.set(L.RUN_MODEL_CALLS, 1, data_dir=dd, actor="test")
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    with run_scope("schedule"):
        result = agent_loop.run_agent("check", dd, max_iters=4)
    assert result["status"] == "stopped_by_budget"
    data = _only_trace(dd)
    assert [c["status"] for c in _spans(data, "model_call")] == ["ok", "refused_by_budget"]
    assert data["status"] == "stopped_by_budget"


# ------------------------------------------------------------------------------ concurrency
def test_two_investigations_in_two_threads_get_two_traces(dd, monkeypatch):
    def chat_for(goal):
        return MeteredScript([_tool("list_processes"), _tool("correlate_findings"), _final(GOOD + " " + goal)],
                             delay=0.05)

    scripts = {"alpha": chat_for("alpha"), "beta": chat_for("beta")}

    def dispatching_chat(system_prompt, user_prompt, max_tokens=None):
        goal = "alpha" if "alpha" in user_prompt else "beta"
        return scripts[goal](system_prompt, user_prompt, max_tokens)

    monkeypatch.setattr(agent_loop, "agent_chat", dispatching_chat)
    results, run_ids = {}, {}
    barrier = threading.Barrier(2)

    def worker(goal):
        with run_scope("interactive") as ctx:
            run_ids[goal] = ctx.run_id
            barrier.wait()
            results[goal] = agent_loop.run_agent(f"look at {goal}", dd, max_iters=5)

    threads = [threading.Thread(target=worker, args=(g,)) for g in ("alpha", "beta")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    traces = {json.loads(p.read_text())["run_id"]: json.loads(p.read_text()) for p in store.trace_files(dd)}
    assert set(traces) == set(run_ids.values())
    for goal, rid in run_ids.items():
        data = traces[rid]
        assert data["spans"][0]["attrs"]["goal"] == f"look at {goal}"
        assert len(_spans(data, "model_call")) == 3 and len(_spans(data, "tool_call")) == 2
        for c in _spans(data, "model_call"):
            pass
        ids = {s["id"] for s in data["spans"]}
        assert all(s["parent_id"] in ids for s in data["spans"][1:])
        assert results[goal]["run_id"] == rid
    from kratos.budget.ledger import BudgetLedger

    rows = {r["id"]: r["run_id"] for r in BudgetLedger(dd).rows()}
    for rid, data in traces.items():
        assert {rows[c["attrs"]["ledger_row_id"]] for c in _spans(data, "model_call")} == {rid}


def test_a_worker_thread_with_a_copied_context_records_into_its_run(dd):
    with run_scope("cli"):
        with recorder.run_trace("pipeline", dd) as tr:
            def work():
                with recorder.span("tool_call", "from_thread"):
                    pass
            t = threading.Thread(target=recorder.bind(work))
            t.start()
            t.join()
            other = threading.Thread(target=work)   # no copied context: records nowhere
            other.start()
            other.join()
    data = json.loads(tr.path.read_text())
    assert [s["name"] for s in _spans(data, "tool_call")] == ["from_thread"]


# ------------------------------------------------------------------------------ child runs
def test_a_trigger_investigation_inside_a_scheduled_run_is_its_own_trace(dd, monkeypatch):
    from kratos.agent import scheduled_run

    seen = {}

    def fake_run_agent(goal, data_dir):
        seen["trace"] = recorder.current_trace_id()
        with recorder.span("tool_call", "inside_trigger"):
            pass
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    with run_scope("schedule") as outer:
        with recorder.run_trace("scheduled", dd, name="nightly"):
            scheduled_run.run_headless_investigation("look deeper", dd, run_agent_fn=fake_run_agent)
    traces = {json.loads(p.read_text())["kind"]: json.loads(p.read_text()) for p in store.trace_files(dd)}
    parent, child = traces["scheduled"], traces["trigger"]
    assert child["parent_run_id"] == outer.run_id == parent["run_id"]
    assert child["run_id"] != parent["run_id"] and seen["trace"] == child["trace_id"]
    assert [s["name"] for s in _spans(child, "tool_call")] == ["inside_trigger"]
    assert not _spans(parent, "tool_call")
    (link,) = _spans(parent, "child_run")
    assert link["attrs"]["child_trace_id"] == child["trace_id"]
    assert [c.trace_id for c in store.children_of(dd, parent["run_id"])] == [child["trace_id"]]


def test_a_nested_run_kind_is_a_span_in_the_same_trace(dd):
    with run_scope("schedule"):
        with recorder.run_trace("scheduled", dd, name="nightly"):
            with recorder.run_trace("audit", dd):
                with recorder.span("collection_check", "ports"):
                    pass
    (p,) = store.trace_files(dd)
    data = json.loads(p.read_text())
    runs = _spans(data, "run")
    assert [r["attrs"]["run_kind"] for r in runs] == ["scheduled", "audit"]
    assert _spans(data, "collection_check")[0]["parent_id"] == runs[1]["id"]


def test_two_runs_in_one_scope_get_two_files(dd):
    with run_scope("interactive") as ctx:
        with recorder.run_trace("investigation", dd):
            pass
        with recorder.run_trace("investigation", dd):
            pass
    ids = sorted(store.trace_id_of(p) for p in store.trace_files(dd))
    assert ids == sorted([ctx.run_id, f"{ctx.run_id}-2"])


def test_pipeline_and_audit_record_their_steps(dd, monkeypatch):
    from kratos.agent import pipeline

    steps = [pipeline.PipelineStep("list_processes"),
             pipeline.PipelineStep("correlate_findings", when=lambda ctx: False)]
    with run_scope("pipeline"):
        out = pipeline.run_pipeline(steps, dd)
    data = json.loads(store.find(dd, out.run_id).path.read_text())
    tools = _spans(data, "tool_call")
    assert [(t["name"], t["attrs"].get("skipped", False)) for t in tools] == [("list_processes", False),
                                                                            ("correlate_findings", True)]
    assert data["kind"] == "pipeline" and data["source"] == "pipeline"


# ------------------------------------------------------------------------------ caps and crashes
def test_a_5mb_result_keeps_its_head_and_sha256(dd, monkeypatch):
    import hashlib

    big = "A" * (5 * 1024 * 1024)
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler", lambda **kw: {"status": "ok", "blob": big})
    with run_scope("cli"):
        with recorder.run_trace("pipeline", dd) as tr:
            out = agent_loop.execute_tool_call("list_processes", {}, dd)
    assert out["result"]["blob"] == big                     # the run itself is unaffected
    data = json.loads(tr.path.read_text())
    res = _spans(data, "tool_call")[0]["attrs"]["result"]
    whole = json.dumps(out, default=str, ensure_ascii=False).encode()
    assert res["truncated"] is True and res["bytes"] == len(whole)
    assert res["sha256"] == hashlib.sha256(whole).hexdigest()
    assert len(res["head"].encode()) <= 256 * 1024
    assert tr.path.stat().st_size < 400 * 1024


def test_a_run_that_raises_leaves_a_readable_partial(dd, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("the model client exploded")

    monkeypatch.setattr(agent_loop, "agent_chat", boom)
    with run_scope("cli") as ctx, pytest.raises(RuntimeError):
        agent_loop.run_agent("check", dd, max_iters=3)
    (p,) = store.trace_files(dd)
    assert p.name == f"{ctx.run_id}.json.partial"
    info = store.find(dd, ctx.run_id[:10])
    assert info.partial and info.data["status"] == "error"
    assert "the model client exploded" in info.data["spans"][0]["attrs"]["error"]
    assert any("unfinished" in line for line in view.show_lines(info))


def test_the_partial_copy_is_written_while_the_run_is_going(dd):
    with run_scope("cli"):
        with recorder.run_trace("investigation", dd) as tr:
            assert tr.partial_path.exists() and not tr.path.exists()
            json.loads(tr.partial_path.read_text())
    assert tr.path.exists() and not tr.partial_path.exists()


def test_a_span_that_ends_after_the_run_rewrites_the_file(dd):
    with run_scope("cli"):
        with recorder.run_trace("investigation", dd) as tr:
            late = recorder.start_span("collection_check", "slow")
    assert json.loads(tr.path.read_text())["spans"][1]["status"] == "unfinished"
    late.finish("ok", settled_later=True)
    assert json.loads(tr.path.read_text())["spans"][1]["status"] == "ok"


def test_a_broken_trace_folder_never_fails_the_run(dd, monkeypatch):
    (dd / "traces").write_text("not a folder")
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("correlate_findings"), _final(GOOD)]))
    result = agent_loop.run_agent("check", dd, max_iters=4)
    assert result["status"] == "final_answer"


# ------------------------------------------------------------------------------ viewing
def _corpus() -> list[str]:
    p = Path(__file__).parent / "fixtures" / "untrusted" / "corpus.json"
    return [str(v) for v in json.loads(p.read_text()).values()]


def test_trace_show_prints_hostile_text_safely(dd, monkeypatch, capsys):
    from kratos.cli import data_cmds

    corpus = _corpus()
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler",
                        lambda **kw: {"status": "error", "observation": " ".join(corpus)})
    with run_scope("cli"):
        with recorder.run_trace("pipeline", dd, name=corpus[0]) as tr:
            agent_loop.execute_tool_call("list_processes", {"user": corpus[1]}, dd)
            recorder.event("guard", corpus[2], guard=corpus[2], action="rejected", correction=corpus[3])
    raw = tr.path.read_text(encoding="utf-8", errors="surrogateescape")
    assert data_cmds.cmd_trace(Namespace(data_dir=dd, trace_action="show", run=tr.trace_id, json=False)) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x9b" not in out and "‮" not in out
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out)
    assert "list_processes" in out
    assert ("\x1b" in raw) or ("\\u001b" in raw)          # the file keeps the original bytes
    assert data_cmds.cmd_trace(Namespace(data_dir=dd, trace_action="show", run=tr.trace_id, json=True)) == 0
    js = capsys.readouterr().out
    assert js.isascii() and json.loads(js)["trace_id"] == tr.trace_id


def test_trace_list_and_prefix_lookup(dd, capsys):
    from kratos.cli import data_cmds

    with run_scope("cli"):
        with recorder.run_trace("investigation", dd) as tr:
            pass
    assert data_cmds.cmd_trace(Namespace(data_dir=dd, trace_action="list", target=None, since=None, limit=10)) == 0
    assert tr.trace_id[:12] in capsys.readouterr().out
    assert store.find(dd, tr.trace_id[:6]).trace_id == tr.trace_id
    assert store.find(dd, "nope") is None
    assert data_cmds.cmd_trace(Namespace(data_dir=dd, trace_action="show", run="nope", json=False)) == 1


# ------------------------------------------------------------------------------ the choke point
def test_model_call_spans_come_only_from_the_choke_point():
    hits = []
    for p in SRC.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"""(?:start_span|span|event)\(\s*["']model_call["']""", text):
            hits.append(str(p.relative_to(SRC)))
    assert hits == ["llm_interface.py"]
    src = (SRC / "llm_interface.py").read_text()
    body = src[src.index("def _metered_call("):src.index("def _budget_exceeded_type")]
    assert 'start_span("model_call"' in body
