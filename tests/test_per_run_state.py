"""Per-run state, not process globals (docs/phaseB/README §4.3, B.3 §3.8).

`kratos serve` runs several investigations at once in one process. What a run may use
(its tools), whom it asks (approval, clarify) and which machine it reads are per run
(contextvars), so concurrent runs can't see each other's -- and the TUI/CLI, which set
nothing per run, behave exactly as before.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path


from kratos import kratos_config
from kratos.agent import loop as agent_loop
from kratos.agent import tools as agent_tools
from kratos.agent.tools import TOOL_REGISTRY
from kratos.run_context import run_scope


# --------------------------------------------------------------------------- approval
def test_approval_scope_overrides_the_process_provider_for_this_run_only(monkeypatch):
    monkeypatch.setattr(agent_tools, "_approval_prompt_provider", lambda tool, details: True)
    with agent_tools.approval_provider_scope(lambda tool, details: False):
        assert agent_tools.request_approval("x", {}) is False
    assert agent_tools.request_approval("x", {}) is True


def test_approval_scope_none_falls_back_to_the_terminal_prompt_which_denies_without_input(monkeypatch):
    monkeypatch.setattr(agent_tools, "_approval_prompt_provider", lambda tool, details: True)
    monkeypatch.setattr("builtins.input", lambda *_a: (_ for _ in ()).throw(EOFError()))
    with agent_tools.approval_provider_scope(None):
        assert agent_tools.request_approval("x", {}) is False


def test_a_broken_scoped_provider_still_fails_safe():
    def boom(tool, details):
        raise RuntimeError("provider broke")

    with agent_tools.approval_provider_scope(boom):
        assert agent_tools.request_approval("x", {}) is False


def test_concurrent_runs_see_their_own_approval_provider(monkeypatch):
    monkeypatch.setattr(agent_tools, "_approval_prompt_provider", lambda tool, details: True)
    results: dict[str, bool] = {}
    barrier = threading.Barrier(2)

    def run(name: str, provider):
        with agent_tools.approval_provider_scope(provider):
            barrier.wait()
            time.sleep(0.05)
            results[name] = agent_tools.request_approval("x", {})

    a = threading.Thread(target=run, args=("deny", lambda t, d: False))
    b = threading.Thread(target=run, args=("allow", lambda t, d: True))
    a.start(); b.start(); a.join(); b.join()
    assert results == {"deny": False, "allow": True}


def test_one_runs_approval_never_satisfies_another_runs_backstop(monkeypatch):
    monkeypatch.setattr(agent_tools, "_approval_prompt_provider", lambda tool, details: True)
    mark = agent_tools.approval_log_length()
    with run_scope("web", target="10.0.0.1"):
        agent_tools.request_approval("capture_traffic", {})
        assert agent_tools.approval_was_recorded("capture_traffic", mark)
    with run_scope("web", target="10.0.0.2"):
        assert not agent_tools.approval_was_recorded("capture_traffic", mark)
        assert agent_tools.approval_entries_since(mark) == []


# --------------------------------------------------------------------------- clarify
def test_clarify_scope_none_hides_clarify_even_when_a_provider_is_installed():
    agent_loop.set_clarify_provider(lambda q, o: "yes")
    try:
        with agent_loop.clarify_provider_scope(None):
            assert agent_loop._active_clarify_provider() is None
            assert "No interactive user is available" in agent_loop._clarify_guidance()
        assert agent_loop._active_clarify_provider() is not None
    finally:
        agent_loop.set_clarify_provider(None)


# --------------------------------------------------------------------------- tool filter
def _only_safe(name: str) -> bool:
    return not agent_tools.tool_reaches_approval(TOOL_REGISTRY.get(name))


def test_no_filter_leaves_the_prompt_byte_identical():
    plain = agent_loop.build_system_prompt("check the box")
    token = agent_loop._run_tool_filter.set(None)
    try:
        assert agent_loop.build_system_prompt("check the box") == plain
    finally:
        agent_loop._run_tool_filter.reset(token)


def test_filter_removes_tools_from_the_prompt_and_dispatch_without_touching_the_registry(tmp_path):
    before = dict(TOOL_REGISTRY)
    token = agent_loop._run_tool_filter.set(_only_safe)
    try:
        filtered = agent_loop.build_system_prompt("check the box")
        for risky in ("capture_traffic", "run_vuln_scan", "check_ip_reputation"):
            assert risky not in agent_tools.render_tools_for_prompt(exclude=agent_loop._filtered_out_tools())
            out = agent_loop._dispatch_tool_call(risky, {}, tmp_path)
            assert out["status"] == "error" and "not available in this investigation" in out["observation"]
        listing = agent_tools.render_tools_for_prompt(exclude=agent_loop._filtered_out_tools())
        assert "run_nmap_scan" in listing and "capture_traffic" not in listing
        for risky in ("capture_traffic", "run_vuln_scan", "check_ip_reputation", "run_linux_command"):
            assert f"\n- {risky}:" not in filtered          # not offered to the model
        assert "\n- run_nmap_scan:" in filtered
    finally:
        agent_loop._run_tool_filter.reset(token)
    assert dict(TOOL_REGISTRY) == before


def test_a_broken_filter_closes_every_tool():
    def boom(name):
        raise RuntimeError("filter broke")

    token = agent_loop._run_tool_filter.set(boom)
    try:
        assert not agent_loop.tool_allowed("run_nmap_scan")
    finally:
        agent_loop._run_tool_filter.reset(token)


def test_filter_reaches_threads_started_with_a_copied_context():
    import contextvars

    seen = {}
    token = agent_loop._run_tool_filter.set(_only_safe)
    try:
        ctx = contextvars.copy_context()
        t = threading.Thread(target=ctx.run, args=(lambda: seen.setdefault("ok", agent_loop.tool_allowed("capture_traffic")),))
        t.start(); t.join()
    finally:
        agent_loop._run_tool_filter.reset(token)
    assert seen["ok"] is False


# --------------------------------------------------------------------------- two machines at once
def _reply(obj: dict) -> str:
    return json.dumps(obj)


def test_two_investigations_of_two_machines_at_once_keep_their_own_machine(tmp_path, monkeypatch):
    """Two runs, two machines, interleaved: every scan reaches the run's own machine, each
    gets its own session and its own run record -- through the real loop and dispatch."""
    from kratos import llm_interface
    from kratos.serve.runs import RunRequest, run_investigation

    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("10.9.9.9")       # the process-wide target: neither run may use it
    scanned: list[tuple[str, str]] = []
    lock = threading.Lock()

    def fake_scan(data_dir, target):
        time.sleep(0.05)
        with lock:
            scanned.append((kratos_config.get_active_target(), target))
        p = Path(data_dir) / f"scan_{target}.xml"
        p.write_text("<nmaprun/>")
        return p

    monkeypatch.setattr(agent_tools, "_run_nmap_scan", fake_scan)
    monkeypatch.setattr(agent_tools, "_parse_nmap_xml_to_dict", lambda p: {"hosts": []})
    monkeypatch.setattr(agent_tools, "_write_parsed_json", lambda d, parsed: Path(d) / "x.json")
    monkeypatch.setattr(agent_tools, "_network_scan_gap", lambda t: None)
    calls: dict[str, int] = {}

    def scripted(system_prompt, user_prompt, max_tokens=None):
        me = kratos_config.get_active_target()
        with lock:
            n = calls[me] = calls.get(me, 0) + 1
        time.sleep(0.02)
        reply = (_reply({"reasoning": "scan", "tool": "run_nmap_scan", "args": {}}) if n <= 2 else
                 _reply({"reasoning": "done", "final_answer": f"done with {me}; nothing to correlate here"}))

        def send(_s, _p):
            return {"choices": [{"message": {"content": reply}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}

        body = llm_interface._metered_call(send, system_prompt=system_prompt, prompt=user_prompt, max_tokens=256,
                                           model="test-model", local=True, masker=llm_interface._masker(local=True))
        return body["choices"][0]["message"]["content"]

    monkeypatch.setattr(agent_loop, "agent_chat", scripted)
    outcomes = {}

    def go(target):
        outcomes[target] = run_investigation(RunRequest(goal="scan it", target=target, data_dir=tmp_path,
                                                        source="web", max_iters=6))

    threads = [threading.Thread(target=go, args=(t,)) for t in ("10.0.0.1", "10.0.0.2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert {o.status for o in outcomes.values()} <= {"final_answer", "max_iters_reached"}, {k: (o.status, o.error, o.final_answer[:300]) for k, o in outcomes.items()}
    assert {t for _a, t in scanned} == {"10.0.0.1", "10.0.0.2"}, ({k: (o.status, o.error, o.final_answer[:400]) for k, o in outcomes.items()}, calls)
    assert scanned and all(active == target for active, target in scanned)
    assert {t for _a, t in scanned} == {"10.0.0.1", "10.0.0.2"}
    assert outcomes["10.0.0.1"].session_id != outcomes["10.0.0.2"].session_id
    assert outcomes["10.0.0.1"].run_id and outcomes["10.0.0.1"].run_id != outcomes["10.0.0.2"].run_id
    traces = list((tmp_path / "traces").rglob("*.json"))
    assert {o.run_id for o in outcomes.values()} <= {p.stem for p in traces}
    assert kratos_config.get_active_target() == "10.9.9.9"   # the process-wide value never moved


def test_answer_parts_add_up_to_the_final_answer(tmp_path, monkeypatch):
    """run_agent reports the block / NOTEs / analysis it composed; together they are the
    final answer exactly (the display may then render each by its own rule)."""
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("10.0.0.5")
    replies = iter([_reply({"reasoning": "done", "final_answer": "Looks quiet."})] * 4)
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: next(replies))
    with run_scope("cli", target="10.0.0.5"):
        out = agent_loop.run_agent("check it", tmp_path, max_iters=4)
    parts = out.get("answer_parts")
    assert parts is not None
    assert parts["block"] + parts["notes"] + parts["analysis"] == out["final_answer"]
    assert parts["analysis"] == "Looks quiet."
    assert "[NOTE:" in parts["notes"]          # correlate_findings never ran -> Guard 1's note


def test_a_code_built_answer_is_reported_as_kratos_text(tmp_path, monkeypatch):
    """The iteration-limit fallback is built from raw tool results: its parts say so, so a
    chat client shows it inert, like the findings block."""
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("10.0.0.5")
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: _reply({"reasoning": "r", "tool": "list_processes", "args": {}}))
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler", lambda **kw: {"processes": ["![x](https://e.test/q)"]})
    with run_scope("cli", target="10.0.0.5"):
        out = agent_loop.run_agent("check it", tmp_path, max_iters=2)
    assert out["status"] == "max_iters_reached"
    assert out["answer_parts"] == {"block": out["final_answer"], "notes": "", "analysis": ""}
    from kratos.serve import render

    md = render.answer_markdown(out["final_answer"], out["answer_parts"])
    assert "<img" not in __import__("markdown_it").MarkdownIt("commonmark").render(md)
