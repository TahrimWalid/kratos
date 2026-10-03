"""A mixed investigation of a sub-agent-only target (docs/subagent_read_routing.md
§5 #13): the network scan is refused (no direct path), the reads go through
the agent, and the final answer may not present the target as fully checked.
Driven through the REAL run_agent loop with a scripted model."""
from __future__ import annotations

import json

import pytest

from kratos import kratos_config as kc
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import routing


def _tool(name: str, args: dict | None = None) -> str:
    return json.dumps({"reasoning": "next", "tool": name, "args": args or {}})


def _final(text: str) -> str:
    return json.dumps({"reasoning": "done", "final_answer": text})


@pytest.fixture
def subagent_only_target(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "_active_target_override", "203.0.113.40")
    kc.set_active_data_dir(tmp_path)
    routing.clear_cache()
    store = SubAgentStore(tmp_path / "kratos.db")
    code = store.create_pairing_code(name="edge")["code"]
    tid = store.redeem_pairing_code(code, agent_id="a", hostname="edge", agent_version="0.3.0")["target_id"]
    store.set_link("203.0.113.40", tid, routing.MODE_SUBAGENT)
    reads: list = []
    monkeypatch.setattr(routing, "agent_read", lambda link, probe, params: reads.append(probe) or {
        "status": "ok", "data": {"returncode": 0, "stderr": "",
                                 "stdout": "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
                                           "root 1 0.0 0.0 1 1 ? Ss 00:00 0:01 /sbin/init\n"}})
    def correlate(**k):
        return {"findings": [], "count": 0, "missing_inputs": [], "input_errors": {}, "staleness_warning": None,
                "findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}}

    correlate.__module__ = "kratos.agent.tools"  # stands in for the built-in
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)

    def no_scan(*a, **k):
        raise AssertionError("no network scan may run against a sub-agent-only target")

    monkeypatch.setattr("kratos.agent.tools._run_nmap_scan", no_scan)
    yield tmp_path, reads
    kc.set_active_data_dir(None)
    routing.clear_cache()


def _run(monkeypatch, data_dir, answer):
    script = [_tool("run_nmap_scan"), _tool("list_processes"), _tool("correlate_findings"), _final(answer)]
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: script.pop(0))
    return agent_loop.run_agent("is this box ok?", data_dir, max_iters=7)


def test_answer_that_skips_the_gap_is_tagged(subagent_only_target, monkeypatch):
    data_dir, reads = subagent_only_target
    result = _run(monkeypatch, data_dir, "Everything looks fine: nothing suspicious is running.")
    assert result["status"] == "final_answer"
    assert result["final_answer"].startswith("[NOTE: not checked in this investigation: network exposure")
    assert reads == ["processes"]
    steps = {s.get("tool"): s for s in result["transcript"] if s.get("tool")}
    nmap = json.dumps(steps["run_nmap_scan"])
    assert "network scan not available" in nmap and "coverage_gap" in nmap
    assert "through its sub-agent (edge)" in json.dumps(steps["list_processes"])


def test_answer_that_names_the_gap_is_left_alone(subagent_only_target, monkeypatch):
    data_dir, _reads = subagent_only_target
    answer = ("Nothing suspicious is running. Open ports were not checked: this box is reached only through its "
              "sub-agent, so no network scan was possible.")
    result = _run(monkeypatch, data_dir, answer)
    assert result["final_answer"] == answer


def test_a_kept_ssh_tool_is_refused_not_turned_into_an_empty_answer(subagent_only_target, monkeypatch, tmp_path):
    """Live finding: a kept tool that returns [] on any SSH failure reported "no listening services" for a
    box reached only through its sub-agent. It must not run there, and the gap must reach the answer."""
    import sys
    import types

    from kratos.agent.tools import Tool

    mod = types.ModuleType("kept_fake_netsvc")
    exec("from kratos.adapters import ssh_remote\n"
         "def tool_list_services():\n"
         "    r = ssh_remote.run_remote_command('ss -tln')\n"
         "    return [] if not r.ok else r.stdout.splitlines()\n", mod.__dict__)
    src = tmp_path / "kept_fake_netsvc.py"
    src.write_text("from kratos.adapters import ssh_remote\n")
    mod.__file__ = str(src)
    monkeypatch.setitem(sys.modules, "kept_fake_netsvc", mod)
    mod.tool_list_services.__module__ = "kept_fake_netsvc"
    monkeypatch.setitem(TOOL_REGISTRY, "list_services",
                        Tool(name="list_services", description="kept", parameters={}, handler=mod.tool_list_services))
    data_dir, _reads = subagent_only_target
    out = agent_loop.execute_tool_call("list_services", {}, data_dir)
    assert out["status"] == "error" and "was NOT run" in out["observation"] and "coverage_gap" in out

    script = [_tool("list_services"), _tool("correlate_findings"), _final("No services are listening.")]
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: script.pop(0))
    result = agent_loop.run_agent("what is listening?", data_dir, max_iters=5)
    assert "[NOTE: not checked in this investigation: what 'list_services' checks" in result["final_answer"]


def test_built_in_tools_are_not_blocked(subagent_only_target):
    data_dir, reads = subagent_only_target
    out = agent_loop.execute_tool_call("list_processes", {}, data_dir)
    assert out["status"] == "ok" and reads == ["processes"]
