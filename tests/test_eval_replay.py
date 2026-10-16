"""Replay (evals/replay.py): a recorded run replays to the same tool results with a real
(here scripted) model, and a call that was not recorded is marked, never invented. Plus
the recording-from-trace reduction and the hygiene scan."""
from __future__ import annotations

import json


from evals import replay
from kratos import kratos_config
from kratos.agent import loop
from kratos.run_context import run_scope

TARGET = "10.136.28.168"
_CORR = {"status": "ok", "result": {"findings": [{"id": "CORR-SSH-001", "severity": "high"}], "count": 1,
                                    "staleness_warning": None, "missing_inputs": [], "input_errors": {},
                                    "inputs_used": {}}}
RECORDING = {"format": replay.RECORDING_FORMAT, "scenario": "A1", "goal": "g", "target": TARGET,
             "collection": None,
             "calls": [{"tool": "correlate_findings", "args": {}, "result": _CORR},
                       {"tool": "list_processes", "args": {}, "result": {"status": "ok", "result": {"processes": []}}}]}


def _scripted(replies):
    seq = list(replies)

    def agent_chat(system_prompt, user_prompt, max_tokens=None, **kw):  # noqa: ANN001
        return seq.pop(0) if seq else json.dumps({"reasoning": "stop", "final_answer": "done"})

    return agent_chat


def _run(monkeypatch, tmp_path, replies):
    monkeypatch.setattr(loop, "agent_chat", _scripted(replies))
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(TARGET)
    with replay.install(RECORDING) as tracker, run_scope("cli"):
        payload = loop.run_agent("g", tmp_path, max_iters=5)
    return payload, tracker


def test_a_recorded_call_replays_to_its_recorded_result(monkeypatch, tmp_path):
    payload, tracker = _run(monkeypatch, tmp_path, [
        json.dumps({"reasoning": "x", "tool": "correlate_findings", "args": {}}),
        json.dumps({"reasoning": "done", "final_answer": "A HIGH brute-force finding (CORR-SSH-001) is active."})])
    assert tracker.hits == 1 and not tracker.left_recording
    corr = [e for e in payload["transcript"] if e.get("tool") == "correlate_findings"][0]
    assert corr["observation"] == _CORR


def test_an_unrecorded_call_is_marked_not_invented(monkeypatch, tmp_path):
    payload, tracker = _run(monkeypatch, tmp_path, [
        json.dumps({"reasoning": "x", "tool": "run_yara_scan", "args": {"path": "/tmp"}}),
        json.dumps({"reasoning": "done", "final_answer": "nothing conclusive"})])
    assert tracker.left_recording and "run_yara_scan" in tracker.not_recorded
    yara = [e for e in payload["transcript"] if e.get("tool") == "run_yara_scan"][0]
    assert yara["observation"].get("replay_not_recorded") is True


def test_same_tool_other_args_uses_the_recorded_result_and_notes_the_mismatch(monkeypatch, tmp_path):
    payload, tracker = _run(monkeypatch, tmp_path, [
        json.dumps({"reasoning": "x", "tool": "list_processes", "args": {"filter": "ssh"}}),
        json.dumps({"reasoning": "done", "final_answer": "done"})])
    assert "list_processes" in tracker.arg_mismatches and not tracker.left_recording


def test_a_recording_is_reduced_from_a_trace():
    trace = {"run_id": "abc", "target": TARGET, "spans": [
        {"kind": "run", "name": "investigation"},
        {"kind": "collection", "attrs": {"report": {"target": TARGET, "checks": []}}},
        {"kind": "tool_call", "name": "correlate_findings", "attrs": {"args": {}, "result": _CORR}},
        {"kind": "tool_call", "name": "run_nmap_scan", "attrs": {"args": {"target": TARGET}}},  # no result: skipped
    ]}
    rec = replay.recording_from_trace(trace, "A1", "g")
    assert rec["collection"] == {"target": TARGET, "checks": []}
    assert [c["tool"] for c in rec["calls"]] == ["correlate_findings"]


def test_the_hygiene_scan_catches_a_non_lab_address_and_a_key():
    clean = replay.scan_recording(RECORDING)
    assert clean == []
    bad = dict(RECORDING, calls=RECORDING["calls"] + [
        {"tool": "x", "args": {}, "result": {"note": "called 8.8.8.8 with sk-abcdefghijklmnopqrstuvwxyz0"}}])
    probs = replay.scan_recording(bad)
    assert any("8.8.8.8" in p for p in probs) and any("key" in p.lower() for p in probs)


def test_documentation_and_private_addresses_are_allowed_in_a_recording():
    ok = dict(RECORDING, calls=RECORDING["calls"] + [
        {"tool": "x", "args": {}, "result": {"note": "attacker 203.0.113.66 and host 10.0.0.5"}}])
    assert replay.scan_recording(ok) == []
