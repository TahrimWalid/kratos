"""Scripted tests for A6.5 schedule groups (agent/schedules.py kind="group" +
agent/scheduled_run.py::_run_group).

No real SSH/LLM: the pipeline dispatcher is canned and run_agent is monkeypatched.
Covers the store (job normalization, validation, round-trip, tolerant listing) and
the worker (ordered execution, union findings, per-job records, the on_failure
policy, gated exclusion applied group-wide)."""
from __future__ import annotations

import tomllib

import pytest

from kratos.agent import schedules as S
from kratos.agent import scheduled_run as W


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #
def test_save_group_round_trips(tmp_path):
    g = S.save_schedule(tmp_path, name="Nightly Suite", kind="group", cadence="daily",
                        on_failure="abort",
                        jobs=[{"kind": "audit", "label": "quick"},
                              {"kind": "preset", "preset": "deep"}])
    assert g.kind == "group" and g.is_runnable and g.on_failure == "abort"
    assert [j["kind"] for j in g.jobs] == ["audit", "preset"]
    data = tomllib.loads(g.path.read_text(encoding="utf-8"))
    assert data["jobs"][1]["preset"] == "deep"  # [[jobs]] array-of-tables round-trips
    reloaded = S.load_schedule(tmp_path, "nightly-suite")
    assert [j.get("preset") for j in reloaded.jobs] == [None, "deep"]


def test_empty_group_rejected(tmp_path):
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="empty", kind="group", jobs=[])


def test_invalid_job_rejected(tmp_path):
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="badjob", kind="group",
                        jobs=[{"kind": "preset"}])  # preset job with no preset name
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="badkind", kind="group",
                        jobs=[{"kind": "group"}])   # no nesting


def test_bad_on_failure_rejected(tmp_path):
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="g", kind="group",
                        jobs=[{"kind": "audit"}], on_failure="explode")


def test_normalize_job_drops_junk():
    assert S.normalize_job({"kind": "audit"}) == {"kind": "audit"}
    assert S.normalize_job({"kind": "preset", "preset": "p", "label": "L"}) == {
        "kind": "preset", "preset": "p", "label": "L"}
    assert S.normalize_job({"kind": "nope"}) is None
    assert S.normalize_job("notadict") is None


def test_listing_tolerates_malformed_jobs(tmp_path):
    # A hand-authored group file with a bad job entry must still list (bad job
    # dropped), not crash.
    (S.schedules_dir(tmp_path)).mkdir(parents=True, exist_ok=True)
    (S.schedules_dir(tmp_path) / "g.toml").write_text(
        'name = "g"\nkind = "group"\ncadence = "daily"\ndeliver = ["ntfy"]\n'
        '[[jobs]]\nkind = "audit"\n[[jobs]]\nkind = "bogus"\n', encoding="utf-8")
    g = S.load_schedule(tmp_path, "g")
    assert [j["kind"] for j in g.jobs] == ["audit"]  # bogus dropped
    assert g.is_runnable


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #
def _audit_dispatch(findings=None, fail=False):
    def dispatch(tool, args, data_dir):
        if fail and tool == "run_nmap_scan":
            return {"status": "error", "observation": "target unreachable"}
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings or []}}
        return {"status": "ok", "result": {}}
    return dispatch


def _fake_agent(findings):
    def run_agent(goal, data_dir):
        return {"status": "final_answer", "final_answer": "done", "transcript": [
            {"tool": "correlate_findings",
             "observation": {"status": "ok", "result": {"findings": findings}}}]}
    return run_agent


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, m, s):
        self.calls.append((m, s))
        return {"status": "sent"}


def test_group_runs_jobs_in_order_union_findings(tmp_path, monkeypatch):
    from kratos.agent import presets as P
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    S.save_schedule(tmp_path, name="suite", kind="group", cadence="daily",
                    jobs=[{"kind": "audit", "label": "quick"},
                          {"kind": "preset", "preset": "deep"}])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call",
                        _audit_dispatch([{"id": "NET-002", "severity": "medium", "title": "a"}]))
    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        _fake_agent([{"id": "CORR-SSH-001", "severity": "high", "title": "b"}]))
    spy = _Spy()
    rec = W.run_scheduled(S.load_schedule(tmp_path, "suite"), tmp_path, notifier=spy)

    assert rec["status"] == "completed"
    assert rec["findings_count"] == 2  # union of both jobs
    assert rec["severity_tally"] == {"high": 1, "medium": 1}
    assert [(j["label"], j["status"]) for j in rec["jobs"]] == [
        ("quick", "completed"), ("preset:deep", "final_answer")]
    assert "jobs (2)" in spy.calls[0][0]  # per-job summary in the notification


def test_group_on_failure_abort_skips_rest(tmp_path, monkeypatch):
    from kratos.agent import presets as P
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    S.save_schedule(tmp_path, name="suite", kind="group", cadence="daily", on_failure="abort",
                    jobs=[{"kind": "audit", "label": "quick"},
                          {"kind": "preset", "preset": "deep"}])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch(fail=True))
    ran = {"agent": 0}

    def _agent(goal, data_dir):
        ran["agent"] += 1
        return {"status": "final_answer", "transcript": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", _agent)
    rec = W.run_scheduled(S.load_schedule(tmp_path, "suite"), tmp_path, notifier=_Spy())

    assert rec["status"] == "aborted"
    assert ran["agent"] == 0  # the preset job never ran
    statuses = [(j["label"], j["status"]) for j in rec["jobs"]]
    assert statuses == [("quick", "aborted"), ("preset:deep", "skipped")]


def test_group_on_failure_continue_runs_all(tmp_path, monkeypatch):
    from kratos.agent import presets as P
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    S.save_schedule(tmp_path, name="suite", kind="group", cadence="daily", on_failure="continue",
                    jobs=[{"kind": "audit", "label": "quick"},
                          {"kind": "preset", "preset": "deep"}])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch(fail=True))
    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        _fake_agent([{"id": "CORR-SSH-001", "severity": "high", "title": "b"}]))
    rec = W.run_scheduled(S.load_schedule(tmp_path, "suite"), tmp_path, notifier=_Spy())

    assert rec["status"] == "completed_with_failures"
    assert rec["findings_count"] == 1  # only the preset job produced findings
    assert [j["status"] for j in rec["jobs"]] == ["aborted", "final_answer"]


def test_group_excludes_gated_tools(tmp_path, monkeypatch):
    from kratos.agent import presets as P
    from kratos.agent import tools as TOOLS
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    S.save_schedule(tmp_path, name="suite", kind="group", cadence="daily",
                    jobs=[{"kind": "preset", "preset": "deep"}])
    seen = {}

    def _agent(goal, data_dir):
        seen["registry"] = set(TOOLS.TOOL_REGISTRY.keys())
        return {"status": "final_answer", "transcript": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", _agent)
    before = set(TOOLS.TOOL_REGISTRY.keys())
    W.run_scheduled(S.load_schedule(tmp_path, "suite"), tmp_path, notifier=_Spy())
    assert "run_linux_command" not in seen["registry"]  # gated tool not selectable
    assert set(TOOLS.TOOL_REGISTRY.keys()) == before      # restored
