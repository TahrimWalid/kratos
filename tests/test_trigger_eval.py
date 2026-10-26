"""Scripted tests for A6.4 trigger evaluation (agent/trigger_eval.py).

The safety-critical suite: matching is on STRUCTURED fields only (never evidence),
the recommend-only boundary holds (no code path executes a state-changing tool),
attacker text in a finding never reaches a notification or an investigation goal,
cooldown/dedupe works, the target filter works, and all three actions fire
correctly with a spy notifier + fake investigator.
"""
from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

import pytest

from kratos.agent import trigger_eval as TE
from kratos.agent import triggers as TR


@pytest.fixture(autouse=True)
def _lab_target(monkeypatch):
    """Kratos ships no default target, so these runs name the one they investigate."""
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_HOST", "10.136.28.168")


_INJECTION = "user=<script>evil</script>; rm -rf / ; id=CRITICAL"
_NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, message, severity):
        self.calls.append((message, severity))
        return {"status": "sent", "severity": severity}


def _findings(sev="high", fid="CORR-SSH-001"):
    return [{"id": fid, "severity": sev, "title": "SSH exposed", "evidence": [_INJECTION]},
            {"id": "NET-001", "severity": "info", "title": "clean", "evidence": [_INJECTION]}]


# --------------------------------------------------------------------------- #
# Matching (structured only)
# --------------------------------------------------------------------------- #
def test_severity_match(tmp_path):
    tg = TR.save_trigger(tmp_path, name="high", action="notify", min_severity="high")
    m = TE._matched(tg, _findings("high"))
    assert [f["id"] for f in m] == ["CORR-SSH-001"]  # info NET-001 excluded


def test_finding_id_match(tmp_path):
    tg = TR.save_trigger(tmp_path, name="ssh", action="notify", finding_id="CORR-SSH-001")
    assert [f["id"] for f in TE._matched(tg, _findings())] == ["CORR-SSH-001"]
    assert TE._matched(tg, _findings(fid="OTHER-1")) == []


def test_combined_condition_requires_both(tmp_path):
    tg = TR.save_trigger(tmp_path, name="c", action="notify", min_severity="high",
                         finding_id="CORR-SSH-001")
    assert len(TE._matched(tg, _findings("high", "CORR-SSH-001"))) == 1
    # right id but too-low severity -> no match
    assert TE._matched(tg, _findings("low", "CORR-SSH-001")) == []


def test_matched_reads_no_evidence():
    # Structural: _matched must never read the 'evidence' key.
    tree = ast.parse(inspect.getsource(TE._matched))
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            keys.add(node.value)
    assert "evidence" not in keys


# --------------------------------------------------------------------------- #
# The three actions
# --------------------------------------------------------------------------- #
def test_notify_action_fires_and_stamps(tmp_path):
    TR.save_trigger(tmp_path, name="n", action="notify", min_severity="high")
    spy = _Spy()
    fired = TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy)
    assert len(fired) == 1 and fired[0]["action"] == "notify"
    assert "When: " in spy.calls[0][0] and spy.calls[0][1] == "critical"  # high -> critical bucket


def test_playbook_action_includes_response_plan(tmp_path):
    TR.save_trigger(tmp_path, name="pb", action="playbook", finding_id="CORR-SSH-001")
    spy = _Spy()
    TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy)
    assert "Response plan" in spy.calls[0][0]


def test_investigate_action_runs_and_reports(tmp_path):
    TR.save_trigger(tmp_path, name="inv", action="investigate", finding_id="CORR-SSH-001")
    spy = _Spy()
    seen = {}

    def fake_investigate(goal, data_dir):
        seen["goal"] = goal
        return {"status": "final_answer", "findings": [],
                "final_answer": "Confirmed a brute-force pattern; recommend blocking the source."}

    TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy,
                         investigate_fn=fake_investigate)
    assert "brute-force" in spy.calls[0][0]
    # The goal is built from id+title only — attacker evidence never enters it.
    assert "evil" not in seen["goal"] and "rm -rf" not in seen["goal"]
    assert "CORR-SSH-001" in seen["goal"]


def test_investigate_deferred_when_investigations_disabled(tmp_path):
    TR.save_trigger(tmp_path, name="inv", action="investigate", min_severity="high")
    spy = _Spy()
    ran = {"n": 0}

    def fake_investigate(goal, data_dir):
        ran["n"] += 1
        return {"status": "final_answer", "final_answer": "x"}

    TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy,
                         run_investigations=False, investigate_fn=fake_investigate)
    assert ran["n"] == 0  # not run inline
    assert "scheduled run" in spy.calls[0][0]


# --------------------------------------------------------------------------- #
# Injection boundary: attacker evidence never reaches a notification
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("action", ["notify", "playbook"])
def test_evidence_never_in_notification(tmp_path, action):
    TR.save_trigger(tmp_path, name="t", action=action, finding_id="CORR-SSH-001")
    spy = _Spy()
    TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy)
    assert "evil" not in spy.calls[0][0] and "rm -rf" not in spy.calls[0][0]


# --------------------------------------------------------------------------- #
# Cooldown + target filter
# --------------------------------------------------------------------------- #
def test_cooldown_suppresses_then_allows(tmp_path):
    TR.save_trigger(tmp_path, name="cd", action="notify", min_severity="high", cooldown_minutes=60)
    spy = _Spy()
    assert len(TE.evaluate_triggers(tmp_path, _findings(), "t", now=_NOW, notifier=spy)) == 1
    assert len(TE.evaluate_triggers(tmp_path, _findings(), "t", now=_NOW + timedelta(minutes=30), notifier=spy)) == 0
    assert len(TE.evaluate_triggers(tmp_path, _findings(), "t", now=_NOW + timedelta(minutes=61), notifier=spy)) == 1


def test_target_filter(tmp_path):
    TR.save_trigger(tmp_path, name="host-a", action="notify", min_severity="high", target="10.0.0.1")
    spy = _Spy()
    assert TE.evaluate_triggers(tmp_path, _findings(), "192.168.9.9", now=_NOW, notifier=spy) == []
    assert len(TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=spy)) == 1


def test_one_bad_trigger_doesnt_sink_the_rest(tmp_path, monkeypatch):
    TR.save_trigger(tmp_path, name="good", action="notify", min_severity="high")
    TR.save_trigger(tmp_path, name="boom", action="notify", min_severity="high")
    spy = _Spy()
    real_fire = TE._fire

    def flaky_fire(data_dir, trigger, *a, **k):
        if trigger.name == "boom":
            raise RuntimeError("kaboom")
        return real_fire(data_dir, trigger, *a, **k)

    monkeypatch.setattr(TE, "_fire", flaky_fire)
    fired = TE.evaluate_triggers(tmp_path, _findings(), "t", now=_NOW, notifier=spy)
    names = {f["trigger"] for f in fired}
    assert "good" in names and "boom" in names  # boom recorded with an error, good still fired
    assert any(f.get("error") for f in fired if f["trigger"] == "boom")


# --------------------------------------------------------------------------- #
# preview_trigger (test command) — no side effects
# --------------------------------------------------------------------------- #
def test_preview_trigger_no_delivery_no_persist(tmp_path):
    tg = TR.save_trigger(tmp_path, name="p", action="playbook", min_severity="high")
    p = TE.preview_trigger(tmp_path, tg, _findings(), "10.0.0.1", now=_NOW)
    assert p["would_fire"] is True and p["body"] and "Response plan" in p["body"]
    assert TR.read_fire_records(tmp_path, "p") == []  # nothing persisted


# --------------------------------------------------------------------------- #
# Recommend-only, structurally
# --------------------------------------------------------------------------- #
def test_module_calls_nothing_that_executes():
    tree = ast.parse(inspect.getsource(TE))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                called.add(fn.attr)
    forbidden = {"execute_tool_call", "run_pipeline", "run_remote_command",
                 "run_remote_script", "Popen", "check_output", "system"}
    assert not (called & forbidden)


# --------------------------------------------------------------------------- #
# Integration: a scheduled run evaluates triggers; the investigate action's
# headless runner strips every approval-gated tool (recommend-only boundary).
# --------------------------------------------------------------------------- #
def test_scheduled_run_fires_a_trigger(tmp_path, monkeypatch):
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run as W

    S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly")
    TR.save_trigger(tmp_path, name="high", action="notify", min_severity="high")
    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "SSH"}]

    def _dispatch(tool, args, data_dir):
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings}}
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _dispatch)
    calls = []
    rec = W.run_scheduled(S.load_schedule(tmp_path, "wk"), tmp_path,
                          notifier=lambda m, s: (calls.append((m, s)) or {"status": "sent"}))
    assert rec["status"] == "completed"
    assert "high" in (rec.get("triggers_fired") or [])
    # the schedule's own report notification AND the trigger notification both went
    assert any("Trigger 'high' (" in m for m, _ in calls)


def test_run_headless_investigation_excludes_gated_tools(tmp_path, monkeypatch):
    from kratos.agent import scheduled_run as W
    from kratos.agent import tools as T

    seen = {}

    def fake_run_agent(goal, data_dir):
        seen["registry"] = set(T.TOOL_REGISTRY.keys())
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    before = set(T.TOOL_REGISTRY.keys())
    out = W.run_headless_investigation("look at CORR-SSH-001", tmp_path, run_agent_fn=fake_run_agent)
    assert out["status"] == "final_answer"
    # requires_approval tools (run_linux_command / capture_traffic) not selectable
    assert "run_linux_command" not in seen["registry"]
    assert "capture_traffic" not in seen["registry"]
    assert set(T.TOOL_REGISTRY.keys()) == before  # restored


def test_investigate_action_does_not_recurse(tmp_path):
    """A trigger's investigate action must NEVER re-evaluate triggers on its own
    findings (the infinite-loop guard). Two independent proofs so a future edit
    that wires evaluate_triggers into the headless investigation is caught."""
    from kratos.agent import scheduled_run as W

    # (1) Structural: the real headless investigation never calls evaluate_triggers.
    assert "evaluate_triggers" not in inspect.getsource(W.run_headless_investigation)

    # (2) Functional: an investigate trigger whose investigation returns a finding
    # that WOULD match the trigger again still fires exactly ONCE per evaluation —
    # the investigation's findings are not fed back into trigger evaluation.
    TR.save_trigger(tmp_path, name="inv", action="investigate", finding_id="CORR-SSH-001")

    def re_matching_investigate(goal, data_dir):
        return {"status": "final_answer",
                "findings": [{"id": "CORR-SSH-001", "severity": "critical", "title": "again"}],
                "final_answer": "found it again"}

    fired = TE.evaluate_triggers(tmp_path, _findings(), "10.0.0.1", now=_NOW, notifier=_Spy(),
                                 investigate_fn=re_matching_investigate)
    assert len([f for f in fired if f["trigger"] == "inv"]) == 1


def test_a_trigger_investigation_looks_at_the_schedules_machine(tmp_path, monkeypatch):
    """B.5 run record of a real scheduled run: the schedule pins its own machine, restores
    the active target when its work is done, and only THEN evaluates triggers -- so a
    trigger's investigation ran with no target (or the person's default machine)."""
    from kratos import kratos_config
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run as W
    from kratos.budget import limits as L
    from kratos import settings_store

    kratos_config.set_active_target("default-box.example")      # the person's default machine
    S.save_schedule(tmp_path, name="other", kind="audit", target="10.0.0.77", cadence="weekly", deliver=[])
    TR.save_trigger(tmp_path, name="dig", action="investigate", finding_id="CORR-SSH-001")
    settings_store.set(L.TRIGGER_INVESTIGATIONS, True, data_dir=tmp_path, actor="test")
    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "SSH"}]

    def _dispatch(tool, args, data_dir):
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings}}
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _dispatch)
    seen = []

    def fake_run_agent(goal, data_dir, *a, **kw):
        seen.append(kratos_config.get_active_target())
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_run_agent)
    rec = W.run_scheduled(S.load_schedule(tmp_path, "other"), tmp_path, deliver=False,
                          notifier=lambda m, s: {"status": "sent"})
    assert "dig" in (rec.get("triggers_fired") or [])
    assert seen == ["10.0.0.77"]
    assert kratos_config.get_active_target() == "default-box.example"   # restored afterwards



def test_an_alert_says_what_happened_and_where_first_and_what_to_do_next(tmp_path):
    """Phase C audit: alerts led with the trigger name and rule ids; a person on a phone
    could not tell what happened. The first line now names severity, the machine (its
    sub-agent name when paired) and what happened; ids and credits come last."""
    from kratos.storage.subagent_store import SubAgentStore

    store = SubAgentStore(tmp_path / "kratos.db")
    code = store.create_pairing_code(name="web-01")
    tid = store.redeem_pairing_code(code["code"], agent_id="a1", hostname="web-01", agent_version="0.9.0")["target_id"]
    store.set_link("198.51.100.20", tid, "subagent")
    trig = TR.save_trigger(tmp_path, name="phone", action="notify", min_severity="high")
    findings = [{"id": "PRIV-001", "severity": "critical", "title": "alice was given sudo"},
                {"id": "NET-002", "severity": "high", "title": "Open ports"}]
    from kratos.agent import trigger_eval as TE

    body, worst, ids, _ = TE._build_body(tmp_path, trig, findings, "198.51.100.20",
                                         datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc), False, None)
    first = body.splitlines()[0]
    assert first.startswith("CRITICAL on web-01 (198.51.100.20): ") and "(+1 more)" in first
    assert "privileged" in first.lower() and "alice" not in first   # the worst first, in Kratos's words
    assert "Next: open Kratos" in body and body.index("Next:") < body.index("ids: ")
    assert TE.machine_label(tmp_path, "203.0.113.9") == "203.0.113.9"
