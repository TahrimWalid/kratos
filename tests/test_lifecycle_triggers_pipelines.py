"""0.1 §5.8: triggers can fire only on news (new / reopened / recurred -- an expired
acceptance reopens), and pipelines can branch on has_new_finding()."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from kratos.agent import trigger_eval, triggers as T
from kratos.agent.pipeline_when import WhenError, compile_when


def _f(change, sev="high", fid="CORR-SSH-001"):
    return {"id": fid, "severity": sev, "change": change}


@pytest.mark.parametrize("change,fires", [("new", True), ("reopened", True), ("recurred", True),
                                          ("unchanged", False), ("changed", False), (None, False)])
def test_only_new_or_reopened(change, fires):
    trig = SimpleNamespace(finding_id=None, min_severity="high", only_new_or_reopened=True)
    assert bool(trigger_eval._matched(trig, [_f(change)])) is fires
    plain = SimpleNamespace(finding_id=None, min_severity="high", only_new_or_reopened=False)
    assert trigger_eval._matched(plain, [_f(change)])        # default: every present finding


def test_the_flag_round_trips_and_old_files_default_off(tmp_path):
    tg = T.save_trigger(tmp_path, name="news", min_severity="high", only_new_or_reopened=True)
    assert T.load_trigger(tmp_path, "news").only_new_or_reopened is True
    old = T.save_trigger(tmp_path, name="old", min_severity="high")
    assert "only_new_or_reopened" not in old.path.read_text() and old.only_new_or_reopened is False
    assert tg.is_valid


def test_an_expired_acceptance_fires_a_news_only_trigger_once(tmp_path):
    """End to end through the lifecycle: unchanged -> no fire; the acceptance expires
    -> reopened -> fires."""
    import time
    import uuid

    from kratos.lifecycle import apply as A, decide as D
    from kratos.lifecycle.coverage import nothing
    from kratos.lifecycle.keys import finding_key
    from kratos.run_context import RunContext

    trig = SimpleNamespace(finding_id="CORR-SSH-001", min_severity=None, only_new_or_reopened=True)
    f = {"id": "CORR-SSH-001", "title": "t", "severity": "high", "entities": ["1.2.3.4"]}
    t0 = time.time()

    def run(now):
        r = RunContext(run_id=uuid.uuid4().hex, source="schedule", target="h", session_id=None, started_at=now)
        return A.apply_run([f], target="h", coverage=nothing(), run=r, data_dir=tmp_path, now=now)[0]

    assert trigger_eval._matched(trig, run(t0))                       # new
    assert not trigger_eval._matched(trig, run(t0 + 10))              # unchanged
    D.accept_risk(finding_key("CORR-SSH-001", "h", ""), actor=D.Actor("a", "cli"), reason="r", owner=None,
                  expires_at=t0 + 100, data_dir=tmp_path, now=t0 + 20)
    assert not trigger_eval._matched(trig, run(t0 + 50))              # accepted, unchanged
    assert trigger_eval._matched(trig, run(t0 + 200))                 # expired -> reopened
    assert not trigger_eval._matched(trig, run(t0 + 300))


def test_has_new_finding_in_pipelines():
    ctx = SimpleNamespace(findings=[_f("unchanged"), _f("new", "low", "NET-002")])
    assert compile_when("has_new_finding()")(ctx) is True
    assert compile_when("has_new_finding(min_severity='high')")(ctx) is False
    assert compile_when("not has_new_finding() or finding_count > 5")(SimpleNamespace(findings=[])) is True
    for bad in ("has_new_finding(1)", "has_new_finding(min_severity='huge')", "has_new_finding(x=1)"):
        with pytest.raises(WhenError):
            compile_when(bad)
