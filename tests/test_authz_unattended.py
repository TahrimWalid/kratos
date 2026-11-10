"""D.7: per-user daily budgets, and schedules / triggers acting as the user they run as."""
from __future__ import annotations

from datetime import timezone

import pytest

pytest.importorskip("requests")

from kratos import authz, kratos_config, llm_interface, settings_store  # noqa: E402
from kratos.authz import audit as AU  # noqa: E402
from kratos.authz import users as U  # noqa: E402
from kratos.budget import limits as L  # noqa: E402
from kratos.budget.guard import BudgetExceeded  # noqa: E402
from kratos.lifecycle.decide import Actor  # noqa: E402
from kratos.run_context import run_scope  # noqa: E402

M1, M2 = "192.0.2.10", "192.0.2.11"
OWNER = authz.owner_actor("cli")


class _Resp:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {"choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 1000, "total_tokens": 2000}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_interface.time.sleep", lambda s: None)
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz", lambda data_dir=None: timezone.utc)
    monkeypatch.setattr(llm_interface.requests, "post", lambda *a, **k: _Resp())
    from kratos.budget import pricing

    pricing.set_rate(tmp_path, "priced-model", 100.0, 100.0, actor="test")   # $0.20 per call
    settings_store.set(L.USER_DAILY_COST, 0.20, data_dir=tmp_path, actor="test")
    U.add_user(tmp_path, "ivy", "investigator", OWNER, scopes=[M1])
    U.add_user(tmp_path, "vic", "viewer", OWNER, scopes=[M1])
    from kratos.serve import auth

    acts = {}
    for n in ("ivy", "vic"):
        _t, row = auth.create_token(tmp_path, name=f"{n}-t", user=n)
        acts[n] = Actor(user=n, interface="serve", user_id=U.find(tmp_path, n).user_id,
                        credential=f"token:{row['token_id']}")
    return tmp_path, acts


def _call():
    return llm_interface._query_openai_compatible("x" * 35, "", 100)


def test_a_user_over_their_daily_cap_is_refused_with_their_own_figure(env):
    dd, acts = env
    with authz.acting_as(acts["ivy"]), run_scope("web"):
        _call()                                         # spends $0.20 of $0.20 (its estimate fit)
        with pytest.raises(BudgetExceeded) as e:
            _call()                                     # nothing left
    assert e.value.scope == L.SCOPE_USER_COST
    msg = e.value.user_message()
    assert "your own daily model budget" in msg and "$0.20 of $0.20" in msg
    with authz.acting_as(acts["vic"]), run_scope("web"):
        _call()                                         # vic is unaffected
    with run_scope("cli"):
        _call()                                         # and so is the owner


def test_the_precheck_refuses_a_user_who_is_out_of_budget_before_anything_starts(env):
    from kratos.budget import guard

    dd, acts = env
    with authz.acting_as(acts["ivy"]), run_scope("web"):
        _call()
    settings_store.set(L.USER_DAILY_COST, 0.10, data_dir=dd, actor="test")
    with authz.acting_as(acts["ivy"]), run_scope("web"):
        refusal = guard.precheck("web", data_dir_=dd)
    assert refusal is not None and refusal.scope == L.SCOPE_USER_COST
    with authz.acting_as(acts["vic"]), run_scope("web"):
        assert guard.precheck("web", data_dir_=dd) is None


# --- schedules and triggers -----------------------------------------------------------
@pytest.fixture
def sched(tmp_path, monkeypatch):
    from kratos.agent import scheduled_run as SR
    from kratos.agent import schedules

    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    U.add_user(tmp_path, "ivy", "investigator", OWNER, scopes=[M1])
    seen = []

    def fake_inner(schedule, data_dir, *, deliver, notifier):
        seen.append((authz.current_actor(), kratos_config.get_active_target()))
        return {"schedule": schedule.name, "status": "completed"}

    monkeypatch.setattr(SR, "_run_scheduled", fake_inner)
    sent = []
    note = lambda message, severity: sent.append(message) or {"status": "queued"}  # noqa: E731
    return tmp_path, schedules, SR, seen, note, sent


def test_a_schedule_runs_as_its_user_with_their_scope(sched):
    dd, schedules, SR, seen, note, _sent = sched
    s = schedules.save_schedule(dd, name="nightly", kind="audit", target=M1)
    schedules.set_run_as(dd, "nightly", U.find(dd, "ivy").user_id)
    s = schedules.load_schedule(dd, "nightly")
    assert s.run_as == U.find(dd, "ivy").user_id
    rec = SR.run_scheduled(s, dd, deliver=False, notifier=note)
    assert rec["status"] == "completed" and seen[-1][0].user_id == s.run_as
    # an edit keeps who it runs as -- never silently the owner
    schedules.save_schedule(dd, name="nightly", kind="audit", target=M1, cadence="daily")
    assert schedules.load_schedule(dd, "nightly").run_as == s.run_as


def test_a_schedule_refuses_when_its_user_is_disabled_or_narrowed(sched):
    dd, schedules, SR, seen, note, sent = sched
    schedules.save_schedule(dd, name="nightly", kind="audit", target=M1)
    schedules.set_run_as(dd, "nightly", U.find(dd, "ivy").user_id)
    U.set_disabled(dd, "ivy", True, OWNER)
    rec = SR.run_scheduled(schedules.load_schedule(dd, "nightly"), dd, deliver=True, notifier=note)
    assert rec["status"] == "refused" and "disabled" in rec["error"] and not seen
    assert sent and "did not run" in sent[-1]
    assert "ivy" not in sent[-1] and "192.0.2" not in sent[-1]     # no account or address in the alert
    U.set_disabled(dd, "ivy", False, OWNER)
    schedules.save_schedule(dd, name="other", kind="audit", target=M2)
    schedules.set_run_as(dd, "other", U.find(dd, "ivy").user_id)
    rec = SR.run_scheduled(schedules.load_schedule(dd, "other"), dd, deliver=False, notifier=note)
    assert rec["status"] == "refused" and "that you may see" in rec["error"]
    assert AU.query(dd, result="refused", interface="schedule")


def test_an_owner_schedule_is_unchanged(sched):
    dd, schedules, SR, seen, note, _ = sched
    s = schedules.save_schedule(dd, name="mine", kind="audit", target="203.0.113.9")
    assert s.run_as == "owner"
    assert SR.run_scheduled(s, dd, deliver=False, notifier=note)["status"] == "completed"


def test_a_trigger_investigation_acts_as_its_user(sched, monkeypatch):
    from kratos.agent import trigger_eval as TE
    from kratos.agent import triggers

    dd, *_ = sched
    triggers.save_trigger(dd, name="deep", action="investigate", min_severity="high")
    triggers.set_run_as(dd, "deep", U.find(dd, "ivy").user_id)
    t = triggers.load_trigger(dd, "deep")
    seen = []

    def investigate(goal, data_dir):
        seen.append(authz.current_actor().user_id)
        return {"status": "final_answer", "final_answer": "ok", "findings": []}

    found = [{"id": "AUTH-004", "severity": "high", "title": "x"}]
    from datetime import datetime

    body, *_ = TE._build_body(dd, t, found, M1, datetime.now(timezone.utc), True, investigate)
    assert seen == [t.run_as]
    U.set_disabled(dd, "ivy", True, OWNER)
    body, _w, _ids, inv = TE._build_body(dd, t, found, M1, datetime.now(timezone.utc), True, investigate)
    assert inv["status"] == "refused" and "disabled" in body and seen == [t.run_as]
