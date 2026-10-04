"""Guard 7 -- structured claims (docs/time_window_design.md §9/§14). The motivating live
incident: measure_auth_activity reported 4,980 distinct failing IPs; the model's answer
said "5,023 distinct source IPs"."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.timewin.claims import measurement_summary, verify_claims
from kratos.timewin.measure import parse_output
from kratos.timewin.toolwin import resolve_tool_window
from kratos.timewin.windows import TimeContext, current_context

UTC = ZoneInfo("UTC")
NOW = datetime(2026, 9, 27, 23, 10, tzinfo=UTC).timestamp()


def _measurement(start: float, end: float, failed: int, ips: dict[str, int], head: float | None = None):
    lines = ["META\tjournald\tpresent", "META\trc\t0"]
    if head is not None:
        lines.append(f"META\tjournal_head\t{head}")
    for ip, n in ips.items():
        lines.append(f"CNT\tssh_failed_login\t{ip}\troot\t{n}\t{start + 10}\t{start + 20}")
    extra = failed - sum(ips.values())
    if extra:
        lines.append(f"CNT\tssh_failed_login\t-\troot\t{extra}\t{start + 10}\t{start + 20}")
    lines.append(f"DONE\t{failed}\t{start + 10}\t{start + 20}")
    return parse_output("\n".join(lines), start, end, 0.0)


def _ctx_with(window_intent, m_factory) -> tuple[TimeContext, str]:
    ctx = TimeContext(UTC, now=NOW)
    w = ctx.resolve(window_intent)
    ctx.queried.setdefault(w.id, set()).add("measure_auth_activity")
    ctx.measurements[w.id] = measurement_summary(m_factory(w))
    return ctx, w.id


def test_count_claim_matching_the_measurement_is_verified():
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 30, "unit": "minute"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 5, {"10.136.28.52": 5}))
    problems, claims = verify_claims(ctx, "There were 5 failed SSH login attempts in the last 30 minutes.",
                                     [{"kind": "count", "metric": "ssh_failed_logins", "window": wid, "value": 5}])
    assert problems == [] and claims[0]["verified"] and claims[0]["measured"] == 5


def test_real_incident_fabricated_ip_count_is_caught_in_claims_and_prose():
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 3, "unit": "hour"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 1000000,
                                                {f"198.51.{i // 250}.{i % 250}": 200 for i in range(4980)} | {"x": 4000}))
    answer = "There were 1,000,000 failed SSH login attempts from 5,023 distinct source IPs."
    problems, _ = verify_claims(ctx, answer, [
        {"kind": "count", "metric": "ssh_failed_logins", "window": wid, "value": 1000000},
        {"kind": "count", "metric": "distinct_failed_login_ips", "window": wid, "value": 5023}])
    assert any("measured as 4981, not 5023" in p for p in problems)
    assert any("5,023" in p and "no measurement" in p for p in problems)


def test_absence_needs_full_coverage():
    start_head = NOW - 3600  # journal only covers the last hour of a 3-hour window
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 3, "unit": "hour"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 0, {}, head=start_head))
    problems, _ = verify_claims(ctx, "No failed logins in the last 3 hours.",
                                [{"kind": "absence", "metric": "ssh_failed_logins", "window": wid}])
    assert any("only 33.3% of" in p for p in problems)
    # the honest version passes: say the rest is unknown
    problems, _ = verify_claims(ctx, "Logs only cover the last hour; the earlier part is unknown.",
                                [{"kind": "unknown", "window": wid, "reason": "journal starts 1h ago"}])
    assert problems == []


def test_absence_with_full_coverage_is_verified():
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 1, "unit": "hour"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 0, {}))
    problems, claims = verify_claims(ctx, "No failed SSH logins in the last hour.",
                                     [{"kind": "absence", "metric": "ssh_failed_logins", "window": wid}])
    assert problems == [] and claims[0]["verified"]


def test_missing_claims_on_a_measured_answer_is_rejected():
    ctx, _ = _ctx_with({"kind": "rolling", "amount": 1, "unit": "hour"},
                       lambda w: _measurement(w.start_utc, w.end_utc, 3, {"1.2.3.4": 3}))
    problems, _ = verify_claims(ctx, "There were 3 failed logins.", None)
    assert any("carries no \"claims\"" in p for p in problems)


def test_claim_about_an_unqueried_window_is_rejected():
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 1, "unit": "hour"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 3, {"1.2.3.4": 3}))
    other = ctx.resolve({"kind": "rolling", "amount": 7, "unit": "day"})
    problems, _ = verify_claims(ctx, "x", [{"kind": "absence", "metric": "ssh_failed_logins", "window": other.id}])
    assert any("never queried" in p for p in problems)


def test_prose_period_not_queried_is_flagged_but_explicit_utc_times_inside_a_window_pass():
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 30, "unit": "minute"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 5, {"10.136.28.52": 5}))
    claim = [{"kind": "count", "metric": "ssh_failed_logins", "window": wid, "value": 5}]
    ok, _ = verify_claims(ctx, "Between 22:45 and 23:05 UTC there were 5 failed attempts.", claim)
    assert ok == []
    bad, _ = verify_claims(ctx, "There were 5 failed attempts, the same as last month.", claim)
    assert any("last month" in p for p in bad)


@pytest.mark.parametrize("text", [
    "5 failed attempts from 10.136.28.52 over 3 hours (33.7% covered) on port 22.",
    "5 failed attempts; the journal starts at 22:08 on 2026-09-27.",
])
def test_durations_percent_ports_ips_times_are_not_treated_as_counts(text):
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 30, "unit": "minute"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 5, {"10.136.28.52": 5}))
    problems, _ = verify_claims(ctx, text, [{"kind": "count", "metric": "ssh_failed_logins", "window": wid, "value": 5}])
    assert problems == []


# ---------------------------------------------------------------------------
# Guard 7 inside run_agent
# ---------------------------------------------------------------------------
class ScriptedChat:
    def __init__(self, responses): self.responses, self.calls = list(responses), []
    def __call__(self, *, system_prompt, user_prompt, **_):
        self.calls.append(user_prompt)
        return self.responses.pop(0)


def test_guard7_rejects_a_wrong_number_then_accepts_the_verified_answer(tmp_path, monkeypatch):
    def fake_measure(data_dir, window=None, since=None, until=None):
        tw = resolve_tool_window(window=window, since=since, until=until, tool="measure_auth_activity")
        m = _measurement(tw.window.start_utc, tw.window.end_utc, 5, {"10.136.28.52": 5})
        current_context().measurements[tw.window.id] = measurement_summary(m)
        return {"status": "ok", "counts": {"ssh_failed_login": 5}}

    monkeypatch.setattr(TOOL_REGISTRY["measure_auth_activity"], "handler", fake_measure)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **k: {"findings": [], "count": 0, "staleness_warning": None})
    good = [{"kind": "count", "metric": "ssh_failed_logins", "window": "w1", "value": 5}]
    chat = ScriptedChat([
        json.dumps({"reasoning": "r", "tool": "measure_auth_activity", "args": {"window": {"id": "w1"}}}),
        json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
        json.dumps({"reasoning": "d", "final_answer": "There were 7 failed attempts in the last 30 minutes.",
                    "claims": [{"kind": "count", "metric": "ssh_failed_logins", "window": "w1", "value": 7}]}),
        json.dumps({"reasoning": "d", "final_answer": "There were 5 failed attempts in the last 30 minutes.",
                    "claims": good}),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("how many failed logins in the last 30 minutes?", tmp_path, timezone="UTC", now=NOW)
    rejected = [s for s in out["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected and "claims_not_verified" in rejected[0]["violations"]
    assert "measured as 5, not 7" in chat.calls[-1]  # the correction reached the model
    assert out["claims"][0]["verified"] and "[NOTE:" not in out["final_answer"]


def test_untimed_goals_are_unaffected_by_guard7(tmp_path, monkeypatch):
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **k: {"findings": [], "count": 0, "staleness_warning": None})
    chat = ScriptedChat([json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
                         json.dumps({"reasoning": "d", "final_answer": "SSH is configured sensibly."})])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("is ssh configured well?", tmp_path, timezone="UTC", now=NOW)
    assert out["status"] == "final_answer" and "[NOTE:" not in out["final_answer"] and len(chat.calls) == 2


def test_claims_written_inside_the_answer_are_pulled_out_and_verified(tmp_path, monkeypatch):
    """Seen live (flash-lite): the claims list was written INTO the answer ('... Claims:
    [{"kind": "count", ...}]'), so the user saw raw JSON and the answer got an
    'unverified' note. It is now taken out of the text and verified like the field."""
    def fake_measure(data_dir, window=None, since=None, until=None):
        tw = resolve_tool_window(window=window, since=since, until=until, tool="measure_auth_activity")
        m = _measurement(tw.window.start_utc, tw.window.end_utc, 5, {"10.136.28.52": 5})
        current_context().measurements[tw.window.id] = measurement_summary(m)
        return {"status": "ok", "counts": {"ssh_failed_login": 5}}

    monkeypatch.setattr(TOOL_REGISTRY["measure_auth_activity"], "handler", fake_measure)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **k: {"findings": [], "count": 0, "staleness_warning": None})
    prose = "There were 5 failed attempts in the last 30 minutes."
    inline = prose + ' Claims: [{"kind": "count", "metric": "ssh_failed_logins", "window": "w1", "value": 5}]'
    chat = ScriptedChat([
        json.dumps({"reasoning": "r", "tool": "measure_auth_activity", "args": {"window": {"id": "w1"}}}),
        json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
        json.dumps({"reasoning": "d", "final_answer": inline}),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("how many failed logins in the last 30 minutes?", tmp_path, timezone="UTC", now=NOW)
    assert out["final_answer"] == prose                       # no JSON shown, no note
    assert out["claims"] and out["claims"][0]["verified"]
    assert not [s for s in out["transcript"] if s.get("status") == "final_answer_rejected"]


@pytest.mark.parametrize("text", [
    "The claims: [1, 2] in the old report were wrong.",              # not claim objects
    'Claims: [{"kind": "count"}] -- and then more prose follows.',    # list isn't the end
    "No structured claims here at all.",
])
def test_prose_that_only_mentions_claims_is_left_alone(text):
    assert agent_loop._split_inline_claims(text) == (text, None)


def test_none_over_a_partial_window_is_fine_when_the_answer_says_the_rest_is_unknown():
    """Seen live: 'In the observed period ... no failed logins were detected ... activity prior
    to 15:24 UTC is unknown.' with an absence claim on the whole window got an 'unverified'
    note although the prose was exactly right."""
    start_head = NOW - 3600
    ctx, wid = _ctx_with({"kind": "rolling", "amount": 3, "unit": "hour"},
                         lambda w: _measurement(w.start_utc, w.end_utc, 0, {}, head=start_head))
    claim = [{"kind": "absence", "metric": "ssh_failed_logins", "window": wid}]
    problems, claims = verify_claims(
        ctx, "In the observed period no failed logins were detected; activity before that is unknown.", claim)
    assert problems == [] and claims[0]["verified"] and claims[0]["partial"]
    problems, _ = verify_claims(ctx, "No failed logins in the last 3 hours.", claim)   # still caught
    assert any("only 33.3% of" in p for p in problems)


def test_the_unverified_note_reads_plainly():
    from types import SimpleNamespace

    ctx = SimpleNamespace(windows={"w1": SimpleNamespace(label="last 24 hours")})
    raw = ("claim #2: only 1.3% of w1 was covered, so 'none' cannot be claimed for the whole window -- "
           'claim the covered part and mark the rest "unknown"')
    assert agent_loop._plain_claim_problem(raw, ctx) == \
        "only 1.3% of the last 24 hours was covered, so 'none' cannot be claimed for the whole window"


def test_the_unverified_note_names_periods_naturally():
    """Seen live (demo pass 5): 'ssh_successful_logins in the yesterday was measured as 0'."""
    from types import SimpleNamespace

    ctx = SimpleNamespace(windows={"w1": SimpleNamespace(label="yesterday"),
                                   "w2": SimpleNamespace(label="since Monday")})
    assert agent_loop._plain_claim_problem("claim #1: ssh_successful_logins in w1 was measured as 0", ctx) == \
        "ssh successful logins for yesterday was measured as 0"
    assert agent_loop._plain_claim_problem("claim #1: sudo_failures in w2 was measured as 3, not 5", ctx) == \
        "sudo failures since Monday was measured as 3, not 5"
