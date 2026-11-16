"""The extracted answer checks (D.2 §5.1) and Guard 13 (an SSVC decision Kratos didn't make).

The extraction itself is proven by every existing loop/guard test passing unchanged; these
tests pin the pure-function surface the fleet answer relies on, and the one new check --
through the pure functions, the single-machine loop, and a fleet answer.
"""
from __future__ import annotations

import json

import pytest

from kratos.agent import answer_checks as AC
from tests.test_collect_loop import Chat, collected, data_dir, make_report, run  # noqa: F401 -- fixtures

ACT_PKG = {"id": "PKG-001", "title": "openssl has known vulnerabilities", "severity": "high", "subject": "openssl",
           "entities": ["CVE-2024-0001"], "state": "new",
           "ssvc": {"outcome": "act", "inputs": {}}}
PRIV = {"id": "PRIV-001", "title": "Recently granted privileged access", "severity": "high", "subject": "bob",
        "entities": ["bob:sudo"], "state": "new"}


def _ev(findings, **kw) -> AC.MachineEvidence:
    return AC.MachineEvidence(machine="10.0.0.5", goal="which machines have an Act decision?", findings=findings,
                              correlate_called=True, any_data_tool_ok=True, **kw)


def test_every_check_has_a_tag_a_budget_and_a_place_in_the_correction_order():
    assert set(AC.MAX_REJECTIONS) == set(AC.VIOLATION_TAGS) == set(AC.CORRECTION_ORDER)


@pytest.mark.parametrize("answer,findings,expected", [
    ("An Act decision is required because of PRIV-001.", [PRIV], ["act"]),
    ("The SSVC decision is Attend for openssl.", [ACT_PKG], ["attend"]),
    ("No Act decision was found on this machine.", [PRIV], []),
    ("We should act on this decision quickly.", [PRIV], []),
    ("PKG-001: openssl, CISA SSVC decision Act -- upgrade it.", [PRIV, ACT_PKG], []),   # the decision it has
])
def test_guard13_an_ssvc_decision_must_be_one_kratos_computed(answer, findings, expected):
    res = AC.evaluate(answer, _ev(findings))["guard13"]
    assert res.data["unmade"] == expected and res.trigger == bool(expected)


def test_guard13_rejects_once_then_notes(monkeypatch):
    ev = _ev([{**PRIV, "severity": "medium"}])     # not serious: only Guard 13 is in play
    counts: dict[str, int] = {}
    answer = "An Act decision is required."
    evaluation = AC.evaluate(answer, ev)
    tags, corr = AC.rejections(evaluation, ev, counts, final_iteration=False)
    assert tags == ["decision_not_computed"] and "Kratos computed no such decision" in corr[0]
    assert AC.rejections(evaluation, ev, counts, final_iteration=False) == ([], [])   # budget of one
    noted = AC.apply_notes(answer, evaluation, ev)
    assert noted.text.startswith("[NOTE: this answer mentions an SSVC decision (Act)")
    assert noted.text.endswith(answer)


def test_guard13_in_the_single_machine_loop(data_dir, collected, monkeypatch):
    collected(make_report([PRIV]))
    fixed = "PRIV-001: bob was recently given sudo; no vulnerability decisions here."
    chat = Chat([json.dumps({"reasoning": "r", "final_answer": "An Act decision is required for PRIV-001."}),
                 json.dumps({"reasoning": "r", "final_answer": fixed})])
    result = run(data_dir, chat, monkeypatch)
    assert "REJECTED (decision not made by Kratos)" in chat.users[1]
    assert result["status"] == "final_answer" and result["final_answer"].endswith(fixed)


# E.1: the dismissive-verdict check (guard3) extends to a code-computed attack path / chokepoint
PATH2 = {"id": "PATH-002", "title": "Attack path to db", "severity": "high", "subject": "machine:db",
         "entities": ["abc123"], "state": "open"}
PATH3 = {"id": "PATH-003", "title": "Fix this first: rotate the reused key (cuts 3 paths)", "severity": "medium",
         "subject": "key-reuse:ab", "entities": ["key-reuse:ab"], "state": "open"}


@pytest.mark.parametrize("answer,findings,flagged", [
    ("PATH-002 is low priority and not worth worrying about.", [PATH2], True),
    ("PATH-003 is low priority; ignore it for now.", [PATH3], True),
    ("PATH-003 is the top fix here -- rotate the reused key now.", [PATH3], False),   # names but acts
    ("Your biggest exposure is the internet-facing web host.", [PATH2], False),        # doesn't name it
])
def test_guard3_flags_dismissing_a_computed_attack_path(answer, findings, flagged):
    """The model may explain the attack-path summary but never re-rank it: calling a
    code-computed PATH-002/PATH-003 low priority is caught by the dismissive-verdict check."""
    res = AC.evaluate(answer, _ev(findings))["guard3"]
    assert res.trigger is flagged


def test_guard3_exempts_a_risk_accepted_path():
    accepted = {**PATH2, "state": "risk_accepted"}
    assert AC.evaluate("PATH-002 is low priority.", _ev([accepted]))["guard3"].trigger is False
