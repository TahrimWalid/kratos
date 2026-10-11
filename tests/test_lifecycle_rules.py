"""Every rule id the findings engine can emit has a lifecycle entry (0.1 §5.2).

A new rule without one fails here -- that's how later features are made to say
whether their findings are conditions, occurrences or run notes."""
from __future__ import annotations

import ast
import inspect

from kratos.adapters import findings_engine as FE
from kratos.lifecycle.rules import KINDS, RULES, rule_info


def _finding_ids() -> tuple[set[str], list[int]]:
    """id= keyword values of every Finding(...) call: literals, and line numbers of
    any computed (f-string / variable) id."""
    tree = ast.parse(inspect.getsource(FE))
    literal: set[str] = set()
    computed: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding"):
            continue
        for kw in node.keywords:
            if kw.arg != "id":
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                literal.add(kw.value.value)
            else:
                computed.append(node.lineno)
    return literal, computed


def test_every_engine_rule_has_a_lifecycle_entry():
    ids, computed = _finding_ids()
    assert len(ids) >= 20, ids   # the scan itself works
    assert computed == [], f"computed finding ids at lines {computed}: list each possible id in lifecycle/rules.py"
    assert sorted(ids - set(RULES)) == []


def test_no_stale_entries():
    ids, _ = _finding_ids()
    assert sorted(set(RULES) - ids) == []


def test_classification_matches_the_spec():
    kinds = {rid: info.kind for rid, info in RULES.items()}
    assert {r for r, k in kinds.items() if k == "run_note"} == {"COV-001", "VULN-003", "SEAL-003"}
    assert {r for r, k in kinds.items() if k == "occurrence"} == {
        "AUTH-001", "AUTH-003", "AUTH-004", "AUTH-TREND-001", "CORR-001", "CORR-002", "CORR-SSH-001", "LOG-003"}
    # 0.3: evidence of tampering never closes itself (spec 0.3 §6; rules.RuleInfo.sticky)
    assert {r for r, i in RULES.items() if i.sticky} == {"LOG-001", "LOG-002", "LOG-004", "LOG-005", "SEAL-001"}
    assert all(k in KINDS for k in kinds.values())


def test_inputs_match_what_the_engine_reads():
    for rid, info in RULES.items():
        assert info.inputs == FE.rule_inputs(rid), rid
        assert set(info.covering_inputs) <= set(info.inputs), rid
    assert rule_info("CORR-SSH-001").covering_inputs == ("auth_patterns",)
    assert rule_info("NET-002").covering_inputs == ("nmap_parsed",)
    assert rule_info("NOPE-001") is None
