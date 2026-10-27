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
    # the engine, and every module a registered snapshot source builds its findings in
    # (a later check may keep its builder in its own package -- FE.register_snapshot_source)
    from kratos.detect import findings as detect_findings

    modules = {FE} | {inspect.getmodule(src.build) for src in FE.snapshot_sources()}
    literal: set[str] = set()
    computed: list[int] = []
    for mod in modules:
        for node in ast.walk(ast.parse(inspect.getsource(mod))):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding"):
                continue
            for kw in node.keywords:
                if kw.arg != "id":
                    continue
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    literal.add(kw.value.value)
                elif mod is not detect_findings:
                    computed.append(node.lineno)
    # C.1: the detection rules' ids are generated with the rule pack (README §4.2): the
    # one computed id is in kratos.detect.findings, and every id it can carry is a rule
    # in the shipped pack (an imported pack's rules follow the same SIGMA-* pattern).
    return literal, computed


def _sigma_ids() -> set[str]:
    from kratos.detect import pack

    return {r.id for r in pack.shipped().pack.rules}


def test_every_engine_rule_has_a_lifecycle_entry():
    ids, computed = _finding_ids()
    assert len(ids) >= 20, ids   # the scan itself works
    assert computed == [], f"computed finding ids at lines {computed}: list each possible id in lifecycle/rules.py"
    assert sorted(ids - set(RULES)) == []


def test_every_shipped_detection_rule_is_an_occurrence():
    ids = _sigma_ids()
    assert 50 <= len(ids) <= 100
    for rid in ids:
        info = rule_info(rid)
        assert info is not None and info.kind == "occurrence" and info.inputs == ("detections",), rid
    assert rule_info("SIGMA-1234") is None and rule_info("SIGMA-0000000G") is None


def test_no_stale_entries():
    ids, _ = _finding_ids()
    assert sorted(set(RULES) - ids) == []


def test_classification_matches_the_spec():
    kinds = {rid: info.kind for rid, info in RULES.items()}
    assert {r for r, k in kinds.items() if k == "run_note"} == {
        "COV-001", "VULN-003", "SEAL-003", "PERSIST-009", "LIVE-007", "PKG-004", "DETECT-001"}
    assert {r for r, k in kinds.items() if k == "occurrence"} == {
        "AUTH-001", "AUTH-003", "AUTH-004", "AUTH-TREND-001", "CORR-001", "CORR-002", "CORR-SSH-001", "LOG-003",
        "LIVE-001", "LIVE-002", "LIVE-003", "LIVE-005", "LIVE-006", "HUNT-001", "WEB-001"}
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
