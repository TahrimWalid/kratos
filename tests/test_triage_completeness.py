"""Every rule the engine can raise as HIGH/CRITICAL has a verifier or an explicit
NoVerifier reason (docs/phaseB/B.1 §3.5) -- same shape as attack/mapping.py's
completeness test. A new rule has to declare how (or why not) it is re-checked.
"""
from __future__ import annotations

import pytest

from kratos.lifecycle.rules import RULES, is_run_note
from kratos.triage import registry
from kratos.triage.registry import NoVerifier, Verifier, verifier_for


def test_every_non_run_note_rule_is_covered():
    assert registry.uncovered_rules() == [], (
        "these rules have neither a verifier nor a NoVerifier (triage/verifiers.py): "
        + ", ".join(registry.uncovered_rules()))


@pytest.mark.parametrize("rule_id", sorted(r for r in RULES if not is_run_note(r)))
def test_each_rule_resolves_to_one_entry(rule_id):
    entry = verifier_for(rule_id)
    assert isinstance(entry, (Verifier, NoVerifier)), f"{rule_id} has no verifier entry"
    if isinstance(entry, NoVerifier):
        assert entry.reason.strip(), f"{rule_id}'s NoVerifier has no reason"
    else:
        assert entry.cost in ("quick", "slow")


def test_run_notes_have_no_verifier():
    # run notes say how complete a run was; they are never HIGH/CRITICAL and never
    # verified -- a NoVerifier/Verifier for one would be a mistake.
    for rid in RULES:
        if is_run_note(rid):
            assert verifier_for(rid) is None, f"{rid} is a run note; it must not have a verifier"


def test_a_specific_id_wins_over_a_family_prefix():
    # VULN-001 has its own offline cross-check; VULN- is not a prefix verifier, but
    # VULN-002 is its own slow entry -- neither should shadow the other.
    assert verifier_for("VULN-001").cost == "quick"
    assert verifier_for("VULN-002").cost == "slow"
