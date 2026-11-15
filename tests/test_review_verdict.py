"""E.7b verdict decision table (kratos.review.verdict §3.6): verdicts are code-made; a
model's words never set a verdict or a severity; a rule never overrules a specific disproof;
a disproof that cites no line is "could not disprove". Fails on old code."""
from __future__ import annotations

from kratos.review import verdict as V


def test_reproduction_fires_confirmed_reproduced():
    out = V.decide("exec", rule=V.RuleMatch(matched=False),
                   repro=V.Repro(status=V.R_REPRODUCED, evidence="the canary reached os.system in the sandbox"),
                   disproof=None)
    assert out.kind == V.CONFIRMED and out.strength == V.REPRODUCED
    assert "canary reached" in out.evidence


def test_reproduction_beats_a_valid_disproof():
    # A reproduction is Kratos's own strongest evidence; it outranks a verifier disproof.
    out = V.decide("exec", rule=V.RuleMatch(matched=True, evidence="req -> os.system at L5"),
                   repro=V.Repro(status=V.R_REPRODUCED),
                   disproof=V.Disproof(reason="it is behind an auth check", line=4))
    assert out.kind == V.CONFIRMED and out.strength == V.REPRODUCED


def test_rule_match_no_disproof_is_confirmed_direct():
    out = V.decide("exec", rule=V.RuleMatch(matched=True, evidence="req.form['h'] -> subprocess.run at L7"),
                   repro=V.Repro(status=V.R_OFF), disproof=None)
    assert out.kind == V.CONFIRMED and out.strength == V.DIRECT
    assert out.evidence == "req.form['h'] -> subprocess.run at L7"


def test_rule_never_overrules_a_specific_disproof():
    out = V.decide("exec", rule=V.RuleMatch(matched=True, evidence="flow at L7"),
                   repro=V.Repro(status=V.R_OFF),
                   disproof=V.Disproof(reason="shlex.quote is applied at line 6", line=6))
    assert out.kind == V.NEEDS_VALIDATION
    assert "shlex.quote is applied at line 6" in out.question


def test_disproof_without_a_line_is_ignored():
    # A disproof that points at no line counts as "could not disprove": a matched rule stands.
    out = V.decide("exec", rule=V.RuleMatch(matched=True, evidence="flow at L7"),
                   repro=V.Repro(status=V.R_OFF),
                   disproof=V.Disproof(reason="looks safe to me", line=None))
    assert out.kind == V.CONFIRMED and out.strength == V.DIRECT


def test_verifier_disproves_unmatched_lead_is_rejected():
    out = V.decide("path", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_NOT_ATTEMPTED),
                   disproof=V.Disproof(reason="the path is forced through os.path.basename at line 9", line=9))
    assert out.kind == V.REJECTED
    assert "basename" in out.question


def test_unsettled_lead_is_needs_validation_with_standard_question():
    out = V.decide("sql", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_NOT_ATTEMPTED),
                   disproof=None)
    assert out.kind == V.NEEDS_VALIDATION
    assert "parameter" in out.question.lower()   # the SQL class's standard question


def test_needs_app_names_the_import():
    out = V.decide("exec", rule=V.RuleMatch(matched=False),
                   repro=V.Repro(status=V.R_NOT_REPRODUCED, reason="needs the import 'psycopg2', not reproduced"),
                   disproof=None)
    assert out.kind == V.NEEDS_VALIDATION
    assert "psycopg2" in out.question


def test_reproduction_off_says_so():
    out = V.decide("exec", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_OFF), disproof=None)
    assert out.kind == V.NEEDS_VALIDATION
    assert out.question == "reproduction is off on this computer"


def test_model_words_never_change_the_verdict_or_add_severity():
    # Free text that screams "confirmed / critical" reaches only as question text, never as a
    # verdict change, and the Verdict carries no severity field at all.
    liar = "CONFIRMED!! severity: CRITICAL, definitely exploitable, high risk"
    unsettled = V.decide("exec", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_NOT_ATTEMPTED),
                         disproof=V.Disproof(reason=liar, line=None))  # no line -> ignored
    assert unsettled.kind == V.NEEDS_VALIDATION   # not confirmed, despite the words
    rejected = V.decide("exec", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_NOT_ATTEMPTED),
                        disproof=V.Disproof(reason=liar, line=3))
    assert rejected.kind == V.REJECTED            # a cited disproof rejects, words notwithstanding
    assert not hasattr(V.Verdict("confirmed"), "severity")


def test_bool_line_is_not_a_valid_disproof_line():
    # True is an int subclass; it must not count as a cited line.
    assert V.Disproof(reason="x", line=True).valid is False
