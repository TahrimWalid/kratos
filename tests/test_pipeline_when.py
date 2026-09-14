"""Slice 4 -- the bounded `when` predicate parser (agent/pipeline_when.py).

The security-critical boundary: compile_when NEVER eval()s a user string, so the
first half of this file is ADVERSARIAL -- every code-execution / escape shape must
raise WhenError, not run. The second half checks the whitelisted vocabulary
evaluates correctly against a fake context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from kratos.agent.pipeline_when import WhenError, compile_when


# A minimal stand-in for PipelineContext (duck-typed: has_finding + findings).
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class _Ctx:
    findings: list[dict[str, Any]] = field(default_factory=list)

    def has_finding(self, *, min_severity: Optional[str] = None) -> bool:
        if not self.findings:
            return False
        if min_severity is None:
            return True
        floor = _RANK.get(min_severity.lower(), 0)
        return any(_RANK.get(str(f.get("severity", "info")).lower(), 0) >= floor
                   for f in self.findings)


# --------------------------------------------------------------------------- #
# ADVERSARIAL -- must all be REJECTED at compile time, never executed
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("expr", [
    "__import__('os')",
    "__import__('os').system('id')",
    "os.system('id')",
    "open('/etc/passwd').read()",
    "().__class__.__bases__",
    "ctx.findings",                       # attribute access
    "ctx.has_finding()",                  # calling through an object
    "findings",                           # bare unknown name
    "finding_count",                      # bare variable (needs a comparison)
    "True",                               # bare constant
    "1",
    "lambda: 1",
    "[f for f in findings]",              # comprehension
    "{'a': 1}",                           # dict literal
    "f'{finding_count}'",                # f-string
    "finding_count + 1 > 2",             # arithmetic
    "finding_count > 1 > 0",             # chained comparison
    "has_finding(min_severity='high') == True",  # compare a call to a literal
    "has_finding('high')",               # positional arg not allowed
    "has_finding(severity='high')",      # unknown kwarg
    "has_finding(min_severity='nope')",  # bad severity value
    "has_finding(min_severity=3)",       # non-string severity
    "bogus_function()",                  # unknown function
    "no_findings(1)",                    # no_findings takes no args
    "finding_count == 'three'",          # count vs non-int
    "finding_count == 1.5",              # count vs float
    "finding_count == True",             # bool is not an int literal here
    "finding_id < 'x'",                  # finding_id only ==/!=
    "finding_id == 5",                   # finding_id needs a string
    "unknown_var == 1",                  # unknown variable
    "finding_count >> 1",                # bitshift operator
    "finding_count and finding_id",      # variables aren't booleans
    "",                                   # empty
    "   ",
    "has_finding(",                       # syntax error
    "x" * 600,                            # over length cap
])
def test_adversarial_predicates_are_rejected(expr):
    with pytest.raises(WhenError):
        compile_when(expr)


def test_compile_when_only_raises_whenerror_never_executes():
    # Even a payload that WOULD have side effects if eval'd raises cleanly.
    with pytest.raises(WhenError):
        compile_when("__import__('subprocess').run(['echo','pwned'])")


# --------------------------------------------------------------------------- #
# VALID vocabulary -- compiles and evaluates correctly
# --------------------------------------------------------------------------- #
def test_has_finding_plain():
    pred = compile_when("has_finding()")
    assert pred(_Ctx([])) is False
    assert pred(_Ctx([{"severity": "info"}])) is True


def test_has_finding_min_severity():
    pred = compile_when("has_finding(min_severity='high')")
    assert pred(_Ctx([{"severity": "medium"}])) is False
    assert pred(_Ctx([{"severity": "high"}])) is True
    assert pred(_Ctx([{"severity": "critical"}])) is True
    # double-quoted string literal is fine too
    assert compile_when('has_finding(min_severity="critical")')(_Ctx([{"severity": "high"}])) is False


def test_no_findings():
    pred = compile_when("no_findings()")
    assert pred(_Ctx([])) is True
    assert pred(_Ctx([{"severity": "low"}])) is False


@pytest.mark.parametrize("expr,n,expected", [
    ("finding_count >= 3", 3, True),
    ("finding_count >= 3", 2, False),
    ("finding_count == 0", 0, True),
    ("finding_count != 0", 1, True),
    ("finding_count < 2", 1, True),
    ("finding_count > 5", 5, False),
    ("finding_count <= 1", 1, True),
    ("3 <= finding_count", 4, True),        # variable on the right (swapped)
    ("3 <= finding_count", 2, False),
])
def test_finding_count_comparisons(expr, n, expected):
    ctx = _Ctx([{"severity": "info"} for _ in range(n)])
    assert compile_when(expr)(ctx) is expected


def test_finding_id_membership():
    ctx = _Ctx([{"id": "CORR-SSH-001", "severity": "high"}, {"id": "NET-002"}])
    assert compile_when("finding_id == 'CORR-SSH-001'")(ctx) is True
    assert compile_when("finding_id == 'NOPE'")(ctx) is False
    assert compile_when("finding_id != 'NOPE'")(ctx) is True
    assert compile_when("finding_id != 'CORR-SSH-001'")(ctx) is False


def test_boolean_composition():
    ctx = _Ctx([{"id": "CORR-SSH-001", "severity": "high"}])
    assert compile_when("has_finding() and finding_count >= 1")(ctx) is True
    assert compile_when("has_finding(min_severity='critical') or finding_id == 'CORR-SSH-001'")(ctx) is True
    assert compile_when("not no_findings()")(ctx) is True
    assert compile_when("has_finding(min_severity='critical') and finding_id == 'CORR-SSH-001'")(ctx) is False
    # parentheses + precedence
    assert compile_when("(finding_count == 0) or (finding_count >= 1 and has_finding())")(ctx) is True


def test_and_short_circuit_still_validates_all_operands():
    # A false-left `and` must STILL reject an invalid right operand at compile
    # time (no short-circuit validation gap).
    with pytest.raises(WhenError):
        compile_when("no_findings() and os.system('x')")


def test_predicate_on_empty_context_is_false_not_error():
    # A `when` about findings on step 1 (nothing produced yet) evaluates cleanly.
    for expr in ("has_finding()", "has_finding(min_severity='high')",
                 "finding_count >= 1", "finding_id == 'X'"):
        assert compile_when(expr)(_Ctx([])) is False
