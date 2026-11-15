"""The code-made verdict for a lead (E.7b §3.6). This module is the whole decision: it reads
only **structured facts** Kratos itself produced -- did a reproduction fire the recorder, did a
closed direct rule match, did the separate verifier cite a line -- and never a model's free
text. A model reply's words ("confirmed", a severity, "exploitable") reach here only as the
*text of an open question*, never as something that changes the verdict; and this module sets
**no severity** (that is judge.py §3.12). A test plants model words and asserts nothing moves.

Order (§3.6):

1. a reproduction fired the recorder with the canary       -> confirmed (reproduced)
2. the direct rule matched and the verifier could not       -> confirmed (direct)
   name a specific check
3. the direct rule matched but the verifier named a check    -> needs_validation (that check
   (a rule never overrules a specific disproof)                 is the open question)
4. the verifier disproved and nothing confirmed              -> rejected (kept with the disproof)
5. anything else                                             -> needs_validation (the open
                                                                 question for why it's unsettled)
"""
from __future__ import annotations

from dataclasses import dataclass

from kratos.review import classes as C

# Verdict kinds and the two confirmed strengths.
CONFIRMED, NEEDS_VALIDATION, REJECTED = "confirmed", "needs_validation", "rejected"
REPRODUCED, DIRECT = "reproduced", "direct"

# Reproduction outcomes.
R_REPRODUCED, R_NOT_REPRODUCED, R_OFF, R_NOT_ATTEMPTED = (
    "reproduced", "not_reproduced", "off", "not_attempted")

_Q_OFF = "reproduction is off on this computer"
_Q_RULE_VS_CHECK = "a rule saw a flow but the verifier named a check Kratos doesn't recognise: {check}"


@dataclass(frozen=True)
class Verdict:
    kind: str                 # confirmed | needs_validation | rejected
    strength: str = ""        # reproduced | direct   (only when confirmed)
    evidence: str = ""        # code-owned: the rule's statement path, or "the canary reached <call>"
    question: str = ""        # the open question (needs_validation), or the disproof (rejected)
    from_verifier: bool = False   # the verdict depended on the verifier's reply (model-derived; cache keys on the model)
    repro_off: bool = False       # needs_validation only because reproduction is off (not cached, so enabling it re-evaluates)


@dataclass(frozen=True)
class RuleMatch:
    """The direct rule's result for a lead (kratos.review.rules). `evidence` is a code-owned
    description of the statement path by line numbers -- never model text."""
    matched: bool
    evidence: str = ""


@dataclass(frozen=True)
class Repro:
    """A reproduction attempt's result (kratos.review.reproduce). `evidence` is set only when
    the recorder fired; `reason` carries why it couldn't be reproduced (an import name, a
    timeout, off), used as the open question."""
    status: str = R_NOT_ATTEMPTED
    evidence: str = ""
    reason: str = ""


@dataclass(frozen=True)
class Disproof:
    """The verifier's reply. A disproof must point at a line IN THE SLICE; one that doesn't
    cite a line counts as "could not disprove" (§3.6, `valid` is False)."""
    reason: str
    line: int | None = None

    @property
    def valid(self) -> bool:
        return bool(str(self.reason).strip()) and isinstance(self.line, int) and not isinstance(self.line, bool)


def _standard_question(cls: str) -> str:
    try:
        return C.get(cls).question
    except KeyError:
        return "Can a request value reach this call, and is it checked first?"


def decide(cls: str, rule: RuleMatch | None, repro: Repro | None, disproof: Disproof | None) -> Verdict:
    """The verdict for one lead of class `cls`. Inputs are facts Kratos produced; no model text
    is read. `cls` is the weakness class (for the standard open question)."""
    dis = disproof if (disproof is not None and disproof.valid) else None

    # 1. a reproduction fired the recorder.
    if repro is not None and repro.status == R_REPRODUCED:
        return Verdict(CONFIRMED, REPRODUCED,
                       evidence=repro.evidence or f"the canary reached the {cls} call in the sandbox")

    matched = rule is not None and rule.matched

    # 2 & 3. the direct rule matched.
    if matched:
        if dis is None:
            return Verdict(CONFIRMED, DIRECT, evidence=(rule.evidence if rule else ""))
        # a rule never overrules a specific disproof.
        return Verdict(NEEDS_VALIDATION, question=_Q_RULE_VS_CHECK.format(check=dis.reason.strip()),
                       from_verifier=True)

    # 4. the verifier disproved and nothing confirmed.
    if dis is not None:
        return Verdict(REJECTED, question=dis.reason.strip(), from_verifier=True)

    # 5. unsettled -> needs_validation with the reason it couldn't be confirmed.
    if repro is not None and repro.status == R_OFF:
        return Verdict(NEEDS_VALIDATION, question=_Q_OFF, repro_off=True)
    if repro is not None and repro.status == R_NOT_REPRODUCED and repro.reason.strip():
        return Verdict(NEEDS_VALIDATION, question=repro.reason.strip())
    return Verdict(NEEDS_VALIDATION, question=_standard_question(cls))
