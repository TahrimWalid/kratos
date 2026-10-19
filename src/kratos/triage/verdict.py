"""What a verifier says about a finding (docs/phaseB/B.1 §1, §5.1).

A verdict is one of four words, a short list of the checks the verifier ran, the
evidence lines it stands behind (Kratos-written, validated values only -- never a
path or command line read off the machine, same rule as finding_facts), and one
plain-words sentence. Nothing here is a lifecycle state: a verdict is a thing a
person reads at the top of an answer and in /findings, next to -- not instead of
-- the finding's state.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# reproduced  -- a fresh read still shows it
# partly      -- true, but with a condition that lowers the risk (say which)
# not_reproduced -- a fresh, complete read no longer shows it
# couldnt_check  -- no safe fresh read was possible (say why)
VERDICTS = ("reproduced", "partly", "not_reproduced", "couldnt_check")

# The short tag shown in the answer's findings block and the model's digest.
_TAG = {
    "reproduced": "reproduced by a fresh read",
    "partly": "partly confirmed",
    "not_reproduced": "not reproduced -- retest?",
    "couldnt_check": "couldn't check",
}

# Plain words for a person, for each verdict (a longer form of the tag).
PHRASE = {
    "reproduced": "Kratos checked this again and it is still there.",
    "partly": "Kratos checked this again: it is still true, but with something that lowers the risk.",
    "not_reproduced": "A fresh check no longer finds this -- it may already be fixed.",
    "couldnt_check": "Kratos could not re-check this.",
}


@dataclass(frozen=True)
class VerifyCheck:
    """One read a verifier made, for the person to see what was actually done."""
    name: str                       # the tool or collection check ("run_nmap_scan", "packages")
    transport: str                  # "ssh" | "agent" | "local" | "" (local computation)
    read_seconds: float = 0.0


@dataclass(frozen=True)
class Verdict:
    verdict: str                    # one of VERDICTS
    sentence: str                   # one plain-words line
    checks: tuple[VerifyCheck, ...] = ()
    evidence: tuple[str, ...] = ()  # Kratos-written, validated lines only
    # the condition that makes a "partly" verdict partly (shown in the tag), or the
    # reason a "couldnt_check" could not check -- both one short clause.
    detail: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}; expected one of {VERDICTS}")

    def tag(self) -> str:
        """The short tag for the findings block / digest."""
        return verdict_tag(self.verdict, self.detail)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "sentence": self.sentence, "detail": self.detail,
                "tag": self.tag(),
                "checks": [{"name": c.name, "transport": c.transport,
                            "read_seconds": round(c.read_seconds, 2)} for c in self.checks],
                "evidence": list(self.evidence)}


def verdict_tag(verdict: str, detail: str = "") -> str:
    """`reproduced by a fresh read` / `partly: filtered from Kratos` /
    `not reproduced -- retest?` / `couldn't check: the logs for that time are gone`."""
    base = _TAG.get(verdict, verdict)
    clause = (detail or "").strip()
    if verdict == "partly" and clause:
        return f"partly: {clause}"
    if verdict == "couldnt_check":
        return f"couldn't check: {clause}" if clause else "couldn't check"
    return base


@dataclass
class VerdictResult:
    """A stored verdict with its metadata (triage.store rows)."""
    finding_key: str
    verdict: Verdict
    verifier: str
    cost: str
    run_id: str | None
    at: float
    duration: float
    fields: dict = field(default_factory=dict)
