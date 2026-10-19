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

# reproduced  -- a SECOND read (recheck / retest / a slow verifier) still shows it
# partly      -- true, but with a condition that lowers the risk (say which)
# not_reproduced -- a second, complete read no longer shows it
# couldnt_check  -- no safe read was possible (say why)
# seen        -- the automatic pass only: the finding is in the read Kratos made for this
#                run -- the same read that raised it -- so it has NOT been re-checked yet.
#                Only a genuine second read may say "reproduced" / "not reproduced".
VERDICTS = ("reproduced", "partly", "not_reproduced", "couldnt_check", "seen")

# What a verdict was judged against: a genuine second read, or this run's own read
# (the automatic pass re-uses the collection that raised the finding).
SECOND_READ = "second_read"
THIS_RUN = "this_run"
BASES = (SECOND_READ, THIS_RUN)
_SECOND_READ_ONLY = frozenset({"reproduced", "not_reproduced"})

# The short tag shown in the answer's findings block and the model's digest.
_TAG = {
    "reproduced": "reproduced by a fresh read",
    "partly": "partly confirmed",
    "not_reproduced": "not reproduced -- retest?",
    "couldnt_check": "couldn't check",
    "seen": "seen in this run's read -- not re-checked yet",
}
_THIS_RUN_SUFFIX = "this run's read, not re-checked yet"

# Plain words for a person, for each verdict (a longer form of the tag).
PHRASE = {
    "reproduced": "Kratos checked this again and it is still there.",
    "partly": "Kratos checked this again: it is still true, but with something that lowers the risk.",
    "not_reproduced": "A fresh check no longer finds this -- it may already be fixed.",
    "couldnt_check": "Kratos could not re-check this.",
}

# Where a person goes to have a "seen" finding genuinely re-checked.
RECHECK_HINT = ("re-check it with a second read: press k in /findings or run `kratos findings recheck KEY`; "
                "after a fix, retest it (t, or `kratos findings retest KEY`)")
SEEN_SENTENCE = ("Kratos saw this in the read it made for this run -- the same read that raised it -- so it "
                 "has not been re-checked yet. To " + RECHECK_HINT + ".")
PHRASE["seen"] = SEEN_SENTENCE


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
    # SECOND_READ (recheck, retest, the slow verifiers) or THIS_RUN (the automatic pass,
    # judged against the read that raised the finding).
    basis: str = SECOND_READ

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict {self.verdict!r}; expected one of {VERDICTS}")
        if self.basis not in BASES:
            raise ValueError(f"unknown verdict basis {self.basis!r}; expected one of {BASES}")
        if self.basis == THIS_RUN and self.verdict in _SECOND_READ_ONLY:
            raise ValueError(f"a verdict judged against this run's own read can't be {self.verdict!r}; "
                             "only a second read reproduces a finding (use from_this_run)")
        if self.verdict == "seen" and self.basis != THIS_RUN:
            raise ValueError("'seen' is only for a verdict judged against this run's own read")

    def tag(self) -> str:
        """The short tag for the findings block / digest."""
        return verdict_tag(self.verdict, self.detail, basis=self.basis)

    def as_dict(self) -> dict:
        return {"verdict": self.verdict, "sentence": self.sentence, "detail": self.detail,
                "basis": self.basis, "tag": self.tag(),
                "checks": [{"name": c.name, "transport": c.transport,
                            "read_seconds": round(c.read_seconds, 2)} for c in self.checks],
                "evidence": list(self.evidence)}


def verdict_tag(verdict: str, detail: str = "", *, basis: str = SECOND_READ) -> str:
    """`reproduced by a fresh read` / `partly: filtered from Kratos` /
    `not reproduced -- retest?` / `couldn't check: the logs for that time are gone` /
    `seen in this run's read -- not re-checked yet`."""
    base = _TAG.get(verdict, verdict)
    clause = (detail or "").strip()
    if verdict == "partly":
        tag = f"partly: {clause}" if clause else base
        return f"{tag} ({_THIS_RUN_SUFFIX})" if basis == THIS_RUN else tag
    if verdict == "couldnt_check":
        return f"couldn't check: {clause}" if clause else "couldn't check"
    return base


def from_this_run(v: Verdict) -> Verdict:
    """Re-label a verifier's verdict that was judged against the read which raised the
    finding (the automatic pass, reuse mode). That read is not a second look, so it may
    not say "reproduced" or "not reproduced":

    - reproduced     -> seen (in this run's read, not re-checked yet; points to recheck/retest)
    - not_reproduced -> couldn't check (this run's latest read no longer shows it -- recheck)
    - partly / couldn't check keep their word, marked as this run's read.
    """
    if v.basis == THIS_RUN:
        return v
    if v.verdict == "reproduced":
        return Verdict("seen", SEEN_SENTENCE, checks=v.checks, evidence=v.evidence, basis=THIS_RUN)
    if v.verdict == "not_reproduced":
        return Verdict("couldnt_check",
                       "This run's latest read no longer shows it, but that is not a second look. To "
                       + RECHECK_HINT + ".",
                       checks=v.checks, evidence=v.evidence,
                       detail="this run's latest read no longer shows it -- recheck to confirm", basis=THIS_RUN)
    sentence = v.sentence
    if v.verdict == "partly":
        sentence = (sentence.rstrip() + " (Judged from this run's read; not re-checked by a second read yet.)")
    return Verdict(v.verdict, sentence, checks=v.checks, evidence=v.evidence, detail=v.detail, basis=THIS_RUN)


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
