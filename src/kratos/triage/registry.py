"""The verifier registry (docs/phaseB/B.1 §3.5).

A verifier re-checks a finding by code with a fresh, narrow read. Each one covers
one or more rule ids or rule prefixes (``PERSIST-``). A rule that has no safe
re-read declares a `NoVerifier(reason)` instead, so the completeness test
(tests/test_triage_completeness.py) can require that EVERY rule the engine can
raise as HIGH/CRITICAL either has a verifier or says, in words, why it has none --
the same shape as attack/mapping.py's completeness.

Nothing here reaches further than the finding's own evidence: a verifier uses an
existing read (a collection check run with `force`, a tool's fetcher, a local
computation), never a new remote command, and never writes on the target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # avoid a runtime import cycle (context imports the registry's types)
    from kratos.triage.context import VerifyContext
    from kratos.triage.verdict import Verdict

Cost = str  # "quick" | "slow"
COSTS = ("quick", "slow")


@dataclass(frozen=True)
class Verifier:
    rules: tuple[str, ...]              # rule ids or prefixes ("PERSIST-")
    cost: Cost                          # quick (auto, in the settle budget) | slow (on request)
    verify: "Callable[[VerifyContext], Verdict]"
    label: str = ""                     # plain words for the person ("a fresh package read")

    def __post_init__(self) -> None:
        if self.cost not in COSTS:
            raise ValueError(f"verifier cost must be one of {COSTS}, not {self.cost!r}")
        if not self.rules:
            raise ValueError("a verifier must cover at least one rule")


@dataclass(frozen=True)
class NoVerifier:
    rules: tuple[str, ...]
    reason: str                         # why this rule has no fresh re-check, in plain words

    def __post_init__(self) -> None:
        if not self.rules:
            raise ValueError("a NoVerifier must name at least one rule")
        if not self.reason.strip():
            raise ValueError("a NoVerifier needs a reason")


_VERIFIERS: list[Verifier] = []
_NO_VERIFIERS: list[NoVerifier] = []


def register_verifier(v: Verifier) -> Verifier:
    _VERIFIERS.append(v)
    return v


def register_no_verifier(nv: NoVerifier) -> NoVerifier:
    _NO_VERIFIERS.append(nv)
    return nv


def _matches(patterns: tuple[str, ...], rule_id: str) -> str | None:
    """The longest pattern that matches (an exact id, or a prefix ending in '-'),
    so a specific id wins over a family prefix."""
    best: str | None = None
    for p in patterns:
        if rule_id == p or (p.endswith("-") and rule_id.startswith(p)):
            if best is None or len(p) > len(best):
                best = p
    return best


def verifier_for(rule_id: str) -> Verifier | NoVerifier | None:
    """The verifier (or NoVerifier) covering `rule_id`, most specific pattern wins;
    a real Verifier beats a NoVerifier when both match equally specifically. Run
    notes (how complete a run was) are never verified -- a family prefix must not
    sweep one in."""
    from kratos.lifecycle.rules import is_run_note

    _ensure_loaded()          # the built-in verifiers register themselves on import
    rule_id = str(rule_id or "")
    if is_run_note(rule_id):
        return None
    best: tuple[int, int, Verifier | NoVerifier] | None = None   # (pattern length, is-verifier, entry)
    for is_v, entries in ((1, _VERIFIERS), (0, _NO_VERIFIERS)):
        for e in entries:
            m = _matches(e.rules, rule_id)
            if m is None:
                continue
            rank = (len(m), is_v)
            if best is None or rank > best[:2]:
                best = (len(m), is_v, e)
    return best[2] if best else None


def registered() -> tuple[list[Verifier], list[NoVerifier]]:
    return list(_VERIFIERS), list(_NO_VERIFIERS)


def _ensure_loaded() -> None:
    from kratos.triage import verifiers  # noqa: F401 -- registers the built-ins on import


def uncovered_rules() -> list[str]:
    """Condition/occurrence rules the engine can emit with neither a verifier nor a
    NoVerifier. Run notes are excluded (they can never be HIGH/CRITICAL and are never
    decidable). The completeness test fails if this is non-empty."""
    from kratos.lifecycle.rules import RULES, is_run_note

    _ensure_loaded()
    return sorted(rid for rid in RULES if not is_run_note(rid) and verifier_for(rid) is None)
