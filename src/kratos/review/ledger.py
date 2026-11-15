"""The coverage ledger (E.7b §3.6): every slice x class is a cell, moving
not-looked-at -> looked-at -> lead-raised -> verdict-reached. Completeness per class is a
**number**; incomplete coverage is reported as such in REVIEW-003 and is never "nothing found".

A slice row already is a cell (the slicer makes one slice per surface x class), and carries its
state in ``review_slices.ledger_state``; this module only reads those rows and reports coverage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

NOT_LOOKED_AT, LOOKED_AT, LEAD_RAISED, VERDICT_REACHED = (
    "not_looked_at", "looked_at", "lead_raised", "verdict_reached")
STATES = (NOT_LOOKED_AT, LOOKED_AT, LEAD_RAISED, VERDICT_REACHED)
_ORDER = {s: i for i, s in enumerate(STATES)}


def advance(current: str, to: str) -> str:
    """The later of two states -- a cell never moves backwards (a dropped lead that was already
    verdict-reached stays reached)."""
    return to if _ORDER.get(to, 0) >= _ORDER.get(current, 0) else current


@dataclass(frozen=True)
class ClassCoverage:
    cls: str
    total: int
    reached: int                  # cells with a verdict

    @property
    def complete(self) -> bool:
        return self.total > 0 and self.reached >= self.total

    @property
    def pct(self) -> float:
        return 100.0 if self.total == 0 else round(100.0 * self.reached / self.total, 1)


def coverage(slice_rows: Iterable[dict[str, Any]]) -> dict[str, ClassCoverage]:
    total: dict[str, int] = {}
    reached: dict[str, int] = {}
    for r in slice_rows:
        cls = r.get("class", "")
        total[cls] = total.get(cls, 0) + 1
        if r.get("ledger_state") == VERDICT_REACHED:
            reached[cls] = reached.get(cls, 0) + 1
    return {cls: ClassCoverage(cls, n, reached.get(cls, 0)) for cls, n in sorted(total.items())}


def incomplete_classes(slice_rows: Iterable[dict[str, Any]]) -> list[ClassCoverage]:
    """The classes whose coverage is below 100% -- the REVIEW-003 'incomplete coverage' list."""
    return [c for c in coverage(slice_rows).values() if not c.complete]


def overall_pct(slice_rows: Iterable[dict[str, Any]]) -> float:
    rows = list(slice_rows)
    if not rows:
        return 100.0
    reached = sum(1 for r in rows if r.get("ledger_state") == VERDICT_REACHED)
    return round(100.0 * reached / len(rows), 1)
