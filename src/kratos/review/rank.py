"""Ranking slices for review (E.7b §3.4): what gets reviewed first when the cap bites.

Order, most important first:

1. slices in files **changed on the server** (E.7a CODE-001 untracked / CODE-002 modified) --
   deployed code that differs from what was committed, reviewed first **always**, even past
   ``review.max_slices``;
2. a dangerous call of an **execution-like** class (command/code execution or deserialisation);
3. the **exposure** of the serving process (A.5/D.3): internet > network > local > unknown, a
   root whose process isn't running last;
4. **served-and-executed** (a route handler, PHP/CGI) > served > imported;
5. slices that import a package with an **open CODE-003 advisory**.

``select`` caps a run at ``review.max_slices`` but never drops a drifted slice; what the cap
dropped is a REVIEW-003 count, never silence.
"""
from __future__ import annotations

from typing import Iterable

from kratos.review import classes as C
from kratos.review.slice import Slice

# Lower is more exposed / reviewed sooner. Mirrors ssvc.exposure.RANK; "unknown" sits between
# local and not-running (it may be running -- the read just couldn't tell).
EXPOSURE_RANK = {"internet": 0, "network": 1, "local": 2, "unknown": 3, "not_running": 4}
SERVED_RANK = {"executed": 0, "served": 1, "imported": 2}


def _exposure_rank(value: str) -> int:
    return EXPOSURE_RANK.get(str(value or "unknown").strip().lower().replace(" ", "_"), 3)


def rank_key(sl: Slice) -> tuple:
    """The §3.4 sort key; ties broken by file, function, class and part so the order is stable."""
    return (
        0 if sl.drift else 1,
        0 if sl.cls in C.EXEC_LIKE else 1,
        _exposure_rank(sl.exposure),
        SERVED_RANK.get(sl.served, 2),
        0 if sl.advisory else 1,
        sl.rel, sl.function, sl.cls, sl.part,
    )


def ordered(slices: Iterable[Slice]) -> list[Slice]:
    return sorted(slices, key=rank_key)


def select(slices: Iterable[Slice], max_slices: int) -> tuple[list[Slice], int]:
    """(kept, dropped). Drifted slices (changed on the server) are always kept, even past the
    cap; the highest-ranked non-drifted slices fill the rest of the budget; the remainder is
    dropped and counted for REVIEW-003 -- never silently skipped."""
    kept: list[Slice] = []
    dropped = 0
    for sl in ordered(slices):
        if sl.drift or len(kept) < max_slices:
            kept.append(sl)
        else:
            dropped += 1
    return kept, dropped
