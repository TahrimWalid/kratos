"""CISA's SSVC decision tree, encoded from the CISA guide (a U.S. government work).

Source: CISA, "CISA Stakeholder-Specific Vulnerability Categorization Guide",
November 2022 -- Table 9 ("Table Representing Vulnerability Prioritization"), the
same decisions as its Figure 1; https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc .
CISA's vulnrichment labels its assessments with this tree's version, "2.0.3".

Encoded here in Kratos's own code, row for row. CERT/CC's SSVC tables (CC BY-NC
4.0) are NOT used or vendored.
"""
from __future__ import annotations

from typing import Final

TREE_VERSION: Final = "cisa-2.0.3"

EXPLOITATION = ("none", "poc", "active")
AUTOMATABLE = ("no", "yes")
TECHNICAL_IMPACT = ("partial", "total")
MISSION_WELLBEING = ("low", "medium", "high")

TRACK, TRACK_STAR, ATTEND, ACT = "track", "track*", "attend", "act"
OUTCOMES = (TRACK, TRACK_STAR, ATTEND, ACT)          # lowest first
RANK = {o: i for i, o in enumerate(OUTCOMES)}
LABELS = {TRACK: "Track", TRACK_STAR: "Track*", ATTEND: "Attend", ACT: "Act"}

# CISA's definitions of each outcome (guide, Table 1), shown to the person.
DEFINITIONS = {
    TRACK: ("The vulnerability does not require action at this time. Keep tracking it and reassess if new "
            "information becomes available. CISA recommends remediating Track vulnerabilities within standard "
            "update timelines."),
    TRACK_STAR: ("The vulnerability has specific characteristics that may require closer monitoring for changes. "
                 "CISA recommends remediating Track* vulnerabilities within standard update timelines."),
    ATTEND: ("The vulnerability requires attention from supervisory-level people in the organisation; actions may "
             "include asking for help or information and notifying others. CISA recommends remediating Attend "
             "vulnerabilities sooner than standard update timelines."),
    ACT: ("The vulnerability requires attention from supervisory and leadership-level people; internal groups "
          "would meet to decide the overall response and carry it out. CISA recommends remediating Act "
          "vulnerabilities as soon as possible."),
}

# (exploitation, automatable, technical impact, mission & well-being) -> outcome:
# the guide's Table 9, rows 1-36 in its order.
_ROWS: Final = (
    ("none", "no", "partial", "low", TRACK), ("none", "no", "partial", "medium", TRACK),
    ("none", "no", "partial", "high", TRACK), ("none", "no", "total", "low", TRACK),
    ("none", "no", "total", "medium", TRACK), ("none", "no", "total", "high", TRACK_STAR),
    ("none", "yes", "partial", "low", TRACK), ("none", "yes", "partial", "medium", TRACK),
    ("none", "yes", "partial", "high", ATTEND), ("none", "yes", "total", "low", TRACK),
    ("none", "yes", "total", "medium", TRACK), ("none", "yes", "total", "high", ATTEND),
    ("poc", "no", "partial", "low", TRACK), ("poc", "no", "partial", "medium", TRACK),
    ("poc", "no", "partial", "high", TRACK_STAR), ("poc", "no", "total", "low", TRACK),
    ("poc", "no", "total", "medium", TRACK_STAR), ("poc", "no", "total", "high", ATTEND),
    ("poc", "yes", "partial", "low", TRACK), ("poc", "yes", "partial", "medium", TRACK),
    ("poc", "yes", "partial", "high", ATTEND), ("poc", "yes", "total", "low", TRACK),
    ("poc", "yes", "total", "medium", TRACK_STAR), ("poc", "yes", "total", "high", ATTEND),
    ("active", "no", "partial", "low", TRACK), ("active", "no", "partial", "medium", TRACK),
    ("active", "no", "partial", "high", ATTEND), ("active", "no", "total", "low", TRACK),
    ("active", "no", "total", "medium", ATTEND), ("active", "no", "total", "high", ACT),
    ("active", "yes", "partial", "low", ATTEND), ("active", "yes", "partial", "medium", ATTEND),
    ("active", "yes", "partial", "high", ACT), ("active", "yes", "total", "low", ATTEND),
    ("active", "yes", "total", "medium", ACT), ("active", "yes", "total", "high", ACT),
)

TABLE: Final = {row[:4]: row[4] for row in _ROWS}


def rows() -> tuple[tuple[str, str, str, str, str], ...]:
    """The table as the guide lists it (for tests and docs)."""
    return _ROWS


def outcome(exploitation: str, automatable: str, technical_impact: str, mission_wellbeing: str) -> str:
    """The tree's outcome. Raises KeyError for a value outside CISA's sets -- callers
    decide "not enough data" before calling, never by catching this."""
    return TABLE[(exploitation, automatable, technical_impact, mission_wellbeing)]


def label(value: str | None) -> str:
    return LABELS.get(str(value or ""), "not enough data")


def rank(value: str | None) -> int:
    """Act 3 ... Track 0; no decision -1."""
    return RANK.get(str(value or ""), -1)
