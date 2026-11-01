"""Mission & Well-being, from the asset record (D.3 §3 decision 3).

CISA's guide, Table 8: Mission Prevalence (minimal / support / essential) and Public
Well-being Impact (minimal / material / irreversible) combine into low / medium /
high. Kratos takes Mission Prevalence from the criticality a person set for the
machine (low -> minimal, medium -> support, high or critical -> essential) and Public
Well-being Impact from the machine's own setting (minimal unless a person raised it).
An unset criticality is computed as medium and says so.
"""
from __future__ import annotations

from dataclasses import dataclass

CRITICALITIES = ("low", "medium", "high", "critical")
PREVALENCE = ("minimal", "support", "essential")
WELLBEING = ("minimal", "material", "irreversible")
ASSUMED_CRITICALITY = "medium"

PREVALENCE_OF = {"low": "minimal", "medium": "support", "high": "essential", "critical": "essential"}

# CISA guide Table 8: rows Mission Prevalence, columns Public Well-being Impact.
TABLE = {
    ("minimal", "minimal"): "low", ("minimal", "material"): "medium", ("minimal", "irreversible"): "high",
    ("support", "minimal"): "medium", ("support", "material"): "medium", ("support", "irreversible"): "high",
    ("essential", "minimal"): "high", ("essential", "material"): "high", ("essential", "irreversible"): "high",
}

WELLBEING_TEXT = {
    "minimal": "a compromise would not physically, financially or psychologically harm people beyond the "
               "organisation (the default)",
    "material": "a compromise could injure people, cause major property or environmental damage, bankrupt several "
                "people, or cause widespread psychological harm",
    "irreversible": "a compromise could cause several deaths, destroy a physical system, cause serious public "
                    "health or environmental damage, or destabilise systems society relies on (elections, the "
                    "financial grid)",
}


@dataclass(frozen=True)
class Mission:
    value: str                 # low | medium | high
    prevalence: str
    wellbeing: str
    criticality: str           # what the computation used
    assumed: bool              # criticality not set by a person -> assumed medium

    def text(self) -> str:
        crit = (f"criticality not set -- assumed {self.criticality}" if self.assumed
                else f"criticality {self.criticality}")
        return f"mission {self.value} ({crit}; public well-being impact {self.wellbeing})"


def mission(criticality: str | None, wellbeing: str | None = None) -> Mission:
    crit = str(criticality or "").lower()
    assumed = crit not in CRITICALITIES
    if assumed:
        crit = ASSUMED_CRITICALITY
    wb = str(wellbeing or "minimal").lower()
    if wb not in WELLBEING:
        wb = "minimal"
    prev = PREVALENCE_OF[crit]
    return Mission(TABLE[(prev, wb)], prev, wb, crit, assumed)
