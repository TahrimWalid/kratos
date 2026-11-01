"""The SSVC decision for one CVE, and for a finding that names several (pure, no I/O).

``decide(cve_inputs, mission)`` applies CISA's tree when all three per-CVE inputs are
known, else returns "not enough data (Exploitation: ...)" -- never a guessed outcome.
``for_finding`` takes the worst CVE's decision for a finding (PKG-001: one package's
CVEs; PKG-002: every unfixed CVE; PKG-003: the running kernel's; VULN-001: the scan's)
and lists each CVE's own decision, worst first.

The returned dict is what a finding carries as ``ssvc``; ``kratos.ssvc.attach`` adds the
measured ``exposure`` beside it. Every value says where it came from.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from kratos.ssvc import tree as T
from kratos.ssvc.inputs import CveInputs
from kratos.ssvc.mission import Mission

CVES_KEPT = 20


@dataclass(frozen=True)
class Decision:
    cve: str
    outcome: str | None          # track | track* | attend | act | None (not enough data)
    inputs: CveInputs
    mission: Mission

    @property
    def label(self) -> str:
        if self.outcome:
            return T.LABELS[self.outcome]
        return f"not enough data (Exploitation: {self.inputs.exploitation.value or 'unknown'})"

    def sort_key(self) -> tuple[Any, ...]:
        return (-T.rank(self.outcome), not self.inputs.kev, -(self.inputs.epss or 0.0), self.cve)

    def cve_dict(self) -> dict[str, Any]:
        i = self.inputs
        return {"cve": self.cve, "outcome": self.outcome, "label": self.label,
                "exploitation": i.exploitation.value, "automatable": i.automatable.value,
                "technical_impact": i.technical_impact.value,
                "sources": {"exploitation": i.exploitation.source, "automatable": i.automatable.source,
                            "technical_impact": i.technical_impact.source},
                "kev": i.kev, "ransomware": i.ransomware, "epss": i.epss, "fixed_in": i.fixed_in}


def decide(cve_inputs: CveInputs, mission: Mission) -> Decision:
    i = cve_inputs
    outcome = None
    if i.enough and mission.value in T.MISSION_WELLBEING:
        try:
            outcome = T.outcome(str(i.exploitation.value), str(i.automatable.value), str(i.technical_impact.value),
                                mission.value)
        except KeyError:
            outcome = None
    return Decision(i.cve, outcome, i, mission)


def _mission_dict(m: Mission) -> dict[str, Any]:
    return {"value": m.value, "criticality": m.criticality, "assumed": m.assumed, "prevalence": m.prevalence,
            "wellbeing": m.wellbeing, "source": "assumed (criticality not set)" if m.assumed else "asset record"}


def for_finding(cve_inputs: Iterable[CveInputs], mission: Mission, *, fix_available: bool | None = None
                ) -> dict[str, Any] | None:
    """The `ssvc` dict for a finding, or None when it names no CVE."""
    decisions = sorted((decide(c, mission) for c in cve_inputs if c.cve), key=Decision.sort_key)
    if not decisions:
        return None
    worst = decisions[0]
    counts: dict[str, int] = {}
    for d in decisions:
        key = d.outcome or "not_enough_data"
        counts[key] = counts.get(key, 0) + 1
    i = worst.inputs
    fixable = fix_available if fix_available is not None else (i.fixed_in is not None)
    return {
        "outcome": worst.outcome, "label": worst.label, "tree": T.TREE_VERSION, "cve": worst.cve,
        "inputs": {"exploitation": i.exploitation.to_dict(), "automatable": i.automatable.to_dict(),
                   "technical_impact": i.technical_impact.to_dict(), "mission_wellbeing": _mission_dict(mission)},
        "definition": T.DEFINITIONS.get(worst.outcome or "", ""),
        "kev": i.kev, "ransomware": i.ransomware, "epss": i.epss, "fix_available": bool(fixable),
        "counts": counts, "cves": [d.cve_dict() for d in decisions[:CVES_KEPT]], "cve_count": len(decisions),
    }


def summary_words(ssvc: dict[str, Any] | None) -> str:
    """'exploited, automatable, total impact, mission high' -- the four inputs in plain words."""
    if not isinstance(ssvc, dict):
        return ""
    inp = ssvc.get("inputs") or {}

    def val(k: str) -> str | None:
        return (inp.get(k) or {}).get("value")

    def src(k: str) -> str:
        return str((inp.get(k) or {}).get("source") or "")

    words = []
    e = val("exploitation")
    words.append({"active": "exploited", "poc": "public proof of concept",
                  "none": "no known exploitation" + (" (not assessed)" if src("exploitation") == "not-assessed" else "")
                  }.get(str(e), "exploitation unknown"))
    a = val("automatable")
    words.append(("automatable" if a == "yes" else "not automatable" if a == "no" else "automatable unknown")
                 + (" (estimated from CVSS)" if src("automatable") == "cvss-estimate" else ""))
    t = val("technical_impact")
    words.append(("total impact" if t == "total" else "partial impact" if t == "partial" else "impact unknown")
                 + (" (estimated from CVSS)" if src("technical_impact") == "cvss-estimate" else ""))
    mw = inp.get("mission_wellbeing") or {}
    words.append(f"mission {mw.get('value', '?')}" + (" (criticality not set -- assumed medium)"
                                                      if mw.get("assumed") else ""))
    return ", ".join(words)
