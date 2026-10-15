"""How urgent a vulnerable package is (A.2 §3.6), layered:

1. listed in CISA's Known Exploited Vulnerabilities catalogue -> **critical, act now**;
2. fixable, EPSS at or above ``vulndb.epss_high`` (default 0.1: at least a 10%
   chance of exploitation in the next 30 days -- the threshold FIRST's EPSS FAQ
   calls "commonly cited in the field", while saying EPSS itself sets none) and
   CVSS >= 7 -> **high**;
3. fixable, CVSS >= 7 -> **medium**;
4. any other fixable CVE -> **low**.

When NVD has no CVSS score for a CVE, the distribution's own rating stands in for
"CVSS >= 7" (Ubuntu/Red Hat "high"/"important"/"critical", Debian urgency "high").
A distribution rating of "negligible"/"unimportant" caps a CVE at low (KEV still
wins: exploitation in the wild outranks a distribution's guess).

A package's severity is its most urgent CVE's. No fix yet is a separate rule
(PKG-002), low -- or info when every CVE in it is rated negligible.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kratos.pkgvuln.match import CveHit, is_negligible

_HIGH_DISTRO = frozenset({"high", "critical", "important", "urgent"})
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Scored:
    cve: str
    severity: str
    kev: dict[str, Any] | None
    epss: float | None
    cvss: float | None
    cvss_vector: str
    fixed_in: str | None
    advisories: tuple[str, ...]
    distro_severity: str

    def sort_key(self) -> tuple[Any, ...]:
        return (-RANK[self.severity], self.kev is None, -(self.epss or 0.0), -(self.cvss or 0.0), self.cve)


def score_cve(hit: CveHit, info: dict[str, Any], epss_high: float) -> Scored:
    kev = info.get("kev")
    epss = (info.get("epss") or {}).get("score")
    cvss = (info.get("cvss") or {}).get("score")
    vector = str((info.get("cvss") or {}).get("vector") or "")
    serious = (cvss is not None and float(cvss) >= 7.0) or (
        cvss is None and str(hit.distro_severity or "").lower() in _HIGH_DISTRO)
    if kev:
        sev = "critical"
    elif not hit.fixable:
        sev = "info" if is_negligible(hit.distro_severity) else "low"
    elif serious and epss is not None and float(epss) >= epss_high:
        sev = "high"
    elif serious:
        sev = "medium"
    else:
        sev = "low"
    if not kev and is_negligible(hit.distro_severity) and RANK[sev] > RANK["low"]:
        sev = "low"
    return Scored(hit.cve, sev, kev, float(epss) if epss is not None else None,
                  float(cvss) if cvss is not None else None, vector, hit.fixed_in, tuple(hit.advisories),
                  hit.distro_severity)


def worst(scored: list[Scored], default: str = "low") -> str:
    if not scored:
        return default
    return max((s.severity for s in scored), key=lambda s: RANK[s])
