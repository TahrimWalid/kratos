"""A code folder's dependencies against the offline vulnerability index (E.7a §3.7) -- pure,
offline. Reuses A.2's index (``kratos.pkgvuln.index``) with OSV's language ecosystems
added by ``kratos vulndb-update`` (``--for-roots`` or the ecosystems named), univers's
version schemes (``kratos.pkgvuln.versions``) and A.2's priority rules
(``kratos.pkgvuln.priority``). Withdrawn advisories are never stored in the index; an
advisory's CVE aliases are joined for KEV / EPSS / CVSS and SSVC.

Severity per advisory: OSV's malicious-package report (MAL-*) installed -> critical; else
A.2's rules over its CVEs (KEV critical; fixable + EPSS high + CVSS >= 7 high; fixable +
CVSS >= 7 medium; else low), with the advisory's own rating (GHSA "high"/"critical")
standing in for CVSS when no CVE has one. A package's severity is its worst advisory's.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.code.deps.parsers import Dep
from kratos.pkgvuln import index as _index
from kratos.pkgvuln import match as _pm
from kratos.pkgvuln import priority as _prio
from kratos.pkgvuln import versions as _v
from kratos.pkgvuln.ecosystems import LANG

FAMILY = {top: fam for top, fam in LANG.values()}


@dataclass
class Advisory:
    osv_id: str
    cves: list[str]
    fixed_in: str | None
    severity: str = "low"
    rating: str = ""                         # the advisory's own rating
    kev: bool = False
    epss: float | None = None
    cvss: float | None = None
    ssvc_inputs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PackageHit:
    ecosystem: str
    package: str
    version: str
    source_files: list[str]
    installed: bool
    advisories: list[Advisory]

    @property
    def severity(self) -> str:
        return max((a.severity for a in self.advisories), key=lambda s: _prio.RANK[s], default="low")


@dataclass
class MatchResult:
    hits: list[PackageHit]
    checked: int = 0
    uncomparable: int = 0
    missing_ecosystems: list[str] = field(default_factory=list)   # ecosystems used but not in the index
    index_present: bool = False
    index_age_days: float | None = None


def _affected(family: str, version: str, e: _index.Entry) -> bool | None:
    if e.version is not None:
        c = _v.compare(family, version, e.version)
        return None if c is None else c == 0
    if e.introduced not in (None, "", "0"):
        c = _v.compare(family, version, e.introduced)
        if c is None:
            return None
        if c < 0:
            return False
    if e.fixed:
        c = _v.compare(family, version, e.fixed)
        return None if c is None else c < 0
    if e.last_affected:
        c = _v.compare(family, version, e.last_affected)
        return None if c is None else c <= 0
    return True


def _score(adv: Advisory, info: dict[str, dict[str, Any]], epss_high: float) -> None:
    if adv.rating == "malicious":
        adv.severity = "critical"
        return
    best = "low"
    cves = adv.cves or [""]
    for cve in cves:
        hit = _pm.CveHit(cve or adv.osv_id, adv.fixed_in, [adv.osv_id], adv.rating)
        s = _prio.score_cve(hit, info.get(cve, {}) if cve else {}, epss_high)
        if _prio.RANK[s.severity] > _prio.RANK[best]:
            best = s.severity
        adv.kev = adv.kev or bool(s.kev)
        if s.epss is not None:
            adv.epss = max(adv.epss or 0.0, s.epss)
        if s.cvss is not None:
            adv.cvss = max(adv.cvss or 0.0, s.cvss)
    if not adv.fixed_in and best != "critical":
        best = "low"                      # no fixed version published yet: nothing to upgrade to
    adv.severity = best


def match(data_dir: Path, deps: list[Dep], *, epss_high: float = 0.1) -> MatchResult:
    conn = _index.open_readonly(data_dir)
    if conn is None:
        return MatchResult([], missing_ecosystems=sorted({d.ecosystem for d in deps}))
    try:
        st = _index.status(data_dir)
        out = MatchResult([], index_present=True, index_age_days=st.age_days())
        eco_ids: dict[str, list[int]] = {}
        for eco in sorted({d.ecosystem for d in deps}):
            ids = _index.ecosystem_ids(conn, eco)
            if not ids:
                out.missing_ecosystems.append(eco)
            eco_ids[eco] = ids
        groups: dict[tuple[str, str, str], list[Dep]] = {}
        for d in deps:
            groups.setdefault((d.ecosystem, d.package, d.version), []).append(d)
        found: list[tuple[PackageHit, dict[int, Advisory]]] = []
        all_adv: set[int] = set()
        for (eco, pkg, ver), ds in sorted(groups.items()):
            ids = eco_ids.get(eco) or []
            if not ids:
                continue
            out.checked += 1
            fam = FAMILY[eco]
            by_adv: dict[int, Advisory] = {}
            for e in _index.entries_for(conn, ids, pkg):
                a = _affected(fam, ver, e)
                if a is None:
                    out.uncomparable += 1
                    continue
                if not a:
                    continue
                cur = by_adv.get(e.advisory)
                if cur is None:
                    by_adv[e.advisory] = Advisory(e.osv_id, [], e.fixed, rating=e.distro_severity or "")
                elif e.fixed and (cur.fixed_in is None or (_v.compare(fam, e.fixed, cur.fixed_in) or 0) > 0):
                    cur.fixed_in = e.fixed
            if by_adv:
                all_adv.update(by_adv)
                found.append((PackageHit(eco, pkg, ver, sorted({d.source_file for d in ds}),
                                         any(d.installed for d in ds), []), by_adv))
        cves = _index.cves_for(conn, all_adv)
        info = _index.enrichment(conn, {c for v in cves.values() for c in v})
        ssvc = _ssvc_rows(conn, {c for v in cves.values() for c in v})
        for hit, by_adv in found:
            for aid, adv in sorted(by_adv.items(), key=lambda kv: kv[1].osv_id):
                adv.cves = sorted(cves.get(aid, []))
                _score(adv, info, epss_high)
                adv.ssvc_inputs = [ssvc[c] for c in adv.cves if c in ssvc]
                hit.advisories.append(adv)
            out.hits.append(hit)
        return out
    except sqlite3.Error:
        return MatchResult([], missing_ecosystems=sorted({d.ecosystem for d in deps}))
    finally:
        conn.close()


def _ssvc_rows(conn: sqlite3.Connection, cves: set[str]) -> dict[str, dict[str, Any]]:
    """CISA's SSVC inputs per CVE (D.3), built exactly as the package check builds them."""
    from kratos.pkgvuln import ssvc_source
    from kratos.ssvc.inputs import for_cve

    wanted = sorted(cves)
    if not wanted:
        return {}
    info = _index.enrichment(conn, wanted)
    try:
        cisa = ssvc_source.lookup(conn, wanted)
    except sqlite3.Error:
        cisa = {}
    out: dict[str, dict[str, Any]] = {}
    for c in wanted:
        e = info.get(c) or {}
        out[c] = for_cve(c, cisa=cisa.get(c), kev=e.get("kev"), cvss=e.get("cvss"),
                         epss=(e.get("epss") or {}).get("score")).to_dict()
    return out
