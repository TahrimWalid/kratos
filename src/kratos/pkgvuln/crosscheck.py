"""Network CVE matches the installed packages already fix (A.2 §5.4).

The network vulnerability scan (VULN-001) matches a service's version text from
nmap against CVE descriptions. Distributions backport fixes without changing the
upstream version, so many of those matches are already fixed on the machine.
Here, for each such CVE: if the machine's distribution lists the CVE for an
installed package, and every installed package it lists it for is at or past the
fixed version, the network match is marked as likely wrong. A CVE the
distribution doesn't list for any installed package is left alone -- nothing is
known either way.

Local only: the saved package inventory and the vulnerability index.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from kratos.pkgvuln import index as _index
from kratos.pkgvuln import inventory_store
from kratos.pkgvuln.ecosystems import lookup_name, parse_selector
from kratos.pkgvuln.match import match


def fixed_by_packages(data_dir: Path, packages_doc: dict[str, Any] | None, cves: Iterable[str]) -> dict[str, str]:
    """{cve: plain explanation} for each CVE the installed packages already fix."""
    wanted = sorted({str(c).upper() for c in cves if str(c).upper().startswith("CVE-")})
    if not packages_doc or not wanted or not packages_doc.get("selector") or not packages_doc.get("inventory_id"):
        return {}
    try:
        selector = parse_selector(str(packages_doc["selector"]))
    except ValueError:
        return {}
    inv = inventory_store.get(data_dir, int(packages_doc["inventory_id"]))
    conn = _index.open_readonly(data_dir)
    if inv is None or conn is None:
        return {}
    try:
        eco_ids = _index.ecosystem_ids(conn, selector.key)
        adv_by_cve = _index.advisories_for_cves(conn, wanted)
        names = _index.packages_for_advisories(conn, eco_ids, {a for ids in adv_by_cve.values() for a in ids})
        installed = [p for p in inv.packages if lookup_name(selector.family, p)[0] in names]
        if not installed:
            return {}
        result = match(conn, selector, installed)
    finally:
        conn.close()
    out: dict[str, str] = {}
    for cve in wanted:
        affected = [pr for pr in result.packages.values() if cve in pr.fixable or cve in pr.unfixed]
        fixed_in = [pr for pr in result.packages.values() if cve in pr.fixed]
        if fixed_in and not affected:
            pr = fixed_in[0]
            versions = ", ".join(sorted(set(pr.versions_checked)))
            out[cve] = (f"{cve}: the distribution fixed this in {pr.package} and the installed version ({versions}) "
                        "already has the fix -- the network match is likely wrong (a backported fix)")
    return out
