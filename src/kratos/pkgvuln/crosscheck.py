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


def fixed_by_packages(data_dir: Path, packages_doc: dict[str, Any] | None, cves: Iterable[str],
                      fixers: dict[str, set[str]] | None = None) -> dict[str, str]:
    """{cve: plain explanation} for each CVE the installed packages already fix. With
    `fixers`, also fills {cve: the advisory package names that fix it} for
    listener_doubts."""
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
            if fixers is not None:
                fixers[cve] = {str(p.package) for p in fixed_in}
            pr = fixed_in[0]
            versions = ", ".join(sorted(set(pr.versions_checked)))
            out[cve] = (f"{cve}: the distribution fixed this in {pr.package} and the installed version ({versions}) "
                        "already has the fix -- the network match is likely wrong (a backported fix)")
    return out


def listener_doubts(packages_doc: dict[str, Any] | None, inventory: Any, scan: dict[str, Any] | None,
                    live_doc: dict[str, Any] | None, fixers: dict[str, set[str]]) -> dict[str, str]:
    """{cve: why the package fix may not cover it} for network matches the packages
    "fix" while the program actually listening on that port is a different one -- a
    build in /usr/local, a copy no package owns, something running from memory. The
    fixed package is installed, but it is not what answered the scan, so the match is
    kept. Only when the live-response read saw the listener: an unseen listener (another
    user's socket over SSH) leaves the package verdict as it is."""
    if not packages_doc or not scan or not live_doc or not fixers:
        return {}
    try:
        family = parse_selector(str(packages_doc.get("selector") or "")).family
    except ValueError:
        return {}
    by_name = {str(p.get("name")): p for p in getattr(inventory, "packages", None) or [] if isinstance(p, dict)}
    seen_ports = {int(x["port"]): x for x in live_doc.get("listeners") or []
                  if isinstance(x, dict) and isinstance(x.get("port"), int) and x.get("seen")}
    out: dict[str, str] = {}
    for item in scan.get("findings") or []:
        if not isinstance(item, dict) or item.get("source") != "vulscan":
            continue
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        lst = seen_ports.get(port)
        if lst is None:
            continue
        pkg = by_name.get(str(lst.get("package") or "").split(":", 1)[0])   # dpkg -S may add ":amd64"
        advisory_name = lookup_name(family, pkg)[0] if pkg else None
        for cve in item.get("cve_ids") or []:
            cve = str(cve).upper()
            names = fixers.get(cve)
            if not names or cve in out or (advisory_name and advisory_name in names):
                continue
            who = (f"{lst.get('exe')}, which comes from the {lst.get('package')} package" if lst.get("package")
                   else f"{lst.get('exe') or 'a program'}, which no installed package owns")
            out[cve] = (f"{cve}: {', '.join(sorted(names))} has the fix, but what listens on port {port} is "
                        f"{who} -- the fix may not apply to it, so this match is kept")
    return out
