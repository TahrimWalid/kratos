"""Read a machine's packages, match them, and save what the rule engine reads (A.2).

One call: read the inventory (over SSH as the SSH user, or through the machine's
sub-agent -- ``ssh_remote.fetch_package_inventory`` routes it), store it in
``pkg_inventory``, match it against the local index (no network), score it, and
write ``data_dir/packages/packages_<key>.json``. ``correlate_findings`` picks that
file up (``findings_engine.find_latest_inputs``, category ``packages``) and turns
its ``signals`` into PKG-* findings.

The file name is derived from what the result depends on (the package set, the
index build, the threshold), and a later check with the same inputs rewrites the
same file -- so the folder grows when packages or data change, not on every check.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from kratos import settings_store
from kratos.pkgvuln import ecosystems as _eco
from kratos.pkgvuln import index as _index
from kratos.pkgvuln import inventory_store
from kratos.pkgvuln import origin as _origin
from kratos.pkgvuln import settings as _settings
from kratos.pkgvuln.match import KernelStatus, MatchResult, PackageResult, kernel_status, match
from kratos.pkgvuln.priority import RANK, Scored, score_cve, worst
from kratos.utils.timeutil import epoch_to_utc_iso

PKG_DIR = "packages"
FILE_GLOB = "packages_*.json"
CVES_SHOWN = 5
ACT_NOW_SHOWN = 3
BINARIES_SHOWN = 8

Reader = Callable[[], Any]

_UPGRADE = {
    _eco.FAMILY_DEB: "sudo apt-get install --only-upgrade {names}",
    _eco.FAMILY_RPM: "sudo dnf upgrade {names}",
    _eco.FAMILY_APK: "sudo apk upgrade {names}",
}
_FAMILY_OF_MANAGER = {"dpkg": _eco.FAMILY_DEB, "rpm": _eco.FAMILY_RPM, "apk": _eco.FAMILY_APK}
UPDATE_HINT = "run `kratos vulndb-update` on the Kratos machine"


def _default_reader() -> Any:
    from kratos.adapters.ssh_remote import fetch_package_inventory

    return fetch_package_inventory()


def _failure_text(result: Any) -> str:
    text = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()
    return " ".join(text.split())[:300] or "the read failed"


def _family(inv: dict[str, Any], choice: _eco.Choice) -> str:
    if choice.selector is not None:
        return choice.selector.family
    for mgr in ("dpkg", "rpm", "apk"):
        if (inv.get("managers") or {}).get(mgr):
            return _FAMILY_OF_MANAGER[mgr]
    return ""


def _list_words(target: str, when: float, list_read_at: float | None) -> str:
    if list_read_at is None:
        return f"From the package check of {target} at {epoch_to_utc_iso(when)}"
    return (f"From the package list of {target} read at {epoch_to_utc_iso(list_read_at)} and matched again at "
            f"{epoch_to_utc_iso(when)} after the vulnerability data was updated (nothing was read from the machine)")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _cve_line(s: Scored) -> str:
    bits = [s.cve]
    if s.kev:
        due = (s.kev or {}).get("due_date")
        bits.append("on CISA's exploited list" + (f" (CISA due date {due})" if due else ""))
    if s.epss is not None:
        bits.append(f"EPSS {s.epss:.2f}")
    if s.cvss is not None:
        bits.append(f"CVSS {s.cvss:.1f}")
    if s.distro_severity and s.distro_severity not in ("not yet assigned",):
        bits.append(f"distribution rates it {s.distro_severity}")
    bits.append(f"fixed in {s.fixed_in}" if s.fixed_in else "no fix yet")
    if s.advisories:
        bits.append(", ".join(s.advisories[:3]) + (" ..." if len(s.advisories) > 3 else ""))
    return " -- ".join(bits)


def _installed_line(pr: PackageResult) -> str:
    items = sorted(set(pr.installed))
    shown = ", ".join(f"{n} {v}" for n, v in items[:BINARIES_SHOWN])
    more = f" (+{len(items) - BINARIES_SHOWN} more)" if len(items) > BINARIES_SHOWN else ""
    older = (f"; judged by the newest installed version ({', '.join(pr.versions_checked)}) -- older copies kept "
             "alongside it (" + ", ".join(sorted(set(pr.older_versions))[:3]) + ") can't be fixed by upgrading")
    return f"Installed: {shown}{more}" + (older if pr.older_versions else "")


def _upgrade_command(family: str, pr: PackageResult) -> str:
    names = sorted({n for n, _v in pr.installed})[:BINARIES_SHOWN * 2]
    return _UPGRADE.get(family, "").format(names=" ".join(names)) if names else ""


def _package_signals(family: str, pr: PackageResult, scored_fix: list[Scored], source_line: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if scored_fix:
        scored_fix.sort(key=Scored.sort_key)
        sev = worst(scored_fix)
        kev = [s for s in scored_fix if s.kev]
        fix_to = scored_fix[0].fixed_in
        for s in scored_fix[1:]:
            if s.fixed_in and fix_to and s.fixed_in != fix_to:
                from kratos.pkgvuln.versions import compare

                c = compare(family, s.fixed_in, fix_to)
                if c is not None and c > 0:
                    fix_to = s.fixed_in
        title = f"{pr.package}: {_plural(len(scored_fix), 'fixable known vulnerability', 'fixable known vulnerabilities')}"
        if kev:
            title += f", {len(kev)} exploited in the wild -- act now"
        evidence = [source_line, _installed_line(pr),
                    f"An update that fixes {'it' if len(scored_fix) == 1 else 'all of them'} is available: "
                    f"version {fix_to} or later"]
        evidence += [_cve_line(s) for s in scored_fix[:CVES_SHOWN]]
        if len(scored_fix) > CVES_SHOWN:
            evidence.append(f"... and {len(scored_fix) - CVES_SHOWN} more CVE(s), listed in the finding's entities")
        cmd = _upgrade_command(family, pr)
        rec = []
        if kev:
            rec.append("Upgrade this package first: CISA lists " + ", ".join(s.cve for s in kev[:3])
                       + " as exploited by attackers right now.")
        rec.append(f"Upgrade {pr.package} on the machine" + (f": `{cmd}`" if cmd else "")
                   + " (Kratos does not run it -- copy it to a terminal on the machine).")
        rec.append("Restart the services that use it (or reboot) so the fixed version is the one running.")
        out.append({"rule": "PKG-001", "severity": sev, "subject": pr.package, "title": title,
                    "entities": sorted(s.cve for s in scored_fix), "evidence": evidence, "recommendation": rec,
                    "package": pr.package, "fixed_in": fix_to, "act_now": bool(kev),
                    "cves": [_scored_dict(s) for s in scored_fix[:50]]})
    return out


PACKAGES_SHOWN = 10


def _unfixed_signal(groups: list[tuple[PackageResult, list[Scored]]], source_line: str) -> dict[str, Any] | None:
    """PKG-002: everything the distribution has not released a fix for yet, as ONE
    finding for the machine, grouped per package in its evidence. There is nothing to
    install, so a finding per package would only be noise (a fully patched Ubuntu
    server has dozens); its entities are `package:CVE`, so a new unfixed CVE still
    reopens a decision."""
    groups = [(pr, sorted(sc, key=Scored.sort_key)) for pr, sc in groups if sc]
    if not groups:
        return None
    groups.sort(key=lambda g: (g[1][0].sort_key(), -len(g[1]), g[0].package))
    every = [s for _pr, sc in groups for s in sc]
    kev = [s for s in every if s.kev]
    sev = "critical" if kev else ("info" if all(s.severity == "info" for s in every) else "low")
    total = len({s.cve for s in every})
    title = (f"{_plural(len(groups), 'installed package has', 'installed packages have')} "
             f"{_plural(total, 'known vulnerability', 'known vulnerabilities')} with no fix released yet")
    if kev:
        title += f", {len({s.cve for s in kev})} exploited in the wild"
    evidence = [source_line,
                "The distribution has not released fixed versions yet -- there is nothing to install today."]
    for pr, sc in groups[:PACKAGES_SHOWN]:
        evidence.append(f"{pr.package} ({_plural(len(sc), 'CVE', 'CVEs')}): " + _cve_line(sc[0])
                        + (f"; and {len(sc) - 1} more" if len(sc) > 1 else ""))
    if len(groups) > PACKAGES_SHOWN:
        evidence.append(f"... and {len(groups) - PACKAGES_SHOWN} more package(s), listed in the finding's entities")
    rec = ["Nothing to install yet: keep vulnerability data current (`kratos vulndb-update`) so Kratos tells you "
           "when a fix ships."]
    if kev:
        rec.insert(0, "Unfixed vulnerabilities attackers are exploiting now (" + ", ".join(sorted({s.cve for s in kev})[:3])
                   + "): limit who can reach that software, or remove it if it isn't needed, until a fix ships.")
    return {"rule": "PKG-002", "severity": sev, "subject": "", "title": title,
            "entities": sorted(f"{pr.package}:{s.cve}" for pr, sc in groups for s in sc),
            "evidence": evidence, "recommendation": rec, "act_now": bool(kev),
            "packages": [{"package": pr.package, "cves": [_scored_dict(s) for s in sc[:20]], "count": len(sc)}
                         for pr, sc in groups[:50]]}


def _scored_dict(s: Scored) -> dict[str, Any]:
    return {"cve": s.cve, "severity": s.severity, "kev": bool(s.kev),
            "kev_due": (s.kev or {}).get("due_date"), "epss": s.epss, "cvss": s.cvss, "fixed_in": s.fixed_in,
            "advisories": list(s.advisories), "distro_severity": s.distro_severity}


def _kernel_signal(ks: KernelStatus, kev_cves: list[str], source_line: str) -> dict[str, Any] | None:
    if not ks.managed or not ks.pending:
        return None
    evidence = [source_line, f"Running kernel: {ks.running}", f"Newest installed kernel: {ks.newest}"]
    if ks.reason:
        evidence.append(ks.reason[:1].upper() + ks.reason[1:] + ".")
    if kev_cves:
        evidence.append("The running kernel has vulnerabilities CISA lists as exploited: " + ", ".join(kev_cves[:5]))
    return {"rule": "PKG-003", "severity": "high" if kev_cves else "medium", "subject": "",
            "title": "A newer kernel is installed than the one running -- a reboot is pending",
            "entities": [ks.newest], "evidence": evidence,
            "recommendation": ["Reboot the machine at a convenient time so the updated kernel's fixes take effect."],
            "running_kernel": ks.running, "newest_kernel": ks.newest}


def _content_key(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _write(path: Path, doc: dict[str, Any]) -> None:
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def run(data_dir: Path, target: str, *, reader: Reader | None = None, now: float | None = None) -> dict[str, Any]:
    """Read, match, save. Returns the saved document plus `file`, or
    `{"status": "error", ...}` when the read failed (nothing is saved -- a failed
    read must never become "no vulnerable packages")."""
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    result = (reader or _default_reader)()
    if not isinstance(result, dict):
        return {"status": "error", "target": target, "observation": _failure_text(result)}
    inv = result
    choice = _eco.for_os(inv.get("os") or {})
    family = _family(inv, choice)
    # Packages from outside the distribution (a PPA, a vendor repository, a downloaded
    # file): the distribution's advisories can't speak for them, so they are left out of
    # matching and named as not checked -- never matched against the wrong fixed versions.
    origins = _origin.classify(inv, choice.selector)
    stored = inventory_store.save(data_dir, target, inv, family=family,
                                  selector=choice.selector.key if choice.selector else None, now=when,
                                  read=_read_facts(inv, origins))
    return _judge(data_dir, target, inv, choice, family, origins, stored, when, list_read_at=None)


def rematch(data_dir: Path, target: str, *, now: float | None = None) -> dict[str, Any] | None:
    """Match the machine's newest STORED package list again -- nothing is read from the
    machine (after `kratos vulndb-update`, so a newly published or newly exploited CVE
    shows up without waiting for the next package check). None when no list is stored.
    The result says when the list was read, and can't close a finding: only a fresh
    read can say a package was upgraded."""
    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    row = inventory_store.latest(data_dir, target)
    if row is None:
        return None
    read = row.read or {}
    sysinfo = row.system or {}
    inv: dict[str, Any] = {
        "header": bool(read.get("header", True)), "complete": bool(read.get("complete", True)),
        "dropped": int(read.get("dropped") or 0), "managers": read.get("managers") or {},
        "os": sysinfo.get("os") or {}, "running_kernel": sysinfo.get("running_kernel") or "",
        "kernel_trees": sysinfo.get("kernel_trees") or [], "reboot_required": bool(sysinfo.get("reboot_required")),
        "reboot_required_pkgs": sysinfo.get("reboot_required_pkgs") or [], "packages": list(row.packages),
        "via": row.via or "ssh"}
    choice = _eco.for_os(inv["os"])
    family = row.family or _family(inv, choice)
    origins = _origin.OriginReport.from_dict(read.get("origins")) if read else _origin.OriginReport(
        reason="this package list was stored by an earlier Kratos that didn't record where each package came "
               "from, so packages from outside the distribution (if any) were matched like its own -- the "
               "machine's next package check records it")
    return _judge(data_dir, target, inv, choice, family, origins, row, when, list_read_at=row.last_seen_at)


def _read_facts(inv: dict[str, Any], origins: _origin.OriginReport) -> dict[str, Any]:
    """How the read went, stored with the list so it can be matched again the same way."""
    return {"header": bool(inv.get("header")), "complete": bool(inv.get("complete")),
            "dropped": int(inv.get("dropped") or 0), "managers": dict(inv.get("managers") or {}),
            "origins": origins.to_dict()}


def _judge(data_dir: Path, target: str, inv: dict[str, Any], choice: Any, family: str,
           origins: _origin.OriginReport, stored: Any, when: float, *, list_read_at: float | None) -> dict[str, Any]:
    """Match a package list and save the judged document. `list_read_at`: when the
    list was read, for a stored list matched again (None: read just now)."""
    rematched = list_read_at is not None
    packages = list(inv.get("packages") or [])
    gaps: list[str] = []
    if not inv.get("header") or not packages and not (inv.get("managers") or {}):
        gaps.append("no package manager's list could be read on this machine")
    elif not inv.get("complete"):
        gaps.append("the package list could not be read completely (a package manager failed or the output "
                    "was cut short)")
    if inv.get("dropped"):
        gaps.append(f"{inv['dropped']} package record(s) were not readable and were skipped")
    distro_name = _origin.DISTRO_NAMES.get(choice.selector.distro, choice.selector.distro) if choice.selector else ""
    gaps += _origin.gap_lines(origins, distro_name)
    outside = origins.names
    to_match = [p for p in packages if p["name"] not in outside]

    st = _index.status(data_dir)
    max_age = settings_store.get(_settings.MAX_AGE_DAYS, data_dir=data_dir)
    epss_high = float(settings_store.get(_settings.EPSS_HIGH, data_dir=data_dir))
    age = st.age_days(when)
    stale_days = int(age) if age is not None and age > max_age else None
    signals: list[dict[str, Any]] = []
    matched = False
    m: MatchResult | None = None
    ks = kernel_status(family, inv, packages) if family else KernelStatus(False, str(inv.get("running_kernel") or ""))
    if choice.selector is None:
        gaps.append(choice.gap)
    elif not st.present:
        gaps.append(f"no vulnerability data has been downloaded yet -- {UPDATE_HINT}")
    elif choice.selector.key not in st.selectors:
        gaps.append(f"the downloaded vulnerability data does not cover {choice.selector.key} yet -- {UPDATE_HINT}")
    else:
        conn = _index.open_readonly(data_dir)
        if conn is None:
            gaps.append(f"the vulnerability data could not be opened -- {UPDATE_HINT}")
        else:
            try:
                m = match(conn, choice.selector, to_match)
                matched = True
                all_cves = {c for pr in m.packages.values() for c in (*pr.fixable, *pr.unfixed)}
                all_cves |= {c for lk in ks.running_lookups for c in m.lookups_affected.get(lk, set())}
                info = _index.enrichment(conn, all_cves)
            finally:
                conn.close()
            pretty = (inv.get("os") or {}).get("PRETTY_NAME") or choice.selector.key
            built = epoch_to_utc_iso(st.built_at) if st.built_at else "unknown"
            source_line = (f"{_list_words(target, when, list_read_at)}: "
                           f"{_plural(len(packages), 'installed package', 'installed packages')} on {pretty}, "
                           f"matched on the Kratos machine against {choice.selector.key} advisory data "
                           f"(downloaded {built})")
            unfixed: list[tuple[PackageResult, list[Scored]]] = []
            for pr in m.packages.values():
                fix = [score_cve(h, info.get(h.cve, {}), epss_high) for h in pr.fixable.values()]
                unfixed.append((pr, [score_cve(h, info.get(h.cve, {}), epss_high) for h in pr.unfixed.values()]))
                signals += _package_signals(family, pr, fix, source_line)
            open_sig = _unfixed_signal(unfixed, source_line)
            if open_sig:
                signals.append(open_sig)
            kev_running = sorted({c for lk in ks.running_lookups for c in m.lookups_affected.get(lk, set())
                                  if (info.get(c) or {}).get("kev")})
            ks_sig = _kernel_signal(ks, kev_running, source_line)
            if ks_sig:
                signals.append(ks_sig)
            if m.uncomparable:
                gaps.append(f"{m.uncomparable} version comparison(s) could not be made (an unusual version string) "
                            "and were left out")
    if not matched and family:
        ks_sig = _kernel_signal(ks, [], _list_words(target, when, list_read_at))
        if ks_sig:
            signals.append(ks_sig)
    if stale_days is not None:
        gaps.append(f"the vulnerability data is {stale_days} days old -- {UPDATE_HINT}")
    if gaps:
        signals.append({"rule": "PKG-004", "severity": "info", "subject": "",
                        "title": "Part of the package vulnerability check could not be done",
                        "entities": [], "evidence": [*gaps,
                                                     "Vulnerabilities in what wasn't checked are unknown, not absent."],
                        "recommendation": [f"Fix what is listed above (most often: {UPDATE_HINT})."]})
    counts = {
        "packages": len(packages),
        "vulnerable_packages": len({s["subject"] for s in signals if s["rule"] == "PKG-001"}),
        "act_now": sum(1 for s in signals if s["rule"] in ("PKG-001", "PKG-002") and s.get("act_now")),
        "unfixed_packages": sum(len(s.get("packages") or []) for s in signals if s["rule"] == "PKG-002"),
        "fixable_cves": sum(len(s["entities"]) for s in signals if s["rule"] == "PKG-001"),
        "unchecked_packages": len(origins.outside),
    }
    # The packages to act on now, by name, for the one-line summary the model starts
    # from. Safe to name there: each is a package the distribution's own advisory data
    # lists for an exploited CVE -- a name found in the vulnerability index, not free
    # text the machine made up.
    act_now = [s["subject"] for s in signals if s["rule"] == "PKG-001" and s.get("act_now")]
    act_now += [p["package"] for s in signals if s["rule"] == "PKG-002" and s.get("act_now")
                for p in s.get("packages") or [] if any(c.get("kev") for c in p.get("cves") or [])]
    complete = bool(inv.get("complete")) and matched
    doc: dict[str, Any] = {
        "target": target, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when,
        "via": inv.get("via") or "ssh", "family": family, "os": inv.get("os") or {},
        "selector": choice.selector.key if choice.selector else None,
        "inventory_id": stored.id, "inventory_hash": stored.hash,
        "index_built_at": st.built_at, "index_stale_days": stale_days, "complete": complete,
        "kernel": {"managed": ks.managed, "running": ks.running, "newest": ks.newest, "pending": ks.pending},
        "counts": counts, "coverage_gaps": gaps, "signals": signals,
        "act_now_packages": list(dict.fromkeys(act_now)),
        "outside_distribution": [{"name": o.name, "version": o.version, "origin": o.origin, "kind": o.kind}
                                 for o in origins.outside[:500]],
        "origins_checked": origins.checked,
        "rematched": rematched,
        "list_read_at": epoch_to_utc_iso(list_read_at if rematched else when),
    }
    out_dir = data_dir / PKG_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    key = _content_key(target, stored.hash, st.built_at, epss_high, choice.selector.key if choice.selector else None,
                       gaps, rematched)
    path = out_dir / f"packages_{key}.json"
    _write(path, doc)
    return {**doc, "status": "ok", "file": str(path)}


def summary_line(doc: dict[str, Any]) -> str:
    """The one plain line the collection digest shows (Kratos's own words). Packages
    to act on now lead the line: the digest shortens long lines, and that is the
    part that must survive."""
    c = doc.get("counts") or {}
    n = int(c.get("packages") or 0)
    parts: list[str] = []
    names = [str(x) for x in doc.get("act_now_packages") or []] if doc.get("complete") else []
    if names:
        shown = ", ".join(names[:ACT_NOW_SHOWN]) + (f" +{len(names) - ACT_NOW_SHOWN} more"
                                                     if len(names) > ACT_NOW_SHOWN else "")
        parts.append(f"ACT NOW: {shown} (vulnerability exploited in the wild, CISA KEV)")
    parts.append(f"{n} installed package(s)")
    vul = int(c.get("vulnerable_packages") or 0)
    if doc.get("complete"):
        parts.append(f"{vul} with fixable vulnerabilities" if vul else "none with a fixable known vulnerability")
    else:
        parts.append("not matched against vulnerability data")
    outside = [str(o.get("name")) for o in doc.get("outside_distribution") or []]
    if outside:
        shown = ", ".join(outside[:3]) + (f" +{len(outside) - 3} more" if len(outside) > 3 else "")
        parts.append(f"{len(outside)} from outside the distribution NOT checked ({shown})")
    if (doc.get("kernel") or {}).get("pending"):
        parts.append("reboot pending for a newer kernel")
    if doc.get("index_stale_days"):
        parts.append(f"vulnerability data {doc['index_stale_days']} days old")
    return "; ".join(parts)


def severity_rank(sev: str) -> int:
    return RANK.get(sev, 0)
