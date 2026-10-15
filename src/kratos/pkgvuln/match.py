"""Installed packages against the vulnerability index -- pure, offline.

For each installed package, under the name its distribution's advisories use
(``ecosystems.lookup_name``: Debian/Ubuntu the source package, Alpine the
origin, RPM the binary):

1. every advisory entry for that (release, package) is read from the index;
2. the installed version is affected by an entry when it is in its range
   (``introduced <= v < fixed``, or ``v <= last_affected``) or is one of its listed
   versions -- compared with ``univers`` (``kratos.pkgvuln.versions``);
3. per CVE: a distribution's **per-CVE record** (DEBIAN-CVE-*, UBUNTU-CVE-*,
   ALPINE-CVE-*) is authoritative when there is one; only otherwise do bundle
   notices (DSA, USN, RLSA, ALSA, RHSA ...) decide. A notice fixes all of its
   CVEs at once, at the notice's version, so it can name a later fix than the CVE
   actually needed -- the per-CVE record says when THIS CVE was fixed. And when the
   per-CVE data covers the release (index.PRECISE_COVERAGE_MIN) but its record for
   a CVE doesn't name this package here, the distribution tracked the CVE and found
   this release unaffected: a notice listing it among others doesn't override that.

A CVE the installed version is past the fix for is "fixed" (that is what lets the
network cross-check say a version match is a backport). A version univers can't
read is counted, never guessed.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from kratos.pkgvuln import index as _index
from kratos.pkgvuln import versions as _v
from kratos.pkgvuln.ecosystems import FAMILY_APK, FAMILY_DEB, FAMILY_RPM, Selector, lookup_name

_NEGLIGIBLE = frozenset({"negligible", "unimportant"})


@dataclass
class CveHit:
    cve: str
    fixed_in: str | None                 # None: no fixed version published yet
    advisories: list[str]
    distro_severity: str = ""

    @property
    def fixable(self) -> bool:
        return self.fixed_in is not None


@dataclass
class PackageResult:
    package: str                          # the group: source package (deb), source RPM (rpm), origin (apk)
    installed: list[tuple[str, str]]      # (binary package, its version)
    versions_checked: list[str]           # the versions compared with the advisories
    fixable: dict[str, CveHit] = field(default_factory=dict)
    unfixed: dict[str, CveHit] = field(default_factory=dict)
    fixed: set[str] = field(default_factory=set)        # CVEs an advisory lists that this version is past
    older_versions: list[str] = field(default_factory=list)   # older copies also installed (kept kernels), not judged


@dataclass
class MatchResult:
    packages: dict[str, PackageResult]
    lookups_affected: dict[tuple[str, str], set[str]]   # (lookup name, version) -> affected CVEs
    checked: int = 0                                     # installed packages compared
    uncomparable: int = 0                                # comparisons univers could not do
    silenced: int = 0                                    # bundle-notice CVEs the per-CVE data says don't apply here


def affected(family: str, version: str, e: _index.Entry) -> bool | None:
    """Is `version` affected by entry `e`? None when a comparison was impossible."""
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
        if c is None:
            return None
        if c >= 0:
            return False
    if e.last_affected:
        c = _v.compare(family, version, e.last_affected)
        if c is None:
            return None
        if c > 0:
            return False
    return True


def group_name(family: str, pkg: dict[str, Any]) -> str:
    """The finding's subject: the package the distribution ships the fix as -- the
    advisory's name on Debian/Ubuntu/Alpine (so a signed kernel image joins its
    kernel, "linux"), the source RPM on RPM systems (curl + libcurl are one)."""
    if family in (FAMILY_DEB, FAMILY_APK):
        return lookup_name(family, pkg)[0]
    return str(pkg.get("source") or pkg.get("name"))


def _highest(family: str, values: list[str]) -> str | None:
    best: str | None = None
    for v in values:
        if best is None:
            best = v
            continue
        c = _v.compare(family, v, best)
        if c is not None and c > 0:
            best = v
    return best


def match(conn: sqlite3.Connection, selector: Selector, packages: list[dict[str, Any]]) -> MatchResult:
    family = selector.family
    eco_ids = _index.ecosystem_ids(conn, selector.key)
    # (lookup name, lookup version) -> the installed packages it stands for
    lookups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for p in packages:
        lookups.setdefault(lookup_name(family, p), []).append(p)

    entries_by_name: dict[str, list[_index.Entry]] = {}
    for name, _ver in lookups:
        if name not in entries_by_name:
            entries_by_name[name] = _index.entries_for(conn, eco_ids, name)
    cves_by_adv = _index.cves_for(conn, {e.advisory for es in entries_by_name.values() for e in es})

    # Several installed versions under one advisory name happen when old copies are
    # kept -- above all kernels (linux-modules-6.8.0-137 and -147 are both source
    # "linux"). Upgrading cannot fix the old copies; the newest installed one is what
    # an upgrade decides, and a stale RUNNING kernel is PKG-003's (a reboot). So a
    # package is judged by its newest installed version; the older ones are still
    # matched for lookups_affected (the running-kernel check reads it).
    newest: dict[str, str] = {}
    for name, ver in lookups:
        cur = newest.get(name)
        if cur is None or (_v.compare(family, ver, cur) or 0) > 0:
            newest[name] = ver

    result = MatchResult(packages={}, lookups_affected={})
    # per group, per CVE: [(precise, affected, fixed, severity, osv_id)]
    verdicts: dict[str, dict[str, list[tuple[bool, bool, str | None, str, str]]]] = {}
    for (name, ver), pkgs in lookups.items():
        result.checked += len(pkgs)
        grp = group_name(family, pkgs[0])
        pr = result.packages.get(grp)
        if pr is None:
            pr = result.packages[grp] = PackageResult(grp, [], [])
        pr.installed.extend((str(p.get("name")), str(p.get("version"))) for p in pkgs)
        judged = newest.get(name) == ver
        if judged and ver not in pr.versions_checked:
            pr.versions_checked.append(ver)
        here: dict[str, list[tuple[bool, bool, str | None, str, str]]] = {}
        for e in entries_by_name.get(name, []):
            verdict = affected(family, ver, e)
            if verdict is None:
                result.uncomparable += 1
                continue
            for cve in cves_by_adv.get(e.advisory, []):
                here.setdefault(cve, []).append((e.precise, verdict, e.fixed, e.distro_severity, e.osv_id))
        # what this exact (name, version) is affected by -- the running-kernel check uses it
        result.lookups_affected[(name, ver)] = {
            cve for cve, vs in here.items() if any(x[1] for x in ([y for y in vs if y[0]] or vs))}
        by_cve = verdicts.setdefault(grp, {})
        if not judged:
            pr.older_versions.append(ver)
            continue
        for cve, vs in here.items():
            by_cve.setdefault(cve, []).extend(vs)

    # CVEs known only from bundle notices in this release, while the distribution's
    # per-CVE data (which covers this release) has a record for them that does not
    # name this package here: the per-CVE record says "not affected here".
    covered = _index.precise_coverage(conn, selector.key) >= _index.PRECISE_COVERAGE_MIN
    bundle_only = {cve for by_cve in verdicts.values() for cve, vs in by_cve.items() if not any(x[0] for x in vs)}
    silenced = _index.cves_with_precise_record(conn, selector.top, bundle_only) if covered and bundle_only else set()
    result.silenced = len(silenced)
    for grp, by_cve in verdicts.items():
        pr = result.packages[grp]
        for cve, vs in by_cve.items():
            if cve in silenced:
                pr.fixed.add(cve)
                continue
            use = [x for x in vs if x[0]] or vs
            hits = [x for x in use if x[1]]
            if not hits:
                pr.fixed.add(cve)
                continue
            fixes = [x[2] for x in hits if x[2]]
            sev = next((x[3] for x in hits if x[3]), "")
            advisories = sorted({x[4] for x in hits})
            hit = CveHit(cve, _highest(family, fixes) if fixes else None, advisories, sev)
            (pr.fixable if hit.fixable else pr.unfixed)[cve] = hit
    result.packages = {k: v for k, v in sorted(result.packages.items())}
    return result


# --------------------------------------------------------------------------- the kernel
_DEB_IMAGE_RE = re.compile(r"^linux-image-(?:unsigned-)?(\d[A-Za-z0-9.+~_-]*)$")
_APK_KERNEL_RE = re.compile(r"^linux-([a-z0-9]+)$")


@dataclass
class KernelStatus:
    managed: bool                         # the running kernel came from this machine's packages
    running: str
    newest: str = ""                      # the newest installed kernel's release
    pending: bool = False                 # a newer kernel is installed than the one running
    reason: str = ""
    running_lookups: list[tuple[str, str]] = field(default_factory=list)   # what to check the running kernel's CVEs with


def _rpm_release(version: str, arch: str) -> str:
    v = version.split(":", 1)[1] if ":" in version else version
    return f"{v}.{arch}" if arch else v


def _apk_release(version: str, flavor: str) -> str:
    base, _, r = version.rpartition("-r")
    return f"{base}-{r}-{flavor}" if base and r.isdigit() else ""


def kernel_status(family: str, inv: dict[str, Any], packages: list[dict[str, Any]]) -> KernelStatus:
    """Is a newer kernel installed than the one running? Compares the running
    kernel (`uname -r`) with the newest installed kernel package; on Debian/Ubuntu
    the distribution's own reboot-required flag also counts when it names a kernel."""
    running = str(inv.get("running_kernel") or "")
    kernels: dict[str, str] = {}                  # release -> package version
    if family == FAMILY_DEB:
        for p in packages:
            m = _DEB_IMAGE_RE.match(str(p.get("name")))
            if m:
                kernels[m.group(1)] = str(p.get("version"))
    elif family == FAMILY_RPM:
        names = {str(p.get("name")) for p in packages}
        want = "kernel-core" if "kernel-core" in names else "kernel"
        for p in packages:
            if p.get("name") == want:
                kernels[_rpm_release(str(p.get("version")), str(p.get("arch") or ""))] = str(p.get("version"))
    elif family == FAMILY_APK:
        for p in packages:
            m = _APK_KERNEL_RE.match(str(p.get("name")))
            if m and m.group(1) not in ("firmware", "headers", "pam") and not m.group(1).startswith("firmware"):
                rel = _apk_release(str(p.get("version")), m.group(1))
                if rel:
                    kernels[rel] = str(p.get("version"))
    flagged = bool(inv.get("reboot_required")) and any(
        str(n).startswith(("linux-image", "linux-base")) for n in inv.get("reboot_required_pkgs") or [])
    if not running or running not in kernels:
        return KernelStatus(False, running, reason=(
            "the running kernel was not installed by this machine's packages (a container shares its host's "
            "kernel, or the kernel was built by hand)" if running else "the running kernel could not be read"))
    newest = running
    for rel, ver in kernels.items():
        c = _v.compare(family, ver, kernels[newest])
        if c is not None and c > 0:
            newest = rel
    pending = newest != running or flagged
    lookups: list[tuple[str, str]] = []
    for p in packages:
        n = str(p.get("name"))
        if family == FAMILY_DEB and n.endswith(running) and n.startswith("linux-"):
            lookups.append(lookup_name(family, p))
        elif family == FAMILY_RPM and n.startswith("kernel") and _rpm_release(str(p.get("version")),
                                                                                str(p.get("arch") or "")) == running:
            lookups.append(lookup_name(family, p))
        elif family == FAMILY_APK and _APK_KERNEL_RE.match(n) and kernels.get(running) == p.get("version"):
            lookups.append(lookup_name(family, p))
    reason = (f"kernel {newest} is installed but {running} is running" if newest != running
              else "the distribution says a reboot is needed for a kernel update" if flagged else "")
    return KernelStatus(True, running, newest, pending, reason, sorted(set(lookups)))


def is_negligible(distro_severity: str) -> bool:
    return str(distro_severity or "").lower() in _NEGLIGIBLE
