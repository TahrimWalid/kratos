"""Which installed packages the distribution's own advisories can speak for.

A package from a PPA (Ondřej Surý's PHP), a vendor repository (Docker, Microsoft) or a
downloaded .deb/.rpm isn't in the distribution's advisory data -- or worse, shares a
name with a distribution package whose fixed versions mean nothing for it. Matching it
anyway gives false answers both ways, so such packages are left out of matching and
named as not checked (a coverage gap), never silently passed as clean.

The facts come from the package read (``kratos.adapters.packages``): for apt, which
repositories (by their Release ``Origin:``) offer the installed version and which offer
the package at all; for rpm, the package's vendor. The judgement is made here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# apt Origin values that are the distribution itself (prefix: "UbuntuESM", "Debian Backports")
DISTRO_ORIGINS = {"ubuntu": ("Ubuntu",), "debian": ("Debian",)}
# rpm vendors that are the distribution itself
DISTRO_VENDORS = {"rocky": ("Rocky Enterprise Software Foundation",), "almalinux": ("AlmaLinux",),
                  "rhel": ("Red Hat",)}
DISTRO_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
                "rhel": "Red Hat"}
# What a PPA build carries in its version, for a package whose repository is gone.
PPA_VERSION_HINTS = ("deb.sury.org", "~ppa", "+ppa", "ppa1", "ppa2")
UNKNOWN_REPO = "a repository with no Origin"
SHOWN_PER_ORIGIN = 6


@dataclass(frozen=True)
class Outside:
    name: str
    version: str
    origin: str          # where it came from, in plain words
    kind: str            # "third_party" | "unknown"


@dataclass
class OriginReport:
    checked: bool = False
    reason: str = ""                      # why origins couldn't be checked ("" = nothing to say)
    outside: list[Outside] = field(default_factory=list)

    @property
    def names(self) -> set[str]:
        return {o.name for o in self.outside}

    def to_dict(self) -> dict[str, Any]:
        return {"checked": self.checked, "reason": self.reason,
                "outside": [[o.name, o.version, o.origin, o.kind] for o in self.outside]}

    @classmethod
    def from_dict(cls, raw: Any) -> "OriginReport":
        """A stored report (inventory_store's read_json). Anything malformed reads as
        "not recorded" -- never as "nothing came from outside"."""
        if not isinstance(raw, dict):
            return cls(reason="where the packages came from wasn't recorded with this stored list")
        outside = [Outside(*(str(x) for x in o)) for o in raw.get("outside") or []
                   if isinstance(o, list) and len(o) == 4 and o[3] in ("third_party", "unknown")]
        return cls(checked=bool(raw.get("checked")), reason=str(raw.get("reason") or ""), outside=outside)


def _label(origins: list[str]) -> str:
    return ", ".join(UNKNOWN_REPO if o == "?" else o for o in origins) or UNKNOWN_REPO


def classify(inv: dict[str, Any], selector: Any) -> OriginReport:
    """The packages that come from outside the distribution (or from nowhere known)."""
    if selector is None:
        return OriginReport()
    distro = selector.distro
    name = DISTRO_NAMES.get(distro, distro)
    if distro in DISTRO_ORIGINS:
        return _apt(inv, DISTRO_ORIGINS[distro], name)
    if distro in DISTRO_VENDORS:
        return _rpm(inv, DISTRO_VENDORS[distro], name)
    return OriginReport()                  # Alpine: third-party repositories are rare; not judged


def _old_agent(inv: dict[str, Any]) -> str:
    if inv.get("via") == "agent":
        return "where the packages came from wasn't reported (this machine's agent is older -- update it with `g` " \
               "in /subagent), so packages from outside the distribution couldn't be told apart"
    return "where the packages came from couldn't be read, so packages from outside the distribution couldn't be " \
           "told apart"


def _apt(inv: dict[str, Any], prefixes: tuple[str, ...], distro: str) -> OriginReport:
    origins = inv.get("origins")
    lists = inv.get("origin_lists") or {}
    if origins is None:
        return OriginReport(reason=_old_agent(inv))
    if not lists.get("lists"):
        return OriginReport(reason="apt's package lists are empty on this machine (a container image, or `apt update` "
                                   f"never ran), so packages from outside {distro}'s repositories couldn't be told "
                                   "apart")

    def own(o: str) -> bool:
        return o.startswith(prefixes)

    if not any(own(o) for v in origins.values() for o in (*v["exact"], *v["any"])):
        return OriginReport(reason=f"none of apt's package lists come from {distro}'s own repositories, so packages "
                                   f"from outside {distro} couldn't be told apart")
    rep = OriginReport(checked=True)
    for pkg in inv.get("packages") or []:
        if pkg.get("manager") != "dpkg" or pkg["name"] not in origins:
            continue
        exact, anyo = origins[pkg["name"]]["exact"], origins[pkg["name"]]["any"]
        version = str(pkg.get("version") or "")
        if any(own(o) for o in exact):
            continue
        if exact:
            rep.outside.append(Outside(pkg["name"], version, _label(exact), "third_party"))
        elif any(own(o) for o in anyo):
            # the installed version isn't in today's lists, the name is the distribution's:
            # an older or newer build of the distribution's package -- unless it is a PPA build
            if any(h in version for h in PPA_VERSION_HINTS):
                rep.outside.append(Outside(pkg["name"], version, "a PPA no longer configured", "third_party"))
        elif anyo:
            rep.outside.append(Outside(pkg["name"], version, _label(anyo), "third_party"))
        else:
            rep.outside.append(Outside(pkg["name"], version, "no configured repository", "unknown"))
    return rep


def _rpm(inv: dict[str, Any], prefixes: tuple[str, ...], distro: str) -> OriginReport:
    vendors = inv.get("vendors") or {}
    if not vendors:
        return OriginReport(reason=_old_agent(inv))
    rep = OriginReport(checked=True)
    for pkg in inv.get("packages") or []:
        if pkg.get("manager") != "rpm" or pkg["name"] not in vendors:
            continue
        vendor = vendors[pkg["name"]]
        if vendor.startswith(prefixes):
            continue
        version = str(pkg.get("version") or "")
        if vendor:
            rep.outside.append(Outside(pkg["name"], version, vendor, "third_party"))
        else:
            rep.outside.append(Outside(pkg["name"], version, "no vendor (built locally?)", "unknown"))
    return rep


def gap_lines(rep: OriginReport, distro: str) -> list[str]:
    """Plain-words coverage gaps: what wasn't checked, grouped by where it came from."""
    lines = []
    if rep.reason:
        lines.append(rep.reason)
    third = [o for o in rep.outside if o.kind == "third_party"]
    unknown = [o for o in rep.outside if o.kind == "unknown"]
    if third:
        by: dict[str, list[str]] = {}
        for o in third:
            by.setdefault(o.origin, []).append(o.name)
        parts = []
        for origin, names in sorted(by.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            more = f" (+{len(names) - SHOWN_PER_ORIGIN} more)" if len(names) > SHOWN_PER_ORIGIN else ""
            parts.append(f"from {origin}: {', '.join(sorted(names)[:SHOWN_PER_ORIGIN])}{more}")
        lines.append(f"{len(third)} package(s) come from outside {distro}'s own repositories, so {distro}'s "
                     f"advisories can't be applied to them and they were not checked -- " + "; ".join(parts))
    if unknown:
        names = sorted(o.name for o in unknown)
        more = f" (+{len(names) - SHOWN_PER_ORIGIN} more)" if len(names) > SHOWN_PER_ORIGIN else ""
        lines.append(f"{len(unknown)} package(s) aren't offered by any configured repository (installed from a file, "
                     f"or their repository was removed) and were not checked: "
                     f"{', '.join(names[:SHOWN_PER_ORIGIN])}{more}")
    return lines
