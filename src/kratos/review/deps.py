"""Dependency reachability for CODE-003 (E.7b §3.9): an ADDITION to E.7a's advisory findings,
never a downgrade. Slicing already knows which top-level packages a network route imports, so
for each open advisory in the root the review records whether the advisory's package is

- ``reached``   -- imported by a slice the network can reach (a route/served slice), or
- ``served``    -- imported by served code but not on any slice's route, or
- ``unseen``    -- not seen imported by any served code at all.

This only ORDERS and ANNOTATES CODE-003 findings; per the README rule it never lowers their
severity or closes them (judge.py attaches the note, the CODE finding keeps its own severity).

Matching is by top-level import name. A package's distribution name differs from its import
name (``PyYAML`` -> ``yaml``), so a small known-aliases table plus a normalised fallback is
used; where OSV names an affected module we also match that. Any package whose import name
Kratos can't resolve is reported ``unseen`` conservatively (it is never claimed reachable on a
guess) -- stated as a limitation in the Handoff.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from kratos.review.slice import Slice

REACHED, SERVED, UNSEEN = "reached", "served", "unseen"

# Distribution name -> import name, for the common cases where they differ. Lower-cased keys.
_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil", "python-dateutil": "dateutil",
    "msgpack-python": "msgpack", "protobuf": "google", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "pycryptodome": "crypto", "pyjwt": "jwt", "django-rest-framework": "rest_framework",
    "djangorestframework": "rest_framework", "python-jose": "jose", "mysqlclient": "mysqldb",
    "psycopg2-binary": "psycopg2", "python-magic": "magic", "setuptools": "setuptools",
}


def _import_names(package: str) -> set[str]:
    """Plausible top-level import names for a distribution package name."""
    p = (package or "").strip().lower()
    out: set[str] = set()
    if p in _ALIASES:
        out.add(_ALIASES[p])
    out.add(p.replace("-", "_"))
    out.add(p.replace("-", ""))
    if p.startswith("python-"):
        out.add(p[len("python-"):].replace("-", "_"))
    return {n for n in out if n}


@dataclass(frozen=True)
class Reachability:
    package: str
    ecosystem: str
    status: str                 # reached | served | unseen
    advisories: tuple[str, ...]  # osv ids / cves, for the note
    via_slice: str = ""         # a slice entity that reaches it (when reached)

    @property
    def note(self) -> str:
        where = {REACHED: "reached from a network route", SERVED: "imported by served code, not on a route",
                 UNSEEN: "not seen in served code"}[self.status]
        return f"{self.package}: {where}"


def _advisory_modules(adv: dict[str, Any]) -> set[str]:
    """Top-level import names an OSV advisory names as affected, where given (``imports`` /
    ``affected.ecosystem_specific``). Best-effort; empty when OSV gives nothing."""
    out: set[str] = set()
    for key in ("imports", "modules", "affected_modules"):
        for m in adv.get(key) or []:
            if isinstance(m, str) and m.strip():
                out.add(m.strip().split(".")[0].lower())
    return out


def reachability(open_advisories: Iterable[dict[str, Any]], slices: Iterable[Slice]) -> list[Reachability]:
    """`open_advisories`: the root's CODE-003 hits, each ``{package, ecosystem, advisories:[{osv_id,
    cves,...}], imports?}``. `slices`: the slices this review looked at (every one carries the
    top-level modules its path imports and whether it is on a route)."""
    slices = list(slices)
    # imports of route (surface-reaching) slices vs. all served slices.
    route_imports: dict[str, str] = {}      # import name -> a slice entity that reaches it
    served_imports: set[str] = set()
    for sl in slices:
        on_route = sl.served in ("executed", "served") or sl.cls == "noauth" or bool(sl.calls)
        for name in sl.imports:
            n = name.lower()
            served_imports.add(n)
            if on_route and n not in route_imports:
                route_imports[n] = sl.entity()
    out: list[Reachability] = []
    for hit in open_advisories:
        pkg = str(hit.get("package") or "")
        eco = str(hit.get("ecosystem") or "")
        names = _import_names(pkg) | _advisory_modules(hit)
        ids = tuple(a.get("osv_id") or (a.get("cves") or [""])[0] for a in (hit.get("advisories") or [])
                    if isinstance(a, dict))
        reached_via = next((route_imports[n] for n in names if n in route_imports), "")
        if reached_via:
            status, via = REACHED, reached_via
        elif names & served_imports:
            status, via = SERVED, ""
        else:
            status, via = UNSEEN, ""
        out.append(Reachability(pkg, eco, status, tuple(i for i in ids if i), via))
    # reached first, then served, then unseen; stable by package within a bucket.
    order = {REACHED: 0, SERVED: 1, UNSEEN: 2}
    out.sort(key=lambda r: (order[r.status], r.package.lower()))
    return out
