"""Version comparison per package family, with the ``univers`` library
(VulnerableCode's comparison: Debian, RPM and Alpine rules). No hand-written
comparison: epochs, ``~`` (sorts before everything), ``+deb12u1``, ``el9_4`` and
Alpine ``_rc``/``-r0`` suffixes are univers's to get right.

A version univers can't read is ``None`` -- the caller counts it as "could not
compare" instead of guessing affected or not.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from univers.versions import AlpineLinuxVersion, DebianVersion, RpmVersion

from kratos.pkgvuln.ecosystems import FAMILY_APK, FAMILY_DEB, FAMILY_RPM

_CLASSES = {FAMILY_DEB: DebianVersion, FAMILY_RPM: RpmVersion, FAMILY_APK: AlpineLinuxVersion}


@lru_cache(maxsize=200_000)
def parse(family: str, text: str) -> Any | None:
    cls = _CLASSES.get(family)
    if cls is None or not text:
        return None
    t = text.strip()
    if family == FAMILY_RPM and t.startswith("(none):"):
        t = "0:" + t[len("(none):"):]
    try:
        return cls(t)
    except Exception:  # noqa: BLE001 -- univers raises several types for unreadable input
        return None


def compare(family: str, a: str, b: str) -> int | None:
    """-1 / 0 / 1 like a<b / a==b / a>b, or None when either can't be read."""
    va, vb = parse(family, a), parse(family, b)
    if va is None or vb is None:
        return None
    try:
        return -1 if va < vb else (1 if va > vb else 0)
    except Exception:  # noqa: BLE001
        return None
