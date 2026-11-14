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

from univers.versions import (AlpineLinuxVersion, ComposerVersion, DebianVersion, GolangVersion, PypiVersion,
                              RpmVersion, RubygemsVersion, SemverVersion)

from kratos.pkgvuln.ecosystems import (FAMILY_APK, FAMILY_CARGO, FAMILY_COMPOSER, FAMILY_DEB, FAMILY_GEM, FAMILY_GO,
                                       FAMILY_NPM, FAMILY_PYPI, FAMILY_RPM)

_CLASSES = {FAMILY_DEB: DebianVersion, FAMILY_RPM: RpmVersion, FAMILY_APK: AlpineLinuxVersion,
            # E.7a: language ecosystems (OSV's version schemes)
            FAMILY_PYPI: PypiVersion, FAMILY_NPM: SemverVersion, FAMILY_CARGO: SemverVersion,
            FAMILY_COMPOSER: ComposerVersion, FAMILY_GO: GolangVersion, FAMILY_GEM: RubygemsVersion}


@lru_cache(maxsize=200_000)
def parse(family: str, text: str) -> Any | None:
    cls = _CLASSES.get(family)
    if cls is None or not text:
        return None
    t = text.strip()
    if family == FAMILY_RPM and t.startswith("(none):"):
        t = "0:" + t[len("(none):"):]
    if family in (FAMILY_GO, FAMILY_COMPOSER, FAMILY_NPM, FAMILY_CARGO) and t[:1] in ("v", "V") and t[1:2].isdigit():
        t = t[1:]                       # go.mod / composer write "v1.2.3"; OSV writes "1.2.3"
    if family == FAMILY_GO and t.endswith("+incompatible"):
        t = t[: -len("+incompatible")]
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
