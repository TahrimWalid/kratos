"""Which distribution advisory data describes a machine.

OSV publishes each distribution's advisories under a top-level ecosystem (a
folder: ``Debian``, ``Ubuntu``, ``Alpine``, ``Rocky Linux``, ``AlmaLinux``,
``Red Hat``), and each advisory names the release it is about
(``Debian:12``, ``Ubuntu:22.04:LTS``, ``Alpine:v3.22``, ``Rocky Linux:9``,
``Red Hat:enterprise_linux:9::baseos``). A **selector** is Kratos's own short
name for one release (``debian:12``, ``ubuntu:22.04``, ``alpine:3.22``,
``rocky:9``, ``almalinux:9``, ``rhel:9``): it says which folder to download and
which release names inside it to keep. The index only holds the releases of the
machines Kratos knows, so its size follows what is actually in use.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

FAMILY_DEB = "deb"
FAMILY_RPM = "rpm"
FAMILY_APK = "apk"

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

_SELECTOR_RE = re.compile(r"^(debian|ubuntu|alpine|rocky|almalinux|rhel):([0-9]{1,3}(?:\.[0-9]{1,3})?)$")


@dataclass(frozen=True)
class Selector:
    key: str            # "ubuntu:22.04"
    distro: str         # "ubuntu"
    release: str        # "22.04"
    top: str            # the OSV folder: "Ubuntu"
    family: str         # deb | rpm | apk (which version comparison, which package name)

    def matches(self, ecosystem: str) -> bool:
        """Is `ecosystem` (an advisory's package.ecosystem) this release's main data?"""
        e = ecosystem
        if self.distro == "debian":
            return e == f"Debian:{self.release}"
        if self.distro == "ubuntu":
            # Plain releases only: Ubuntu Pro / FIPS / Realtime streams are separate
            # package sets a machine has to opt into.
            return e in (f"Ubuntu:{self.release}:LTS", f"Ubuntu:{self.release}")
        if self.distro == "alpine":
            return e == f"Alpine:v{self.release}"
        if self.distro == "rocky":
            return e == f"Rocky Linux:{self.release}"
        if self.distro == "almalinux":
            return e == f"AlmaLinux:{self.release}"
        if self.distro == "rhel":
            return (e.startswith(f"Red Hat:enterprise_linux:{self.release}::")
                    or e == f"Red Hat:enterprise_linux:{self.release}"
                    or e.startswith(f"Red Hat:enterprise_linux:{self.release}."))
        return False

    @property
    def raw_marker(self) -> bytes:
        """Bytes every advisory relevant to this release contains -- a cheap filter
        before parsing a whole export (most of Ubuntu's 7 GB is other releases)."""
        return {
            "debian": f'"Debian:{self.release}"',
            "ubuntu": f'"Ubuntu:{self.release}',
            "alpine": f'"Alpine:v{self.release}"',
            "rocky": f'"Rocky Linux:{self.release}"',
            "almalinux": f'"AlmaLinux:{self.release}"',
            "rhel": f'"Red Hat:enterprise_linux:{self.release}',
        }[self.distro].encode()


_DISTROS: dict[str, tuple[str, str]] = {
    "debian": ("Debian", FAMILY_DEB),
    "ubuntu": ("Ubuntu", FAMILY_DEB),
    "alpine": ("Alpine", FAMILY_APK),
    "rocky": ("Rocky Linux", FAMILY_RPM),
    "almalinux": ("AlmaLinux", FAMILY_RPM),
    "rhel": ("Red Hat", FAMILY_RPM),
}


def parse_selector(text: str) -> Selector:
    """'ubuntu:22.04' -> Selector. Raises ValueError with a plain message."""
    key = str(text or "").strip().lower()
    m = _SELECTOR_RE.fullmatch(key)
    if not m:
        raise ValueError(f"{text!r} is not a release Kratos knows how to check "
                         "(examples: debian:12, ubuntu:22.04, alpine:3.22, rocky:9, almalinux:9, rhel:9)")
    distro, release = m.groups()
    if distro in ("debian", "rocky", "almalinux", "rhel"):
        release = release.split(".")[0]
    top, family = _DISTROS[distro]
    return Selector(f"{distro}:{release}", distro, release, top, family)


@dataclass(frozen=True)
class Choice:
    """What a machine's /etc/os-release means for matching: its selector, or why
    there is none (a coverage gap -- never "no vulnerabilities")."""
    selector: Selector | None
    gap: str = ""


def for_os(os_info: dict[str, Any]) -> Choice:
    os_id = str(os_info.get("ID") or "").strip().lower()
    version = str(os_info.get("VERSION_ID") or "").strip()
    pretty = str(os_info.get("PRETTY_NAME") or os_id or "this distribution")
    if os_id == "centos":
        return Choice(None, f"{pretty}: no distribution advisory data in OSV for CentOS")
    if os_id not in _DISTROS:
        like = str(os_info.get("ID_LIKE") or "").split()
        hint = f" (it is like {', '.join(like)}, but its packages are its own)" if like else ""
        return Choice(None, f"{pretty}: Kratos has no vulnerability data for this distribution{hint}")
    if not version:
        return Choice(None, f"{pretty}: no release number (a testing or rolling release) -- no advisory data to match")
    if os_id == "alpine":
        parts = version.split(".")
        version = ".".join(parts[:2])
    try:
        return Choice(parse_selector(f"{os_id}:{version}"))
    except ValueError:
        return Choice(None, f"{pretty}: release {version!r} is not one Kratos can map to advisory data")


def lookup_name(family: str, pkg: dict[str, Any]) -> tuple[str, str]:
    """(name, version) an advisory lists this installed package under. Debian and
    Ubuntu advisories name the SOURCE package (and its version); Alpine names the
    origin (the version is the package's own); RPM advisories name the binary."""
    if family == FAMILY_DEB:
        return str(pkg.get("source") or pkg.get("name")), str(pkg.get("source_version") or pkg.get("version"))
    if family == FAMILY_APK:
        return str(pkg.get("source") or pkg.get("name")), str(pkg.get("version"))
    return str(pkg.get("name")), str(pkg.get("version"))
