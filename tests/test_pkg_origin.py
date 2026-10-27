"""Packages from outside the distribution (PHP2Shell follow-up): a PPA's PHP, a vendor
repository, a downloaded .deb. The distribution's advisories can't speak for them, so
they are named as not checked -- never matched against the distribution's fixed
versions, and never silently passed as clean."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import packages as P
from kratos.pkgvuln import ecosystems as ECO
from kratos.pkgvuln import origin as O
from kratos.pkgvuln import record as REC
from test_pkgvuln import AWKS, DEB12_PACKAGES, _bindir, _deb_inv, deb_index  # noqa: F401  (fixture)

UBU = ECO.for_os({"ID": "ubuntu", "VERSION_ID": "22.04"}).selector
ROCKY = ECO.for_os({"ID": "rocky", "VERSION_ID": "9.4"}).selector

PPA = "ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy"
ARCHIVE = "archive.ubuntu.com_ubuntu_dists_jammy"
ESM = "esm.ubuntu.com_apps_ubuntu_dists_jammy-apps-security"


def _lists(root: Path) -> None:
    L = root / "var/lib/apt/lists"
    L.mkdir(parents=True)
    (L / f"{ARCHIVE}_InRelease").write_text("-----BEGIN PGP SIGNED MESSAGE-----\nOrigin: Ubuntu\nLabel: Ubuntu\n")
    (L / f"{ARCHIVE}_main_binary-amd64_Packages").write_text(
        "Package: curl\nVersion: 7.81.0-1ubuntu1.15\n\nPackage: php8.1\nVersion: 8.1.2-1ubuntu2.19\n\n"
        "Package: netplan.io\nVersion: 0.106-0ubuntu3\n\n")
    (L / f"{PPA}_InRelease").write_text("Origin: LP-PPA-ondrej-php\n")
    (L / f"{PPA}_main_binary-amd64_Packages").write_text("Package: php8.3\nVersion: 8.3.12-1+ubuntu22.04.1+deb.sury.org+1\n")
    (L / f"{ESM}_InRelease").write_text("Origin: UbuntuESMApps\n")
    (L / f"{ESM}_main_binary-amd64_Packages").write_text("Package: redis\nVersion: 5:6.0.16-1ubuntu1+esm1\n")


INSTALLED = [  # name, installed version
    ("curl", "7.81.0-1ubuntu1.15"),                          # Ubuntu, the exact version
    ("php8.3", "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"),     # the PPA
    ("php8.1", "8.1.30-1+ubuntu22.04.1+deb.sury.org+1"),     # a PPA build, its PPA since removed
    ("netplan.io", "0.107-0ubuntu0.22.04.1"),                # Ubuntu's package, a version the lists dropped
    ("redis", "5:6.0.16-1ubuntu1+esm1"),                     # Ubuntu Pro (ESM)
    ("mytool", "1.0"),                                       # installed from a .deb file
]


def _dpkg_fake() -> str:
    lines = "".join(f"D\\t{n}\\t{v}\\tamd64\\t{n}\\t{v}\\tii \\n" for n, v in INSTALLED)
    return f'case "$*" in *--admindir=*) ;; *) exit 9;; esac\nprintf \'{lines}\'\n'


def _read(tmp_path: Path, awk: str, with_lists: bool = True) -> dict:
    root = tmp_path / f"root_{awk}"
    (root / "etc").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
    if with_lists:
        _lists(root)
    b = _bindir(tmp_path, awk, {"dpkg-query": _dpkg_fake()})
    if not (b / "ls").exists():
        os.symlink(shutil.which("ls"), b / "ls")
    out = subprocess.run([str(b / "sh"), "-s"], input=P.build_script(root=str(root)), capture_output=True,
                         text=True, env={"PATH": str(b), "LC_ALL": "C"}, timeout=60)
    assert out.returncode == 0, out.stderr
    return P.parse_output(out.stdout)


@pytest.mark.skipif(not AWKS, reason="no awk available")
@pytest.mark.parametrize("awk", AWKS)
def test_the_real_script_reports_where_each_package_came_from(tmp_path, awk):
    inv = _read(tmp_path, awk)
    assert inv["complete"] and inv["origin_lists"] == {"lists": 3, "known": 3}
    o = inv["origins"]
    assert o["curl"] == {"exact": ["Ubuntu"], "any": ["Ubuntu"]}
    assert o["php8.3"] == {"exact": ["LP-PPA-ondrej-php"], "any": ["LP-PPA-ondrej-php"]}
    assert o["php8.1"] == {"exact": [], "any": ["Ubuntu"]}
    assert o["netplan.io"] == {"exact": [], "any": ["Ubuntu"]}
    assert o["redis"]["exact"] == ["UbuntuESMApps"] and o["mytool"] == {"exact": [], "any": []}


@pytest.mark.skipif(not AWKS, reason="no awk available")
def test_classification_names_what_the_distribution_cannot_speak_for(tmp_path):
    inv = _read(tmp_path, AWKS[0])
    rep = O.classify(inv, UBU)
    got = {o.name: (o.kind, o.origin) for o in rep.outside}
    assert rep.checked and got == {
        "php8.3": ("third_party", "LP-PPA-ondrej-php"),
        "php8.1": ("third_party", "a PPA no longer configured"),
        "mytool": ("unknown", "no configured repository"),
    }                                       # curl, netplan.io (an older/newer Ubuntu build) and ESM redis are Ubuntu's
    lines = O.gap_lines(rep, "Ubuntu")
    assert any("2 package(s) come from outside Ubuntu's own repositories" in ln and "php8.3" in ln for ln in lines)
    assert any("aren't offered by any configured repository" in ln and "mytool" in ln for ln in lines)


@pytest.mark.skipif(not AWKS, reason="no awk available")
def test_empty_package_lists_say_so_instead_of_flagging_everything(tmp_path):
    """Container images ship without apt lists: every package would look unknown."""
    inv = _read(tmp_path, AWKS[0], with_lists=False)
    assert inv["origin_lists"] == {"lists": 0, "known": 0}
    rep = O.classify(inv, UBU)
    assert not rep.checked and rep.outside == [] and "package lists are empty" in rep.reason


def test_an_older_agent_says_update_it():
    inv = P.parse_output("PKGINV\t1\nOS\tID=ubuntu\nD\tcurl\t1.0\tamd64\tcurl\t1.0\tii \nMGR\tdpkg\tok\nEND\n")
    inv["via"] = "agent"
    rep = O.classify(inv, UBU)
    assert not rep.checked and "update it with `g`" in rep.reason


def test_machine_text_in_origins_is_validated():
    inv = P.parse_output("PKGINV\t1\nPO\tcurl\tUbuntu,\x1b[31mevil\tUbuntu\nPO\tbad;name\tX\tX\nPOS\t1\t1\nEND\n")
    assert inv["origins"] == {"curl": {"exact": ["Ubuntu"], "any": ["Ubuntu"]}}


def test_a_ppa_package_is_not_matched_against_the_distributions_fixed_versions(deb_index):
    """curl from a PPA shares its name with Debian's vulnerable curl: matching it against
    Debian's fixed version would invent (or hide) a vulnerability. It is named as not
    checked instead, and the rest is still matched."""
    inv = _deb_inv()
    for name in ("curl", "libcurl4"):      # a PPA ships every binary of its source package
        inv["origins"][name] = {"exact": ["LP-PPA-someone"], "any": ["LP-PPA-someone"]}
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: inv)
    assert not [s for s in doc["signals"] if s["rule"] == "PKG-001" and s["subject"] == "curl"]
    assert [s for s in doc["signals"] if s["rule"] == "PKG-001" and s["subject"] == "openssh"]     # still checked
    note = next(s for s in doc["signals"] if s["rule"] == "PKG-004")
    assert any("from LP-PPA-someone: curl, libcurl4" in ln for ln in note["evidence"])
    assert doc["counts"]["unchecked_packages"] == 2
    assert "2 from outside the distribution NOT checked (curl, libcurl4)" in REC.summary_line(doc)


def test_rpm_vendors_tell_epel_and_local_builds_apart():
    inv = P.parse_output("\n".join([
        "PKGINV\t1", 'OS\tID="rocky"', 'OS\tVERSION_ID="9.4"',
        "R\tbash\t(none):5.1.8-9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm",
        "R\thtop\t(none):3.3.0-1.el9\tx86_64\thtop-3.3.0-1.el9.src.rpm",
        "R\tmytool\t(none):1.0-1\tx86_64\tmytool-1.0-1.src.rpm",
        "MGR\trpm\tok",
        "RV\tbash\tRocky Enterprise Software Foundation", "RV\thtop\tFedora Project", "RV\tmytool\t(none)", "END"]))
    rep = O.classify(inv, ROCKY)
    assert {o.name: (o.kind, o.origin) for o in rep.outside} == {
        "htop": ("third_party", "Fedora Project"), "mytool": ("unknown", "no vendor (built locally?)")}
