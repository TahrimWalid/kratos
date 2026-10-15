"""Package vulnerabilities (A.2): the inventory read, version comparison, the index
builder (`kratos vulndb-update`), matching, priority, the PKG rules and their
identity, the network cross-check, and the privacy rule (no package data leaves).

Everything runs on tmp_path with a fake HTTP session -- no network. The advisory
fixtures are trimmed copies of real OSV records (field shapes as published).
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
import requests

from kratos.adapters import packages as P
from kratos.pkgvuln import ecosystems as E
from kratos.pkgvuln import index as IX
from kratos.pkgvuln import inventory_store as INV
from kratos.pkgvuln import match as M
from kratos.pkgvuln import priority as PR
from kratos.pkgvuln import record as REC
from kratos.pkgvuln import update as U
from kratos.pkgvuln import versions as V
from tests._logsources_util import awks

# ============================================================== inventory read
DEB_OUT = "\n".join([
    "PKGINV\t1",
    "OS\tID=ubuntu", 'OS\tVERSION_ID="22.04"', "OS\tVERSION_CODENAME=jammy", 'OS\tPRETTY_NAME="Ubuntu 22.04 LTS"',
    "KREL\t5.15.0-91-generic", "RR\t1", "RRP\tlinux-image-5.15.0-94-generic",
    "KMOD\t5.15.0-91-generic", "KMOD\t5.15.0-94-generic",
    "D\tcurl\t7.81.0-1ubuntu1.10\tamd64\tcurl\t7.81.0-1ubuntu1.10\tii ",
    "D\tlibcurl4\t7.81.0-1ubuntu1.10\tamd64\tcurl\t7.81.0-1ubuntu1.10\tii ",
    "D\tlibssl3\t3.0.2-0ubuntu1.10\tamd64\topenssl\t\tii ",
    "D\topenssh-server\t1:8.9p1-3ubuntu0.1\tamd64\topenssh (1:8.9p1-3ubuntu0.1)\t1:8.9p1-3ubuntu0.1\thi ",
    "D\told-thing\t1.0-1\tamd64\told-thing\t1.0-1\trc ",
    "D\tlinux-image-5.15.0-91-generic\t5.15.0-91.101\tamd64\tlinux-signed\t5.15.0-91.101\tii ",
    "D\tlinux-image-5.15.0-94-generic\t5.15.0-94.104\tamd64\tlinux-signed\t5.15.0-94.104\tii ",
    "D\tlinux-modules-5.15.0-91-generic\t5.15.0-91.101\tamd64\tlinux\t5.15.0-91.101\tii ",
    "D\tbad;name\t1.0\tamd64\tbad\t1.0\tii ",
    "MGR\tdpkg\tok", "END", ""])

RPM_OUT = "\n".join([
    "PKGINV\t1", 'OS\tID="rocky"', 'OS\tVERSION_ID="9.0"', "KREL\t5.14.0-70.13.1.el9_0.x86_64", "RR\t0",
    "R\tcurl\t(none):7.76.1-14.el9\tx86_64\tcurl-7.76.1-14.el9.src.rpm",
    "R\tlibcurl\t(none):7.76.1-14.el9\tx86_64\tcurl-7.76.1-14.el9.src.rpm",
    "R\tqemu-img\t17:6.2.0-11.el9_0.2\tx86_64\tqemu-kvm-6.2.0-11.el9_0.2.src.rpm",
    "R\tkernel-core\t(none):5.14.0-70.13.1.el9_0\tx86_64\tkernel-5.14.0-70.13.1.el9_0.src.rpm",
    "R\tgpg-pubkey\t(none):350d275d-6279f1ef\t(none)\t(none)",
    "MGR\trpm\tok", "END", ""])

APK_OUT = "\n".join([
    "PKGINV\t1", "OS\tID=alpine", "OS\tVERSION_ID=3.22.0", "KREL\t6.8.0-1-lts", "RR\t0",
    "A\tlibcurl\t8.14.0-r0\tx86_64\tcurl", "A\tcurl\t8.14.0-r0\tx86_64\tcurl",
    "A\tbusybox\t1.37.0-r18\tx86_64\tbusybox",
    "MGR\tapk\tok", "END", ""])


def test_debian_inventory_maps_source_packages_and_skips_what_is_not_installed():
    inv = P.parse_output(DEB_OUT)
    names = {p["name"]: p for p in inv["packages"]}
    assert inv["complete"] and inv["os"]["VERSION_ID"] == "22.04" and inv["running_kernel"] == "5.15.0-91-generic"
    assert inv["reboot_required"] and inv["reboot_required_pkgs"] == ["linux-image-5.15.0-94-generic"]
    assert names["libcurl4"]["source"] == "curl"
    assert names["libssl3"]["source"] == "openssl" and names["libssl3"]["source_version"] == "3.0.2-0ubuntu1.10"
    assert names["openssh-server"]["source"] == "openssh"      # old dpkg "name (version)" form
    assert "openssh-server" in names                            # "hi" = held, still installed
    assert "old-thing" not in names                             # "rc" = config files only
    assert "bad;name" not in names and inv["dropped"] == 1


def test_rpm_inventory_normalises_epochs_and_finds_the_source_rpm():
    inv = P.parse_output(RPM_OUT)
    names = {p["name"]: p for p in inv["packages"]}
    assert names["curl"]["version"] == "0:7.76.1-14.el9" and names["libcurl"]["source"] == "curl"
    assert names["qemu-img"]["version"] == "17:6.2.0-11.el9_0.2" and names["qemu-img"]["source"] == "qemu-kvm"
    assert "gpg-pubkey" not in names and inv["dropped"] == 0


def test_apk_inventory_uses_the_origin():
    inv = P.parse_output(APK_OUT)
    names = {p["name"]: p for p in inv["packages"]}
    assert names["libcurl"]["source"] == "curl" and names["libcurl"]["version"] == "8.14.0-r0"


def test_a_cut_short_read_is_incomplete():
    assert not P.parse_output(DEB_OUT.replace("END\n", ""))["complete"]
    assert not P.parse_output(DEB_OUT.replace("MGR\tdpkg\tok", "MGR\tdpkg\tfailed"))["complete"]


AWKS = awks()


def _bindir(tmp_path: Path, awk: str, fakes: dict[str, str]) -> Path:
    b = tmp_path / f"bin_{awk}"
    b.mkdir()
    for tool in ("sh", "grep", "head", "sort", "uname", "cat", "printf"):
        src = shutil.which(tool)
        if src:
            os.symlink(src, b / tool)
    bb = os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
    os.symlink(bb if awk == "busybox" else shutil.which(awk), b / "awk")
    for name, body in fakes.items():
        (b / name).write_text("#!/bin/sh\n" + body)
        (b / name).chmod(0o755)
    return b


@pytest.mark.skipif(not AWKS, reason="no awk available")
@pytest.mark.parametrize("awk", AWKS)
def test_the_real_script_reads_each_family(tmp_path, awk):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/rpm").mkdir(parents=True)
    (root / "lib/apk/db").mkdir(parents=True)
    (root / "lib/modules/5.15.0-91-generic").mkdir(parents=True)
    (root / "var/run").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"\nHOME_URL=x\n')
    (root / "var/run/reboot-required").write_text("")
    (root / "var/run/reboot-required.pkgs").write_text("linux-image-6.1.0-13-amd64\n")
    (root / "lib/apk/db/installed").write_text("C:x\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:zlib\nV:1.3-r0\nA:x86_64\n")
    fakes = {
        "dpkg-query": 'case "$*" in *--admindir=*) ;; *) exit 9;; esac\nprintf \'D\\tcurl\\t7.88.1-10+deb12u4\\tamd64\\tcurl\\t7.88.1-10+deb12u4\\tii \\n\'\n',
        "rpm": 'printf \'R\\tbash\\t(none):5.1.8-6.el9\\tx86_64\\tbash-5.1.8-6.el9.src.rpm\\n\'\n',
    }
    b = _bindir(tmp_path, awk, fakes)
    out = subprocess.run([str(b / "sh"), "-s"], input=P.build_script(root=str(root)), capture_output=True, text=True,
                         env={"PATH": str(b), "LC_ALL": "C"}, timeout=60)
    assert out.returncode == 0, out.stderr
    inv = P.parse_output(out.stdout)
    assert inv["complete"] and inv["os"]["ID"] == "debian" and "HOME_URL" not in inv["os"]
    assert inv["kernel_trees"] == ["5.15.0-91-generic"] and inv["reboot_required"]
    assert {(p["manager"], p["name"], p["source"]) for p in inv["packages"]} == {
        ("dpkg", "curl", "curl"), ("rpm", "bash", "bash"), ("apk", "musl", "musl"), ("apk", "zlib", "zlib")}


def test_the_script_writes_nothing_on_the_machine():
    s = P.build_script()
    for forbidden in (">>", "tee ", "mktemp", "touch ", " dd ", "> /", "of=", "sudo"):
        assert forbidden not in s, forbidden


def test_the_agent_probe_runs_the_same_script(monkeypatch):
    from kratos.subagent import reads
    seen = {}
    monkeypatch.setattr(reads, "run_capped", lambda argv, **kw: seen.update(kw) or {"stdout": "", "returncode": 0})
    reads._p_package_inventory({})
    assert seen["stdin_text"] == P.build_script()
    assert reads.validate_params("package_inventory", {}) == {}
    with pytest.raises(reads.ReadParamError):
        reads.validate_params("package_inventory", {"path": "/etc/shadow"})


def test_an_old_agent_gets_an_update_hint_not_a_crash():
    from kratos.subagent import core_server
    assert core_server.PROBE_MIN_AGENT_VERSION["package_inventory"] == (0, 7, 0)


# ============================================================== distributions and versions
@pytest.mark.parametrize("os_info,key", [
    ({"ID": "ubuntu", "VERSION_ID": "22.04"}, "ubuntu:22.04"),
    ({"ID": "debian", "VERSION_ID": "12"}, "debian:12"),
    ({"ID": "alpine", "VERSION_ID": "3.22.5"}, "alpine:3.22"),
    ({"ID": "rocky", "VERSION_ID": "9.4"}, "rocky:9"),
    ({"ID": "almalinux", "VERSION_ID": "8.10"}, "almalinux:8"),
    ({"ID": "rhel", "VERSION_ID": "9.4"}, "rhel:9"),
])
def test_os_release_maps_to_a_release_selector(os_info, key):
    assert E.for_os(os_info).selector.key == key


@pytest.mark.parametrize("os_info", [{"ID": "linuxmint", "ID_LIKE": "ubuntu", "VERSION_ID": "21"},
                                     {"ID": "debian"}, {"ID": "centos", "VERSION_ID": "7"}, {}])
def test_an_unsupported_distribution_is_a_gap_not_clean(os_info):
    c = E.for_os(os_info)
    assert c.selector is None and c.gap


def test_ubuntu_selector_keeps_the_plain_release_only():
    s = E.parse_selector("ubuntu:22.04")
    assert s.matches("Ubuntu:22.04:LTS") and not s.matches("Ubuntu:Pro:22.04:LTS") and not s.matches("Ubuntu:20.04:LTS")
    r = E.parse_selector("rhel:9")
    assert r.matches("Red Hat:enterprise_linux:9::baseos") and not r.matches("Red Hat:enterprise_linux:8::baseos")


@pytest.mark.parametrize("family,a,b,want", [
    # Debian/Ubuntu: epochs, tildes, backport suffixes, ubuntu revisions (cross-checked with dpkg --compare-versions)
    ("deb", "1.0~rc1-1", "1.0-1", -1),
    ("deb", "1:1.0-1", "2.0-1", 1),
    ("deb", "7.88.1-10+deb12u5", "7.88.1-10+deb12u12", -1),
    ("deb", "2.9.4+dfsg1-6.1ubuntu1.9", "2.9.4+dfsg1-6.1ubuntu1.10", -1),
    ("deb", "1.2.3-0ubuntu0.22.04.1", "1.2.3-0ubuntu1", -1),
    ("deb", "1.0-1", "1.0-1+b1", -1),
    ("deb", "1.0~~a", "1.0~", -1),
    # RPM: epochs (missing = 0), el9_4 dist tags
    ("rpm", "0:7.76.1-14.el9_0.5", "7.76.1-14.el9_0.5", 0),
    ("rpm", "(none):1.2-3.el9_4", "0:1.2-3.el9_5", -1),
    ("rpm", "17:6.2.0-11.el9_0.3", "6.2.0-20.el9", 1),
    ("rpm", "1.2-3.el9_4", "1.2-3.el9_4.1", -1),
    # Alpine: -rN, _rc, _p
    ("apk", "1.36.1-r29", "1.36.1-r30", -1),
    ("apk", "8.4.0_rc1-r0", "8.4.0-r0", -1),
    ("apk", "1.2.3-r0", "1.2.3_p1-r0", -1),
])
def test_univers_comparisons_on_tricky_versions(family, a, b, want):
    assert V.compare(family, a, b) == want


def test_an_unreadable_version_is_none_not_a_guess():
    assert V.compare("deb", "not a version", "1.0") is None


# ============================================================== advisory fixtures (trimmed real OSV records)
def _deb_cve(cve, eco, pkg, fixed=None, urgency="not yet assigned", versions=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    a = {"package": {"name": pkg, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}],
         "ecosystem_specific": {"urgency": urgency}}
    if versions:
        a["versions"] = versions
    return {"schema_version": "1.9.0", "id": f"DEBIAN-{cve}", "modified": "2026-09-15T09:02:27Z",
            "upstream": [cve], "affected": [a]}


DEBIAN_RECORDS = [
    # curl in bookworm: the per-CVE record says fixed in +deb12u4 ...
    _deb_cve("CVE-2023-38545", "Debian:12", "curl", "7.88.1-10+deb12u4"),
    # ... while the bundle notice for two OTHER CVEs fixes at +deb12u5
    {"id": "DSA-5587-1", "modified": "2026-03-09T02:10:45Z", "upstream": ["CVE-2023-46218", "DEBIAN-CVE-2023-46218"],
     "summary": "curl - security update",
     "affected": [{"package": {"name": "curl", "ecosystem": "Debian:12"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.88.1-10+deb12u5"}]}]},
                  {"package": {"name": "curl", "ecosystem": "Debian:11"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.74.0-1.3+deb11u11"}]}]}]},
    _deb_cve("CVE-2023-46218", "Debian:12", "curl", "7.88.1-10+deb12u5", urgency="medium"),
    # unfixed, rated unimportant by Debian
    _deb_cve("CVE-2016-2781", "Debian:12", "coreutils", None, urgency="unimportant"),
    # unfixed, rated medium
    _deb_cve("CVE-2025-0001", "Debian:12", "coreutils", None, urgency="medium"),
    # fixed only in a later upstream version (introduced later than installed): not affected
    {"id": "DEBIAN-CVE-2024-1111", "modified": "2026-01-01T00:00:00Z", "upstream": ["CVE-2024-1111"],
     "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.1.0-1"}, {"fixed": "3.1.4-1"}]}]}]},
    # last_affected
    {"id": "DEBIAN-CVE-2024-2222", "modified": "2026-01-01T00:00:00Z", "upstream": ["CVE-2024-2222"],
     "affected": [{"package": {"name": "zlib", "ecosystem": "Debian:12"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1:1.2.13.dfsg-1"}]}]}]},
    # explicit versions only (no range)
    {"id": "DEBIAN-CVE-2024-3333", "modified": "2026-01-01T00:00:00Z", "upstream": ["CVE-2024-3333"],
     "affected": [{"package": {"name": "bash", "ecosystem": "Debian:12"}, "versions": ["5.2.15-2"]}]},
    # withdrawn: ignored
    {"id": "DEBIAN-CVE-2024-4444", "modified": "2026-01-01T00:00:00Z", "withdrawn": "2026-01-02T00:00:00Z",
     "upstream": ["CVE-2024-4444"],
     "affected": [{"package": {"name": "bash", "ecosystem": "Debian:12"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]},
    # a release Kratos does not hold: not stored
    _deb_cve("CVE-2024-5555", "Debian:13", "bash", None),
    # KEV-listed, fixable
    _deb_cve("CVE-2024-6387", "Debian:12", "openssh", "1:9.2p1-2+deb12u3", urgency="high"),
]

DEB12_PACKAGES = [
    {"manager": "dpkg", "name": "curl", "version": "7.88.1-10+deb12u4", "arch": "amd64", "source": "curl",
     "source_version": "7.88.1-10+deb12u4"},
    {"manager": "dpkg", "name": "libcurl4", "version": "7.88.1-10+deb12u4", "arch": "amd64", "source": "curl",
     "source_version": "7.88.1-10+deb12u4"},
    {"manager": "dpkg", "name": "coreutils", "version": "9.1-1", "arch": "amd64", "source": "coreutils",
     "source_version": "9.1-1"},
    {"manager": "dpkg", "name": "libssl3", "version": "3.0.11-1~deb12u2", "arch": "amd64", "source": "openssl",
     "source_version": "3.0.11-1~deb12u2"},
    {"manager": "dpkg", "name": "zlib1g", "version": "1:1.2.13.dfsg-1", "arch": "amd64", "source": "zlib",
     "source_version": "1:1.2.13.dfsg-1"},
    {"manager": "dpkg", "name": "bash", "version": "5.2.15-2+b2", "arch": "amd64", "source": "bash",
     "source_version": "5.2.15-2"},
    {"manager": "dpkg", "name": "openssh-server", "version": "1:9.2p1-2+deb12u2", "arch": "amd64",
     "source": "openssh", "source_version": "1:9.2p1-2+deb12u2"},
]

KEV = {"catalogVersion": "2026.10.14", "vulnerabilities": [
    {"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH", "vulnerabilityName": "regreSSHion",
     "dateAdded": "2024-07-10", "dueDate": "2024-07-31", "knownRansomwareCampaignUse": "Unknown"}]
    + [{"cveID": f"CVE-2000-{i:04d}", "dateAdded": "2022-01-01", "dueDate": "2022-02-01"} for i in range(1000, 1200)]}


def _epss_gz(rows: dict[str, float]) -> bytes:
    lines = ["#model_version:v2025.03.14,score_date:2026-10-14T12:55:00Z", "cve,epss,percentile"]
    lines += [f"{c},{s},0.5" for c, s in rows.items()]
    lines += [f"CVE-1999-{i:04d},0.001,0.1" for i in range(1000, 2200)]
    return gzip.compress(("\n".join(lines) + "\n").encode())


def _nvd(items: dict[str, tuple[float, str]]) -> tuple[bytes, bytes]:
    vulns = [{"cve": {"id": c, "metrics": {"cvssMetricV31": [
        {"type": "Primary", "cvssData": {"baseScore": s, "vectorString": v, "baseSeverity": "HIGH"}}]}}}
        for c, (s, v) in items.items()]
    raw = json.dumps({"format": "NVD_CVE", "vulnerabilities": vulns}).encode()
    meta = f"lastModifiedDate:2026-10-14T03:00:22-04:00\nsize:{len(raw)}\nsha256:{hashlib.sha256(raw).hexdigest().upper()}\n"
    return gzip.compress(raw), meta.encode()


def _zip(records: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in records:
            zf.writestr(f"{r['id']}.json", json.dumps(r))
    return buf.getvalue()


class _Resp:
    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status
        self._body = body
        self.headers = {"content-length": str(len(body)), **(headers or {})}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]


class FakeSession:
    """Serves canned files by URL; anything else is a connection error. Records
    every request (URL + headers) for the privacy test."""

    def __init__(self, files: dict[str, bytes], *, md5: bool = True, etags: dict[str, str] | None = None,
                 fail: set[str] = frozenset()):
        self.files, self.md5, self.etags, self.fail = files, md5, etags or {}, fail
        self.requests: list[tuple[str, dict]] = []

    def get(self, url, stream=False, timeout=None, headers=None):
        self.requests.append((url, dict(headers or {})))
        if url in self.fail or url not in self.files:
            raise requests.ConnectionError(f"no route to {url}")
        etag = self.etags.get(url, "")
        if etag and (headers or {}).get("If-None-Match") == etag:
            return _Resp(304)
        body = self.files[url]
        h = {"etag": etag} if etag else {}
        if self.md5:
            h["x-goog-hash"] = "crc32c=AAAAAA==, md5=" + base64.b64encode(hashlib.md5(body).digest()).decode()
        return _Resp(200, body, h)


OSV = E.OSV_BASE


def _feeds(debian_records=DEBIAN_RECORDS, epss=None, nvd=None):
    epss = epss or {"CVE-2024-6387": 0.94, "CVE-2023-46218": 0.02, "CVE-2023-38545": 0.30}
    nvd = nvd or {"CVE-2024-6387": (8.1, "CVSS:3.1/AV:N/AC:H"), "CVE-2023-46218": (6.5, "CVSS:3.1/AV:N"),
                  "CVE-2023-38545": (9.8, "CVSS:3.1/AV:N/AC:L")}
    gz, meta = _nvd(nvd)
    files = {f"{OSV}/Debian/all.zip": _zip(debian_records),
             f"{OSV}/Debian/modified_id.csv": "\n".join(f"{r['modified']},{r['id']}" for r in debian_records).encode(),
             U.KEV_URL: json.dumps(KEV).encode(), U.EPSS_URL: _epss_gz(epss)}
    year = time.gmtime().tm_year
    for y in range(U.NVD_FIRST_YEAR, year + 1):
        g, m = (gz, meta) if y == year else _nvd({})
        files[U.NVD_FEED_URL.format(name=y)] = g
        files[U.NVD_META_URL.format(name=y)] = m
    files[U.NVD_FEED_URL.format(name="modified")], files[U.NVD_META_URL.format(name="modified")] = gz, meta
    return files


def build(tmp_path, files=None, **kw) -> U.UpdateResult:
    return U.run_update(tmp_path, selectors=["debian:12"], session=FakeSession(files or _feeds()), **kw)


# ============================================================== update
def test_update_builds_an_index_with_all_sources(tmp_path):
    res = build(tmp_path)
    assert res.ok, res.message
    st = IX.status(tmp_path)
    assert st.present and st.selectors == ["debian:12"]
    conn = IX.open_readonly(tmp_path)
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 201
    assert conn.execute("SELECT score FROM cvss WHERE cve='CVE-2024-6387'").fetchone()[0] == 8.1
    assert conn.execute("SELECT score FROM epss WHERE cve='CVE-2024-6387'").fetchone()[0] == 0.94
    ids = {r[0] for r in conn.execute("SELECT osv_id FROM advisories")}
    assert "DEBIAN-CVE-2024-4444" not in ids          # withdrawn
    assert "DEBIAN-CVE-2024-5555" not in ids          # another release
    with pytest.raises(sqlite3.OperationalError):     # opened read-only
        conn.execute("DELETE FROM kev")
    assert oct(os.stat(IX.path_for(tmp_path)).st_mode & 0o777) == "0o600"


def _index_bytes(tmp_path):
    return IX.path_for(tmp_path).read_bytes()


def test_no_network_is_a_clean_failure_and_keeps_the_previous_index(tmp_path):
    assert build(tmp_path).ok
    before = _index_bytes(tmp_path)
    res = U.run_update(tmp_path, selectors=["debian:12"], full=True, session=FakeSession({}))
    assert not res.ok and "previous vulnerability data is kept" in res.message and "no network" in res.message
    assert _index_bytes(tmp_path) == before
    assert not list((tmp_path / "vulndb").glob("*.tmp")) and not (tmp_path / "vulndb/download.tmp").exists()


def test_a_corrupt_zip_is_refused_and_the_old_index_kept(tmp_path):
    assert build(tmp_path).ok
    before = _index_bytes(tmp_path)
    files = _feeds()
    files[f"{OSV}/Debian/all.zip"] = b"PK\x03\x04 this is not a zip at all" * 10
    res = U.run_update(tmp_path, selectors=["debian:12"], full=True, session=FakeSession(files))
    assert not res.ok and "not a valid zip" in res.message
    assert _index_bytes(tmp_path) == before


def test_a_download_not_matching_its_checksum_is_refused(tmp_path):
    files = _feeds()

    class Tamper(FakeSession):
        def get(self, url, **kw):
            r = super().get(url, **kw)
            if url.endswith("all.zip"):
                mid = len(r._body) // 2
                r._body = r._body[:mid] + bytes([r._body[mid] ^ 0xFF]) + r._body[mid + 1:]
            return r
    res = U.run_update(tmp_path, selectors=["debian:12"], session=Tamper(files))
    assert not res.ok and "checksum" in res.message and not IX.path_for(tmp_path).exists()


def test_an_interrupted_update_keeps_the_previous_index(tmp_path, monkeypatch):
    assert build(tmp_path).ok
    before = _index_bytes(tmp_path)

    def boom(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(U, "_update_kev", boom)          # dies mid-build, after OSV was rewritten
    with pytest.raises(KeyboardInterrupt):
        U.run_update(tmp_path, selectors=["debian:12"], full=True, session=FakeSession(_feeds()))
    assert _index_bytes(tmp_path) == before
    assert not (tmp_path / "vulndb" / "vulndb.sqlite.tmp").exists()


def test_a_killed_update_process_keeps_the_previous_index(tmp_path):
    """Kill -9 in the middle of a build: nothing replaced the index, and the next
    update cleans up the leftover temp file."""
    assert build(tmp_path).ok
    before = _index_bytes(tmp_path)
    script = (
        "import sys, os, signal; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
        "from tests import test_pkgvuln as T\nfrom kratos.pkgvuln import update as U\n"
        "orig = U._update_epss\n"
        "def die(*a, **k):\n    os.kill(os.getpid(), signal.SIGKILL)\n"
        "U._update_epss = die\n"
        "U.run_update(%r, selectors=['debian:12'], full=True, session=T.FakeSession(T._feeds()))\n"
    ) % (str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parents[1]), str(tmp_path))
    p = subprocess.run([os.sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
    assert p.returncode == -9, p.stderr
    assert _index_bytes(tmp_path) == before
    assert build(tmp_path).ok and not (tmp_path / "vulndb" / "vulndb.sqlite.tmp").exists()


def test_the_swap_is_atomic(tmp_path, monkeypatch):
    assert build(tmp_path).ok
    calls = []
    real = os.replace

    def spy(src, dst):
        calls.append((Path(src).name, Path(dst).name))
        return real(src, dst)
    monkeypatch.setattr(U.os, "replace", spy)
    assert build(tmp_path, full=True).ok
    assert calls == [("vulndb.sqlite.tmp", "vulndb.sqlite")]


def test_an_unreachable_enrichment_source_keeps_its_old_rows(tmp_path):
    assert build(tmp_path).ok
    files = _feeds()
    res = U.run_update(tmp_path, selectors=["debian:12"], full=False,
                       session=FakeSession(files, fail={U.KEV_URL}))
    assert res.ok and res.stale_sources == ["KEV"] and "KEV" in res.message
    conn = IX.open_readonly(tmp_path)
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 201


def test_incremental_update_fetches_only_changed_records(tmp_path):
    etags = {f"{OSV}/Debian/modified_id.csv": "v1", U.KEV_URL: "k1", U.EPSS_URL: "e1"}
    files = _feeds()
    assert U.run_update(tmp_path, selectors=["debian:12"], session=FakeSession(files, etags=etags)).ok
    # nothing changed: the modification index answers 304, no record is fetched
    s = FakeSession(files, etags=etags)
    res = U.run_update(tmp_path, selectors=["debian:12"], session=s)
    assert res.ok and res.sources["OSV Debian"] == "unchanged"
    assert not any(u.endswith("all.zip") or u.endswith("-1.json") for u, _ in s.requests)
    # one advisory changed: only it is fetched, and its new fix version is used
    changed = _deb_cve("CVE-2023-38545", "Debian:12", "curl", "7.88.1-10+deb12u9")
    changed["modified"] = "2026-10-15T00:00:00Z"
    recs = [changed if r["id"] == changed["id"] else r for r in DEBIAN_RECORDS]
    files2 = _feeds(recs)
    files2[f"{OSV}/Debian/{changed['id']}.json"] = json.dumps(changed).encode()
    s = FakeSession(files2, etags={**etags, f"{OSV}/Debian/modified_id.csv": "v2"})
    res = U.run_update(tmp_path, selectors=["debian:12"], session=s)
    assert res.ok and "1 changed" in res.sources["OSV Debian"], res.sources
    fetched = [u for u, _ in s.requests if u.startswith(f"{OSV}/Debian/") and u.endswith(".json")]
    assert fetched == [f"{OSV}/Debian/DEBIAN-CVE-2023-38545.json"]
    conn = IX.open_readonly(tmp_path)
    assert conn.execute("SELECT fixed FROM ranges r JOIN advisories a ON a.id=r.advisory "
                        "WHERE a.osv_id='DEBIAN-CVE-2023-38545'").fetchone()[0] == "7.88.1-10+deb12u9"


def test_no_known_machine_and_no_selector_says_what_to_do(tmp_path):
    res = U.run_update(tmp_path, session=FakeSession({}))
    assert not res.ok and "--ecosystems" in res.message


def test_update_selectors_come_from_inventories(tmp_path):
    INV.save(tmp_path, "10.0.0.5", P.parse_output(DEB_OUT), family="deb", selector="ubuntu:22.04")
    assert [s.key for s in U.resolve_selectors(tmp_path, None)] == ["ubuntu:22.04"]


# ============================================================== matching
@pytest.fixture()
def deb_index(tmp_path):
    assert build(tmp_path).ok
    return tmp_path


def _match(data_dir, packages=DEB12_PACKAGES, key="debian:12"):
    conn = IX.open_readonly(data_dir)
    try:
        return M.match(conn, E.parse_selector(key), packages)
    finally:
        conn.close()


def test_matching_in_range_fixed_last_affected_and_explicit_versions(deb_index):
    m = _match(deb_index)
    curl, core, ssl, zlib, bash, ssh = (m.packages[n] for n in ("curl", "coreutils", "openssl", "zlib", "bash", "openssh"))
    # curl 7.88.1-10+deb12u4: CVE-2023-38545 fixed at u4 (per-CVE record) -> fixed; CVE-2023-46218 fixed at u5 -> affected
    assert "CVE-2023-38545" in curl.fixed and "CVE-2023-38545" not in curl.fixable
    assert curl.fixable["CVE-2023-46218"].fixed_in == "7.88.1-10+deb12u5"
    assert set(core.unfixed) == {"CVE-2016-2781", "CVE-2025-0001"} and not core.fixable
    assert not ssl.fixable and not ssl.unfixed                      # introduced after the installed version
    assert "CVE-2024-2222" in zlib.unfixed                          # last_affected == installed: affected, no fix
    assert "CVE-2024-3333" in bash.unfixed                          # explicit version list (source version 5.2.15-2)
    assert "CVE-2024-4444" not in bash.unfixed                      # withdrawn
    assert "CVE-2024-6387" in ssh.fixable
    assert sorted(n for n, _ in curl.installed) == ["curl", "libcurl4"]


def test_a_per_cve_record_wins_over_a_bundle_notice(deb_index):
    """DSA-5587-1 fixes all its CVEs at u5; the per-CVE record for CVE-2023-38545
    says u4. An installed u4 is NOT affected by CVE-2023-38545."""
    m = _match(deb_index)
    assert "CVE-2023-38545" in m.packages["curl"].fixed


def test_backported_fix_is_not_reported(deb_index):
    """A real Debian backport: upstream fixed CVE-2023-38545 in curl 8.4.0; Debian
    backported it to 7.88.1-10+deb12u4 without changing the upstream version. A
    version-text match (7.88.1 < 8.4.0) says vulnerable; package data says fixed."""
    m = _match(deb_index)
    assert "CVE-2023-38545" not in m.packages["curl"].fixable and "CVE-2023-38545" in m.packages["curl"].fixed


def test_uncomparable_versions_are_counted_not_guessed(deb_index):
    m = _match(deb_index, [{"manager": "dpkg", "name": "curl", "version": "x", "arch": "", "source": "curl",
                            "source_version": "not a version"}])
    assert m.uncomparable > 0 and not m.packages["curl"].fixable


# ============================================================== priority
def _hit(cve="CVE-1", fixed="1.1", sev=""):
    return M.CveHit(cve, fixed, ["A-1"], sev)


@pytest.mark.parametrize("info,hit,want", [
    ({"kev": {"due_date": "x"}}, _hit(), "critical"),
    ({"kev": {"due_date": "x"}}, _hit(fixed=None), "critical"),                 # exploited and unfixed
    ({"epss": {"score": 0.2}, "cvss": {"score": 7.5}}, _hit(), "high"),
    ({"epss": {"score": 0.09}, "cvss": {"score": 7.5}}, _hit(), "medium"),
    ({"epss": {"score": 0.9}, "cvss": {"score": 6.9}}, _hit(), "low"),
    ({}, _hit(), "low"),
    ({}, _hit(sev="high"), "medium"),                                            # distro rating stands in for CVSS
    ({"epss": {"score": 0.5}, "cvss": {"score": 9.8}}, _hit(sev="negligible"), "low"),   # negligible caps
    ({}, _hit(fixed=None), "low"),
    ({}, _hit(fixed=None, sev="unimportant"), "info"),
])
def test_priority_layers(info, hit, want):
    assert PR.score_cve(hit, info, 0.1).severity == want


# ============================================================== record, rules, kernel
def _deb_inv(packages=DEB12_PACKAGES, **extra):
    return {"header": True, "complete": True, "os": {"ID": "debian", "VERSION_ID": "12", "PRETTY_NAME": "Debian 12"},
            "running_kernel": "", "packages": list(packages), "managers": {"dpkg": "ok"}, "dropped": 0, **extra}


def test_record_turns_matches_into_pkg_rules(deb_index):
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv())
    by = {(s["rule"], s["subject"]): s for s in doc["signals"]}
    ssh = by[("PKG-001", "openssh")]
    assert ssh["severity"] == "critical" and ssh["act_now"] and "act now" in ssh["title"]
    assert ssh["entities"] == ["CVE-2024-6387"]
    assert any("sudo apt-get install --only-upgrade openssh-server" in r for r in ssh["recommendation"])
    curl = by[("PKG-001", "curl")]
    assert curl["entities"] == ["CVE-2023-46218"] and curl["severity"] == "low"
    unfixed = [s for s in doc["signals"] if s["rule"] == "PKG-002"]
    assert len(unfixed) == 1 and unfixed[0]["subject"] == ""             # one finding per machine, grouped per package
    assert unfixed[0]["severity"] == "low"
    assert {"coreutils:CVE-2016-2781", "coreutils:CVE-2025-0001", "zlib:CVE-2024-2222",
            "bash:CVE-2024-3333"} == set(unfixed[0]["entities"])
    assert any(e.startswith("coreutils (2 CVEs)") for e in unfixed[0]["evidence"])
    assert doc["counts"]["unfixed_packages"] == 3
    assert doc["complete"] and Path(doc["file"]).exists()
    assert "1 on CISA's exploited list" in REC.summary_line(doc)


def test_record_without_an_index_is_a_gap_not_clean(tmp_path):
    doc = REC.run(tmp_path, "10.0.0.5", reader=lambda: _deb_inv())
    notes = [s for s in doc["signals"] if s["rule"] == "PKG-004"]
    assert notes and "kratos vulndb-update" in " ".join(notes[0]["evidence"])
    assert not doc["complete"] and not [s for s in doc["signals"] if s["rule"] == "PKG-001"]


def test_an_unsupported_distribution_is_a_pkg004_gap(deb_index):
    inv = _deb_inv(os={"ID": "gentoo", "VERSION_ID": "2.15"})
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: inv)
    assert any("no vulnerability data for this distribution" in e
               for s in doc["signals"] if s["rule"] == "PKG-004" for e in s["evidence"])


def test_stale_data_is_a_run_note_in_every_result(deb_index):
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv(), now=time.time() + 30 * 86400)
    assert doc["index_stale_days"] >= 29
    assert any("days old" in e for s in doc["signals"] if s["rule"] == "PKG-004" for e in s["evidence"])


def test_a_failed_read_saves_nothing(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult
    doc = REC.run(tmp_path, "10.0.0.5", reader=lambda: SSHResult(ok=False, returncode=255, stdout="", stderr="no route"))
    assert doc["status"] == "error" and "no route" in doc["observation"]
    assert not (tmp_path / "packages").exists()


def test_same_inputs_rewrite_the_same_file_and_dedupe_the_inventory(deb_index):
    a = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv(), now=1_800_000_000.0)
    b = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv(), now=1_800_000_100.0)
    assert a["file"] == b["file"] and len(list((deb_index / "packages").glob("*.json"))) == 1
    assert INV.counts(deb_index) == {"rows": 1, "machines": 1}
    assert INV.latest(deb_index, "10.0.0.5").last_seen_at == 1_800_000_100.0


DEB_KERNEL = [
    {"manager": "dpkg", "name": "linux-image-6.1.0-13-amd64", "version": "6.1.55-1", "arch": "amd64",
     "source": "linux-signed-amd64", "source_version": "6.1.55+1"},
    {"manager": "dpkg", "name": "linux-image-6.1.0-18-amd64", "version": "6.1.76-1", "arch": "amd64",
     "source": "linux-signed-amd64", "source_version": "6.1.76+1"},
]


def test_kernel_newer_installed_than_running_is_pkg003():
    ks = M.kernel_status("deb", {"running_kernel": "6.1.0-13-amd64"}, DEB_KERNEL)
    assert ks.managed and ks.pending and ks.newest == "6.1.0-18-amd64"
    ks = M.kernel_status("deb", {"running_kernel": "6.1.0-18-amd64"}, DEB_KERNEL)
    assert ks.managed and not ks.pending
    ks = M.kernel_status("deb", {"running_kernel": "6.8.0-137-generic"}, DEB12_PACKAGES)   # a container
    assert not ks.managed and not ks.pending


def test_kernel_status_rpm_and_apk():
    rpm = [{"name": "kernel-core", "version": "0:5.14.0-70.13.1.el9_0", "arch": "x86_64"},
           {"name": "kernel-core", "version": "0:5.14.0-162.6.1.el9_1", "arch": "x86_64"}]
    ks = M.kernel_status("rpm", {"running_kernel": "5.14.0-70.13.1.el9_0.x86_64"}, rpm)
    assert ks.pending and ks.newest == "5.14.0-162.6.1.el9_1.x86_64"
    apk = [{"name": "linux-lts", "version": "6.6.31-r0", "source": "linux-lts"}]
    assert not M.kernel_status("apk", {"running_kernel": "6.6.31-0-lts"}, apk).pending
    assert M.kernel_status("apk", {"running_kernel": "6.6.30-0-lts"}, apk).managed is False


def test_pkg003_rule_and_its_disappearance_after_reboot(deb_index):
    inv = _deb_inv(DEB12_PACKAGES + DEB_KERNEL, running_kernel="6.1.0-13-amd64")
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: inv)
    k = [s for s in doc["signals"] if s["rule"] == "PKG-003"]
    assert k and k[0]["severity"] == "medium" and k[0]["entities"] == ["6.1.0-18-amd64"]
    inv2 = _deb_inv(DEB12_PACKAGES + DEB_KERNEL, running_kernel="6.1.0-18-amd64")
    doc2 = REC.run(deb_index, "10.0.0.5", reader=lambda: inv2)
    assert not [s for s in doc2["signals"] if s["rule"] == "PKG-003"]


# ============================================================== findings, identity, lifecycle
def test_pkg_findings_carry_subject_and_cve_entities(deb_index):
    from kratos.adapters import findings_engine as FE
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv())
    fs = FE._package_findings(doc)
    ssh = next(f for f in fs if f.id == "PKG-001" and f.subject == "openssh")
    assert ssh.entities == ["CVE-2024-6387"] and ssh.severity == "critical" and ssh.attack == []
    assert FE.rule_inputs("PKG-001") == ("packages",)
    assert all(rid in FE.FINDING_SUMMARY_TEMPLATES for rid in ("PKG-001", "PKG-002", "PKG-003", "PKG-004"))


def test_a_new_cve_for_a_decided_package_reopens_it(tmp_path):
    from kratos.lifecycle import apply as A, decide as D
    from kratos.lifecycle.coverage import Coverage
    from kratos.lifecycle.keys import finding_key
    from kratos.run_context import RunContext
    import uuid

    cov = Coverage(inputs={"packages": None})
    me = D.Actor(user="alice", interface="cli")

    def f(cves):
        return {"id": "PKG-001", "title": "curl: fixable", "severity": "medium", "evidence": ["x"],
                "subject": "curl", "entities": list(cves)}

    def run(fs, now):
        return A.apply_run(fs, target="10.0.0.5", coverage=cov, data_dir=tmp_path, now=now,
                           run=RunContext(run_id=uuid.uuid4().hex, source="interactive", target="10.0.0.5",
                                          session_id=None, started_at=now))
    run([f(["CVE-2023-46218"])], 1_000_000.0)
    key = finding_key("PKG-001", "10.0.0.5", "curl")
    assert key != finding_key("PKG-001", "10.0.0.5", "openssl")      # one finding per package
    D.accept_risk(key, actor=me, reason="internal only", owner=None, expires_at=1_000_000.0 + 86400,
                  data_dir=tmp_path, now=1_000_010.0)
    out, _ = run([f(["CVE-2023-46218"])], 1_000_100.0)
    assert out[0]["state"] == "risk_accepted"                          # same CVE set: stays decided
    out, _ = run([f(["CVE-2023-46218", "CVE-2026-9999"])], 1_000_200.0)
    assert out[0]["state"] == "open" and out[0]["change"] == "reopened"


def test_an_incomplete_package_check_cannot_close_a_pkg_finding(tmp_path, monkeypatch):
    from kratos.adapters import findings_engine as FE
    from kratos.lifecycle import coverage as lc_cov
    import kratos.run_context as rc

    captured = {}
    orig = lc_cov.for_report

    def spy(inputs, *, target, run, incomplete=frozenset()):
        captured["incomplete"] = set(incomplete)
        return orig(inputs, target=target, run=run, incomplete=incomplete)
    monkeypatch.setattr(lc_cov, "for_report", spy)
    with rc.run_scope("cli", target="10.0.0.5"):
        for doc, should in (({"complete": True}, False), ({"complete": False}, True)):
            FE._apply_lifecycle([], data_dir=tmp_path, target="10.0.0.5", inputs={}, auth_stats=None,
                                patterns_stats=None, packages=doc)
            assert ("packages" in captured["incomplete"]) is should


def test_lifecycle_rules_for_pkg():
    from kratos.lifecycle.rules import rule_info
    assert rule_info("PKG-001").kind == "condition" and rule_info("PKG-003").kind == "condition"
    assert rule_info("PKG-004").kind == "run_note" and not rule_info("PKG-001").sticky


def test_digest_never_shows_a_pkg_title():
    from kratos.collect import digest
    assert "PKG-" in digest._TITLE_UNSAFE_PREFIXES


def test_the_check_is_registered_quick_and_runs(deb_index, monkeypatch):
    import kratos.collect.checks  # noqa: F401
    from kratos.collect.registry import CheckContext, get

    chk = get("packages")
    assert chk is not None and chk.cost == "quick" and chk.inputs == ("packages",)
    monkeypatch.setattr(REC, "_default_reader", lambda: _deb_inv())
    res = chk.run(CheckContext(target="10.0.0.5", target_key="10.0.0.5", data_dir=deb_index, transport="ssh",
                               dispatch=lambda *a, **k: {}, deadline=0.0, now=0.0))
    assert res.status == "ok" and "installed package" in res.summary and res.tools == []


def test_vulndb_update_marks_the_package_check_stale(tmp_path):
    from kratos.collect import state as CS
    owner = CS.new_owner()
    CS.claim(tmp_path, "10.0.0.5", "packages", ttl_seconds=3600, stale_claim_seconds=60, owner=owner)
    CS.finish(tmp_path, "10.0.0.5", "packages", owner=owner, started_at=time.time(), finished_at=time.time(),
              status="ok", summary="x", gaps=[])
    assert CS.get(tmp_path, "10.0.0.5", "packages").fresh(3600, time.time())
    assert CS.expire(tmp_path, "packages") == 1
    assert not CS.get(tmp_path, "10.0.0.5", "packages").fresh(3600, time.time())


# ============================================================== network cross-check
def test_network_cve_fixed_by_a_package_is_noted_and_dropped_from_entities(deb_index):
    from kratos.adapters import findings_engine as FE
    from kratos.pkgvuln import crosscheck
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv())
    fixed = crosscheck.fixed_by_packages(deb_index, doc, ["CVE-2023-38545", "CVE-2023-46218", "CVE-2099-0001"])
    assert set(fixed) == {"CVE-2023-38545"} and "backported" in fixed["CVE-2023-38545"]
    scan = {"target": "10.0.0.5", "scanned_at": "2026-10-15T00:00:00Z", "cve_matching": "done", "services_checked": 1,
            "findings": [{"source": "vulscan", "host": "10.0.0.5", "port": 443, "product": "curl", "version": "7.88.1",
                          "cve_ids": ["CVE-2023-38545", "CVE-2023-46218"]}]}
    v = [f for f in FE._vulnerability_findings(scan, fixed) if f.id == "VULN-001"][0]
    assert v.entities == ["CVE-2023-46218"] and v.severity == "medium"
    assert any("backported" in e and "CVE-2023-38545" in e for e in v.evidence)
    only_fixed = [f for f in FE._vulnerability_findings(
        {**scan, "findings": [{**scan["findings"][0], "cve_ids": ["CVE-2023-38545"]}]}, fixed) if f.id == "VULN-001"][0]
    assert only_fixed.entities == [] and only_fixed.severity == "info" and "already fix" in only_fixed.title
    plain = [f for f in FE._vulnerability_findings(scan) if f.id == "VULN-001"][0]
    assert plain.entities == ["CVE-2023-38545", "CVE-2023-46218"]          # no package data: unchanged


# ============================================================== privacy
def test_no_package_name_or_version_leaves_kratos(deb_index, monkeypatch):
    """During an investigation-time package check no HTTP request is made at all;
    during `vulndb-update` the only requests are public file names."""
    sent: list[str] = []
    real_request = requests.Session.request

    def watch(self, method, url, *a, **kw):
        sent.append(json.dumps([method, url, kw.get("headers"), kw.get("params"), kw.get("data"), kw.get("json")],
                               default=str))
        raise requests.ConnectionError("blocked in the privacy test")
    monkeypatch.setattr(requests.Session, "request", watch)
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: sent.append(str(a)) or (_ for _ in ()).throw(OSError()))

    distinctive = [dict(p, name=f"zz-secret-{p['name']}", version=p["version"] + "zzsecret") for p in DEB12_PACKAGES]
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv(distinctive))
    assert doc["status"] == "ok" and sent == []                         # matching is offline

    s = FakeSession(_feeds())
    INV.save(deb_index, "10.0.0.6", _deb_inv(distinctive), family="deb", selector="debian:12")
    assert U.run_update(deb_index, session=s, full=True).ok
    blob = json.dumps(s.requests)
    for p in distinctive:
        assert p["name"] not in blob and p["version"] not in blob
    assert all(u.startswith((E.OSV_BASE, "https://www.cisa.gov/", "https://epss.", "https://nvd.nist.gov/"))
               for u, _ in s.requests)
    # the real HTTP layer was never reached by either
    monkeypatch.setattr(requests.Session, "request", real_request)
    assert sent == []


# ============================================================== guard 3 still fires
def test_guard3_rejects_a_clean_verdict_over_a_critical_pkg_finding(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    finding = {"id": "PKG-001", "title": "openssh: 1 fixable known vulnerability, 1 exploited in the wild -- act now",
               "severity": "critical", "subject": "openssh", "evidence": ["x"], "recommendation": ["upgrade"],
               "entities": ["CVE-2024-6387"]}

    def correlate(**kwargs):
        return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
                "input_errors": {}, "staleness_warning": None, "findings": [finding], "count": 1}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)
    kratos_config.set_active_target("10.136.28.168")
    answer = "Everything is patched -- the system looks clean."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(answer), _final_json(answer), _final_json(answer)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("is this box vulnerable?", tmp_path, max_iters=10)
    assert any("dismissive_verdict_contradiction" in s.get("violations", [])
               for s in result["transcript"] if s.get("status") == "final_answer_rejected")


# ============================================================== suggested commands
def test_upgrade_template_only_names_packages_from_a_finding():
    from kratos.remediation import catalogue as C
    from kratos.remediation.evidence import Evidence
    ev = Evidence(finding_texts=["openssh: 1 fixable known vulnerability", "Installed: openssh-server 1:9.2p1-2"])
    assert C.render_template("package.upgrade", {"package": "openssh-server", "manager": "apt"}, ev) == \
        "sudo apt-get install --only-upgrade openssh-server"
    assert C.render_template("package.upgrade", {"package": "openssh-server", "manager": "dnf"}, ev) == \
        "sudo dnf upgrade openssh-server"
    for bad in ({"package": "nginx", "manager": "apt"}, {"package": "openssh-server;id", "manager": "apt"},
                {"package": "-oops", "manager": "apt"}, {"package": "openssh-server", "manager": "yum"}):
        with pytest.raises(C.TemplateError):
            C.render_template("package.upgrade", bad, ev)
    assert C.recognise("sudo apt-get install --only-upgrade openssh-server") == (
        "package.upgrade", {"manager": "apt", "package": "openssh-server"})


def test_a_bundle_notice_is_silenced_by_a_per_cve_record_that_skips_this_release(tmp_path, monkeypatch):
    """Ubuntu's USN-6409-1 lists glibc for 22.04 with CVEs whose per-CVE records name
    only other releases (the tracker found 22.04 unaffected). When the per-CVE data
    covers the release, the notice alone must not report them; when it does not
    (Debian 11 today), the notice still decides."""
    recs = [
        {"id": "DSA-9999-1", "modified": "2026-01-01T00:00:00Z", "upstream": ["CVE-2026-0001", "CVE-2026-0002"],
         "affected": [{"package": {"name": "glibc", "ecosystem": "Debian:12"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.36-9+deb12u9"}]}]}]},
        # the per-CVE record for 0001 names only Debian:13 -> bookworm unaffected
        _deb_cve("CVE-2026-0001", "Debian:13", "glibc", "2.40-1"),
        # padding so the release counts as covered by per-CVE data once the threshold is lowered
        _deb_cve("CVE-2026-0003", "Debian:12", "bash", None),
    ]
    glibc = [{"manager": "dpkg", "name": "libc6", "version": "2.36-9+deb12u1", "arch": "amd64", "source": "glibc",
              "source_version": "2.36-9+deb12u1"}]
    assert U.run_update(tmp_path, selectors=["debian:12"], session=FakeSession(_feeds(recs))).ok
    m = _match(tmp_path, glibc)
    assert set(m.packages["glibc"].fixable) == {"CVE-2026-0001", "CVE-2026-0002"}       # coverage too thin: notice decides
    monkeypatch.setattr(IX, "PRECISE_COVERAGE_MIN", 1)
    m = _match(tmp_path, glibc)
    assert set(m.packages["glibc"].fixable) == {"CVE-2026-0002"} and "CVE-2026-0001" in m.packages["glibc"].fixed
    assert m.silenced == 1



def test_unfixed_is_info_when_every_cve_is_negligible_and_critical_when_exploited(deb_index):
    only_core = [p for p in DEB12_PACKAGES if p["name"] == "coreutils"]
    doc = REC.run(deb_index, "10.0.0.5", reader=lambda: _deb_inv(only_core))
    sig = next(s for s in doc["signals"] if s["rule"] == "PKG-002")
    assert sig["severity"] == "low"                       # CVE-2025-0001 is rated medium
    s1 = M.CveHit("CVE-2016-2781", None, ["DEBIAN-CVE-2016-2781"], "unimportant")
    pr = M.PackageResult("coreutils", [("coreutils", "9.1-1")], ["9.1-1"])
    one = REC._unfixed_signal([(pr, [PR.score_cve(s1, {}, 0.1)])], "src")
    assert one["severity"] == "info"
    kev = REC._unfixed_signal([(pr, [PR.score_cve(s1, {"kev": {"due_date": "x"}}, 0.1)])], "src")
    assert kev["severity"] == "critical" and kev["act_now"]



def test_a_rebuild_keeps_the_releases_of_an_index_it_cannot_read(tmp_path):
    """An index from an older schema can't be opened for matching, but the releases
    it was built for still decide what the rebuild downloads."""
    assert build(tmp_path).ok
    with sqlite3.connect(IX.path_for(tmp_path)) as c:
        c.execute("UPDATE info SET value = '0' WHERE key = 'schema_version'")
    assert IX.open_readonly(tmp_path) is None
    assert [s.key for s in U.resolve_selectors(tmp_path, None)] == ["debian:12"]


def test_a_package_is_judged_by_its_newest_installed_version(deb_index):
    """Old kernels stay installed next to the new one; upgrading can't fix them, and a
    stale running kernel is PKG-003's. The newest copy decides PKG-001; older copies
    are still matched for the running-kernel check."""
    old = {"manager": "dpkg", "name": "openssh-client-old", "version": "1:9.2p1-2+deb12u2", "arch": "amd64",
           "source": "openssh", "source_version": "1:9.2p1-2+deb12u2"}
    new = dict(old, name="openssh-server", version="1:9.2p1-2+deb12u3", source_version="1:9.2p1-2+deb12u3")
    m = _match(deb_index, [old, new])
    assert "CVE-2024-6387" in m.packages["openssh"].fixed and not m.packages["openssh"].fixable
    assert m.packages["openssh"].older_versions == ["1:9.2p1-2+deb12u2"]
    assert "CVE-2024-6387" in m.lookups_affected[("openssh", "1:9.2p1-2+deb12u2")]
    only_old = _match(deb_index, [old])
    assert "CVE-2024-6387" in only_old.packages["openssh"].fixable


def test_signed_kernel_images_are_looked_up_as_the_kernel_source():
    deb = {"name": "linux-image-6.1.0-18-amd64", "version": "6.1.76-1", "source": "linux-signed-amd64",
           "source_version": "6.1.76+1"}
    assert E.lookup_name("deb", deb) == ("linux", "6.1.76-1")
    ubu = {"name": "linux-image-6.8.0-138-generic", "version": "6.8.0-138.138~22.04.1",
           "source": "linux-signed-hwe-6.8", "source_version": "6.8.0-138.138~22.04.1"}
    assert E.lookup_name("deb", ubu) == ("linux-hwe-6.8", "6.8.0-138.138~22.04.1")
    assert E.lookup_name("deb", {"name": "curl", "version": "1", "source": "curl", "source_version": "1"}) == ("curl", "1")


def test_a_stale_running_kernel_with_an_exploited_cve_is_a_high_pkg003_not_an_upgrade(tmp_path):
    """Debian: kernel 6.1.0-13 is running (affected by a KEV CVE), 6.1.0-18 is installed
    and fixed. The fix is a reboot: PKG-003 high, and no PKG-001 for linux."""
    recs = [_deb_cve("CVE-2024-6387", "Debian:12", "linux", "6.1.66-1")]      # a KEV CVE in the fixture feed
    assert U.run_update(tmp_path, selectors=["debian:12"], session=FakeSession(_feeds(recs))).ok
    kernels = [{"manager": "dpkg", "name": "linux-image-6.1.0-13-amd64", "version": "6.1.55-1", "arch": "amd64",
                "source": "linux-signed-amd64", "source_version": "6.1.55+1"},
               {"manager": "dpkg", "name": "linux-image-6.1.0-18-amd64", "version": "6.1.76-1", "arch": "amd64",
                "source": "linux-signed-amd64", "source_version": "6.1.76+1"}]
    doc = REC.run(tmp_path, "10.0.0.5", reader=lambda: _deb_inv(kernels, running_kernel="6.1.0-13-amd64"))
    rules = {s["rule"]: s for s in doc["signals"]}
    assert "PKG-001" not in rules
    assert rules["PKG-003"]["severity"] == "high" and "CVE-2024-6387" in " ".join(rules["PKG-003"]["evidence"])
    # running the fixed kernel: nothing to say about the kernel
    doc = REC.run(tmp_path, "10.0.0.5", reader=lambda: _deb_inv(kernels, running_kernel="6.1.0-18-amd64"))
    assert not [s for s in doc["signals"] if s["rule"] in ("PKG-001", "PKG-003")]
    # only the old kernel installed: an upgrade fixes it -> PKG-001 critical
    doc = REC.run(tmp_path, "10.0.0.5", reader=lambda: _deb_inv(kernels[:1], running_kernel="6.1.0-13-amd64"))
    assert any(s["rule"] == "PKG-001" and s["subject"] == "linux" and s["severity"] == "critical"
               for s in doc["signals"])


def test_an_investigation_start_sends_no_package_list_anywhere(deb_index, monkeypatch):
    """The collection an investigation starts from (the packages check, the digest the
    model reads, and the correlated findings) makes no HTTP request, and nothing bound
    for the model carries a package that has no finding -- only the vulnerable
    packages, by name, in their findings. (The model sees findings like any other
    evidence; the full package list stays on the Kratos machine.)"""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.collect import runner
    from kratos.collect.digest import build_digest
    from kratos.run_context import run_scope

    monkeypatch.setenv("KRATOS_COLLECT", "on")
    sent: list[str] = []

    def block(self, method, url, *a, **kw):
        sent.append(url)
        raise requests.ConnectionError("blocked")
    monkeypatch.setattr(requests.Session, "request", block)
    harmless = {"manager": "dpkg", "name": "zz-quiet-tool", "version": "9.9-1", "arch": "amd64",
                "source": "zz-quiet-tool", "source_version": "9.9-1"}
    monkeypatch.setattr(REC, "_default_reader", lambda: _deb_inv(DEB12_PACKAGES + [harmless]))
    kratos_config.set_active_target("10.0.0.5")
    with run_scope("cli", target="10.0.0.5"):
        rep = runner.prepare("10.0.0.5", deb_index, only=("packages",), correlate=False,
                             dispatch=lambda *a, **k: {"status": "ok", "result": {}})
        digest = build_digest(rep)
        j, md = FE.write_findings_report(deb_index)
    assert any(c.name == "packages" and c.status == "ok" for c in rep.checks)
    assert "installed package" in digest
    assert sent == []
    findings_text = Path(j).read_text()
    assert "openssh" in findings_text                         # the vulnerable package is named in its finding
    for text in (digest, findings_text, Path(md).read_text()):
        assert "zz-quiet-tool" not in text and "9.9-1" not in text
