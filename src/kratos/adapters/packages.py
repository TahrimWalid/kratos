"""The installed packages of a Linux machine -- the package inventory read (A.2).

Read-only, and cheap: the package manager's own list of what is installed, the
distribution name and version (``/etc/os-release``), the running kernel
(``uname -r``), the installed kernel module trees, and whether the distribution
says a reboot is pending (``/var/run/reboot-required``). Nothing is judged here
-- matching against vulnerability data happens on Kratos (``kratos.pkgvuln``),
and the package list never leaves Kratos.

One fixed POSIX sh script (``build_script``) prints tab-separated records; the
SSH path runs it as the SSH user (package databases are world-readable, so no
sudo), and the sub-agent runs the SAME script through ``sh -s`` (its
``package_inventory`` read). One parser (``parse_output``) reads both.

- Debian/Ubuntu: ``dpkg-query -W`` (installed packages only, with their source
  package and source version -- Debian advisories are listed by source package);
- RHEL family: ``rpm -qa`` (``EPOCH:VERSION-RELEASE`` and the source RPM);
- Alpine: ``/lib/apk/db/installed`` (``P:``, ``V:``, ``A:``, ``o:`` origin).

Where each package came from, so Kratos can tell the distribution's own packages from
ones it has no advisories for (a PPA's PHP, a vendor repository, a downloaded .deb):

- Debian/Ubuntu: one pass over apt's package lists (``/var/lib/apt/lists``), each list
  named by the ``Origin:`` of its repository's Release file: which origins offer the
  installed version, and which offer the package at all (``PO`` records, ``POS`` counts);
- RHEL family: each package's ``%{VENDOR}`` (``RV`` records).

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import re
import shlex
from typing import Any

# --------------------------------------------------------------------------- caps
MAX_PACKAGES = 20000
MAX_REBOOT_PKGS = 200
MAX_KERNEL_TREES = 64
OUTPUT_CAP_BYTES = 8 * 1024 * 1024
DEFAULT_BUDGET_SECONDS = 60

OS_KEYS: tuple[str, ...] = ("ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME")

# What a package name and a version may look like. Anything else is dropped (and
# counted) rather than carried: these strings come from the machine.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._~^-]{0,199}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9.+~:_^-]{1,128}$")
_ARCH_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_KREL_RE = re.compile(r"^[A-Za-z0-9.+~_-]{1,128}$")
# A repository's Origin (apt) or a package's vendor (rpm): machine text, kept only when
# it looks like a name -- "Ubuntu", "LP-PPA-ondrej-php", "Red Hat, Inc.", "Fedora Project".
_ORIGIN_RE = re.compile(r"^[A-Za-z0-9 ._:+()/@-]{1,64}$")
_VENDOR_RE = re.compile(r"^[A-Za-z0-9 ._:+(),'/@<>-]{1,120}$")

# One awk program: the Alpine installed database, one record per blank-line
# separated stanza -> A<TAB>name<TAB>version<TAB>arch<TAB>origin.
AWK_APK = r"""
function flush() { if (p != "") print "A\t" p "\t" v "\t" a "\t" o; p = ""; v = ""; a = ""; o = "" }
/^P:/ { p = substr($0, 3); next }
/^V:/ { v = substr($0, 3); next }
/^A:/ { a = substr($0, 3); next }
/^o:/ { o = substr($0, 3); next }
/^$/ { flush() }
END { flush() }
"""

# One awk program: where each installed Debian/Ubuntu package came from. Input, in
# order: `grep -H '^Origin: '` of the Release files (path:Origin: X), the dpkg D lines,
# then `grep -H` of Package:/Version: lines of every package list. A list belongs to the
# repository whose Release file name is the longest prefix of the list's file name.
# Output: PO<TAB>name<TAB>origins offering the installed version<TAB>origins offering the
# name (comma-separated, "?" for a list with no Release origin), then POS<TAB>lists<TAB>
# lists with a known origin.
AWK_APT = r"""
function origin_of(f,   b, k, best) {
  b = f; sub(/.*\//, "", b); best = ""
  for (k = 1; k <= npre; k++) if (index(b, pre[k] "_") == 1 && length(pre[k]) > length(best)) best = pre[k]
  return best == "" ? "?" : org[best]
}
function add(arr, k, o) { if (index("," arr[k] ",", "," o ",") == 0) arr[k] = (arr[k] == "" ? o : arr[k] "," o) }
BEGIN { FS = "\t" }
$1 == "D" { if ($7 ~ /^.i/ && !($2 in ver)) { ver[$2] = $3; order[++ni] = $2 }; next }
{
  i = index($0, ":"); if (i == 0) next
  f = substr($0, 1, i - 1); line = substr($0, i + 1)
  if (substr(line, 1, 8) == "Origin: ") {
    p = f; sub(/.*\//, "", p); sub(/_(In)?Release$/, "", p); o = substr(line, 9); gsub(/[,\t]/, " ", o)
    if (o == "") o = "?"
    if (!(p in org)) pre[++npre] = p
    org[p] = o; next
  }
  if (!(f in fo)) { fo[f] = origin_of(f); nl++; if (fo[f] != "?") known++ }
  if (substr(line, 1, 9) == "Package: ") { cur = substr(line, 10); if (!(cur in ver)) cur = ""; next }
  if (cur != "" && substr(line, 1, 9) == "Version: ") {
    o = fo[f]; add(anyo, cur, o); if (substr(line, 10) == ver[cur]) add(exact, cur, o); cur = ""
  }
}
END {
  for (j = 1; j <= ni; j++) print "PO\t" order[j] "\t" exact[order[j]] "\t" anyo[order[j]]
  print "POS\t" (nl + 0) "\t" (known + 0)
}
"""

_SH = r"""
LC_ALL=C; export LC_ALL
printf 'PKGINV\t1\n'
for _f in @ROOT@/etc/os-release @ROOT@/usr/lib/os-release; do
  if [ -r "$_f" ]; then
    grep -E '^(ID|ID_LIKE|VERSION_ID|VERSION_CODENAME|PRETTY_NAME)=' "$_f" 2>/dev/null | head -n 10 | while IFS= read -r _l; do
      printf 'OS\t%s\n' "$_l"
    done
    break
  fi
done
printf 'KREL\t%s\n' "$(uname -r 2>/dev/null)"
if [ -e @ROOT@/var/run/reboot-required ] || [ -e @ROOT@/run/reboot-required ]; then
  printf 'RR\t1\n'
  for _f in @ROOT@/var/run/reboot-required.pkgs @ROOT@/run/reboot-required.pkgs; do
    [ -r "$_f" ] && { head -n @MAXRR@ "$_f" | while IFS= read -r _l; do printf 'RRP\t%s\n' "$_l"; done; break; }
  done
else
  printf 'RR\t0\n'
fi
for _d in @ROOT@/lib/modules/* @ROOT@/usr/lib/modules/*; do
  [ -d "$_d" ] && printf 'KMOD\t%s\n' "${_d##*/}"
done | sort -u | head -n @MAXK@
if command -v dpkg-query >/dev/null 2>&1 && [ -d @ROOT@/var/lib/dpkg ]; then
  if _D=$(dpkg-query @DPKGROOT@ -W -f='D\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' 2>/dev/null); then
    printf '%s\n' "$_D"
    printf 'MGR\tdpkg\tok\n'
    _L=@ROOT@/var/lib/apt/lists
    if ls "$_L"/*_Packages >/dev/null 2>&1; then
      { grep -H -m 1 '^Origin: ' "$_L"/*Release 2>/dev/null
        printf '%s\n' "$_D"
        grep -H -E '^(Package|Version): ' "$_L"/*_Packages 2>/dev/null; } | awk @AWKAPT@
    else
      printf 'POS\t0\t0\n'
    fi
  else
    printf 'MGR\tdpkg\tfailed\n'
  fi
fi
if command -v rpm >/dev/null 2>&1 && { [ -d @ROOT@/var/lib/rpm ] || [ -d @ROOT@/usr/lib/sysimage/rpm ]; }; then
  if rpm @RPMROOT@ -qa --qf 'R\t%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null; then
    printf 'MGR\trpm\tok\n'
    rpm @RPMROOT@ -qa --qf 'RV\t%{NAME}\t%{VENDOR}\n' 2>/dev/null | head -n @MAXPKG@
  else
    printf 'MGR\trpm\tfailed\n'
  fi
fi
for _f in @ROOT@/lib/apk/db/installed @ROOT@/usr/lib/apk/db/installed; do
  if [ -r "$_f" ]; then
    if awk @AWKAPK@ "$_f"; then printf 'MGR\tapk\tok\n'; else printf 'MGR\tapk\tfailed\n'; fi
    break
  fi
done
printf 'END\n'
"""


def build_script(root: str = "") -> str:
    """The fixed read script. `root` is "" in production; tests point it at a fake tree."""
    q = shlex.quote
    rootq = q(root) if root else ""
    return (_SH
            .replace("@DPKGROOT@", f"--admindir={q(root + '/var/lib/dpkg')}" if root else "")
            .replace("@RPMROOT@", f"--root {rootq}" if root else "")
            .replace("@AWKAPK@", q(AWK_APK))
            .replace("@AWKAPT@", q(AWK_APT))
            .replace("@MAXPKG@", str(MAX_PACKAGES))
            .replace("@MAXRR@", str(MAX_REBOOT_PKGS))
            .replace("@MAXK@", str(MAX_KERNEL_TREES))
            .replace("@ROOT@", rootq))


def _os_value(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        raw = raw[1:-1]
    return raw[:120]


def _rpm_source_name(srpm: str) -> str:
    """'curl-7.76.1-14.el9.src.rpm' -> 'curl'. Empty when it can't be read."""
    s = srpm.strip()
    for suffix in (".src.rpm", ".nosrc.rpm"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    else:
        return ""
    parts = s.rsplit("-", 2)
    return parts[0] if len(parts) == 3 and parts[0] else ""


def _rpm_version(evr: str) -> str:
    """'(none):1.2-3.el9' -> '0:1.2-3.el9' (rpm prints (none) for no epoch)."""
    epoch, sep, rest = evr.partition(":")
    if not sep:
        return evr
    if epoch in ("(none)", ""):
        epoch = "0"
    return f"{epoch}:{rest}"


def parse_output(stdout: str) -> dict[str, Any]:
    """The script's records as one dict:

    {os: {ID, VERSION_ID, ...}, running_kernel, reboot_required, reboot_required_pkgs,
     kernel_trees, managers: {dpkg|rpm|apk: ok|failed}, packages: [{manager, name,
     version, arch, source, source_version}], dropped, complete, truncated}

    Packages that are known but not installed (Debian's "rc", rpm's gpg-pubkey)
    are skipped, not counted.

    `complete` is False when the read did not reach its end marker or a package
    manager failed. Nothing here is trusted: names and versions that don't look
    like names and versions are dropped and counted in `dropped`."""
    out: dict[str, Any] = {
        "os": {}, "running_kernel": "", "reboot_required": False, "reboot_required_pkgs": [],
        "kernel_trees": [], "managers": {}, "packages": [], "dropped": 0,
        "complete": False, "truncated": False, "header": False,
        # where packages came from: apt origins (None: not reported -- an older agent's
        # script) and rpm vendors
        "origins": None, "origin_lists": None, "vendors": {},
    }
    seen: set[tuple[str, str, str]] = set()
    for line in (stdout or "").splitlines():
        f = line.split("\t")
        tag = f[0]
        if tag == "PKGINV":
            out["header"] = True
        elif tag == "OS" and len(f) >= 2:
            key, _, value = f[1].partition("=")
            if key in OS_KEYS:
                out["os"][key] = _os_value(value)
        elif tag == "KREL" and len(f) >= 2:
            out["running_kernel"] = f[1].strip() if _KREL_RE.fullmatch(f[1].strip()) else ""
        elif tag == "RR" and len(f) >= 2:
            out["reboot_required"] = f[1].strip() == "1"
        elif tag == "RRP" and len(f) >= 2:
            name = f[1].strip()
            if _NAME_RE.fullmatch(name) and len(out["reboot_required_pkgs"]) < MAX_REBOOT_PKGS:
                out["reboot_required_pkgs"].append(name)
        elif tag == "KMOD" and len(f) >= 2:
            k = f[1].strip()
            if _KREL_RE.fullmatch(k) and len(out["kernel_trees"]) < MAX_KERNEL_TREES:
                out["kernel_trees"].append(k)
        elif tag == "MGR" and len(f) >= 3:
            if f[1] in ("dpkg", "rpm", "apk"):
                out["managers"][f[1]] = "ok" if f[2].strip() == "ok" else "failed"
        elif tag in ("D", "R", "A"):
            pkg = _package(tag, f)
            if pkg is _NOT_INSTALLED:
                continue
            if pkg is None:
                out["dropped"] += 1
                continue
            key = (pkg["manager"], pkg["name"], pkg["arch"])
            if key in seen:
                continue
            if len(out["packages"]) >= MAX_PACKAGES:
                out["truncated"] = True
                continue
            seen.add(key)
            out["packages"].append(pkg)
        elif tag == "PO" and len(f) >= 4:
            name = f[1].strip()
            if _NAME_RE.fullmatch(name):
                if out["origins"] is None:
                    out["origins"] = {}
                if len(out["origins"]) < MAX_PACKAGES:
                    out["origins"][name] = {"exact": _origins(f[2]), "any": _origins(f[3])}
        elif tag == "POS" and len(f) >= 3:
            if f[1].strip().isdigit() and f[2].strip().isdigit():
                out["origin_lists"] = {"lists": int(f[1]), "known": int(f[2])}
                if out["origins"] is None:
                    out["origins"] = {}
        elif tag == "RV" and len(f) >= 3:
            name, vendor = f[1].strip(), f[2].strip()
            if _NAME_RE.fullmatch(name) and len(out["vendors"]) < MAX_PACKAGES:
                out["vendors"][name] = vendor if (vendor != "(none)" and _VENDOR_RE.fullmatch(vendor)) else ""
        elif tag == "END":
            out["complete"] = True
    if any(v != "ok" for v in out["managers"].values()) or out["truncated"]:
        out["complete"] = False
    return out


_NOT_INSTALLED: dict[str, str] = {}


def _origins(field: str) -> list[str]:
    out = []
    for o in field.split(","):
        o = o.strip()
        if o and (o == "?" or _ORIGIN_RE.fullmatch(o)) and o not in out:
            out.append(o)
    return out[:8]


def _package(tag: str, f: list[str]) -> dict[str, str] | None:
    """One package record, None when it is malformed, _NOT_INSTALLED when it is a
    package the manager knows about but is not installed (config files left behind,
    rpm's signing keys)."""
    if tag == "D":
        if len(f) < 7:
            return None
        name, version, arch, src, src_ver, status = (x.strip() for x in f[1:7])
        # db:Status-Abbrev: desired / status / error. Only an installed status counts
        # ("ii", or "hi" for a held package); config-files-only, half-installed etc. don't.
        if len(status) < 2 or status[1] != "i":
            return _NOT_INSTALLED
        # ${source:Package} can carry " (version)" on old dpkg; keep the name only.
        src = src.split(" ")[0] or name
        src_ver = src_ver or version
        manager = "dpkg"
    elif tag == "R":
        if len(f) < 5:
            return None
        name, evr, arch, srpm = (x.strip() for x in f[1:5])
        if name == "gpg-pubkey":                     # rpm's imported signing keys, not software
            return _NOT_INSTALLED
        version = _rpm_version(evr)
        src = _rpm_source_name(srpm) or name
        src_ver = version
        manager = "rpm"
    else:
        if len(f) < 5:
            return None
        name, version, arch, src = (x.strip() for x in f[1:5])
        src = src or name
        src_ver = version
        manager = "apk"
    if not (_NAME_RE.fullmatch(name) and _NAME_RE.fullmatch(src)
            and _VERSION_RE.fullmatch(version) and _VERSION_RE.fullmatch(src_ver)):
        return None
    if arch and not _ARCH_RE.fullmatch(arch):
        arch = ""
    return {"manager": manager, "name": name, "version": version, "arch": arch,
            "source": src, "source_version": src_ver}
