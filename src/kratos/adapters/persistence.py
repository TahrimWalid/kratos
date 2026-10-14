"""
Where attackers keep access to a Linux machine -- the persistence inventory (A.1).

Read-only. ONE closed table of locations (cron, at, systemd, SSH keys, SUID
files, preload, kernel modules, shell startup, PAM, boot scripts, udev,
package-manager hooks, ...) per distribution family, and two ways to walk it
that print the SAME tab-separated records:

  - ``build_script()`` -- a fixed POSIX sh + awk script for SSH. It runs AS THE
    SSH USER (no sudo): what that user can't read is reported as a coverage gap,
    never as "nothing there";
  - ``inventory_output()`` -- the sub-agent's walk in stdlib Python, as root,
    every file opened through the hardened opener (kratos.logsources.hostfiles:
    no symlink anywhere in the path, no hard link, no file swapped mid-open).

One parser (``parse_output``) reads both. Nothing is judged here: judging
happens on Kratos (kratos.persist.judge). The read never sends whole files --
for text files only the lines that execute something, at most
``MAX_LINES_PER_FILE`` per file and ``MAX_LINE_CHARS`` bytes each, chosen the
same way by the awk program and its Python twin (a test runs both on the same
files). Authorized keys leave the machine only as type, SHA-256 fingerprint,
options and comment -- never the key itself.

Package ownership (dpkg's file lists, the rpm database, apk's installed db) is
looked up ON the machine for every listed path, so the main noise filter
("owned by an installed package") doesn't need the package database on
Kratos. Package verification (``verify=True``: dpkg --verify / rpm -V /
apk audit, restricted to the packages that own a listed item) is the slow part.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shlex
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Callable

try:  # in the agent bundle: sibling modules
    from . import catalog, hostfiles  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources import catalog, hostfiles
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]
        import hostfiles  # type: ignore[no-redef]

# --------------------------------------------------------------------------- caps
MAX_LINES_PER_FILE = 20          # excerpt lines sent per file
MAX_LINE_CHARS = 200             # bytes per excerpt line
MAX_FILES_PER_LOCATION = 1000    # directory entries looked at per location (a vendor unit tree is big)
MAX_USERS = 200                  # accounts whose home is looked at
MAX_KEYS_PER_FILE = 50
MAX_SUID_FILES = 500
MAX_TEXT_BYTES = 1024 * 1024     # a text file larger than this is listed, not read
MAX_HASH_BYTES = 64 * 1024 * 1024
OUTPUT_CAP_BYTES = 2 * 1024 * 1024
SUID_FIND_SECONDS = 25
DEFAULT_BUDGET_SECONDS = 50
VERIFY_EXTRA_SECONDS = 150     # dpkg --verify / rpm -V on the owning packages

AREAS: tuple[str, ...] = ("cron", "at", "systemd", "ssh", "suid", "preload", "kernel", "shell", "pam",
                          "boot", "udev", "pkg_hooks", "misc")

AREA_LABELS: dict[str, str] = {
    "cron": "cron jobs", "at": "at jobs", "systemd": "systemd units and timers", "ssh": "SSH authorized keys",
    "suid": "SUID/SGID files", "preload": "dynamic linker preload", "kernel": "kernel modules",
    "shell": "shell startup files", "pam": "PAM modules", "boot": "boot and login scripts",
    "udev": "udev rules", "pkg_hooks": "package manager hooks", "misc": "network dispatcher scripts",
}

# Extraction modes: which lines of a text file count as "executing something".
MODES: tuple[str, ...] = ("cron", "shell", "unit", "conf", "preload", "pam", "udev", "apt", "desktop",
                          "modprobe", "keys", "none")

# The filesystem types the SUID search walks (local, real files). Everything else
# -- proc/sysfs/cgroup, network filesystems, FUSE, squashfs snap images (read-only
# package images, owned by their snap, not by the system package manager) -- is
# skipped and said so.
LOCAL_FS_TYPES: tuple[str, ...] = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs",
                                   "tmpfs", "overlay", "bcachefs", "nilfs2", "vfat")
SKIP_MOUNT_PREFIXES: tuple[str, ...] = ("/proc", "/sys", "/dev/pts", "/run/user", "/var/lib/docker",
                                        "/var/lib/containers", "/snap")


@dataclass(frozen=True)
class Loc:
    area: str
    path: str
    kind: str                       # "file" | "dir" (its entries) | "tree" (entries up to depth 3)
    mode: str                       # extraction mode (MODES)
    families: tuple[str, ...] = catalog.FAMILIES
    vendor: bool = False            # a package-managed directory: only items NOT owned by a package matter
    name_suffix: str = ""           # only entries whose name ends with this (".rules", ".conf", ...)


_DEB, _RHEL, _ALP = ("debian",), ("rhel",), ("alpine",)
_DR = ("debian", "rhel")

# The closed table. Paths are the canonical location on each family; an alias
# (a directory that is itself a symlink to another listed one, e.g. /lib ->
# /usr/lib on merged-/usr systems, /etc/init.d -> rc.d/init.d on RHEL) is
# reported as an alias and not walked twice.
LOCATIONS: tuple[Loc, ...] = (
    # cron / at
    Loc("cron", "/etc/crontab", "file", "cron", _DR),
    Loc("cron", "/etc/cron.d", "dir", "cron", _DR),
    Loc("cron", "/etc/cron.hourly", "dir", "shell", _DR),
    Loc("cron", "/etc/cron.daily", "dir", "shell", _DR),
    Loc("cron", "/etc/cron.weekly", "dir", "shell", _DR),
    Loc("cron", "/etc/cron.monthly", "dir", "shell", _DR),
    Loc("cron", "/etc/anacrontab", "file", "cron", _DR),
    Loc("cron", "/var/spool/cron/crontabs", "dir", "cron", _DEB),
    Loc("cron", "/var/spool/cron", "dir", "cron", _RHEL),
    Loc("cron", "/etc/crontabs", "dir", "cron", _ALP),
    Loc("cron", "/etc/periodic/15min", "dir", "shell", _ALP),
    Loc("cron", "/etc/periodic/hourly", "dir", "shell", _ALP),
    Loc("cron", "/etc/periodic/daily", "dir", "shell", _ALP),
    Loc("cron", "/etc/periodic/weekly", "dir", "shell", _ALP),
    Loc("cron", "/etc/periodic/monthly", "dir", "shell", _ALP),
    Loc("at", "/var/spool/cron/atjobs", "dir", "shell", _DEB),
    Loc("at", "/var/spool/at", "dir", "shell", ("rhel", "alpine")),
    # systemd (none on Alpine)
    Loc("systemd", "/etc/systemd/system", "tree", "unit", _DR),
    Loc("systemd", "/run/systemd/system", "tree", "unit", _DR),
    Loc("systemd", "/etc/systemd/user", "tree", "unit", _DR),
    Loc("systemd", "/usr/lib/systemd/system", "tree", "unit", _DR, vendor=True),
    Loc("systemd", "/lib/systemd/system", "tree", "unit", _DR, vendor=True),
    Loc("systemd", "/usr/lib/systemd/user", "tree", "unit", _DR, vendor=True),
    Loc("systemd", "/etc/systemd/system-generators", "dir", "none", _DR),
    Loc("systemd", "/usr/local/lib/systemd/system-generators", "dir", "none", _DR),
    Loc("systemd", "/usr/lib/systemd/system-generators", "dir", "none", _DR, vendor=True),
    Loc("systemd", "/etc/systemd/user-generators", "dir", "none", _DR),
    # dynamic linker preload
    Loc("preload", "/etc/ld.so.preload", "file", "preload"),
    Loc("preload", "/etc/ld.so.conf.d", "dir", "conf", _DR),
    # kernel module configuration (the loaded modules come from /proc/modules)
    Loc("kernel", "/etc/modules", "file", "conf", ("debian", "alpine")),
    Loc("kernel", "/etc/modules-load.d", "dir", "conf"),
    Loc("kernel", "/etc/modprobe.d", "dir", "modprobe"),
    # shell startup
    Loc("shell", "/etc/profile", "file", "shell"),
    Loc("shell", "/etc/profile.d", "dir", "shell"),
    Loc("shell", "/etc/bash.bashrc", "file", "shell", _DEB),
    Loc("shell", "/etc/bashrc", "file", "shell", _RHEL),
    Loc("shell", "/etc/bash/bashrc", "file", "shell", _ALP),
    Loc("shell", "/etc/zsh", "dir", "shell"),
    Loc("shell", "/etc/environment", "file", "conf"),
    # PAM
    Loc("pam", "/etc/pam.d", "dir", "pam"),
    Loc("pam", "/usr/lib/x86_64-linux-gnu/security", "dir", "none", _DEB, vendor=True),
    Loc("pam", "/lib/x86_64-linux-gnu/security", "dir", "none", _DEB, vendor=True),
    Loc("pam", "/usr/lib/aarch64-linux-gnu/security", "dir", "none", _DEB, vendor=True),
    Loc("pam", "/usr/lib64/security", "dir", "none", _RHEL, vendor=True),
    Loc("pam", "/lib/security", "dir", "none", _ALP, vendor=True),
    # boot / init / login
    Loc("boot", "/etc/rc.local", "file", "shell", _DEB),
    Loc("boot", "/etc/rc.d/rc.local", "file", "shell", _RHEL),
    Loc("boot", "/etc/init.d", "dir", "shell", ("debian", "alpine"), vendor=True),
    Loc("boot", "/etc/rc.d/init.d", "dir", "shell", _RHEL, vendor=True),
    Loc("boot", "/etc/local.d", "dir", "shell", _ALP),
    Loc("boot", "/etc/update-motd.d", "dir", "shell", _DEB),
    Loc("boot", "/etc/xdg/autostart", "dir", "desktop", _DR),
    # udev
    Loc("udev", "/etc/udev/rules.d", "dir", "udev", name_suffix=".rules"),
    Loc("udev", "/usr/lib/udev/rules.d", "dir", "udev", _DR, vendor=True, name_suffix=".rules"),
    Loc("udev", "/lib/udev/rules.d", "dir", "udev", vendor=True, name_suffix=".rules"),
    # package manager hooks
    Loc("pkg_hooks", "/etc/apt/apt.conf.d", "dir", "apt", _DEB),
    Loc("pkg_hooks", "/etc/dnf/plugins", "dir", "conf", _RHEL),
    Loc("pkg_hooks", "/etc/yum/pluginconf.d", "dir", "conf", _RHEL),
    Loc("pkg_hooks", "/etc/apk/commit_hooks.d", "dir", "shell", _ALP),
    # misc
    Loc("misc", "/etc/NetworkManager/dispatcher.d", "tree", "shell", _DR),
)

# Per-account locations, relative to the home directory.
HOME_LOCATIONS: tuple[Loc, ...] = (
    Loc("ssh", ".ssh/authorized_keys", "file", "keys"),
    Loc("ssh", ".ssh/authorized_keys2", "file", "keys"),
    Loc("shell", ".bashrc", "file", "shell"),
    Loc("shell", ".bash_profile", "file", "shell"),
    Loc("shell", ".bash_login", "file", "shell"),
    Loc("shell", ".profile", "file", "shell"),
    Loc("shell", ".bash_logout", "file", "shell"),
    Loc("shell", ".zshrc", "file", "shell"),
    Loc("shell", ".zprofile", "file", "shell"),
    Loc("systemd", ".config/systemd/user", "tree", "unit", _DR),
    Loc("boot", ".config/autostart", "dir", "desktop", _DR),
)

# sudoers / sudoers.d belong to the privileged-accounts check: not read here.
LEFT_TO_OTHER_CHECKS = {"/etc/sudoers": "privileged_accounts", "/etc/sudoers.d": "privileged_accounts"}

# Where a root-only location can be read: the coverage-gap fix text.
AGENT_FIX = "read this machine through its sub-agent (it reads as root)"

PACKAGE_DB: dict[str, str] = {"debian": "/var/lib/dpkg/info", "rhel": "/var/lib/rpm", "alpine": "/lib/apk/db/installed"}
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,127}$")

# Directories whose files are package-owned trees we map usr-merged aliases between.
_USRMERGE = (("/usr/lib/", "/lib/"), ("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib64/", "/lib64/"))


def locations_for(family: str | None) -> list[Loc]:
    return [loc for loc in LOCATIONS if (family or "") in loc.families]


def home_locations_for(family: str | None) -> list[Loc]:
    return [loc for loc in HOME_LOCATIONS if (family or "") in loc.families]


def usrmerge_alternates(path: str) -> list[str]:
    out = []
    for a, b in _USRMERGE:
        if path.startswith(a):
            out.append(b + path[len(a):])
        elif path.startswith(b):
            out.append(a + path[len(b):])
    return out


# --------------------------------------------------------------------------- line selection
# The same rules, twice: an awk program (SSH) and a Python twin (agent). Both see
# a line with CR dropped, tabs turned into spaces and leading blanks trimmed.
_RISKY = (r"(curl|wget|/dev/tcp|/dev/udp|nc -|ncat|netcat|socat|base64|xxd|openssl|python|perl|ruby|php|"
          r"bash -i|sh -i|mkfifo|/tmp/|/dev/shm|/var/tmp|nohup|setsid|chattr|LD_PRELOAD|eval )")
_SHELL_CONTROL = r"^(fi|done|esac|else|then|do|[{]|[}]|;;|[)])[ ;]*$"
_PLAIN_ASSIGN = r"^(export +)?[A-Za-z_][A-Za-z0-9_]*="
_WATCHED_VAR = r"^(export +)?(PATH|LD_[A-Z_]*|PROMPT_COMMAND|BASH_ENV|ENV)="
_EXPORT_ONLY = r"^export +[A-Za-z_][A-Za-z0-9_ ]*$"
_UNIT_KEEP = r"^(Exec[A-Za-z]*|OnCalendar|On[A-Za-z]*Sec) *="
_DESKTOP_KEEP = r"^(Exec|TryExec) *="
_KEY_TYPE = (r"(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh[.]com|"
             r"sk-ecdsa-sha2-nistp256@openssh[.]com)")

AWK = r"""
function select_line(t) {
  if (t ~ /^(#|;|$)/) return 0
  if (mode == "cron" || mode == "conf" || mode == "preload") return 1
  if (mode == "shell") {
    if (t ~ /""" + _SHELL_CONTROL + r"""/) return 0
    if (t ~ /""" + _EXPORT_ONLY + r"""/) return 0
    if (t ~ /""" + _PLAIN_ASSIGN + r"""/ && t !~ /[$][(]/ && index(t, "`") == 0 && t !~ /""" + _WATCHED_VAR + r"""/) return 0
    return 1
  }
  if (mode == "unit") return (t ~ /""" + _UNIT_KEEP + r"""/ || index(t, "LD_PRELOAD") > 0)
  if (mode == "pam") return (index(t, ".so") > 0)
  if (mode == "udev") return (index(t, "RUN") > 0 || index(t, "PROGRAM") > 0 || index(t, "IMPORT{program}") > 0)
  if (mode == "apt") return (index(t, "Invoke") > 0 || index(t, "Install-Pkgs") > 0)
  if (mode == "desktop") return (t ~ /""" + _DESKTOP_KEEP + r"""/)
  if (mode == "modprobe") return (t ~ /^install[ ]/)
  return 0
}
function flush(   i, n, rest, cnt) {
  if (fname == "") return
  n = 0
  for (i = 1; i <= nr; i++) if (rk[i] && n < maxl) { print "L\t" fname "\t" ln[i] "\t" tx[i]; n++; pr[i] = 1 }
  rest = maxl - n; cnt = 0
  for (i = nr; i >= 1; i--) if (!pr[i] && cnt < rest) { keep[i] = 1; cnt++ }
  for (i = 1; i <= nr; i++) if (keep[i]) print "L\t" fname "\t" ln[i] "\t" tx[i]
  if (nr > maxl) print "LT\t" fname "\t" nr
  split("", ln); split("", tx); split("", rk); split("", pr); split("", keep); nr = 0
}
FNR == 1 { flush(); fname = FILENAME }
{
  t = $0; sub(/\r$/, "", t); gsub(/\t/, " ", t); sub(/^ +/, "", t)
  if (!select_line(t)) next
  nr++; ln[nr] = FNR; tx[nr] = substr(t, 1, maxc); rk[nr] = (t ~ /""" + _RISKY.replace("/", "\\/") + r"""/)
  if (mode == "preload") print "P\t" t
  if (mode == "pam") {
    nf = split(t, w, " "); np = 0
    for (j = 1; j <= nf && np < 4; j++) if (substr(w[j], 1, 1) == "/") { print "P\t" w[j]; np++ }
  }
}
END { flush() }
"""

# authorized_keys: one K line per key -- BLOB, path, line, options, type, comment. The
# shell replaces the blob with its sha256 before anything leaves the machine, so the
# record that leaves is K<TAB>sha256<TAB>path<TAB>line<TAB>options<TAB>type<TAB>comment.
AWK_KEYS = r"""
{
  t = $0; sub(/\r$/, "", t); gsub(/\t/, " ", t); sub(/^ +/, "", t)
  if (t ~ /^(#|$)/) next
  if (++nk > maxk) { if (nk == maxk + 1) print "KT\t" FILENAME; next }
  if (match(t, /(^| )""" + _KEY_TYPE + r""" +[A-Za-z0-9+\/=]+/)) {
    opts = (RSTART > 1) ? substr(t, 1, RSTART - 1) : ""; sub(/ +$/, "", opts)
    rest = substr(t, RSTART + (substr(t, RSTART, 1) == " " ? 1 : 0)); n = split(rest, w, " ")
    c = ""; for (j = 3; j <= n; j++) c = c (j > 3 ? " " : "") w[j]
    print "K\t" w[2] "\t" FILENAME "\t" FNR "\t" substr(opts, 1, maxc) "\t" w[1] "\t" substr(c, 1, 100)
  } else print "K\t-\t" FILENAME "\t" FNR "\t" substr(t, 1, maxc) "\tunparsed\t"
}
"""

_RISKY_RE = re.compile(_RISKY.encode())
_SHELL_CONTROL_RE = re.compile(_SHELL_CONTROL.encode())
_PLAIN_ASSIGN_RE = re.compile(_PLAIN_ASSIGN.encode())
_WATCHED_VAR_RE = re.compile(_WATCHED_VAR.encode())
_EXPORT_ONLY_RE = re.compile(_EXPORT_ONLY.encode())
_UNIT_KEEP_RE = re.compile(_UNIT_KEEP.encode())
_DESKTOP_KEEP_RE = re.compile(_DESKTOP_KEEP.encode())
_KEY_RE = re.compile(rb"(^| )" + _KEY_TYPE.encode() + rb" +[A-Za-z0-9+/=]+")
_COMMENT_RE = re.compile(rb"^(#|;|$)")


def _normalise(raw: bytes) -> bytes:
    t = raw[:-1] if raw.endswith(b"\r") else raw
    return t.replace(b"\t", b" ").lstrip(b" ")


def select_line(mode: str, t: bytes) -> bool:
    """The Python twin of AWK's select_line (t already normalised)."""
    if _COMMENT_RE.match(t):
        return False
    if mode in ("cron", "conf", "preload"):
        return True
    if mode == "shell":
        if _SHELL_CONTROL_RE.search(t) or _EXPORT_ONLY_RE.search(t):
            return False
        if _PLAIN_ASSIGN_RE.search(t) and b"$(" not in t and b"`" not in t and not _WATCHED_VAR_RE.search(t):
            return False
        return True
    if mode == "unit":
        return bool(_UNIT_KEEP_RE.search(t)) or b"LD_PRELOAD" in t
    if mode == "pam":
        return b".so" in t
    if mode == "udev":
        return b"RUN" in t or b"PROGRAM" in t or b"IMPORT{program}" in t
    if mode == "apt":
        return b"Invoke" in t or b"Install-Pkgs" in t
    if mode == "desktop":
        return bool(_DESKTOP_KEEP_RE.search(t))
    if mode == "modprobe":
        return t.startswith(b"install ")
    return False


def _b(text: bytes) -> str:
    return text.decode("utf-8", "replace")


def extract_lines(mode: str, path: str, data: bytes) -> list[str]:
    """The records AWK prints for one file (L/LT/P), byte for byte."""
    out: list[str] = []
    picked: list[tuple[int, bytes, bool]] = []
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for n, raw in enumerate(lines, 1):
        t = _normalise(raw)
        if not select_line(mode, t):
            continue
        picked.append((n, t[:MAX_LINE_CHARS], bool(_RISKY_RE.search(t))))
        if mode == "preload":
            out.append("P\t" + _b(t))
        if mode == "pam":
            for w in [w for w in t.split(b" ") if w.startswith(b"/")][:4]:
                out.append("P\t" + _b(w))
    shown: list[int] = []
    for i, (_n, _t, risky) in enumerate(picked):
        if risky and len(shown) < MAX_LINES_PER_FILE:
            shown.append(i)
    rest = MAX_LINES_PER_FILE - len(shown)
    tail = [i for i in range(len(picked) - 1, -1, -1) if i not in shown][:rest]
    lines_out = [f"L\t{path}\t{picked[i][0]}\t{_b(picked[i][1])}" for i in shown]
    lines_out += [f"L\t{path}\t{picked[i][0]}\t{_b(picked[i][1])}" for i in sorted(tail)]
    # awk prints P records as it reads and L records at the end of the file
    out += lines_out
    if len(picked) > MAX_LINES_PER_FILE:
        out.append(f"LT\t{path}\t{len(picked)}")
    return out


def key_records(path: str, data: bytes) -> list[str]:
    """K/KT records for one authorized_keys file -- the fingerprint, never the key."""
    out: list[str] = []
    n = 0
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for lineno, raw in enumerate(lines, 1):
        t = _normalise(raw)
        if t == b"" or t.startswith(b"#"):
            continue
        n += 1
        if n > MAX_KEYS_PER_FILE:
            if n == MAX_KEYS_PER_FILE + 1:
                out.append(f"KT\t{path}")
            continue
        m = _KEY_RE.search(t)
        if not m:
            out.append(f"K\t-\t{path}\t{lineno}\t{_b(t[:MAX_LINE_CHARS])}\tunparsed\t")
            continue
        start = m.start() + (1 if t[m.start():m.start() + 1] == b" " else 0)
        opts = t[:m.start()].rstrip(b" ")
        words = [w for w in t[start:].split(b" ") if w]
        comment = b" ".join(words[2:])[:100]
        out.append(f"K\t{blob_sha256(words[1].decode('ascii', 'replace'))}\t{path}\t{lineno}\t"
                   f"{_b(opts[:MAX_LINE_CHARS])}\t{_b(words[0])}\t{_b(comment)}")
    return out


_B64_ALPHABET = re.compile(rb"[^A-Za-z0-9+/]")


def blob_sha256(blob: str) -> str:
    """sha256 (hex) of a base64 key blob, as `base64 -d | sha256sum` prints it.

    GNU `base64 -d` ignores characters outside the alphabet and decodes what is
    left, dropping a dangling partial group of one character; Python's
    `b64decode` raises on either. We match GNU so the SSH script (which pipes
    through real `base64 -d`) and this Python twin agree on the same line -- a
    real key blob is always well-formed, so this only matters for odd input, but
    the two transports must still produce the same fingerprint for it."""
    cleaned = _B64_ALPHABET.sub(b"", blob.encode("ascii", "ignore"))
    if len(cleaned) % 4 == 1:
        cleaned = cleaned[:-1]
    try:
        raw = base64.b64decode(cleaned + b"=" * (-len(cleaned) % 4), validate=False)
    except (binascii.Error, ValueError):
        return "-"
    return hashlib.sha256(raw).hexdigest()


def fingerprint(hex_digest: str) -> str | None:
    """OpenSSH's SHA256 fingerprint ("SHA256:...") from a hex sha256 of the blob."""
    try:
        raw = bytes.fromhex(hex_digest)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return "SHA256:" + base64.b64encode(raw).decode().rstrip("=")


# --------------------------------------------------------------------------- the SSH script
_SH_HEAD = r"""
LC_ALL=C; export LC_ALL
TAB=$(printf '\t')
NL='
'
"""

# kr_list area mode vendor kind path [suffix]: an item line "area<TAB>mode<TAB>vendor<TAB>path"
# for the location itself (file) or each of its entries (dir/tree); notes (alias, gap,
# truncated, odd name) as "N<TAB>..." lines. Unreadable directories become gaps.
_SH_LIST = r"""
kr_list() {
  _a=$1; _m=$2; _v=$3; _k=$4; _p=$5; _s=$6
  if [ -L "$_p" ]; then
    if [ "$_k" = file ]; then printf '%s\t%s\t%s\t%s\n' "$_a" "$_m" "$_v" "$_p"
    else printf 'N\tA\t%s\t%s\t%s\n' "$_a" "$_p" "$(readlink "$_p" 2>/dev/null)"; fi
    return
  fi
  [ -e "$_p" ] || return
  if [ "$_k" = file ]; then printf '%s\t%s\t%s\t%s\n' "$_a" "$_m" "$_v" "$_p"; return; fi
  [ -d "$_p" ] || return
  _rp=$(readlink -f "$_p" 2>/dev/null)
  if [ -n "$_rp" ] && [ "$_rp" != "$_p" ]; then printf 'N\tA\t%s\t%s\t%s\n' "$_a" "$_p" "$_rp"; return; fi
  if [ ! -r "$_p" ] || [ ! -x "$_p" ]; then printf 'N\tG\t%s\t%s\tunreadable\n' "$_a" "$_p"; return; fi
  _d=1; [ "$_k" = tree ] && _d=3
  _all=$(find "$_p" -mindepth 1 -maxdepth $_d \( -type f -o -type l \) 2>/dev/null | sort)
  [ -n "$_all" ] || return
  _n=$(printf '%s\n' "$_all" | wc -l)
  [ "$_n" -gt @MAXF@ ] && printf 'N\tT\t%s\t%s\t%s\n' "$_a" "$_p" "$_n"
  printf '%s\n' "$_all" | head -n @MAXF@ | while IFS= read -r _f; do
    case "$_f" in
      "$_p"/*) ;;
      *) printf 'N\tODD\t%s\t%s\n' "$_a" "$_p"; continue ;;
    esac
    case "$_f" in *"$TAB"*) printf 'N\tODD\t%s\t%s\n' "$_a" "$_p"; continue ;; esac
    if [ -n "$_s" ]; then case "$_f" in *"$_s") ;; *) continue ;; esac; fi
    printf '%s\t%s\t%s\t%s\n' "$_a" "$_m" "$_v" "$_f"
  done
  if [ "$_k" = tree ]; then
    find "$_p" -mindepth 1 -maxdepth 2 -type d 2>/dev/null | head -n 50 | while IFS= read -r _f; do
      { [ -r "$_f" ] && [ -x "$_f" ]; } || printf 'N\tG\t%s\t%s\tunreadable\n' "$_a" "$_f"
    done
  fi
}
"""


def _sh_q(s: str) -> str:
    return shlex.quote(s)


def build_script(root: str = "", verify: bool = False) -> str:
    """The persistence read over SSH. Read-only, as the SSH user (no sudo), POSIX
    sh + awk (gawk, mawk, BusyBox). Every interpolated value is a constant from
    this file. `root` exists for tests only (a fake tree)."""
    r = root.rstrip("/")
    awk_prog, keys_prog = _sh_q(AWK), _sh_q(AWK_KEYS)
    out = [_SH_HEAD, catalog.FAMILY_SH.replace("/etc/os-release", f"{r}/etc/os-release"),
           "printf 'M\\tfamily\\t%s\\n' \"$FAMILY\"",
           "printf 'M\\tnow\\t%s\\n' \"$(date +%s)\"",
           "printf 'M\\tuid\\t%s\\n' \"$(id -u)\"",
           "printf 'M\\tverify\\t%s\\n' " + ("1" if verify else "0"),
           _SH_LIST.replace("@MAXF@", str(MAX_FILES_PER_LOCATION)),
           "kr_listing() {", "case \"$FAMILY\" in"]
    for family in catalog.FAMILIES:
        body = [f"kr_list {loc.area} {loc.mode} {1 if loc.vendor else 0} {loc.kind} "
                f"{_sh_q(r + loc.path)} {_sh_q(loc.name_suffix)}" for loc in locations_for(family)]
        out.append(f"{family})\n" + "\n".join(body) + "\n;;")
    out += ["*) : ;;", "esac"]
    home_cases = []
    for family in catalog.FAMILIES:
        lines = [f"    kr_list {loc.area} {loc.mode} 0 {loc.kind} \"$_h\"/{_sh_q(loc.path)} ''"
                 for loc in home_locations_for(family)]
        home_cases.append(f"  {family})\n" + "\n".join(lines) + "\n  ;;")
    out.append(
        "awk -F: 'NF >= 7 && $7 !~ /(nologin|false|sync|halt|shutdown)$/ && $6 != \"\" && $6 != \"/\" "
        f"{{ print $1 \"\\t\" $6 }}' {_sh_q(r + '/etc/passwd')} 2>/dev/null | head -n {MAX_USERS} | "
        "while IFS=\"$TAB\" read -r _u _h; do\n"
        f"  _h={_sh_q(r)}\"$_h\"\n"
        "  [ -d \"$_h\" ] || continue\n"
        "  printf 'N\\tU\\t%s\\t%s\\n' \"$_u\" \"$_h\"\n"
        "  if [ ! -r \"$_h\" ] || [ ! -x \"$_h\" ]; then printf 'N\\tG\\thome\\t%s\\tunreadable\\n' \"$_h\"; continue; fi\n"
        "  case \"$FAMILY\" in\n" + "\n".join(home_cases) + "\n  *) : ;;\n  esac\n"
        "  if [ -d \"$_h/.ssh\" ] && { [ ! -r \"$_h/.ssh\" ] || [ ! -x \"$_h/.ssh\" ]; }; then "
        "printf 'N\\tG\\tssh\\t%s\\tunreadable\\n' \"$_h/.ssh\"; fi\n"
        "done")
    out.append("}")
    out.append(_SH_MAIN)
    script = "\n".join(out)
    mods = " ".join(m for m in MODES if m not in ("keys", "none"))
    skip = "|".join(f"{p}|{p}/*" for p in SKIP_MOUNT_PREFIXES)
    q = _sh_q(r) if r else ""
    for key, val in (("SUIDT", str(SUID_FIND_SECONDS)), ("LOCALFS", " ".join(LOCAL_FS_TYPES)),
                     ("SKIPMOUNTS", skip), ("MAXSUID", str(MAX_SUID_FILES)), ("MAXTEXT", str(MAX_TEXT_BYTES)),
                     ("MODELIST", mods), ("MAXL", str(MAX_LINES_PER_FILE)), ("MAXC", str(MAX_LINE_CHARS)),
                     ("MAXK", str(MAX_KEYS_PER_FILE)), ("AWKPROG", awk_prog), ("KEYSPROG", keys_prog),
                     ("ROOTV", q or "''"), ("ROOT", q)):
        script = script.replace(f"@{key}@", val)
    if verify:
        script += _VERIFY_SH
    # everything through one byte cap: a cut-off read has no END line (the parser says partial)
    return "{\n" + script + "printf 'END\\n'\n} | head -c " + str(OUTPUT_CAP_BYTES) + "\nexit 0\n"


_SH_MAIN = r"""
LIST=$(kr_listing)
printf '%s\n' "$LIST" | grep '^N	'
LIST=$(printf '%s\n' "$LIST" | grep -v '^N	' | grep -v '^$')
# SUID/SGID: local filesystems only, one bounded find per mount
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout @SUIDT@"
MOUNTS=$(awk 'BEGIN { n = split("@LOCALFS@", ok, " "); for (i = 1; i <= n; i++) good[ok[i]] = 1 }
  ($3 in good) { print $2 }' /proc/mounts 2>/dev/null | sort -u)
SUIDRAW=$(printf '%s\n' "$MOUNTS" | while IFS= read -r _mp; do
  [ -n "$_mp" ] || continue
  case "$_mp" in @SKIPMOUNTS@) continue ;; esac
  $TO find @ROOT@"$_mp" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
  [ $? -eq 124 ] && printf 'SUIDTO\t%s\n' "$_mp"
done | sort -u)
printf '%s\n' "$SUIDRAW" | grep '^SUIDTO	'
SUIDLIST=$(printf '%s\n' "$SUIDRAW" | grep '^/' | head -n @MAXSUID@)
_ns=$(printf '%s\n' "$SUIDRAW" | grep -c '^/')
[ "$_ns" -gt @MAXSUID@ ] && printf 'N\tT\tsuid\t/\t%s\n' "$_ns"
ITEMS=$( { printf '%s\n' "$LIST"; printf '%s\n' "$SUIDLIST" | grep '^/' | sed "s/^/suid${TAB}none${TAB}0${TAB}/"; } | grep -v '^$')
printf '%s\n' "$ITEMS" | sed 's/^/I	/'
PATHS=$(printf '%s\n' "$ITEMS" | cut -f4)
STATS=$(printf '%s\n' "$PATHS" | grep -v '^$' | tr '\n' '\0' | xargs -0 -r stat -c "%n${TAB}%u${TAB}%U${TAB}%a${TAB}%s${TAB}%Y${TAB}%h${TAB}%F" 2>/dev/null)
printf '%s\n' "$STATS" | grep -v '^$' | sed 's/^/S	/'
printf '%s\n' "$STATS" | awk -F'\t' '$8 == "symbolic link" { print $1 }' | while IFS= read -r _f; do
  printf 'LNK\t%s\t%s\n' "$_f" "$(readlink "$_f" 2>/dev/null)"
done
# readable regular single-link files under the size cap
OKF=$(printf '%s\n' "$STATS" | awk -F'\t' '$8 ~ /^regular/ && $7 == 1 && $5 <= @MAXTEXT@ { print $1 }' | while IFS= read -r _f; do
  [ -r "$_f" ] && printf '%s\n' "$_f"
done)
printf '%s\n' "$STATS" | awk -F'\t' '$8 ~ /^regular/ && $7 == 1 { print $1 }' | while IFS= read -r _f; do
  [ -r "$_f" ] || printf 'NR\t%s\n' "$_f"
done
kr_pick() {  # mode vendor(0|1|all): the readable files of that mode
  printf '%s\n' "$ITEMS" | awk -F'\t' -v m="$1" -v v="$2" '$2 == m && (v == "all" || $3 == v) { print $4 }' | while IFS= read -r _f; do
    case "$NL$OKF$NL" in *"$NL$_f$NL"*) printf '%s\n' "$_f" ;; esac
  done
}
EXTRACT=""
for _m in @MODELIST@; do
  _o=$(kr_pick "$_m" 0 | tr '\n' '\0' | xargs -0 -r awk -v mode="$_m" -v maxl=@MAXL@ -v maxc=@MAXC@ @AWKPROG@ 2>/dev/null)
  [ -n "$_o" ] && EXTRACT="$EXTRACT$NL$_o"
done
printf '%s\n' "$EXTRACT" | grep -E '^(L|LT)	'
kr_pick keys all | tr '\n' '\0' | xargs -0 -r awk -v maxk=@MAXK@ -v maxc=@MAXC@ @KEYSPROG@ 2>/dev/null | while IFS= read -r _l; do
  _k=${_l%%"$TAB"*}; _r=${_l#*"$TAB"}
  if [ "$_k" = KT ]; then printf 'KT\t%s\n' "$_r"; continue; fi
  _b=${_r%%"$TAB"*}; _r=${_r#*"$TAB"}
  [ "$_b" != "-" ] && _b=$(printf '%s' "$_b" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1)
  printf 'K\t%s\t%s\n' "$_b" "$_r"
done
REFS=$(printf '%s\n' "$EXTRACT" | sed -n 's/^P	//p' | grep '^/' | grep -v ' ' | sort -u | head -n 50)
[ -n "$REFS" ] && printf '%s\n' "$REFS" | sed 's/^/REF	/'
# where sshd looks for keys (a non-default place, or a command that hands out keys)
for _f in @ROOT@/etc/ssh/sshd_config @ROOT@/etc/ssh/sshd_config.d/*.conf; do
  [ -r "$_f" ] && grep -iE '^[[:space:]]*(AuthorizedKeysFile|AuthorizedKeysCommand)[[:space:]]' "$_f" 2>/dev/null | head -n 10 | while IFS= read -r _l; do
    printf 'SSHD\t%s\t%s\n' "$_f" "$(printf '%s' "$_l" | tr '\t' ' ' | cut -c1-@MAXC@)"
  done
done
# kernel: loaded modules + taint -- not in a container (its kernel is the host's)
CT=none
if command -v systemd-detect-virt >/dev/null 2>&1; then
  CT=$(systemd-detect-virt -c 2>/dev/null | head -n 1); [ -n "$CT" ] || CT=none
else
  for _c in @ROOT@/run/.containerenv @ROOT@/.dockerenv; do [ -e "$_c" ] && CT=container; done
  grep -q ' fuse.lxcfs ' @ROOT@/proc/mounts 2>/dev/null && CT=lxc
  grep -qa 'container=' @ROOT@/proc/1/environ 2>/dev/null && CT=container
fi
printf 'M\tcontainer\t%s\n' "$CT"
MODPATHS=""
if [ "$CT" = none ] && [ -r @ROOT@/proc/modules ]; then
  printf 'TAINT\t%s\n' "$(cat @ROOT@/proc/sys/kernel/tainted 2>/dev/null)"
  awk '{ t = ""; if (match($0, /[(][A-Z]+[)]$/)) t = substr($0, RSTART + 1, RLENGTH - 2); print "MOD\t" $1 "\t" t }' @ROOT@/proc/modules | head -n 1000
  KREL=$(uname -r)
  DEP=@ROOT@/lib/modules/$KREL/modules.dep; [ -r "$DEP" ] || DEP=@ROOT@/usr/lib/modules/$KREL/modules.dep
  if [ -r "$DEP" ]; then
    MODPATHS=$(awk -v d="${DEP%/modules.dep}" 'NR == FNR { want[$1] = 1; next }
      { p = $1; sub(/:$/, "", p); n = p; sub(/.*\//, "", n); sub(/[.]ko([.](xz|zst|gz))?$/, "", n); gsub(/-/, "_", n)
        if (n in want) print "MODPATH\t" n "\t" d "/" p }' @ROOT@/proc/modules "$DEP")
    [ -n "$MODPATHS" ] && printf '%s\n' "$MODPATHS"
  else printf 'MODERR\tthe module list (modules.dep) is not readable\n'; fi
fi
# package ownership of every path above, from the package database files
WANT=$( { printf '%s\n' "$PATHS"; printf '%s\n' "$REFS"; printf '%s\n' "$MODPATHS" | cut -f3; } | grep '^/' | sort -u)
kr_alts='function alt(p) { if (p ~ /^\/usr\/(lib|bin|sbin|lib64)\//) return substr(p, 5); if (p ~ /^\/(lib|bin|sbin|lib64)\//) return "/usr" p; return "" }'
OWNOUT=""
case "$FAMILY" in
debian)
  if [ -r @ROOT@/var/lib/dpkg/info ]; then
    printf 'OWNSRC\tdpkg\n'
    OWNOUT=$(printf '%s\n' "$WANT" | awk -v root=@ROOTV@ "$kr_alts"'
      NR == FNR { k = substr($0, length(root) + 1); want[k] = $0; a = alt(k); if (a != "") want[a] = $0; next }
      ($0 in want) { f = FILENAME; sub(/.*\//, "", f); sub(/[.]list$/, "", f); print "OWN\t" want[$0] "\t" f }' - @ROOT@/var/lib/dpkg/info/*.list 2>/dev/null | sort -u)
  else printf 'OWNERR\tthe dpkg database is not readable here\n'; fi ;;
rhel)
  if command -v rpm >/dev/null 2>&1; then
    printf 'OWNSRC\trpm\n'
    OWNOUT=$( { printf '%s\n' "$WANT" | sed 's/^/W	/'; rpm -qa --qf '[R\t%{FILENAMES}\t%{=NAME}\n]' 2>/dev/null; } | awk -F'\t' -v root=@ROOTV@ "$kr_alts"'
      $1 == "W" { k = substr($2, length(root) + 1); want[k] = $2; a = alt(k); if (a != "") want[a] = $2; next }
      $1 == "R" && ($2 in want) { print "OWN\t" want[$2] "\t" $3 }' | sort -u)
    [ -n "$OWNOUT" ] || printf 'OWNERR\tthe rpm database gave no answer\n'
  else printf 'OWNERR\tno rpm command on this machine\n'; fi ;;
alpine)
  if [ -r @ROOT@/lib/apk/db/installed ]; then
    printf 'OWNSRC\tapk\n'
    OWNOUT=$(printf '%s\n' "$WANT" | awk -v root=@ROOTV@ "$kr_alts"'
      NR == FNR { k = substr($0, length(root) + 1); want[k] = $0; a = alt(k); if (a != "") want[a] = $0; next }
      /^P:/ { pkg = substr($0, 3) } /^F:/ { dir = substr($0, 3) }
      /^R:/ { p = "/" dir "/" substr($0, 3); if (p in want) print "OWN\t" want[p] "\t" pkg }' - @ROOT@/lib/apk/db/installed 2>/dev/null | sort -u)
  else printf 'OWNERR\tthe apk database is not readable here\n'; fi ;;
*) printf 'OWNERR\tunknown Linux distribution\n' ;;
esac
[ -n "$OWNOUT" ] && printf '%s\n' "$OWNOUT"
OWNED=$(printf '%s\n' "$OWNOUT" | cut -f2)
# hashes: everything except package-owned files in package-managed directories
VEND=$(printf '%s\n' "$ITEMS" | awk -F'\t' '$3 == "1" { print $4 }')
HASHME=$(printf '%s\n' "$OKF" | while IFS= read -r _f; do
  [ -n "$_f" ] || continue
  case "$NL$VEND$NL" in *"$NL$_f$NL"*) case "$NL$OWNED$NL" in *"$NL$_f$NL"*) continue ;; esac ;; esac
  printf '%s\n' "$_f"
done)
SUIDOK=$(printf '%s\n' "$SUIDLIST" | while IFS= read -r _f; do
  [ -n "$_f" ] && [ -f "$_f" ] && [ ! -L "$_f" ] && [ -r "$_f" ] && printf '%s\n' "$_f"
done)
{ printf '%s\n' "$HASHME"; printf '%s\n' "$SUIDOK"; } | grep -v '^$' | sort -u | tr '\n' '\0' | xargs -0 -r sha256sum 2>/dev/null | sed 's/^\\\([0-9a-f]\{64\}\)  /HE	\1	/; s/^\([0-9a-f]\{64\}\)  /H	\1	/'
# package-managed files NOT owned by any package: their lines too
VUN=$(printf '%s\n' "$ITEMS" | awk -F'\t' '$3 == "1" { print $2 "\t" $4 }' | while IFS="$TAB" read -r _m _f; do
  case "$NL$OWNED$NL" in *"$NL$_f$NL"*) continue ;; esac
  case "$NL$OKF$NL" in *"$NL$_f$NL"*) printf '%s\t%s\n' "$_m" "$_f" ;; esac
done)
for _m in @MODELIST@; do
  printf '%s\n' "$VUN" | awk -F'\t' -v m="$_m" '$1 == m { print $2 }' | grep -v '^$' | tr '\n' '\0' | xargs -0 -r awk -v mode="$_m" -v maxl=@MAXL@ -v maxc=@MAXC@ @AWKPROG@ 2>/dev/null | grep -E '^(L|LT)	'
done
"""

_VERIFY_SH = r"""
PKGS=$(printf '%s\n' "$OWNOUT" | cut -f3 | grep -E '^[A-Za-z0-9][A-Za-z0-9+._:~-]*$' | sort -u | head -n 300)
case "$FAMILY" in
debian) if [ -n "$PKGS" ]; then dpkg --verify $PKGS 2>/dev/null | awk '{ print "V\t" $0 }'; fi; printf 'VDONE\tdpkg\n' ;;
rhel) if [ -n "$PKGS" ]; then rpm -V $PKGS 2>/dev/null | awk '{ print "V\t" $0 }'; fi; printf 'VDONE\trpm\n' ;;
alpine) if command -v apk >/dev/null 2>&1; then { apk audit 2>/dev/null; apk audit --system 2>/dev/null; } | awk '$1 == "U" { print "V\t" $0 }'; printf 'VDONE\tapk\n'; else printf 'VERR\tno apk command\n'; fi ;;
*) printf 'VERR\tunknown Linux distribution\n' ;;
esac
"""


# --------------------------------------------------------------------------- parsing (both transports)
_V_DPKG_RPM_RE = re.compile(r"^(?P<flags>\S{9})\s+(?:(?P<attr>[cdglr])\s+)?(?P<path>/.*)$")
_V_APK_RE = re.compile(r"^(?P<flag>[A-Za-z])\s+(?P<path>\S.*)$")


def _unescape_sum_name(name: str) -> str:
    """sha256sum's escaped file name ("\\\\" and "\\n") back to the real name."""
    out, i = [], 0
    while i < len(name):
        if name[i] == "\\" and i + 1 < len(name):
            out.append("\n" if name[i + 1] == "n" else name[i + 1])
            i += 2
        else:
            out.append(name[i])
            i += 1
    return "".join(out)


def _int_or_none(text: str) -> int | None:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_output(stdout: str, root: str = "") -> dict[str, Any]:
    """The inventory both transports print, as one structure. `root` (tests
    only) is stripped from every path."""
    r = root.rstrip("/")

    def p(path: str) -> str:
        return path[len(r):] if r and path.startswith(r) else path

    inv: dict[str, Any] = {
        "family": None, "now": None, "reader_uid": None, "verify_requested": False, "container": None,
        "items": {}, "keys": [], "modules": {}, "taint": None, "refs": {}, "gaps": [], "aliases": [],
        "truncated": [], "odd_names": [], "users": {}, "sshd": [], "suid_timeouts": [],
        "ownership": {"source": None, "error": None},
        "verify": {"done": False, "tool": None, "error": None, "changed": {}},
        "module_error": None, "complete": False,
    }
    items: dict[str, dict[str, Any]] = inv["items"]
    lines_by_path: dict[str, list[tuple[int, str]]] = {}
    owners: dict[str, str] = {}
    for raw in stdout.split("\n"):
        cols = raw.split("\t")
        tag = cols[0]
        if tag in AREAS and len(cols) >= 4:     # an item line straight from the listing (agent)
            continue
        if tag == "M" and len(cols) >= 3:
            key, val = cols[1], cols[2]
            if key == "family":
                inv["family"] = val if val in catalog.FAMILIES else None
            elif key == "now":
                inv["now"] = _int_or_none(val)
            elif key == "uid":
                inv["reader_uid"] = _int_or_none(val)
            elif key == "verify":
                inv["verify_requested"] = val == "1"
            elif key == "container":
                inv["container"] = val or "none"
        elif tag == "N" and len(cols) >= 4:
            kind = cols[1]
            if kind == "G":
                inv["gaps"].append({"area": cols[2], "path": p(cols[3]), "reason": cols[4] if len(cols) > 4 else ""})
            elif kind == "A":
                inv["aliases"].append({"area": cols[2], "path": p(cols[3]), "target": cols[4] if len(cols) > 4 else ""})
            elif kind == "T":
                inv["truncated"].append({"area": cols[2], "path": p(cols[3]), "count": _int_or_none(cols[4] if len(cols) > 4 else "")})
            elif kind == "ODD":
                inv["odd_names"].append({"area": cols[2], "path": p(cols[3])})
            elif kind == "U":
                inv["users"][cols[2]] = p(cols[3]) if len(cols) > 3 else ""
        elif tag == "I" and len(cols) >= 5:     # agent: area mode vendor path
            items.setdefault(p(cols[4]), {"path": p(cols[4]), "area": cols[1], "mode": cols[2], "vendor": cols[3] == "1"})
        elif tag == "S" and len(cols) >= 9:
            path = p(cols[1])
            it = items.setdefault(path, {"path": path})
            it.update({"uid": _int_or_none(cols[2]), "owner": cols[3], "perm": cols[4], "size": _int_or_none(cols[5]),
                       "mtime": _int_or_none(cols[6]), "nlink": _int_or_none(cols[7]), "type": cols[8]})
        elif tag == "LNK" and len(cols) >= 3:
            items.setdefault(p(cols[1]), {"path": p(cols[1])})["link"] = cols[2]
        elif tag == "NR" and len(cols) >= 2:
            items.setdefault(p(cols[1]), {"path": p(cols[1])})["unreadable"] = True
        elif tag == "RF" and len(cols) >= 3:     # agent: refused by the hardened opener
            items.setdefault(p(cols[1]), {"path": p(cols[1])})["refused"] = cols[2]
        elif tag in ("H", "HE") and len(cols) >= 3:
            path = p(_unescape_sum_name("\t".join(cols[2:])) if tag == "HE" else "\t".join(cols[2:]))
            items.setdefault(path, {"path": path})["sha256"] = cols[1]
        elif tag == "L" and len(cols) >= 4:
            n = _int_or_none(cols[2])
            if n is not None:
                lines_by_path.setdefault(p(cols[1]), []).append((n, "\t".join(cols[3:])))
        elif tag == "LT" and len(cols) >= 3:
            items.setdefault(p(cols[1]), {"path": p(cols[1])})["lines_total"] = _int_or_none(cols[2])
        elif tag == "K" and len(cols) >= 6:
            inv["keys"].append({"path": p(cols[2]), "line": _int_or_none(cols[3]), "options": cols[4], "type": cols[5],
                                "fingerprint": fingerprint(cols[1]) if cols[1] != "-" else None,
                                "comment": cols[6] if len(cols) > 6 else ""})
        elif tag == "KT" and len(cols) >= 2:
            items.setdefault(p(cols[1]), {"path": p(cols[1])})["keys_truncated"] = True
        elif tag == "REF" and len(cols) >= 2:
            inv["refs"].setdefault(p(cols[1]), None)
        elif tag == "SSHD" and len(cols) >= 3:
            inv["sshd"].append({"file": p(cols[1]), "line": cols[2]})
        elif tag == "SUIDTO" and len(cols) >= 2:
            inv["suid_timeouts"].append(cols[1])
        elif tag == "TAINT" and len(cols) >= 2:
            inv["taint"] = _int_or_none(cols[1])
        elif tag == "MOD" and len(cols) >= 2:
            inv["modules"].setdefault(cols[1], {"name": cols[1], "taint": cols[2] if len(cols) > 2 else "", "path": None})
        elif tag == "MODPATH" and len(cols) >= 3:
            inv["modules"].setdefault(cols[1], {"name": cols[1], "taint": "", "path": None})["path"] = p(cols[2])
        elif tag == "MODERR" and len(cols) >= 2:
            inv["module_error"] = cols[1]
        elif tag == "OWNSRC" and len(cols) >= 2:
            inv["ownership"]["source"] = cols[1]
        elif tag == "OWNERR" and len(cols) >= 2:
            inv["ownership"]["error"] = cols[1]
        elif tag == "OWN" and len(cols) >= 3:
            owners[p(cols[1])] = cols[2]
        elif tag == "V" and len(cols) >= 2:
            _parse_verify_line("\t".join(cols[1:]), inv["verify"]["changed"], p)
        elif tag == "VDONE":
            inv["verify"]["done"] = True
            inv["verify"]["tool"] = cols[1] if len(cols) > 1 else None
        elif tag == "VERR":
            inv["verify"]["error"] = cols[1] if len(cols) > 1 else "verification failed"
        elif tag == "END":
            inv["complete"] = True
    # areas/modes for SSH items come from the listing lines -- reconstruct from the table
    _attach_locations(inv, r)
    for path, it in items.items():
        if path in owners:
            it["package"] = owners[path]
        if path in lines_by_path:
            it["lines"] = [{"n": n, "text": t} for n, t in sorted(set(lines_by_path[path]))]
    for path in list(inv["refs"]):
        inv["refs"][path] = owners.get(path)
    for m in inv["modules"].values():
        if m.get("path"):
            m["package"] = owners.get(m["path"])
    for k in inv["keys"]:
        k["user"] = _key_user(k["path"], inv["users"])
    return inv


def _parse_verify_line(line: str, out: dict[str, dict[str, Any]], p: Callable[[str], str]) -> None:
    m = _V_DPKG_RPM_RE.match(line.strip())
    if m:
        flags = m.group("flags")
        if flags.startswith("missing"):
            return
        out[p(m.group("path"))] = {"flags": flags, "config": m.group("attr") == "c",
                                   "content_changed": len(flags) > 2 and flags[2] == "5"}
        return
    m = _V_APK_RE.match(line.strip())
    if m and m.group("flag") == "U":
        path = m.group("path")
        path = path if path.startswith("/") else "/" + path
        out[p(path)] = {"flags": "U", "config": path.startswith("/etc/"), "content_changed": True}


def _key_user(path: str, users: dict[str, str]) -> str | None:
    best = None
    for user, home in users.items():
        if home and path.startswith(home.rstrip("/") + "/"):
            if best is None or len(home) > len(users[best]):
                best = user
    return best


def _location_of(path: str, family: str | None, users: dict[str, str], r: str) -> Loc | None:
    """The table entry a path was listed under (longest matching location)."""
    best: Loc | None = None
    best_len = -1
    for loc in locations_for(family):
        lp = loc.path
        if (path == lp or path.startswith(lp.rstrip("/") + "/")) and len(lp) > best_len:
            best, best_len = loc, len(lp)
    for home in users.values():
        h = home.rstrip("/")
        for loc in home_locations_for(family):
            lp = h + "/" + loc.path
            if (path == lp or path.startswith(lp + "/")) and len(lp) > best_len:
                best, best_len = loc, len(lp)
    return best


def _attach_locations(inv: dict[str, Any], r: str) -> None:
    for path, it in inv["items"].items():
        if "area" in it:
            continue
        loc = _location_of(path, inv["family"], inv["users"], r)
        if loc is not None:
            it.update({"area": loc.area, "mode": loc.mode, "vendor": loc.vendor})
        else:
            it.update({"area": "suid", "mode": "none", "vendor": False})
    # a SUID/SGID file is a SUID item whatever directory it is in
    for it in inv["items"].values():
        perm = str(it.get("perm") or "")
        if len(perm) == 4 and perm[0] in "2367" and it.get("area") != "suid" and str(it.get("type", "")).startswith("regular"):
            it["suid_bits"] = True
        if it.get("area") == "suid":
            it["suid_bits"] = True


# --------------------------------------------------------------------------- the agent's walk (root, hardened)
Runner = Callable[[list, float, int], dict]


def _os_family(root: str) -> str | None:
    try:
        with open(root + "/etc/os-release", encoding="utf-8", errors="replace") as f:
            return catalog.family_from_os_release(f.read(16384))
    except OSError:
        return None


_TYPE_NAMES = {stat.S_IFREG: "regular file", stat.S_IFLNK: "symbolic link", stat.S_IFDIR: "directory",
               stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket", stat.S_IFCHR: "character special file",
               stat.S_IFBLK: "block special file"}


def _type_name(st: os.stat_result) -> str:
    kind = stat.S_IFMT(st.st_mode)
    if kind == stat.S_IFREG and st.st_size == 0:
        return "regular empty file"
    return _TYPE_NAMES.get(kind, "weird file")


def _user_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return "UNKNOWN"


def _list_location(loc_area: str, mode: str, vendor: bool, kind: str, path: str, suffix: str,
                   items: list[tuple[str, str, bool, str]], notes: list[str]) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        if kind == "file":
            items.append((loc_area, mode, vendor, path))
        else:
            try:
                target = os.readlink(path)
            except OSError:
                target = ""
            notes.append(f"N\tA\t{loc_area}\t{path}\t{target}")
        return
    if kind == "file":
        items.append((loc_area, mode, vendor, path))
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    real = os.path.realpath(path)
    if real != path:
        notes.append(f"N\tA\t{loc_area}\t{path}\t{real}")
        return
    depth = 3 if kind == "tree" else 1
    found: list[str] = []
    odd = False

    def walk(d: str, level: int) -> None:
        nonlocal odd
        try:
            entries = list(os.scandir(d))
        except OSError:
            notes.append(f"N\tG\t{loc_area}\t{d}\tunreadable")
            return
        for e in entries:
            if "\n" in e.name or "\t" in e.name:
                odd = True
                continue
            full = d.rstrip("/") + "/" + e.name
            try:
                is_dir = e.is_dir(follow_symlinks=False)
                is_file_or_link = e.is_file(follow_symlinks=False) or e.is_symlink()
            except OSError:
                continue
            if is_file_or_link:
                found.append(full)
            elif is_dir and level < depth:
                walk(full, level + 1)

    walk(path, 1)
    if odd:
        notes.append(f"N\tODD\t{loc_area}\t{path}")
    found.sort()
    if len(found) > MAX_FILES_PER_LOCATION:
        notes.append(f"N\tT\t{loc_area}\t{path}\t{len(found)}")
    for f in found[:MAX_FILES_PER_LOCATION]:
        if suffix and not f.endswith(suffix):
            continue
        items.append((loc_area, mode, vendor, f))


def _homes(root: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        fd, _st = hostfiles.open_log_file(root + "/etc/passwd")
    except hostfiles.FileRefused:
        return out
    with os.fdopen(fd, "rb") as f:
        text = f.read(4 * 1024 * 1024).decode("utf-8", "replace")
    for line in text.split("\n"):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        shell, home = parts[6], parts[5]
        if re.search(r"(nologin|false|sync|halt|shutdown)$", shell) or home in ("", "/"):
            continue
        out.append((parts[0], home))
        if len(out) >= MAX_USERS:
            break
    return out


def _read_capped(path: str, cap: int, is_credential: Callable[[str], bool], allow_keys: bool) -> tuple[bytes | None, str]:
    """(content, status) through the hardened opener. Credential locations are never
    read -- except authorized_keys files, and only to derive fingerprints."""
    if is_credential(path) and not (allow_keys and os.path.basename(path) in ("authorized_keys", "authorized_keys2")):
        return None, "refused"
    try:
        fd, st = hostfiles.open_log_file(path)
    except hostfiles.FileRefused as e:
        return None, e.status
    try:
        if st.st_size > cap:
            return None, "too_large"
        chunks, left = [], cap
        while left > 0:
            b = os.read(fd, min(65536, left))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks), "ok"
    finally:
        os.close(fd)


def _hash_file(path: str, is_credential: Callable[[str], bool]) -> str | None:
    if is_credential(path) and os.path.basename(path) not in ("authorized_keys", "authorized_keys2"):
        return None
    try:
        fd, st = hostfiles.open_log_file(path)
    except hostfiles.FileRefused:
        return None
    try:
        if st.st_size > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        while True:
            b = os.read(fd, 1024 * 1024)
            if not b:
                break
            h.update(b)
        return h.hexdigest()
    finally:
        os.close(fd)


def _detect_container(root: str, run: Runner | None) -> str:
    if run is not None and not root:
        try:
            r = run(["systemd-detect-virt", "-c"], 5, 4096)
            word = (r.get("stdout") or "").strip().split()
            if word:
                return word[0] if re.fullmatch(r"[a-z0-9-]{1,32}", word[0]) else "none"
        except Exception:  # noqa: BLE001 -- missing binary etc.: fall back to files
            pass
    ct = "none"
    for f in (root + "/run/.containerenv", root + "/.dockerenv"):
        if os.path.exists(f):
            ct = "container"
    try:
        with open(root + "/proc/mounts", encoding="utf-8", errors="replace") as fh:
            if " fuse.lxcfs " in fh.read(1024 * 1024):
                ct = "lxc"
    except OSError:
        pass
    try:
        with open(root + "/proc/1/environ", "rb") as fh:
            if b"container=" in fh.read(65536):
                ct = "container"
    except OSError:
        pass
    return ct


def _local_mounts(root: str) -> list[str]:
    out = []
    try:
        with open(root + "/proc/mounts", encoding="utf-8", errors="replace") as fh:
            for line in fh.read(4 * 1024 * 1024).split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[2] in LOCAL_FS_TYPES:
                    mp = parts[1].replace("\\040", " ")
                    if not any(mp == s or mp.startswith(s + "/") for s in SKIP_MOUNT_PREFIXES):
                        out.append(mp)
    except OSError:
        pass
    return sorted(set(out))


def _ownership(family: str | None, wanted: set[str], root: str, run: Runner | None) -> tuple[dict[str, str], list[str]]:
    """(path -> package, record lines OWNSRC/OWNERR) -- the same joins the script does."""
    want: dict[str, str] = {}
    for full in wanted:
        k = full[len(root):] if root and full.startswith(root) else full
        want[k] = full
        for a in usrmerge_alternates(k):
            want.setdefault(a, full)
    owners: dict[str, str] = {}
    if family == "debian":
        d = root + "/var/lib/dpkg/info"
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".list"))
        except OSError:
            return owners, ["OWNERR\tthe dpkg database is not readable here"]
        for n in names:
            try:
                with open(os.path.join(d, n), "rb") as fh:
                    for line in fh.read(32 * 1024 * 1024).decode("utf-8", "replace").split("\n"):
                        if line in want:
                            owners.setdefault(want[line], n[:-5])
            except OSError:
                continue
        return owners, ["OWNSRC\tdpkg"]
    if family == "rhel":
        if run is None:
            return owners, ["OWNERR\tno rpm command on this machine"]
        try:
            r = run(["rpm", "-qa", "--qf", "[R\\t%{FILENAMES}\\t%{=NAME}\\n]"], 60, 64 * 1024 * 1024)
        except Exception as e:  # noqa: BLE001
            return owners, [f"OWNERR\trpm failed: {str(e)[:120]}"]
        for line in (r.get("stdout") or "").split("\n"):
            cols = line.split("\t")
            if len(cols) >= 3 and cols[0] == "R" and cols[1] in want:
                owners.setdefault(want[cols[1]], cols[2])
        return owners, (["OWNSRC\trpm"] if owners or (r.get("stdout") or "").strip() else
                        ["OWNSRC\trpm", "OWNERR\tthe rpm database gave no answer"])
    if family == "alpine":
        try:
            with open(root + "/lib/apk/db/installed", "rb") as fh:
                text = fh.read(64 * 1024 * 1024).decode("utf-8", "replace")
        except OSError:
            return owners, ["OWNERR\tthe apk database is not readable here"]
        pkg, d = "", ""
        for line in text.split("\n"):
            if line.startswith("P:"):
                pkg = line[2:]
            elif line.startswith("F:"):
                d = line[2:]
            elif line.startswith("R:"):
                path = "/" + d + "/" + line[2:]
                if path in want:
                    owners.setdefault(want[path], pkg)
        return owners, ["OWNSRC\tapk"]
    return owners, ["OWNERR\tunknown Linux distribution"]


def inventory_output(*, root: str = "", verify: bool = False, run: Runner | None = None,
                     is_credential: Callable[[str], bool] = lambda p: False,
                     deadline: float | None = None) -> dict[str, Any]:
    """The persistence read on the agent: the same records build_script prints,
    walked in Python as root. Every file content read goes through the hardened
    opener; credential locations are never read (authorized_keys only for
    fingerprints). `run(argv, timeout, cap)` runs a fixed command (rpm, find,
    dpkg --verify, systemd-detect-virt); `root` is for tests only, never the wire."""
    deadline = deadline if deadline is not None else time.monotonic() + DEFAULT_BUDGET_SECONDS
    r = root.rstrip("/")
    family = _os_family(r)
    out: list[str] = [f"M\tfamily\t{family or 'unknown'}", f"M\tnow\t{int(time.time())}",
                      f"M\tuid\t{os.geteuid() if hasattr(os, 'geteuid') else -1}", f"M\tverify\t{1 if verify else 0}"]
    listed: list[tuple[str, str, bool, str]] = []
    notes: list[str] = []
    for loc in locations_for(family):
        _list_location(loc.area, loc.mode, loc.vendor, loc.kind, r + loc.path, loc.name_suffix, listed, notes)
    for user, home in _homes(r):
        h = r + home
        if not os.path.isdir(h) or os.path.islink(h):
            continue
        notes.append(f"N\tU\t{user}\t{h}")
        for loc in home_locations_for(family):
            _list_location(loc.area, loc.mode, False, loc.kind, h + "/" + loc.path, "", listed, notes)
    out += notes
    # SUID/SGID: one bounded find per local mount (find never follows links)
    suid: list[str] = []
    if run is not None:
        for mp in _local_mounts(r):
            left = deadline - time.monotonic()
            if left <= 1:
                out.append(f"SUIDTO\t{mp}")
                continue
            try:
                res = run(["find", r + mp, "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f"],
                          min(float(SUID_FIND_SECONDS), left), 4 * 1024 * 1024)
            except Exception:  # noqa: BLE001 -- a timeout or missing find: say so
                out.append(f"SUIDTO\t{mp}")
                continue
            suid += [ln for ln in (res.get("stdout") or "").split("\n") if ln.startswith("/") and "\t" not in ln]
    suid = sorted(set(suid))
    if len(suid) > MAX_SUID_FILES:
        out.append(f"N\tT\tsuid\t/\t{len(suid)}")
        suid = suid[:MAX_SUID_FILES]
    seen = {p for _a, _m, _v, p in listed}
    listed += [("suid", "none", False, p) for p in suid if p not in seen]
    for area, mode, vendor, path in listed:
        out.append(f"I\t{area}\t{mode}\t{1 if vendor else 0}\t{path}")
    # metadata
    okf: dict[str, tuple[str, bool, str]] = {}
    for area, mode, vendor, path in listed:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        out.append(f"S\t{path}\t{st.st_uid}\t{_user_name(st.st_uid)}\t{stat.S_IMODE(st.st_mode):o}\t{st.st_size}\t"
                   f"{int(st.st_mtime)}\t{st.st_nlink}\t{_type_name(st)}")
        if stat.S_ISLNK(st.st_mode):
            try:
                out.append(f"LNK\t{path}\t{os.readlink(path)}")
            except OSError:
                out.append(f"LNK\t{path}\t")
        elif stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_TEXT_BYTES:
            okf[path] = (mode, vendor, area)
    # lines of every non-vendor text file; keys; references
    refs: list[str] = []
    contents: dict[str, bytes] = {}
    for path, (mode, vendor, area) in okf.items():
        if vendor or mode == "none" or time.monotonic() > deadline:
            continue
        data, status = _read_capped(path, MAX_TEXT_BYTES, is_credential, allow_keys=(mode == "keys"))
        if data is None:
            out.append(f"RF\t{path}\t{status}")
            continue
        contents[path] = data
        if mode == "keys":
            out += key_records(path, data)
            continue
        recs = extract_lines(mode, path, data)
        refs += [rec[2:] for rec in recs if rec.startswith("P\t")]
        out += [rec for rec in recs if not rec.startswith("P\t")]
    refs = sorted({x for x in refs if x.startswith("/") and " " not in x})[:50]
    out += [f"REF\t{x}" for x in refs]
    # sshd key settings
    sshd_files = [r + "/etc/ssh/sshd_config"]
    try:
        sshd_files += sorted(r + "/etc/ssh/sshd_config.d/" + n for n in os.listdir(r + "/etc/ssh/sshd_config.d")
                             if n.endswith(".conf"))
    except OSError:
        pass
    for f in sshd_files:
        data, _status = _read_capped(f, MAX_TEXT_BYTES, lambda _p: False, allow_keys=False)
        if data is None:
            continue
        n = 0
        for line in data.decode("utf-8", "replace").split("\n"):
            if re.match(r"^\s*(AuthorizedKeysFile|AuthorizedKeysCommand)\s", line, re.IGNORECASE) and n < 10:
                n += 1
                out.append(f"SSHD\t{f}\t{line.replace(chr(9), ' ')[:MAX_LINE_CHARS]}")
    # kernel
    ct = _detect_container(r, run)
    out.append(f"M\tcontainer\t{ct}")
    modpaths: dict[str, str] = {}
    if ct == "none":
        try:
            with open(r + "/proc/sys/kernel/tainted", encoding="ascii") as fh:
                out.append(f"TAINT\t{fh.read(64).strip()}")
            with open(r + "/proc/modules", encoding="utf-8", errors="replace") as fh:
                mods = fh.read(4 * 1024 * 1024).split("\n")
        except OSError:
            mods = []
        loaded = []
        for line in mods[:1000]:
            if not line.strip():
                continue
            name = line.split()[0]
            m = re.search(r"\(([A-Z]+)\)$", line)
            loaded.append(name)
            out.append(f"MOD\t{name}\t{m.group(1) if m else ''}")
        if loaded:
            rel = os.uname().release
            dep = None
            for cand in (f"{r}/lib/modules/{rel}/modules.dep", f"{r}/usr/lib/modules/{rel}/modules.dep"):
                if os.access(cand, os.R_OK):
                    dep = cand
                    break
            if dep is None:
                out.append("MODERR\tthe module list (modules.dep) is not readable")
            else:
                want = set(loaded)
                base = os.path.dirname(dep)
                with open(dep, encoding="utf-8", errors="replace") as fh:
                    for line in fh.read(32 * 1024 * 1024).split("\n"):
                        rel_path = line.split(":", 1)[0]
                        if not rel_path:
                            continue
                        n = re.sub(r"\.ko(\.(xz|zst|gz))?$", "", rel_path.rsplit("/", 1)[-1]).replace("-", "_")
                        if n in want:
                            modpaths[n] = base + "/" + rel_path
                            out.append(f"MODPATH\t{n}\t{base}/{rel_path}")
    # ownership
    wanted = {p for _a, _m, _v, p in listed} | set(refs) | set(modpaths.values())
    owners, own_lines = _ownership(family, wanted, r, run)
    out += own_lines
    out += [f"OWN\t{p}\t{pkg}" for p, pkg in sorted(owners.items())]
    # hashes: everything but package-owned files in package-managed directories (+ SUID files)
    for path, (mode, vendor, area) in okf.items():
        if (vendor and path in owners) or time.monotonic() > deadline:
            continue
        h = hashlib.sha256(contents[path]).hexdigest() if path in contents else _hash_file(path, is_credential)
        if h:
            out.append(f"H\t{h}\t{path}")
    for path in suid:
        if path in okf:
            continue
        h = _hash_file(path, is_credential)
        if h:
            out.append(f"H\t{h}\t{path}")
    # package-managed files NOT owned by a package: their lines too
    for path, (mode, vendor, area) in okf.items():
        if not vendor or path in owners or mode in ("none", "keys") or time.monotonic() > deadline:
            continue
        data, status = _read_capped(path, MAX_TEXT_BYTES, is_credential, allow_keys=False)
        if data is not None:
            out += [rec for rec in extract_lines(mode, path, data) if not rec.startswith("P\t")]
    if verify:
        out += _verify_agent(family, sorted(set(owners.values())), run, deadline)
    complete = time.monotonic() <= deadline
    if complete:
        out.append("END")
    text = "\n".join(out) + "\n"
    truncated = False
    if len(text.encode("utf-8", "replace")) > OUTPUT_CAP_BYTES:
        text = text.encode("utf-8", "replace")[:OUTPUT_CAP_BYTES].decode("utf-8", "ignore")
        text = text[:text.rfind("\n") + 1]
        truncated = True
    return {"returncode": 0, "stdout": text, "stderr": "", "truncated": truncated}


def _verify_agent(family: str | None, packages: list[str], run: Runner | None, deadline: float) -> list[str]:
    pkgs = [p for p in packages if _PKG_NAME_RE.fullmatch(p)][:300]
    if run is None:
        return ["VERR\tverification is not available"]
    left = max(5.0, deadline - time.monotonic())
    try:
        if family == "debian":
            res = run(["dpkg", "--verify", *pkgs], left, 4 * 1024 * 1024) if pkgs else {"stdout": ""}
            return [f"V\t{ln}" for ln in (res.get("stdout") or "").split("\n") if ln.strip()] + ["VDONE\tdpkg"]
        if family == "rhel":
            res = run(["rpm", "-V", *pkgs], left, 4 * 1024 * 1024) if pkgs else {"stdout": ""}
            return [f"V\t{ln}" for ln in (res.get("stdout") or "").split("\n") if ln.strip()] + ["VDONE\trpm"]
        if family == "alpine":
            a = run(["apk", "audit"], left, 4 * 1024 * 1024)
            b = run(["apk", "audit", "--system"], left, 4 * 1024 * 1024)
            lines = (a.get("stdout") or "").split("\n") + (b.get("stdout") or "").split("\n")
            return [f"V\t{ln}" for ln in lines if ln.startswith("U ")] + ["VDONE\tapk"]
    except Exception as e:  # noqa: BLE001 -- timeout / missing tool: say so
        return [f"VERR\t{str(e)[:160] or 'verification failed'}"]
    return ["VERR\tunknown Linux distribution"]
