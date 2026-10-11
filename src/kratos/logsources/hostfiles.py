"""Reading log files safely, and the facts the tamper checks need (0.3).

Two halves, both read-only:

* **The hardened opener** (`open_log_file`) -- how the sub-agent, which runs as
  root, opens a log file. Every path component is opened with O_NOFOLLOW from a
  pinned root descriptor, so a symlink anywhere in the path is refused; the file
  must be a regular file with exactly one link (a hard link to /etc/shadow
  planted in a log directory is refused); after opening, the name is looked up
  again and must still be the very inode that was opened. Same approach as the
  YARA walker (subagent.reads._YaraScan, review v2 F-1).

* **Fixed scripts + parsers** for the tamper checks: file state (inode, size,
  mtime, link count, hash of the first 4 KiB), logrotate's state file, login
  record tails (wtmp/btmp/lastlog), journal file headers, boot history and
  auditd status. Over SSH they run as the SSH user (group membership, never
  `sudo cat`; the only sudo used is the journalctl prefix Kratos already uses and
  `auditctl -s`/`-l`). The agent runs the same scripts for metadata, and reads
  file CONTENT (head hash, login records, journal files) through the opener.

Every path comes from catalog.py; journal file names must match a strict
pattern AND appear in the machine's own journal directory listing.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import os
import re
import shlex
import stat
from typing import Any

try:  # in the agent bundle: a sibling module
    from . import catalog  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources import catalog
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]

UTMP_RECORD_BYTES = 384           # struct utmp on glibc x86_64 / aarch64
UTMP_MAX_BYTES = 384 * 2048       # the most of a login file one read returns (newest records)
JOURNAL_CHUNK_MAX = 4 * 1024 * 1024
MAX_JOURNAL_FILES = 400
MAX_BOOTS = 10
BOOT_TAIL_ENTRIES = 60

# Journal file names, as systemd names them (verified on systemd 249 and 252):
#   system.journal / user-1000.journal                       -- the active files
#   system@<seqnum id:32>-<head seqnum:16>-<head realtime:16>.journal   -- archived cleanly
#   system@<realtime:16>-<random:16>.journal~                -- set aside after an unclean stop
JOURNAL_NAME_RE = re.compile(
    r"^(system|user-[0-9]+)"
    r"(@([0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{16}\.journal|[0-9a-f]{16}-[0-9a-f]{16}\.journal~)|\.journal~?)$")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class FileRefused(Exception):
    """The file was not opened. `status` is one of: missing, symlink, hardlink,
    not_regular, unreadable, changed."""

    def __init__(self, status: str, detail: str = ""):
        super().__init__(f"{status}: {detail}" if detail else status)
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------
# The hardened opener (agent side)
# ---------------------------------------------------------------------------
def _walk_to_parent(path: str) -> tuple[int, str]:
    """(descriptor of the parent directory, final name), every directory opened
    without following a symlink."""
    if not path.startswith("/") or "\x00" in path or any(p in ("", ".", "..") for p in path.split("/")[1:]):
        raise FileRefused("missing", "not a plain absolute path")
    parts = path.split("/")[1:]
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as e:
                raise _refusal(e, part) from None
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def _refusal(e: OSError, what: str) -> FileRefused:
    if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
        return FileRefused("symlink", f"{what} is a symbolic link (or not a directory)")
    if e.errno == errno.ENOENT:
        return FileRefused("missing", "")
    if e.errno in (errno.EACCES, errno.EPERM):
        return FileRefused("unreadable", "permission denied")
    return FileRefused("unreadable", e.strerror or str(e))


def open_log_file(path: str) -> tuple[int, os.stat_result]:
    """Open `path` for reading, refusing symlinks (anywhere in the path), hard
    links, non-regular files and a file swapped while it was being opened.
    Returns (fd, its fstat). The caller closes the fd."""
    dir_fd, name = _walk_to_parent(path)
    try:
        try:
            before = os.lstat(name, dir_fd=dir_fd)
        except OSError as e:
            raise _refusal(e, name) from None
        if stat.S_ISLNK(before.st_mode):
            raise FileRefused("symlink", f"{path} is a symbolic link")
        if not stat.S_ISREG(before.st_mode):
            raise FileRefused("not_regular", f"{path} is not a regular file")
        try:
            fd = os.open(name, _OPEN_FLAGS, dir_fd=dir_fd)
        except OSError as e:
            raise _refusal(e, name) from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise FileRefused("not_regular", f"{path} is not a regular file")
            if st.st_nlink != 1:
                raise FileRefused("hardlink", f"{path} has {st.st_nlink} hard links")
            after = os.lstat(name, dir_fd=dir_fd)
            if (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino) or (before.st_dev, before.st_ino) != (st.st_dev, st.st_ino):
                raise FileRefused("changed", f"{path} was replaced while it was being opened")
        except BaseException:
            os.close(fd)
            raise
        return fd, st
    finally:
        os.close(dir_fd)


def read_head(fd: int, n: int = catalog.HEAD_HASH_BYTES) -> bytes:
    return os.pread(fd, n, 0)


# ---------------------------------------------------------------------------
# File state (log_file_stat)
# ---------------------------------------------------------------------------
# One line per file: FS <role> <path> <status> <inode> <size> <mtime> <nlink> <head sha256 | ->
# role: cur (the log itself) or rot (its first plain rotation: .0, .1 or newest -YYYYMMDD)
_STAT_FN = r'''
kr_fs() {  # role path
  if [ -L "$2" ]; then printf 'FS\t%s\t%s\tsymlink\t-\t-\t-\t-\t-\n' "$1" "$2"; return; fi
  if [ ! -e "$2" ]; then
    _p=${2%/*}
    if [ -d "$_p" ] && { [ ! -x "$_p" ] || [ ! -r "$_p" ]; }; then printf 'FS\t%s\t%s\tunreadable\t-\t-\t-\t-\t-\n' "$1" "$2"
    else printf 'FS\t%s\t%s\tmissing\t-\t-\t-\t-\t-\n' "$1" "$2"; fi
    return
  fi
  if [ ! -f "$2" ]; then printf 'FS\t%s\t%s\tnot_regular\t-\t-\t-\t-\t-\n' "$1" "$2"; return; fi
  _st=$(stat -c '%i %s %Y %h' "$2" 2>/dev/null) || { printf 'FS\t%s\t%s\tunreadable\t-\t-\t-\t-\t-\n' "$1" "$2"; return; }
  set -- "$1" "$2" $_st
  _h=-; _s=ok
  if [ "$6" -gt 1 ]; then _s=hardlink
  elif [ -r "$2" ]; then _h=$(head -c 4096 "$2" | sha256sum | cut -d' ' -f1)
  else _s=no_content; fi
  printf 'FS\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$_s" "$3" "$4" "$5" "$6" "$_h"
}
kr_track() {  # path
  kr_fs cur "$1"
  _prev=""
  if [ -e "$1.0" ] || [ -L "$1.0" ]; then _prev="$1.0"
  elif [ -e "$1.1" ] || [ -L "$1.1" ]; then _prev="$1.1"
  else
    for _g in "$1"-[0-9]*; do
      case "$_g" in *.gz|*.xz|*.bz2|*.zst|*.lz4) ;; *) { [ -e "$_g" ] || [ -L "$_g" ]; } && _prev="$_g" ;; esac
    done
  fi
  [ -n "$_prev" ] && kr_fs "rot:$1" "$_prev"
}
'''


def stat_script(root: str = "") -> str:
    """log_file_stat over SSH: state of every tracked log file for this machine's
    family, its first rotation, and logrotate's own record of rotations."""
    parts = ["LC_ALL=C; export LC_ALL", catalog.FAMILY_SH.replace("/etc/os-release", f"{root}/etc/os-release"),
             "printf 'M\\tfamily\\t%s\\n' \"$FAMILY\"", "printf 'M\\tnow\\t%s\\n' \"$(date +%s)\"", _STAT_FN,
             "case \"$FAMILY\" in"]
    for family, paths in catalog.TRACKED_FILES.items():
        parts.append(f"{family})\n" + "\n".join(f"kr_track {shlex.quote(root + p)}" for p in paths) + "\n;;")
    parts += ["*) : ;;", "esac"]
    for status_file in catalog.LOGROTATE_STATUS_FILES:
        q = shlex.quote(root + status_file)
        parts.append(f"[ -r {q} ] && [ ! -L {q} ] && grep -E '^\"?/' {q} | head -n 400 | awk '{{ print \"LR\\t\" $0 }}'")
    parts.append("exit 0")
    return "\n".join(parts) + "\n"


def _previous_rotation_name(base: str, names: list[str]) -> str | None:
    if base + ".0" in names:
        return base + ".0"
    if base + ".1" in names:
        return base + ".1"
    dated = sorted(n for n in names if n.startswith(base + "-") and n[len(base) + 1:len(base) + 2].isdigit()
                   and not n.endswith((".gz", ".xz", ".bz2", ".zst", ".lz4")))
    return dated[-1] if dated else None


def file_state_line(role: str, path: str) -> str:
    """The FS line for one file, read the agent's way (the opener for content)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return f"FS\t{role}\t{path}\tmissing\t-\t-\t-\t-\t-"
    except OSError:
        return f"FS\t{role}\t{path}\tunreadable\t-\t-\t-\t-\t-"
    if stat.S_ISLNK(st.st_mode):
        return f"FS\t{role}\t{path}\tsymlink\t-\t-\t-\t-\t-"
    if not stat.S_ISREG(st.st_mode):
        return f"FS\t{role}\t{path}\tnot_regular\t-\t-\t-\t-\t-"
    status, head = "ok", "-"
    if st.st_nlink > 1:
        status = "hardlink"
    else:
        try:
            fd, st = open_log_file(path)
        except FileRefused as e:
            status = "no_content" if e.status == "unreadable" else e.status
        else:
            try:
                head = hashlib.sha256(read_head(fd)).hexdigest()
            finally:
                os.close(fd)
    return f"FS\t{role}\t{path}\t{status}\t{st.st_ino}\t{st.st_size}\t{int(st.st_mtime)}\t{st.st_nlink}\t{head}"


def file_state_lines(family: str | None, root: str = "") -> list[str]:
    """log_file_stat on the agent: the same lines stat_script prints."""
    out: list[str] = []
    for path in catalog.TRACKED_FILES.get(family or "", ()):
        full = root + path
        out.append(file_state_line("cur", full))
        directory, base = os.path.split(full)
        try:
            names = os.listdir(directory)
        except OSError:
            names = []
        prev = _previous_rotation_name(base, names)
        if prev:
            out.append(file_state_line(f"rot:{full}", os.path.join(directory, prev)))
    for status_file in catalog.LOGROTATE_STATUS_FILES:
        try:
            fd, _st = open_log_file(root + status_file)
        except FileRefused:
            continue
        try:
            with os.fdopen(fd, "rb") as f:
                text = f.read(256 * 1024).decode("utf-8", "replace")
        except OSError:
            continue
        rows = [ln for ln in text.split("\n") if re.match(r'^"?/', ln)][:400]
        out += [f"LR\t{ln}" for ln in rows]
    return out


def parse_file_states(stdout: str) -> dict[str, Any]:
    """{family, now, files: {path: state}, rotations: {path: state of its rotation},
    logrotate: {path: 'YYYY-M-D-h:m:s'}}."""
    out: dict[str, Any] = {"family": None, "now": None, "files": {}, "rotations": {}, "logrotate": {}}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "M" and len(cols) >= 3:
            if cols[1] == "family":
                out["family"] = cols[2] if cols[2] in catalog.FAMILIES else None
            elif cols[1] == "now":
                out["now"] = _int(cols[2])
        elif cols[0] == "FS" and len(cols) >= 9:
            role, path, status = cols[1], cols[2], cols[3]
            state = {"path": path, "status": status, "inode": _int(cols[4]), "size": _int(cols[5]),
                     "mtime": _int(cols[6]), "nlink": _int(cols[7]), "head_hash": None if cols[8] == "-" else cols[8]}
            if role == "cur":
                out["files"][path] = state
            elif role.startswith("rot:"):
                out["rotations"][role[4:]] = state
        elif cols[0] == "LR" and len(cols) >= 2:
            m = re.match(r'^"?(/[^"\s]+)"?\s+(\S+)', "\t".join(cols[1:]))
            if m:
                out["logrotate"][m.group(1)] = m.group(2)
    return out


def _int(text: str) -> int | None:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Login records (utmp_read)
# ---------------------------------------------------------------------------
# U <file> <status> <size> <inode> <offset> <base64 of the bytes from offset to the end>
def utmp_script(name: str, max_bytes: int, root: str = "") -> str:
    path = shlex.quote(root + catalog.UTMP_FILES[name])
    max_bytes = int(max_bytes)
    rec = UTMP_RECORD_BYTES
    return (
        "LC_ALL=C; export LC_ALL\n"
        f"F={path}\n"
        f"if [ -L \"$F\" ]; then printf 'U\\t{name}\\tsymlink\\t-\\t-\\t-\\t-\\n'; exit 0; fi\n"
        f"if [ ! -e \"$F\" ]; then if [ -d \"${{F%/*}}\" ] && [ ! -x \"${{F%/*}}\" ]; then "
        f"printf 'U\\t{name}\\tunreadable\\t-\\t-\\t-\\t-\\n'; else printf 'U\\t{name}\\tmissing\\t-\\t-\\t-\\t-\\n'; fi; exit 0; fi\n"
        f"if [ ! -f \"$F\" ]; then printf 'U\\t{name}\\tnot_regular\\t-\\t-\\t-\\t-\\n'; exit 0; fi\n"
        "set -- $(stat -c '%s %i %h' \"$F\")\n"
        f"if [ \"$3\" -gt 1 ]; then printf 'U\\t{name}\\thardlink\\t%s\\t%s\\t-\\t-\\n' \"$1\" \"$2\"; exit 0; fi\n"
        f"if [ ! -r \"$F\" ]; then printf 'U\\t{name}\\tunreadable\\t%s\\t%s\\t-\\t-\\n' \"$1\" \"$2\"; exit 0; fi\n"
        + f"N=$(( {max_bytes} / {rec} * {rec} )); O=$(( $1 - $1 % {rec} - N )); [ \"$O\" -lt 0 ] && O=0\n"
        "B=$(tail -c +$((O + 1)) \"$F\" | head -c \"$N\" | base64 | tr -d '\\n')\n"
        + f"printf 'U\\t{name}\\tok\\t%s\\t%s\\t%s\\t%s\\n' \"$1\" \"$2\" \"$O\" \"$B\"\n"
        "exit 0\n"
    )


def utmp_line(name: str, max_bytes: int, root: str = "") -> str:
    """utmp_read on the agent: the same U line, the file read through the opener."""
    path = root + catalog.UTMP_FILES[name]
    rec = UTMP_RECORD_BYTES
    try:
        fd, st = open_log_file(path)
    except FileRefused as e:
        if e.status in ("missing", "symlink", "not_regular"):
            return f"U\t{name}\t{e.status}\t-\t-\t-\t-"
        try:
            lst = os.lstat(path)
            return f"U\t{name}\t{e.status}\t{lst.st_size}\t{lst.st_ino}\t-\t-"
        except OSError:
            return f"U\t{name}\t{e.status}\t-\t-\t-\t-"
    try:
        n = int(max_bytes) // rec * rec
        size = st.st_size
        offset = max(0, size - size % rec - n)
        data = os.pread(fd, n, offset)
    finally:
        os.close(fd)
    return f"U\t{name}\tok\t{size}\t{st.st_ino}\t{offset}\t{base64.b64encode(data).decode('ascii')}"


def parse_utmp_line(stdout: str) -> dict[str, Any] | None:
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "U" and len(cols) >= 7:
            data = None
            if cols[2] == "ok":
                try:
                    data = base64.b64decode(cols[6] or "", validate=False)
                except ValueError:
                    data = None
            return {"file": cols[1], "status": cols[2], "size": _int(cols[3]), "inode": _int(cols[4]),
                    "offset": _int(cols[5]), "data": data}
    return None


# ---------------------------------------------------------------------------
# Journal files (journal_headers, journal_file_hash, journal_file_chunk)
# ---------------------------------------------------------------------------
_HEADER_KEYS = ("File ID", "Machine ID", "Boot ID", "Sequential number ID", "State", "Compatible flags",
                "Incompatible flags", "Head sequential number", "Tail sequential number",
                "Head realtime timestamp", "Tail realtime timestamp", "Tag objects", "Entry objects")


def journal_headers_script(journal_prefix: str = "sudo -n", root: str = "") -> str:
    """Every journal file of this machine with its header fields. Read with the
    same journalctl privilege Kratos already uses (the journal group or `sudo -n
    journalctl`); file sizes come from `stat` (metadata, no content)."""
    jp = journal_prefix.strip()
    if jp not in ("", "sudo -n"):
        raise ValueError("journal prefix must be '' or 'sudo -n'")
    keys = "|".join(_HEADER_KEYS)
    dirs = " ".join(shlex.quote(root + d) for d in catalog.JOURNAL_DIRS)
    return (
        "LC_ALL=C; export LC_ALL\n"
        f"printf 'M\\tmachine_id\\t%s\\n' \"$(cat {shlex.quote(root + '/etc/machine-id')} 2>/dev/null | head -c 64)\"\n"
        "command -v journalctl >/dev/null 2>&1 || { printf 'M\\tjournalctl\\tabsent\\n'; exit 0; }\n"
        "printf 'M\\tsystemd\\t%s\\n' \"$(journalctl --version 2>/dev/null | head -1 | cut -d' ' -f2)\"\n"
        "_n=0\n"
        f"for D in {dirs}; do\n"
        "  [ -d \"$D\" ] && [ ! -L \"$D\" ] || continue\n"
        "  for M in \"$D\"/*; do\n"
        "    [ -d \"$M\" ] && [ ! -L \"$M\" ] || continue\n"
        "    if [ ! -r \"$M\" ] || [ ! -x \"$M\" ]; then printf 'JDU\\t%s\\n' \"$M\"; continue; fi\n"
        "    printf 'JD\\t%s\\n' \"$M\"\n"
        "    for F in \"$M\"/*.journal \"$M\"/*.journal~; do\n"
        "      [ -f \"$F\" ] && [ ! -L \"$F\" ] || continue\n"
        f"      _n=$((_n + 1)); [ \"$_n\" -gt {MAX_JOURNAL_FILES} ] && break\n"
        "      _b=$(basename \"$F\")\n"
        "      printf 'JF\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$M\" \"$_b\" \"$(stat -c '%s %Y %h %i' \"$F\")\" "
        "\"$([ -r \"$F\" ] && echo r || echo -)\" \"$([ -s \"$F\" ] && echo s || echo 0)\"\n"
        f"      {jp + ' ' if jp else ''}journalctl --header --file \"$F\" 2>&1 | grep -E '^({keys}):' "
        "| awk -v b=\"$_b\" '{ print \"JHL\\t\" b \"\\t\" $0 }'\n"
        "    done\n"
        "  done\n"
        "done\n"
        "exit 0\n"
    )


def parse_journal_headers(stdout: str) -> dict[str, Any]:
    """{machine_id, systemd, available, dirs, files: [{dir, name, size, mtime, nlink,
    inode, readable, header: {...}}]}"""
    out: dict[str, Any] = {"machine_id": None, "systemd": None, "available": True, "dirs": [], "files": [],
                           "unreadable_dirs": []}
    by_name: dict[str, dict[str, Any]] = {}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "M" and len(cols) >= 3:
            if cols[1] == "machine_id":
                mid = cols[2].strip()
                out["machine_id"] = mid if MACHINE_ID_RE.fullmatch(mid) else None
            elif cols[1] == "journalctl":
                out["available"] = False
            elif cols[1] == "systemd":
                out["systemd"] = _int(cols[2].strip())
        elif cols[0] == "JD" and len(cols) >= 2:
            out["dirs"].append(cols[1])
        elif cols[0] == "JDU" and len(cols) >= 2:
            out.setdefault("unreadable_dirs", []).append(cols[1])
        elif cols[0] == "JF" and len(cols) >= 6:
            meta = cols[3].split()
            f = {"dir": cols[1], "name": cols[2], "size": _int(meta[0]) if meta else None,
                 "mtime": _int(meta[1]) if len(meta) > 1 else None, "nlink": _int(meta[2]) if len(meta) > 2 else None,
                 "inode": _int(meta[3]) if len(meta) > 3 else None, "readable": cols[4] == "r", "header": {}}
            if JOURNAL_NAME_RE.fullmatch(f["name"]):
                out["files"].append(f)
                by_name[f["name"]] = f
        elif cols[0] == "JHL" and len(cols) >= 3:
            f = by_name.get(cols[1])
            if f is not None:
                key, _, val = "\t".join(cols[2:]).partition(":")
                f["header"][key.strip()] = val.strip()
    for f in out["files"]:
        f.update(_header_facts(f["header"], f["name"]))
    return out


_SEQ_RE = re.compile(r"^(\d+)")
_HEX_RE = re.compile(r"\(([0-9a-f]+)\)\s*$")


def _header_facts(h: dict[str, str], name: str) -> dict[str, Any]:
    def seq(key: str) -> int | None:
        m = _SEQ_RE.match(h.get(key, ""))
        return int(m.group(1)) if m else None

    def realtime(key: str) -> float | None:
        m = _HEX_RE.search(h.get(key, ""))
        return int(m.group(1), 16) / 1_000_000 if m else None

    flags = (h.get("Compatible flags", "") + " " + h.get("Incompatible flags", "")).upper().split()
    tags = _int(h.get("Tag objects", "").split()[0]) if h.get("Tag objects") else None
    return {
        "seqnum_id": (h.get("Sequential number ID") or "").lower() or None,
        "head_seqnum": seq("Head sequential number"), "tail_seqnum": seq("Tail sequential number"),
        "head_realtime": realtime("Head realtime timestamp"), "tail_realtime": realtime("Tail realtime timestamp"),
        "state": (h.get("State") or "").upper() or None,
        "sealed": any(fl.startswith("SEALED") for fl in flags),
        "tag_objects": tags,
        "archived": "@" in name,
        "dirty": name.endswith("~"),
        "journal": name.split("@", 1)[0].split(".", 1)[0],
        "header_read": bool(h),
    }


def journal_file_path(directory: str, name: str, root: str = "") -> str:
    """The absolute path of journal file `name` in `directory`, only if the
    directory is a machine directory under a journal dir and the name has the
    exact systemd naming. Raises ValueError otherwise."""
    if not JOURNAL_NAME_RE.fullmatch(name or ""):
        raise ValueError("not a journal file name")
    for base in catalog.JOURNAL_DIRS:
        prefix = root + base + "/"
        if directory.startswith(prefix):
            machine = directory[len(prefix):]
            if MACHINE_ID_RE.fullmatch(machine):
                return f"{directory}/{name}"
    raise ValueError("not a journal directory")


def list_journal_files(root: str = "") -> list[tuple[str, str]]:
    """(machine directory, file name) of every journal file, by directory listing
    (agent side) -- the names `journal_file_*` reads may use."""
    out: list[tuple[str, str]] = []
    for base in catalog.JOURNAL_DIRS:
        d = root + base
        try:
            machines = sorted(os.listdir(d))
        except OSError:
            continue
        for m in machines:
            if not MACHINE_ID_RE.fullmatch(m):
                continue
            md = f"{d}/{m}"
            try:
                if stat.S_ISLNK(os.lstat(md).st_mode):
                    continue
                names = sorted(os.listdir(md))
            except OSError:
                continue
            out += [(md, n) for n in names if JOURNAL_NAME_RE.fullmatch(n)]
    return out[:MAX_JOURNAL_FILES]


def find_journal_file(name: str, root: str = "") -> str:
    """The path of a journal file by NAME, only if it is in the live listing."""
    if not JOURNAL_NAME_RE.fullmatch(name or ""):
        raise FileRefused("missing", "not a journal file name")
    for directory, n in list_journal_files(root):
        if n == name:
            return f"{directory}/{n}"
    raise FileRefused("missing", f"{name} is not in this machine's journal directory")


def journal_file_hash(name: str, root: str = "") -> dict[str, Any]:
    path = find_journal_file(name, root)
    fd, st = open_log_file(path)
    try:
        h = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(fd, 1024 * 1024, offset)
            if not chunk:
                break
            h.update(chunk)
            offset += len(chunk)
    finally:
        os.close(fd)
    return {"name": name, "size": offset, "inode": st.st_ino, "sha256": h.hexdigest()}


def journal_file_chunk(name: str, offset: int, length: int, root: str = "") -> dict[str, Any]:
    path = find_journal_file(name, root)
    fd, st = open_log_file(path)
    try:
        data = os.pread(fd, min(int(length), JOURNAL_CHUNK_MAX), int(offset))
    finally:
        os.close(fd)
    return {"name": name, "size": st.st_size, "offset": int(offset), "data": base64.b64encode(data).decode("ascii"),
            "eof": int(offset) + len(data) >= st.st_size}


# ---------------------------------------------------------------------------
# Boot history (boot_history)
# ---------------------------------------------------------------------------
def boot_history_script(journal_prefix: str = "sudo -n") -> str:
    """The previous boots in the journal and the last entries of each -- enough to
    tell whether each one ended with a clean shutdown. Boot IDs are taken from
    journalctl's own listing and kept only if they are 32 hex characters."""
    jp = journal_prefix.strip()
    if jp not in ("", "sudo -n"):
        raise ValueError("journal prefix must be '' or 'sudo -n'")
    j = (jp + " " if jp else "") + "journalctl"
    return (
        "LC_ALL=C; export LC_ALL\n"
        "command -v journalctl >/dev/null 2>&1 || { printf 'M\\tjournalctl\\tabsent\\n'; exit 0; }\n"
        "printf 'M\\tcontainer\\t%s\\n' \"$(systemd-detect-virt -c 2>/dev/null || echo none)\"\n"
        "printf 'M\\tcurrent_boot\\t%s\\n' \"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '-')\"\n"
        f"KR_BOOTS=$({j} --list-boots --no-pager 2>/dev/null | awk 'length($2) == 32 && $2 ~ /^[0-9a-f]+$/ {{ print $2 }}' "
        f"| tail -n {MAX_BOOTS + 1})\n"
        "for B in $KR_BOOTS; do\n"
        "  printf 'B\\t%s\\n' \"$B\"\n"
        f"  {j} -b \"$B\" --no-pager -o json --output-fields=MESSAGE,_PID,SYSLOG_IDENTIFIER,_COMM "
        f"--reverse -n {BOOT_TAIL_ENTRIES} 2>/dev/null | awk -v b=\"$B\" '{{ print \"BE\\t\" b \"\\t\" $0 }}'\n"
        "done\n"
        "exit 0\n"
    )


# Written by systemd (PID 1) only on an orderly shutdown/reboot; journald writes
# "Journal stopped" as it closes the journal cleanly.
_PID1_SHUTDOWN_MARKERS = (
    "Reached target System Shutdown", "Reached target Shutdown.", "Reached target Power-Off",
    "Reached target System Power Off", "Reached target Reboot", "Reached target System Reboot",
    "Reached target Halt", "Reached target System Halt", "Reached target Final Step",
    "Reached target Kexec", "Reached target System Kexec",
    "systemd-journald.service: Deactivated successfully", "Stopped Journal Service",
)


def parse_boot_history(stdout: str) -> dict[str, Any]:
    """{available, container, current, boots: [{boot_id, last_ts, clean, marker}]}
    oldest first; the current boot is never judged (it hasn't ended)."""
    import json as _json

    out: dict[str, Any] = {"available": True, "container": None, "current": None, "boots": []}
    entries: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "M" and len(cols) >= 3:
            if cols[1] == "journalctl":
                out["available"] = False
            elif cols[1] == "container":
                out["container"] = None if cols[2].strip() in ("", "none") else cols[2].strip()
            elif cols[1] == "current_boot":
                out["current"] = cols[2].strip() or None
        elif cols[0] == "B" and len(cols) >= 2 and BOOT_ID_RE.fullmatch(cols[1]):
            order.append(cols[1])
            entries.setdefault(cols[1], [])
        elif cols[0] == "BE" and len(cols) >= 3:
            try:
                e = _json.loads("\t".join(cols[2:]))
            except ValueError:
                continue
            if isinstance(e, dict):
                entries.setdefault(cols[1], []).append(e)
    for boot in order:
        if boot == out["current"]:
            continue
        es = entries.get(boot, [])
        ts = None
        if es:
            try:
                ts = int(es[0].get("__REALTIME_TIMESTAMP")) / 1_000_000
            except (TypeError, ValueError):
                ts = None
        marker = None
        for e in es:
            msg = e.get("MESSAGE")
            if not isinstance(msg, str):
                continue
            if "Journal stopped" in msg:
                marker = "Journal stopped"
                break
            if str(e.get("_PID")) == "1":
                marker = next((m for m in _PID1_SHUTDOWN_MARKERS if m in msg), None)
                if marker:
                    break
        out["boots"].append({"boot_id": boot, "last_ts": ts, "entries": len(es), "clean": marker is not None,
                             "marker": marker})
    return out


# ---------------------------------------------------------------------------
# auditd status (audit_status)
# ---------------------------------------------------------------------------
def audit_status_script(sudo: str = "sudo -n") -> str:
    """Is auditd installed, running, enabled, and how many rules are loaded.
    Over SSH `auditctl -s`/`-l` need `sudo -n` (the two exact lines the setup
    checklist grants); the rules themselves never leave the machine -- only their
    count and a hash (to notice a change)."""
    sudo = sudo.strip()
    if sudo not in ("", "sudo -n"):
        raise ValueError("sudo must be '' or 'sudo -n'")
    s = sudo + " " if sudo else ""
    return (
        "LC_ALL=C; export LC_ALL\n"
        "if command -v auditctl >/dev/null 2>&1 || [ -x /sbin/auditctl ] || [ -x /usr/sbin/auditctl ]; then\n"
        "  printf 'AS\\tinstalled\\tyes\\n'\nelse\n  printf 'AS\\tinstalled\\tno\\n'\nfi\n"
        "printf 'AS\\tactive\\t%s\\n' \"$(systemctl is-active auditd 2>/dev/null || echo unknown)\"\n"
        "printf 'AS\\tenabled\\t%s\\n' \"$(systemctl is-enabled auditd 2>/dev/null || echo unknown)\"\n"
        f"if _o=$({s}auditctl -s 2>&1); then\n"
        "  printf 'AS\\tstatus_read\\tyes\\n'\n"
        "  printf '%s\\n' \"$_o\" | awk '$1 == \"enabled\" || $1 == \"pid\" || $1 == \"lost\" "
        "{ print \"AS\\t\" ($1 == \"enabled\" ? \"kernel_enabled\" : $1) \"\\t\" $2 }'\n"
        "else printf 'AS\\tstatus_read\\tno\\t%s\\n' \"$(printf '%s' \"$_o\" | head -c 200 | tr '\\t\\n' '  ')\"; fi\n"
        f"if _r=$({s}auditctl -l 2>&1); then\n"
        "  printf 'AS\\trules_read\\tyes\\n'\n"
        "  if printf '%s' \"$_r\" | grep -q '^No rules'; then printf 'AS\\trules\\t0\\n'; else\n"
        "    printf 'AS\\trules\\t%s\\n' \"$(printf '%s\\n' \"$_r\" | grep -c .)\"; fi\n"
        "  printf 'AS\\trules_sha256\\t%s\\n' \"$(printf '%s\\n' \"$_r\" | sha256sum | cut -d' ' -f1)\"\n"
        "else printf 'AS\\trules_read\\tno\\t%s\\n' \"$(printf '%s' \"$_r\" | head -c 200 | tr '\\t\\n' '  ')\"; fi\n"
        "exit 0\n"
    )


def parse_audit_status(stdout: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "AS" and len(cols) >= 3:
            key, val = cols[1], cols[2].strip()
            if key in ("kernel_enabled", "pid", "lost", "rules"):
                out[key] = _int(val)
            elif key in ("installed", "status_read", "rules_read"):
                out[key] = val == "yes"
                if val == "no" and len(cols) >= 4 and key != "installed":
                    out[key + "_error"] = cols[3].strip()
            else:
                out[key] = val
    return out
