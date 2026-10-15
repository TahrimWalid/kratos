"""What is running right now on a Linux machine -- the live-response read (A.5).

Read-only. It looks at ``/proc`` for the classic signs of a live intrusion:
executables deleted while still running, programs running from memory-only files
(``memfd:``), processes started with ``LD_PRELOAD``/``LD_AUDIT``, executables
dropped in ``/tmp``, ``/dev/shm`` and ``/var/tmp``, listening sockets owned by
such processes, and a shell running under a network service. Velociraptor's Linux
artifacts are the reference set.

Two ways to walk ``/proc`` that print the SAME tab-separated records:

  - ``build_script()`` -- a fixed POSIX sh + awk script for SSH. It runs AS THE
    SSH USER (no sudo): a process whose ``/proc/<pid>`` the user cannot read is
    reported as a coverage gap, never as "nothing there";
  - ``inventory_output()`` -- the sub-agent's walk in stdlib Python, as root. It
    reads ``/proc`` directly (those are not regular files, so the hardened opener
    is used only for the header and hash of a dropped file in ``/tmp``).

One parser (``parse_output``) reads both. Nothing is judged here -- judging is on
Kratos (``kratos.live.judge``). The read never sends an environment variable's
value except the ``LD_PRELOAD``/``LD_AUDIT`` library path (which it must check for
package ownership), masked on Kratos; ``LD_LIBRARY_PATH`` is reported as present
only. Command lines are capped and masked.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
import time
from typing import Any, Callable

try:  # in the agent bundle: sibling modules
    from . import catalog, hostfiles  # type: ignore[attr-defined]
    from . import persistence as _persistence  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.adapters import persistence as _persistence
        from kratos.logsources import catalog, hostfiles
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]
        import hostfiles  # type: ignore[no-redef]
        import persistence as _persistence  # type: ignore[no-redef]

OWNERSHIP_SH = _persistence.OWNERSHIP_SH

# --------------------------------------------------------------------------- caps
MAX_PROCS = 5000
MAX_CMDLINE_CHARS = 400
MAX_FD_PER_PROC = 256          # socket fds mapped per process
MAX_TEMP_FILES = 500
MAX_HASH_BYTES = 64 * 1024 * 1024
HEADER_BYTES = 256             # read this many bytes to tell ELF/script apart
OUTPUT_CAP_BYTES = 4 * 1024 * 1024
DEFAULT_BUDGET_SECONDS = 40
TEMP_FIND_SECONDS = 15
HASH_SECONDS = 15              # all dropped-file hashes together, over SSH

# The directories a dropped executable is looked for in. /run/user/* is only read
# by the agent (as root); over SSH the user sees only its own.
TEMP_DIRS: tuple[str, ...] = ("/tmp", "/dev/shm", "/var/tmp")
RUN_USER_GLOB = "/run/user"

# The LD_* variables that change what a process loads. Only the first two name a
# library and are sent with their value; LD_LIBRARY_PATH is reported present only.
PRELOAD_VARS: tuple[str, ...] = ("LD_PRELOAD", "LD_AUDIT")
LDPATH_VARS: tuple[str, ...] = ("LD_LIBRARY_PATH",)

# A path that exists again and is package-owned behind a (deleted) exe is a
# restart-pending service, not compromise (§3 decision 3).
_DELETED_MARK = " (deleted)"
_MEMFD_PREFIX = "/memfd:"

# Where a non-root SSH user cannot look: the coverage-gap fix.
AGENT_FIX = "read this machine through its sub-agent (it reads as root)"


# --------------------------------------------------------------------------- shell helpers
def _sh_q(s: str) -> str:
    return shlex.quote(s)


# One awk program: split a /proc/<pid>/stat line into pid, ppid, starttime. The
# comm field (field 2) is wrapped in parens and may contain spaces and parens, so
# everything up to the LAST ')' is dropped and the remaining fields are counted
# from `state` (so ppid is field 2 and starttime field 20 of the remainder).
AWK_STAT = r"""
{
  line = $0
  pid = line; sub(/ .*/, "", pid)
  close_paren = 0
  for (i = length(line); i >= 1; i--) if (substr(line, i, 1) == ")") { close_paren = i; break }
  rest = substr(line, close_paren + 2)
  n = split(rest, f, " ")
  if (close_paren > 0 && n >= 20) print "PP\t" pid "\t" f[2] "\t" f[20]
}
"""

# One awk program: the local sockets (listening and established) from a
# /proc/net/{tcp,tcp6,udp,udp6} table -> NET<TAB>proto<TAB>hexlocal<TAB>hexrem<TAB>st<TAB>inode.
AWK_NET = r"""
FNR == 1 { next }
{ print "NET\t" proto "\t" $2 "\t" $3 "\t" $4 "\t" $10 }
"""

_SH_HEAD = r"""
LC_ALL=C; export LC_ALL
TAB=$(printf '\t')
NL='
'
"""

# Walk /proc as the SSH user. @ROOT@ is "" in production and a fake tree in tests.
_SH_PROC = r"""
kr_cmdline() {  # cmdline with nulls turned to spaces, newlines/tabs dropped, capped
  tr '\0' ' ' < "$1" 2>/dev/null | tr '\t\n\r' '   ' | cut -c1-@MAXCMD@
}
kr_proc() {
  _np=0; _fdtotal=0
  for _d in @ROOT@/proc/[0-9]*; do
    [ -d "$_d" ] || continue
    _pid=${_d##*/}
    case "$_pid" in *[!0-9]*) continue ;; esac
    _np=$((_np + 1))
    [ "$_np" -gt @MAXPROCS@ ] && { printf 'N\tPT\t%s\n' "$_np"; break; }
    if [ ! -r "$_d/stat" ]; then printf 'PGAP\t%s\tstat\n' "$_pid"; continue; fi
    _owner=$(stat -c '%u %U' "$_d" 2>/dev/null); _uid=${_owner%% *}; _un=${_owner#* }
    [ -n "$_uid" ] || { _uid=-1; _un='UNKNOWN'; }
    awk @AWKSTAT@ "$_d/stat" 2>/dev/null
    _exe=$(readlink "$_d/exe" 2>/dev/null)
    _comm=$(cat "$_d/comm" 2>/dev/null | tr '\t\n\r' '   ')
    [ -n "$_comm" ] && printf 'PC\t%s\t%s\n' "$_pid" "$_comm"
    _cmd=$(kr_cmdline "$_d/cmdline")
    [ -n "$_cmd" ] && printf 'PL\t%s\t%s\n' "$_pid" "$_cmd"
    # a process with no exe link AND no command line is a kernel thread: it has no
    # executable by nature, so that is not a coverage gap (even as root).
    _kt=0; { [ -z "$_exe" ] && [ -z "$_cmd" ]; } && _kt=1
    if [ -n "$_exe" ]; then printf 'PX\t%s\t%s\n' "$_pid" "$_exe"
    elif [ "$_kt" = 0 ] && [ -L "$_d/exe" ]; then printf 'PGAP\t%s\texe\n' "$_pid"; fi
    _cwd=$(readlink "$_d/cwd" 2>/dev/null)
    [ -n "$_cwd" ] && printf 'PW\t%s\t%s\n' "$_pid" "$_cwd"
    _cg=$(head -n 1 "$_d/cgroup" 2>/dev/null | tr '\t\n\r' '   ')
    [ -n "$_cg" ] && printf 'PG\t%s\t%s\n' "$_pid" "$_cg"
    printf 'PP2\t%s\t%s\t%s\n' "$_pid" "$_uid" "$_un"
    if [ -r "$_d/environ" ]; then
      for _v in @PRELOADVARS@; do
        _val=$(tr '\0' '\n' < "$_d/environ" 2>/dev/null | grep "^$_v=" | head -n 1 | cut -c1-@MAXCMD@)
        [ -n "$_val" ] && printf 'PENV\t%s\t%s\t%s\n' "$_pid" "$_v" "${_val#*=}"
      done
      for _v in @LDPATHVARS@; do
        tr '\0' '\n' < "$_d/environ" 2>/dev/null | grep -q "^$_v=" && printf 'PENV\t%s\t%s\t(set)\n' "$_pid" "$_v"
      done
    elif [ "$_kt" = 0 ] && [ -e "$_d/environ" ]; then printf 'PGAP\t%s\tenviron\n' "$_pid"; fi
    if [ -r "$_d/fd" ] && [ -x "$_d/fd" ]; then
      _nf=0
      for _f in "$_d"/fd/*; do
        [ -e "$_f" ] || [ -L "$_f" ] || continue
        _l=$(readlink "$_f" 2>/dev/null)
        case "$_l" in
          socket:\[*\]) _ino=${_l#socket:\[}; _ino=${_ino%\]}; printf 'FD\t%s\t%s\n' "$_pid" "$_ino"
            _nf=$((_nf + 1)); [ "$_nf" -ge @MAXFD@ ] && break ;;
        esac
      done
    elif [ -e "$_d/fd" ]; then printf 'PGAP\t%s\tfd\n' "$_pid"; fi
  done
}
"""

# Listening/established sockets from /proc/net, and the dropped-file search.
_SH_NET_TEMP = r"""
kr_net() {
  for _p in tcp tcp6 udp udp6; do
    [ -r @ROOT@/proc/net/$_p ] && awk -v proto=$_p @AWKNET@ @ROOT@/proc/net/$_p 2>/dev/null
  done
}
kr_temp() {
  TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout @TEMPT@"
  _raw=$(for _dir in @TEMPDIRS@; do
    [ -d @ROOT@"$_dir" ] || continue
    $TO find @ROOT@"$_dir" -xdev -type f -perm -111 2>/dev/null
    [ $? -eq 124 ] && printf 'TMPTO\t%s\n' "$_dir"
  done)
  printf '%s\n' "$_raw" | grep '^TMPTO	'
  # folders under the temp dirs this login cannot enter: anything in them is unseen
  for _dir in @TEMPDIRS@; do
    [ -d @ROOT@"$_dir" ] || continue
    $TO find @ROOT@"$_dir" -xdev -type d 2>/dev/null | head -n @MAXTEMP@ | while IFS= read -r _sd; do
      { [ -r "$_sd" ] && [ -x "$_sd" ]; } || printf 'TDENY\t%s\n' "$_sd"
    done
  done
  _files=$(printf '%s\n' "$_raw" | grep '^@ROOT@/' | grep -v '	' | sort -u | head -n @MAXTEMP@)
  _n=$(printf '%s\n' "$_raw" | grep -c '^@ROOT@/')
  [ "$_n" -gt @MAXTEMP@ ] && printf 'N\tTT\ttemp\t%s\n' "$_n"
  printf '%s\n' "$_files" | grep -v '^$' | while IFS= read -r _f; do printf 'TMP\t%s\n' "$_f"; done
  printf '%s\n' "$_files"
}
"""

_SH_MAIN = r"""
printf 'M\tfamily\t%s\n' "$FAMILY"
printf 'M\tnow\t%s\n' "$(date +%s)"
printf 'M\tuid\t%s\n' "$(id -u)"
kr_proc
NETOUT=$(kr_net); printf '%s\n' "$NETOUT" | grep '^NET	'
TEMPOUT=$(kr_temp)
printf '%s\n' "$TEMPOUT" | grep -v '^@ROOT@/' | grep -v '^$'
TEMPFILES=$(printf '%s\n' "$TEMPOUT" | grep '^@ROOT@/')
# /proc mounted with hidepid: other users' processes are invisible to a non-root login
awk '$2 == "/proc" && $3 == "proc" && $4 ~ /hidepid=(1|2|invisible|noaccess)/ { print "M\thidepid\t1"; exit }' @ROOT@/proc/mounts 2>/dev/null
# stat + header + hash of every dropped executable found
printf '%s\n' "$TEMPFILES" | grep -v '^$' | tr '\n' '\0' | xargs -0 -r stat -c "%n${TAB}%u${TAB}%U${TAB}%a${TAB}%s${TAB}%Y${TAB}%h${TAB}%F" 2>/dev/null | sed 's/^/S\t/'
printf '%s\n' "$TEMPFILES" | grep -v '^$' | while IFS= read -r _f; do
  [ -f "$_f" ] && [ ! -L "$_f" ] && [ -r "$_f" ] || { printf 'HDR\t%s\tunreadable\n' "$_f"; continue; }
  _hd=$(head -c 4 "$_f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
  case "$_hd" in
    7f454c46*) printf 'HDR\t%s\telf\n' "$_f" ;;
    2321*) printf 'HDR\t%s\tscript\n' "$_f" ;;
    '') printf 'HDR\t%s\tempty\n' "$_f" ;;
    *) printf 'HDR\t%s\tother\n' "$_f" ;;
  esac
done
# hash only what the agent would hash too (MAXHASH bytes), and never for longer than
# HASHT seconds: one huge executable dropped in /tmp must not use up the read's time
HASHLIST=$(printf '%s\n' "$TEMPFILES" | grep -v '^$' | while IFS= read -r _f; do
  [ -f "$_f" ] && [ ! -L "$_f" ] && [ -r "$_f" ] || continue
  _sz=$(stat -c %s "$_f" 2>/dev/null) || continue
  if [ "$_sz" -le @MAXHASH@ ]; then printf 'OK\t%s\n' "$_f"; else printf 'HBIG\t%s\n' "$_f"; fi
done)
printf '%s\n' "$HASHLIST" | grep '^HBIG	'
printf '%s\n' "$HASHLIST" | awk -F'\t' '$1 == "OK" { print substr($0, 4) }' | tr '\n' '\0' \
  | { if command -v timeout >/dev/null 2>&1; then timeout @HASHT@ xargs -0 -r sha256sum; else xargs -0 -r sha256sum; fi; } 2>/dev/null | sed 's/^\\\([0-9a-f]\{64\}\)  /HE\t\1\t/; s/^\([0-9a-f]\{64\}\)  /H\t\1\t/'
# package ownership: every exe path, preload library and dropped-file path
EXES=$(printf '%s\n' "$PROCEXES" | sed 's/ (deleted)$//' | grep '^@ROOT@/' | grep -v '^/memfd:' | grep -v '^@ROOT@/tmp/' | grep -v '^@ROOT@/dev/shm/' | grep -v '^@ROOT@/var/tmp/' | sort -u)
WANT=$( { printf '%s\n' "$EXES"; printf '%s\n' "$PRELOADS" | grep '^/'; printf '%s\n' "$TEMPFILES"; } | grep '^/' | sort -u)
@OWNERSHIP@# which deleted-exe paths exist again (a package upgrade leaves the old inode running)
printf '%s\n' "$PROCEXES" | grep ' (deleted)$' | sed 's/ (deleted)$//' | grep '^/' | sort -u | while IFS= read -r _p; do
  [ -e "$_p" ] && printf 'EXIST\t%s\n' "$_p"
done
"""


def build_script(root: str = "") -> str:
    """The live-response read over SSH. Read-only, as the SSH user (no sudo),
    POSIX sh + awk (gawk, mawk, BusyBox). Every interpolated value is a constant
    from this file. `root` exists for tests only (a fake /proc tree)."""
    r = root.rstrip("/")
    out = [
        _SH_HEAD,
        catalog.FAMILY_SH.replace("/etc/os-release", f"{r}/etc/os-release"),
        _SH_PROC, _SH_NET_TEMP,
        # Two passes over /proc are expensive, so the main body captures the process
        # records once and reuses the exe/preload lists for ownership.
        "PROCOUT=$(kr_proc)",
        "printf '%s\\n' \"$PROCOUT\"",
        "PROCEXES=$(printf '%s\\n' \"$PROCOUT\" | awk -F'\\t' '$1 == \"PX\" { print $3 }')",
        "PRELOADS=$(printf '%s\\n' \"$PROCOUT\" | awk -F'\\t' '$1 == \"PENV\" && ($3 == \"LD_PRELOAD\" || $3 == \"LD_AUDIT\") { print $4 }')",
        _SH_MAIN.replace("kr_proc\n", ""),   # kr_proc already run into PROCOUT
    ]
    script = "\n".join(out).replace("@OWNERSHIP@", OWNERSHIP_SH)
    tempdirs = " ".join(_sh_q(d) for d in TEMP_DIRS)
    for key, val in (
        ("ROOT", _sh_q(r) if r else ""),
        ("ROOTV", (_sh_q(r) if r else "") or "''"),
        ("MAXPROCS", str(MAX_PROCS)), ("MAXCMD", str(MAX_CMDLINE_CHARS)), ("MAXFD", str(MAX_FD_PER_PROC)),
        ("MAXTEMP", str(MAX_TEMP_FILES)), ("TEMPT", str(TEMP_FIND_SECONDS)), ("TEMPDIRS", tempdirs),
        ("MAXHASH", str(MAX_HASH_BYTES)), ("HASHT", str(HASH_SECONDS)),
        ("PRELOADVARS", " ".join(PRELOAD_VARS)), ("LDPATHVARS", " ".join(LDPATH_VARS)),
        ("AWKSTAT", _sh_q(AWK_STAT)), ("AWKNET", _sh_q(AWK_NET)),
    ):
        script = script.replace(f"@{key}@", val)
    return "{\n" + script + "\nprintf 'END\\n'\n} | head -c " + str(OUTPUT_CAP_BYTES) + "\nexit 0\n"


# --------------------------------------------------------------------------- parsing (both transports)
def _int_or_none(text: str) -> int | None:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _unescape_sum_name(name: str) -> str:
    out, i = [], 0
    while i < len(name):
        if name[i] == "\\" and i + 1 < len(name):
            out.append("\n" if name[i + 1] == "n" else name[i + 1])
            i += 2
        else:
            out.append(name[i])
            i += 1
    return "".join(out)


def _hex_addr_port(token: str) -> tuple[str, int | None]:
    """A /proc/net address:port ("0100007F:0016" or an IPv6 128-bit hex) to
    (printable address, port). The address is only used to tell loopback apart;
    exact rendering is not needed, so the hex is kept for display."""
    addr, _, port_hex = token.partition(":")
    try:
        port = int(port_hex, 16)
    except ValueError:
        port = None
    return addr, port


_LOOPBACK_HEX = frozenset({"0100007F",                          # 127.0.0.1 (little-endian)
                           "00000000000000000000000001000000"})  # ::1
_WILDCARD_HEX = frozenset({"00000000",                          # 0.0.0.0
                           "00000000000000000000000000000000"})  # ::


def is_loopback_hex(addr: str) -> bool:
    return addr.upper() in _LOOPBACK_HEX


def is_wildcard_hex(addr: str) -> bool:
    return addr.upper() in _WILDCARD_HEX


def parse_output(stdout: str, root: str = "") -> dict[str, Any]:
    """The inventory both transports print, as one structure. `root` (tests only)
    is stripped from every path."""
    r = root.rstrip("/")

    def p(path: str) -> str:
        return path[len(r):] if r and path.startswith(r) else path

    inv: dict[str, Any] = {
        "family": None, "now": None, "reader_uid": None,
        "procs": {}, "sockets": [], "temp_files": {},
        "ownership": {"source": None, "error": None},
        "exists_again": set(), "proc_gaps": {}, "temp_timeouts": [],
        "truncated": [], "complete": False,
        # what this read could not look at (lifecycle blind spots, kratos.live.record):
        # pid -> what of it was unreadable; temp folders it could not enter; hidepid
        "proc_gap_pids": {}, "temp_denied": [], "hidepid": False,
    }
    procs: dict[int, dict[str, Any]] = inv["procs"]
    temp: dict[str, dict[str, Any]] = inv["temp_files"]
    fds: dict[int, list[int]] = {}             # pid -> socket inodes
    owners: dict[str, str] = {}

    def proc(pid: int) -> dict[str, Any]:
        return procs.setdefault(pid, {"pid": pid})

    for raw in stdout.split("\n"):
        cols = raw.split("\t")
        tag = cols[0]
        if tag == "M" and len(cols) >= 3:
            key, val = cols[1], cols[2]
            if key == "family":
                inv["family"] = val if val in catalog.FAMILIES else None
            elif key == "now":
                inv["now"] = _int_or_none(val)
            elif key == "uid":
                inv["reader_uid"] = _int_or_none(val)
            elif key == "hidepid":
                inv["hidepid"] = val == "1"
        elif tag == "PP" and len(cols) >= 4:
            it = proc(int(cols[1])) if cols[1].isdigit() else None
            if it is not None:
                it["ppid"] = _int_or_none(cols[2])
                it["starttime"] = _int_or_none(cols[3])
        elif tag == "PP2" and len(cols) >= 4 and cols[1].isdigit():
            it = proc(int(cols[1]))
            it["uid"] = _int_or_none(cols[2])
            it["user"] = cols[3]
        elif tag == "PX" and len(cols) >= 3 and cols[1].isdigit():
            proc(int(cols[1]))["exe"] = _strip_root_exe(cols[2], r)
        elif tag == "PC" and len(cols) >= 3 and cols[1].isdigit():
            proc(int(cols[1]))["comm"] = cols[2].rstrip()
        elif tag == "PL" and len(cols) >= 3 and cols[1].isdigit():
            proc(int(cols[1]))["cmdline"] = "\t".join(cols[2:])[:MAX_CMDLINE_CHARS].rstrip()
        elif tag == "PW" and len(cols) >= 3 and cols[1].isdigit():
            proc(int(cols[1]))["cwd"] = p(cols[2].rstrip())
        elif tag == "PG" and len(cols) >= 3 and cols[1].isdigit():
            proc(int(cols[1]))["cgroup"] = cols[2].rstrip()
        elif tag == "PENV" and len(cols) >= 4 and cols[1].isdigit():
            proc(int(cols[1])).setdefault("ld", {})[cols[2]] = "\t".join(cols[3:])
        elif tag == "FD" and len(cols) >= 3 and cols[1].isdigit():
            ino = _int_or_none(cols[2])
            if ino is not None:
                fds.setdefault(int(cols[1]), []).append(ino)
        elif tag == "PGAP" and len(cols) >= 3 and cols[1].isdigit():
            inv["proc_gaps"].setdefault(cols[2], 0)
            inv["proc_gaps"][cols[2]] += 1
            inv["proc_gap_pids"].setdefault(int(cols[1]), set()).add(cols[2])
        elif tag == "NET" and len(cols) >= 6:
            laddr, lport = _hex_addr_port(cols[2])
            raddr, rport = _hex_addr_port(cols[3])
            inv["sockets"].append({"proto": cols[1], "local_addr": laddr, "local_port": lport,
                                   "remote_addr": raddr, "remote_port": rport, "state": cols[4],
                                   "inode": _int_or_none(cols[5])})
        elif tag == "TMP" and len(cols) >= 2:
            temp.setdefault(p(cols[1]), {"path": p(cols[1])})
        elif tag == "S" and len(cols) >= 9:
            path = p(cols[1])
            it = temp.setdefault(path, {"path": path})
            it.update({"uid": _int_or_none(cols[2]), "owner": cols[3], "perm": cols[4], "size": _int_or_none(cols[5]),
                       "mtime": _int_or_none(cols[6]), "nlink": _int_or_none(cols[7]), "type": cols[8]})
        elif tag == "HDR" and len(cols) >= 3:
            temp.setdefault(p(cols[1]), {"path": p(cols[1])})["header"] = cols[2]
        elif tag in ("H", "HE") and len(cols) >= 3:
            path = p(_unescape_sum_name("\t".join(cols[2:])) if tag == "HE" else "\t".join(cols[2:]))
            temp.setdefault(path, {"path": path})["sha256"] = cols[1]
        elif tag == "EXIST" and len(cols) >= 2:
            inv["exists_again"].add(p(cols[1]))
        elif tag == "TMPTO" and len(cols) >= 2:
            inv["temp_timeouts"].append(p(cols[1]))
        elif tag == "TDENY" and len(cols) >= 2:
            inv["temp_denied"].append(p(cols[1]))
        elif tag == "N" and len(cols) >= 3 and cols[1] in ("PT", "TT"):
            inv["truncated"].append({"what": "processes" if cols[1] == "PT" else "temp files",
                                     "count": _int_or_none(cols[-1])})
        elif tag == "OWNSRC" and len(cols) >= 2:
            inv["ownership"]["source"] = cols[1]
        elif tag == "OWNERR" and len(cols) >= 2:
            inv["ownership"]["error"] = cols[1]
        elif tag == "OWN" and len(cols) >= 3:
            owners[p(cols[1])] = cols[2]
        elif tag == "HBIG" and len(cols) >= 2:
            temp.setdefault(p(cols[1]), {"path": p(cols[1])})["hash_skipped"] = "too large to hash"
        elif tag == "END":
            inv["complete"] = True
    # wire the sockets' owning process in, and mark package ownership of exes/temp files
    inode_pid: dict[int, int] = {}
    for pid, inodes in fds.items():
        for ino in inodes:
            inode_pid.setdefault(ino, pid)
    for sock in inv["sockets"]:
        pid = inode_pid.get(sock.get("inode"))
        if pid is not None:
            sock["pid"] = pid
    for it in procs.values():
        exe = _exe_real_path(str(it.get("exe") or ""))
        if exe:
            it["exe_package"] = owners.get(exe)
            it["exe_exists"] = exe in inv["exists_again"]
        preloads = (it.get("ld") or {})
        it["preload_packages"] = {lib: owners.get(lib) for var in PRELOAD_VARS
                                  for lib in [preloads.get(var)] if lib and lib.startswith("/")}
    for path, it in temp.items():
        if path in owners:
            it["package"] = owners[path]
    inv["exists_again"] = sorted(inv["exists_again"])
    return inv


def _strip_root_exe(target: str, r: str) -> str:
    """An exe readlink, with the fake-root prefix removed from its real-path part
    but any marker (`(deleted)`, `memfd:`) kept."""
    if not r:
        return target
    base, marker = _split_marker(target)
    if base.startswith(r):
        base = base[len(r):]
    return base + marker


def _split_marker(target: str) -> tuple[str, str]:
    if target.endswith(_DELETED_MARK):
        return target[: -len(_DELETED_MARK)], _DELETED_MARK
    return target, ""


def _exe_real_path(exe: str) -> str | None:
    """The on-disk path an exe link points at, or None for a memory-only exe."""
    base, _marker = _split_marker(exe)
    if not base or base.startswith(_MEMFD_PREFIX) or base.startswith("/memfd:") or "memfd:" in base:
        return None
    return base if base.startswith("/") else None


# --------------------------------------------------------------------------- the agent's walk (root)
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


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def _read_proc_file(path: str, cap: int = 1024 * 1024) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(cap)
    except OSError:
        return None


def _clean(text: str) -> str:
    return text.replace("\t", " ").replace("\n", " ").replace("\r", " ")


def _parse_stat(data: bytes) -> tuple[int | None, int | None]:
    """ppid, starttime from a /proc/<pid>/stat body (the same split AWK_STAT does)."""
    line = data.decode("latin-1")
    close = line.rfind(")")
    if close < 0:
        return None, None
    rest = line[close + 2:].split()
    if len(rest) < 20:
        return None, None
    return _int_or_none(rest[1]), _int_or_none(rest[19])


def _env_vars(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in data.split(b"\x00"):
        name, eq, value = item.partition(b"=")
        if not eq:
            continue
        key = name.decode("latin-1")
        if key in PRELOAD_VARS:
            out[key] = _clean(value.decode("utf-8", "replace"))[:MAX_CMDLINE_CHARS]
        elif key in LDPATH_VARS:
            out[key] = "(set)"
    return out


def inventory_output(*, root: str = "", run: Runner | None = None,
                     is_credential: Callable[[str], bool] = lambda p: False,
                     deadline: float | None = None) -> dict[str, Any]:
    """The live-response read on the agent: the same records build_script prints,
    walked in Python as root. /proc is read directly; a dropped executable's
    header and hash go through the hardened opener. `run(argv, timeout, cap)` runs
    a fixed command (find); `root` is for tests only, never the wire."""
    deadline = deadline if deadline is not None else time.monotonic() + DEFAULT_BUDGET_SECONDS
    r = root.rstrip("/")
    family = _os_family(r)
    out: list[str] = [f"M\tfamily\t{family or 'unknown'}", f"M\tnow\t{int(time.time())}",
                      f"M\tuid\t{os.geteuid() if hasattr(os, 'geteuid') else -1}"]
    proc_exes: list[str] = []
    preloads: list[str] = []
    try:
        pids = sorted((int(n) for n in os.listdir(r + "/proc") if n.isdigit()))
    except OSError:
        pids = []
    gaps: dict[str, int] = {}
    n = 0
    for pid in pids:
        if time.monotonic() > deadline:
            break
        n += 1
        if n > MAX_PROCS:
            out.append(f"N\tPT\t{n}")
            break
        d = f"{r}/proc/{pid}"
        stat_data = _read_proc_file(d + "/stat", 65536)
        if stat_data is None:
            out.append(f"PGAP\t{pid}\tstat")
            gaps["stat"] = gaps.get("stat", 0) + 1
            continue
        try:
            pst = os.stat(d)
            uid, un = pst.st_uid, _user_name(pst.st_uid)
        except OSError:
            uid, un = -1, "UNKNOWN"
        ppid, starttime = _parse_stat(stat_data)
        if ppid is not None and starttime is not None:
            out.append(f"PP\t{pid}\t{ppid}\t{starttime}")
        out.append(f"PP2\t{pid}\t{uid}\t{un}")
        exe = _readlink(d + "/exe")
        comm = _read_proc_file(d + "/comm", 256)
        if comm:
            out.append(f"PC\t{pid}\t{_clean(comm.decode('utf-8', 'replace')).strip()}")
        cmd = _read_proc_file(d + "/cmdline", 1024 * 1024)
        cmd_text = _clean((cmd or b"").replace(b"\x00", b" ").decode("utf-8", "replace")).strip()
        if cmd_text:
            out.append(f"PL\t{pid}\t{cmd_text[:MAX_CMDLINE_CHARS]}")
        # no exe link AND no command line = a kernel thread: it has no executable by
        # nature, so that is not a coverage gap (even as root).
        kernel_thread = not exe and not cmd_text
        if exe:
            out.append(f"PX\t{pid}\t{exe}")
            proc_exes.append(_strip_root_exe(exe, r))
        elif not kernel_thread and os.path.islink(d + "/exe"):
            out.append(f"PGAP\t{pid}\texe")
            gaps["exe"] = gaps.get("exe", 0) + 1
        cwd = _readlink(d + "/cwd")
        if cwd:
            out.append(f"PW\t{pid}\t{cwd}")
        cg = _read_proc_file(d + "/cgroup", 65536)
        if cg:
            first = _clean(cg.decode("utf-8", "replace").split("\n")[0])
            if first:
                out.append(f"PG\t{pid}\t{first}")
        env = _read_proc_file(d + "/environ", 1024 * 1024)
        if env is not None:
            for var, value in _env_vars(env).items():
                out.append(f"PENV\t{pid}\t{var}\t{value}")
                if var in PRELOAD_VARS and value.startswith("/"):
                    preloads.append(value)
        elif not kernel_thread and os.path.exists(d + "/environ"):
            out.append(f"PGAP\t{pid}\tenviron")
            gaps["environ"] = gaps.get("environ", 0) + 1
        _scan_fds(d, pid, out, gaps)
    # sockets
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        data = _read_proc_file(f"{r}/proc/net/{proto}", 8 * 1024 * 1024)
        if data is None:
            continue
        for line in data.decode("latin-1").split("\n")[1:]:
            f = line.split()
            if len(f) >= 10:
                out.append(f"NET\t{proto}\t{f[1]}\t{f[2]}\t{f[3]}\t{f[9]}")
    # dropped executables
    temp_files = _find_temp_files(r, run, deadline, out)
    for path in temp_files:
        _stat_header_hash(path, is_credential, out)
    # package ownership of exes, preload libs and dropped files
    real_exes = sorted({_exe_real_path(e) for e in proc_exes} - {None})      # type: ignore[arg-type]
    wanted = {e for e in real_exes if e} | {x for x in preloads if x.startswith("/")} \
        | {p for p in temp_files}
    owners, own_lines = _persistence._ownership(family, wanted, r, run)
    out += own_lines
    out += [f"OWN\t{p}\t{pkg}" for p, pkg in sorted(owners.items())]
    # Only a DELETED exe whose path exists again matters (a restart-pending service).
    deleted_real = {_exe_real_path(x) for x in proc_exes if x.endswith(_DELETED_MARK)} - {None}
    for e in sorted(deleted_real):                                             # type: ignore[arg-type]
        if e and os.path.exists((r + e) if r else e):
            out.append(f"EXIST\t{e}")
    complete = time.monotonic() <= deadline
    if complete:
        out.append("END")
    text = "\n".join(out) + "\n"
    truncated = False
    enc = text.encode("utf-8", "replace")
    if len(enc) > OUTPUT_CAP_BYTES:
        text = enc[:OUTPUT_CAP_BYTES].decode("utf-8", "ignore")
        text = text[:text.rfind("\n") + 1]
        truncated = True
    return {"returncode": 0, "stdout": text, "stderr": "", "truncated": truncated}


def _scan_fds(d: str, pid: int, out: list[str], gaps: dict[str, int]) -> None:
    try:
        names = os.listdir(d + "/fd")
    except OSError:
        if os.path.exists(d + "/fd"):
            out.append(f"PGAP\t{pid}\tfd")
            gaps["fd"] = gaps.get("fd", 0) + 1
        return
    nf = 0
    for name in names:
        link = _readlink(f"{d}/fd/{name}")
        if link and link.startswith("socket:[") and link.endswith("]"):
            ino = link[len("socket:["):-1]
            if ino.isdigit():
                out.append(f"FD\t{pid}\t{ino}")
                nf += 1
                if nf >= MAX_FD_PER_PROC:
                    break


def _find_temp_files(r: str, run: Runner | None, deadline: float, out: list[str]) -> list[str]:
    dirs = list(TEMP_DIRS)
    try:
        for entry in os.listdir(r + RUN_USER_GLOB):
            dirs.append(f"{RUN_USER_GLOB}/{entry}")
    except OSError:
        pass
    found: list[str] = []
    for d in dirs:
        base = r + d
        if not os.path.isdir(base):
            continue
        if time.monotonic() > deadline:
            out.append(f"TMPTO\t{d}")
            continue
        if run is not None:
            try:
                res = run(["find", base, "-xdev", "-type", "f", "-perm", "-111"],
                          min(float(TEMP_FIND_SECONDS), max(1.0, deadline - time.monotonic())), 4 * 1024 * 1024)
                found += [ln for ln in (res.get("stdout") or "").split("\n") if ln.startswith(base) and "\t" not in ln]
            except Exception:  # noqa: BLE001
                out.append(f"TMPTO\t{d}")
        else:
            found += _walk_exec(base)
    for d in dirs:                     # folders this reader cannot enter (TDENY, as over SSH)
        for denied in _denied_dirs(r + d):
            out.append(f"TDENY\t{denied}")
    found = sorted(set(found))
    if len(found) > MAX_TEMP_FILES:
        out.append(f"N\tTT\ttemp\t{len(found)}")
        found = found[:MAX_TEMP_FILES]
    for f in found:
        out.append(f"TMP\t{f}")
    return found


def _denied_dirs(base: str) -> list[str]:
    """Folders under `base` this reader cannot list or enter (at most MAX_TEMP_FILES
    folders looked at), without following symlinks or leaving the file system."""
    if not os.path.isdir(base):
        return []
    try:
        dev = os.lstat(base).st_dev
    except OSError:
        return []
    denied: list[str] = []
    seen = 0
    for root_dir, dirs, _files in os.walk(base):
        for name in list(dirs):
            full = os.path.join(root_dir, name)
            seen += 1
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_dev != dev:
                dirs.remove(name)
                continue
            if not os.access(full, os.R_OK | os.X_OK):
                denied.append(full)
                dirs.remove(name)
        if seen >= MAX_TEMP_FILES:
            break
    return sorted(denied)


def _walk_exec(base: str) -> list[str]:
    out: list[str] = []
    for root_dir, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(root_dir, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o111):
                out.append(full)
    return out


def _stat_header_hash(path: str, is_credential: Callable[[str], bool], out: list[str]) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        return
    out.append(f"S\t{path}\t{st.st_uid}\t{_user_name(st.st_uid)}\t{stat.S_IMODE(st.st_mode):o}\t{st.st_size}\t"
               f"{int(st.st_mtime)}\t{st.st_nlink}\t{_type_name(st)}")
    if is_credential(path) or stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        out.append(f"HDR\t{path}\tunreadable")
        return
    try:
        fd, fst = hostfiles.open_log_file(path)
    except hostfiles.FileRefused:
        out.append(f"HDR\t{path}\tunreadable")
        return
    try:
        head = os.pread(fd, HEADER_BYTES, 0)
        out.append(f"HDR\t{path}\t{_classify(head)}")
        if fst.st_size <= MAX_HASH_BYTES:
            h = hashlib.sha256()
            off = 0
            while off <= MAX_HASH_BYTES:          # a file that grows while it is read stops here
                b = os.pread(fd, min(1024 * 1024, MAX_HASH_BYTES + 1 - off), off)
                if not b:
                    break
                h.update(b)
                off += len(b)
            if off <= MAX_HASH_BYTES:
                out.append(f"H\t{h.hexdigest()}\t{path}")
            else:
                out.append(f"HBIG\t{path}")
        else:
            out.append(f"HBIG\t{path}")
    finally:
        os.close(fd)


def _classify(head: bytes) -> str:
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    if head == b"":
        return "empty"
    return "other"
