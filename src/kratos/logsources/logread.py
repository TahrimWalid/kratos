"""Reading one log source in a time window, on the machine (0.3).

ONE awk program extracts lines from every file format in catalog.FORMATS. It
reads a file on stdin and prints only the lines inside the requested window,
newest first, up to a line cap and a byte cap -- so only the window crosses the
link, never the whole file. Both transports feed it the same way:

  * over SSH, a fixed script (`build_script`) reads the files as the SSH user
    (group membership -- `adm`, `systemd-journal`, auditd's log group -- never
    `sudo cat`) and pipes each into awk;
  * the sub-agent runs as root, so it opens each file with the hardened opener
    (hostfiles.open_log_file: no symlinks, no hard links, inode re-checked) and
    hands awk the open descriptor (kratos.subagent.reads._p_log_read).

Both print the same tab-separated lines, read by one parser (`parse_output`).
Journal sources are journalctl reads with a closed match (catalog.JOURNAL_MATCHES),
newest first, with absolute epochs.

Portability (review v2 F-9): plain POSIX sh and awk with no gawk-only features
(no match() arrays, no mktime/strftime, no interval expressions `{n}`), so it
runs under mawk (Debian/Ubuntu), gawk (RHEL) and BusyBox awk (Alpine); tested
under all three. Fixed regexes reach awk through ENVIRON, never `-v` (which
would process backslash escapes differently per awk).

Times. Formats with a zone (audit epochs, access logs, ISO with an offset) give
an exact UTC instant ("E"). Formats without one (syslog, dpkg, apt, nginx/apache
error logs) give the machine's local wall-clock time as a "pseudo-epoch" ("W":
seconds since 1970 as if the wall clock were UTC); awk keeps those within a
2-hour margin of the window (zone offset + a DST change), and the parser turns
them into UTC with the machine's zone and filters the window exactly. Syslog
lines have no year: a month later than the machine's current month belongs to
the previous year.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

try:  # in the agent bundle: a sibling module
    from . import catalog  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources import catalog
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]

DEFAULT_MAX_LINES = 5000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
LINE_MAX_BYTES = 2048
WALL_MARGIN_SECONDS = 7200          # zone offset uncertainty: a DST change, plus a margin
JOURNAL_FIELDS = ("MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_PID", "_UID", "_SYSTEMD_UNIT", "UNIT", "PRIORITY",
                  "_BOOT_ID", "_TRANSPORT", "SYSLOG_PID", "_HOSTNAME")
COMPRESSED_SUFFIXES = (".gz", ".xz", ".bz2", ".zst", ".lz4")
MAX_SKIPPED_LISTED = 20

# --------------------------------------------------------------------------
# The extractor. Input: one file on stdin. ENVIRON: KR_FMT, KR_KEEP.
# -v: idx slot lo hi (epochs, -1 = open) tzs (date +%z) ynow mnow maxl maxb lmax margin
# Output: "L idx slot E|W time text" newest first, then one
#         "S idx slot matched emitted first_kind first last_kind last parsed cut".
# --------------------------------------------------------------------------
AWK = r'''
BEGIN { CONVFMT = "%.6f"; OFMT = "%.6f"; fmt = ENVIRON["KR_FMT"]; keep = ENVIRON["KR_KEEP"]
  n = 0; matched = 0; parsed = 0; cut = 0; fk = ""; fv = ""; lk = ""; lv = ""; ro = 0
  if (chunk == "") chunk = -1
  chunk += 0; nb = 0; havep = 0; pos = 0; rstart = 0; skip1 += 0
  tzoff = offsec(tzs) }
function dfc(y, m, d,   era, yoe, doy, doe) {   # days from civil (H. Hinnant), pure arithmetic
  y -= (m <= 2); era = int((y >= 0 ? y : y - 399) / 400); yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}
function mon(name) { return (index("JanFebMarAprMayJunJulAugSepOctNovDec", substr(name, 1, 3)) + 2) / 3 }
function offsec(z,   sign) {
  if (z == "Z" || z == "") return 0
  sign = (substr(z, 1, 1) == "-") ? -1 : 1; gsub(/:/, "", z)
  return sign * ((substr(z, 2, 2) + 0) * 3600 + (substr(z, 4, 2) + 0) * 60)
}
function wall(y, m, d, hh, mi, ss) { TK = "W"; TV = dfc(y, m, d) * 86400 + hh * 3600 + mi * 60 + ss; return 1 }
function exact(y, m, d, hh, mi, ss, off, frac) {
  TK = "E"; TV = dfc(y, m, d) * 86400 + hh * 3600 + mi * 60 + ss - off + frac; return 1
}
function syear(m) { return (m > mnow + 0) ? ynow - 1 : ynow + 0 }
function iso(s,   rest, frac, z, k) {   # YYYY-MM-DD[T ]HH:MM:SS[.frac][Z|+hh[:]mm]
  rest = substr(s, 20); frac = 0
  if (rest ~ /^[.,][0-9]+/) {
    k = 2; while (substr(rest, k, 1) ~ /[0-9]/) k++
    frac = ("0." substr(rest, 2, k - 2)) + 0; rest = substr(rest, k)
  }
  z = rest; sub(/[ \t].*/, "", z)
  if (z == "Z" || z ~ /^[+-][0-9][0-9]:?[0-9][0-9]$/)
    return exact(substr(s, 1, 4) + 0, substr(s, 6, 2) + 0, substr(s, 9, 2) + 0, substr(s, 12, 2) + 0,
                 substr(s, 15, 2) + 0, substr(s, 18, 2) + 0, offsec(z), frac)
  return wall(substr(s, 1, 4) + 0, substr(s, 6, 2) + 0, substr(s, 9, 2) + 0, substr(s, 12, 2) + 0,
              substr(s, 15, 2) + 0, substr(s, 18, 2) + 0)
}
function sysl(s,   a, t, m) {      # "Oct 11 17:18:01 ..." (day may be space-padded)
  split(s, a, " "); m = mon(a[1]); if (m < 1) return 0
  split(a[3], t, ":"); return wall(syear(m), m, a[2] + 0, t[1] + 0, t[2] + 0, t[3] + 0)
}
function ptime(s,   p, a, t, m, q) {
  TK = ""; TV = 0
  if (fmt == "syslog" || fmt == "sudo_log") {
    if (s ~ /^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return sysl(s)
    if (s ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return iso(s)
    return 0
  }
  if (fmt == "iso" || fmt == "dpkg") {
    if (s ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return iso(s)
    return 0
  }
  if (fmt == "audit") {
    p = index(s, "msg=audit("); if (!p) return 0
    t = substr(s, p + 10); sub(/:.*/, "", t)
    if (t !~ /^[0-9]+(\.[0-9]+)?$/) return 0
    TK = "E"; TV = t + 0; return 1
  }
  if (fmt == "clf") {
    p = index(s, " ["); if (!p) return 0
    t = substr(s, p + 2, 26)   # 11/Oct/2026:17:12:05 +0000
    if (t !~ /^[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9] [+-][0-9][0-9][0-9][0-9]$/) return 0
    m = mon(substr(t, 4, 3)); if (m < 1) return 0
    return exact(substr(t, 8, 4) + 0, m, substr(t, 1, 2) + 0, substr(t, 13, 2) + 0, substr(t, 16, 2) + 0,
                 substr(t, 19, 2) + 0, offsec(substr(t, 22, 5)), 0)
  }
  if (fmt == "nginx_error") {
    if (s !~ /^[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return 0
    return wall(substr(s, 1, 4) + 0, substr(s, 6, 2) + 0, substr(s, 9, 2) + 0, substr(s, 12, 2) + 0,
                substr(s, 15, 2) + 0, substr(s, 18, 2) + 0)
  }
  if (fmt == "apache_error") {    # [Sun Oct 11 17:11:52.123456 2026] [...]
    if (s !~ /^\[[A-Z][a-z][a-z] [A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9][.0-9]* [0-9][0-9][0-9][0-9]\]/) return 0
    t = substr(s, 2); sub(/\].*/, "", t); split(t, a, " "); m = mon(a[2]); if (m < 1) return 0
    split(a[4], q, ":")
    return wall(a[5] + 0, m, a[3] + 0, q[1] + 0, q[2] + 0, int(q[3] + 0))
  }
  return 0
}
function inwin(k, v) {
  if (k == "E") return (lo < 0 || v >= lo) && (hi < 0 || v <= hi)
  return (lo < 0 || v >= lo + tzoff - margin) && (hi < 0 || v <= hi + tzoff + margin)
}
function seen_time(k, v) { parsed++; if (fk == "") { fk = k; fv = v } lk = k; lv = v }
function consider(k, v, text) {
  if (keep != "" && text !~ keep) return
  if (!inwin(k, v)) return
  matched++
  gsub(/\t/, " ", text)
  if (length(text) > lmax) { text = substr(text, 1, lmax); cut++ }
  ring[n % maxl] = k "\t" v "\t" text; n++
}
# multi-line records: apt history blocks, sudo logfile continuations
function ropen(k, v, text) { rclose(); ro = 1; rk = k; rv = v; rt = text; rstart = pos }
function radd(text) { if (ro && length(rt) < lmax) rt = rt "\037" text }
function rclose() { if (ro) consider(rk, rv, rt); ro = 0 }
function proc(   aa, tt, cont) {
  sub(/\r$/, "")
  if (fmt == "apt_history") {
    if ($0 ~ /^Start-Date: [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] +[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
      split($0, aa, " "); split(aa[3], tt, ":")
      wall(substr(aa[2], 1, 4) + 0, substr(aa[2], 6, 2) + 0, substr(aa[2], 9, 2) + 0, tt[1] + 0, tt[2] + 0, tt[3] + 0)
      seen_time(TK, TV); ropen(TK, TV, $0)
    } else if ($0 ~ /^End-Date:/) { radd($0); rclose() }
    else if ($0 == "") rclose()
    else radd($0)
    return
  }
  if (fmt == "sudo_log") {
    if ($0 ~ /^[ \t]/) { cont = $0; sub(/^[ \t]+/, "", cont); radd(cont); return }
    if (ptime($0)) { seen_time(TK, TV); ropen(TK, TV, $0) }
    return
  }
  if (ptime($0)) { seen_time(TK, TV); consider(TK, TV, $0) }
}
# chunk >= 0 (incremental sync): the input is a slice of a file that may end mid-line,
# so a line is only processed once the next one proves it was complete; a record still
# open at the end (an apt block, a sudo entry with continuations) is held back. The S
# line then also reports `consumed`: how many bytes of the slice are fully handled, so
# the caller advances exactly that far. chunk < 0 (the default) is the whole-file
# behaviour, line for line as before.
{
  if (chunk < 0) { proc(); next }
  curlen = length($0) + 1
  if (skip1 + 0 && NR == 1) { nb += curlen; next }      # a first sync starts mid-line: drop the partial line
  if (havep) { cur = $0; $0 = pend; pos = pendpos; proc(); $0 = cur }
  pend = $0; pendlen = curlen; pendpos = nb; havep = 1; nb += curlen
}
END {
  if (chunk >= 0) {
    if (havep) {
      if (nb == chunk) { $0 = pend; pos = pendpos; proc() } else nb -= pendlen
    }
    consumed = nb
    if (consumed > chunk) consumed = chunk
    if (ro) { consumed = rstart; ro = 0 }
  } else rclose()
  c = (n < maxl) ? n : maxl; b = 0; e = 0
  for (j = n - 1; j >= n - c; j--) {
    r = ring[j % maxl]; b += length(r) + 1
    if (b > maxb) break
    printf "L\t%s\t%s\t%s\n", idx, slot, r; e++
  }
  if (chunk >= 0)
    printf "S\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\n", idx, slot, matched, e, fk, fv, lk, lv, parsed, cut, consumed
  else
    printf "S\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%d\t%d\n", idx, slot, matched, e, fk, fv, lk, lv, parsed, cut
}
'''

# How a journal part's lines are capped in bytes on the way out (SSH path; the
# agent caps with run_capped). Prints JT when the cap stops it.
_JOURNAL_CAP_AWK = r'''{ b += length($0) + 1; if (b > cap) { print "JT\t" m; exit } print "J\t" m "\t" $0 }'''


# --------------------------------------------------------------------------
# Which files a FileSpec reads: the current file and its first rotation
# --------------------------------------------------------------------------
def previous_rotation(base: str, names: list[str]) -> str | None:
    """The plain (not compressed) first rotation of `base` among the names in its
    directory: `.0` (BusyBox syslogd), else `.1` (logrotate), else the newest
    dateext `-YYYYMMDD` (RHEL). Mirrors the shell in `_FILE_FN` exactly."""
    if base + ".0" in names:
        return base + ".0"
    if base + ".1" in names:
        return base + ".1"
    dated = sorted(n for n in names if n.startswith(base + "-") and n[len(base) + 1:len(base) + 2].isdigit()
                   and not n.endswith(COMPRESSED_SUFFIXES))
    return dated[-1] if dated else None


def skipped_rotations(base: str, names: list[str], chosen: str | None) -> list[str]:
    """Other rotations of `base` that were not read (compressed or older), in the
    order the shell lists them: `base.*` sorted, then `base-*` sorted."""
    out = [n for n in sorted(names) if n.startswith(base + ".") and n != chosen]
    out += [n for n in sorted(names) if n.startswith(base + "-") and n != chosen]
    return out[:MAX_SKIPPED_LISTED]


# --------------------------------------------------------------------------
# The SSH script
# --------------------------------------------------------------------------
_ALLOWED_PREFIXES = frozenset({"", "sudo -n"})
_ROOT_RE = re.compile(r"(/[A-Za-z0-9._-]+)*")   # tests only: a plain absolute directory


def _checked_prefix(prefix: str) -> str:
    if str(prefix).strip() not in _ALLOWED_PREFIXES:
        raise ValueError(f"journalctl prefix must be one of {sorted(_ALLOWED_PREFIXES)}, not {prefix!r}")
    return str(prefix).strip()


def _checked_root(root: str) -> str:
    if not _ROOT_RE.fullmatch(str(root)):
        raise ValueError(f"root {root!r} must be '' or a plain absolute directory")
    return str(root)


def journal_argv(match: str, since: float | None, until: float | None, lines: int,
                 prefix: list[str] | tuple[str, ...] = ()) -> list[str]:
    """journalctl for one closed match: newest first, absolute epochs, one extra
    line so truncation shows (same contract as subagent.reads.window_args)."""
    args = [*prefix, "journalctl", "--no-pager", "-o", "json", "--output-fields=" + ",".join(JOURNAL_FIELDS),
            *catalog.JOURNAL_MATCHES[match]]
    if since is not None:
        args += ["--since", f"@{int(since)}"]
    if until is not None:
        args += ["--until", f"@{int(until) + 1}"]
    return args + ["--reverse", "-n", str(int(lines) + 1)]


_FILE_FN = r'''
kr_one() {  # idx slot path fmt
  if [ -L "$3" ]; then printf 'F\t%s\t%s\t%s\tsymlink\t-\n' "$1" "$2" "$3"; return; fi
  if [ ! -e "$3" ]; then
    _p=${3%/*}
    if [ -d "$_p" ] && { [ ! -x "$_p" ] || [ ! -r "$_p" ]; }; then printf 'F\t%s\t%s\t%s\tunreadable\tdirectory\n' "$1" "$2" "$3"
    else printf 'F\t%s\t%s\t%s\tmissing\t-\n' "$1" "$2" "$3"; fi
    return
  fi
  if [ ! -f "$3" ]; then printf 'F\t%s\t%s\t%s\tnot_regular\t-\n' "$1" "$2" "$3"; return; fi
  _nl=$(stat -c %h "$3" 2>/dev/null || echo 1)
  if [ "${_nl:-1}" -gt 1 ]; then printf 'F\t%s\t%s\t%s\thardlink\t%s\n' "$1" "$2" "$3" "$_nl"; return; fi
  if [ ! -r "$3" ]; then printf 'F\t%s\t%s\t%s\tunreadable\t-\n' "$1" "$2" "$3"; return; fi
  case "$3" in *.gz|*.xz|*.bz2|*.zst|*.lz4) printf 'F\t%s\t%s\t%s\tcompressed\t-\n' "$1" "$2" "$3"; return;; esac
  printf 'F\t%s\t%s\t%s\tread\t%s\n' "$1" "$2" "$3" "$(stat -c %s "$3" 2>/dev/null || echo -)"
  KR_FMT="$4" awk -v idx="$1" -v slot="$2" -v lo="$KR_LO" -v hi="$KR_HI" -v tzs="$KR_TZS" -v ynow="$KR_Y" \
      -v mnow="$KR_M" -v maxl="$KR_MAXL" -v maxb="$KR_MAXB" -v lmax="$KR_LMAX" -v margin="$KR_MARGIN" \
      "$KR_AWK" < "$3"
}
kr_file() {  # idx path fmt when   (KR_KEEP set by the caller)
  if [ "$4" = no_journal ] && [ "$KR_HAVE_J" = 1 ]; then printf 'F\t%s\t0\t%s\tskipped_journal\t-\n' "$1" "$2"; return; fi
  kr_one "$1" 0 "$2" "$3"
  _prev=""
  if [ -e "$2.0" ] || [ -L "$2.0" ]; then _prev="$2.0"
  elif [ -e "$2.1" ] || [ -L "$2.1" ]; then _prev="$2.1"
  else
    for _g in "$2"-[0-9]*; do
      case "$_g" in *.gz|*.xz|*.bz2|*.zst|*.lz4) ;; *) { [ -e "$_g" ] || [ -L "$_g" ]; } && _prev="$_g" ;; esac
    done
  fi
  [ -n "$_prev" ] && kr_one "$1" 1 "$_prev" "$3"
  _k=0
  for _g in "$2".* "$2"-*; do
    { [ -e "$_g" ] || [ -L "$_g" ]; } || continue
    [ "$_g" = "$_prev" ] && continue
    _k=$((_k + 1)); [ "$_k" -gt __MAXSKIP__ ] && break
    printf 'R\t%s\t%s\n' "$1" "$_g"
  done
}
'''


def build_script(source: str, since: float | None, until: float | None, *, journal_prefix: str = "sudo -n",
                 max_lines: int = DEFAULT_MAX_LINES, max_bytes: int = DEFAULT_MAX_BYTES, root: str = "") -> str:
    """The read-only script for one source over SSH. Every value placed in it is a
    constant from this file / the catalog, an int, or checked here. `root` exists
    for tests (a fake filesystem tree); the agent and SSH reads use "/"."""
    src = catalog.SOURCES[source]
    jp = _checked_prefix(journal_prefix)
    root = _checked_root(root)
    lo = -1 if since is None else int(since)
    hi = -1 if until is None else int(until) + 1
    max_lines, max_bytes = int(max_lines), int(max_bytes)
    parts: list[str] = [
        "LC_ALL=C; export LC_ALL",
        catalog.FAMILY_SH.replace("/etc/os-release", f"{root}/etc/os-release"),
        "printf 'M\\tfamily\\t%s\\n' \"$FAMILY\"",
        f"printf 'M\\ttz_name\\t%s\\n' \"$( (cat {root}/etc/timezone 2>/dev/null || readlink {root}/etc/localtime "
        "2>/dev/null | sed 's|.*zoneinfo/||') | head -1)\"",
        "KR_TZS=$(date +%z); printf 'M\\ttz_offset\\t%s\\n' \"$KR_TZS\"",
        "printf 'M\\tnow\\t%s\\n' \"$(date +%s)\"",
        "KR_YM=$(date '+%Y %m'); KR_Y=${KR_YM% *}; KR_M=$(echo \"${KR_YM#* }\" | sed 's/^0//')",
        "KR_HAVE_J=0; command -v journalctl >/dev/null 2>&1 && KR_HAVE_J=1",
        "printf 'M\\tjournal\\t%s\\n' \"$KR_HAVE_J\"",
        "printf 'M\\tcontainer\\t%s\\n' \"$(systemd-detect-virt -c 2>/dev/null || echo none)\"",
        f"KR_LO={lo}; KR_HI={hi}; KR_MAXL={max_lines}; KR_MAXB={max_bytes}; KR_LMAX={LINE_MAX_BYTES}; "
        f"KR_MARGIN={WALL_MARGIN_SECONDS}",
        f"KR_AWK={shlex.quote(AWK)}",
        "KR_T=$(mktemp -d 2>/dev/null || { _d=/tmp/kratos_logread.$$; mkdir -m 700 \"$_d\" && echo \"$_d\"; })",
        "trap 'rm -rf \"$KR_T\"' EXIT",
        _FILE_FN.replace("__MAXSKIP__", str(MAX_SKIPPED_LISTED)),
        "case \"$FAMILY\" in",
    ]
    for family in catalog.FAMILIES:
        body: list[str] = []
        if family in src.gaps:
            body.append(f"printf 'M\\tgap\\t%s\\n' {shlex.quote(src.gaps[family])}")
        for match in src.journal.get(family, ()):
            argv = journal_argv(match, since, until, max_lines, prefix=jp.split() if jp else ())
            body.append(
                "if [ \"$KR_HAVE_J\" = 1 ]; then\n"
                f"  {shlex.join(argv)} 2>\"$KR_T/je\" | awk -v m={match} -v cap={max_bytes} "
                f"{shlex.quote(_JOURNAL_CAP_AWK)}\n"
                f"  [ -s \"$KR_T/je\" ] && printf 'JE\\t%s\\t%s\\n' {match} \"$(head -c 300 \"$KR_T/je\" | tr '\\t\\n' '  ')\"\n"
                f"else printf 'JE\\t%s\\t%s\\n' {match} 'no journalctl on this machine'; fi"
            )
        for i, spec in enumerate(src.files.get(family, ())):
            body.append(f"KR_KEEP={shlex.quote(spec.keep)}; export KR_KEEP; "
                        f"kr_file {i} {shlex.quote(root + spec.path)} {spec.fmt} {spec.when}")
        parts.append(f"{family})\n" + ("\n".join(body) if body else ":") + "\n;;")
    parts.append("*) printf 'M\\tgap\\t%s\\n' 'unknown Linux distribution: no log paths are known for it' ;;")
    parts.append("esac")
    parts.append("exit 0")   # problems are reported in the output, never as the script's exit status
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------
# Parsing (both transports)
# --------------------------------------------------------------------------
@dataclass
class FileRead:
    index: int
    slot: int                 # 0 = the current file, 1 = its first rotation
    path: str
    status: str               # read / missing / unreadable / symlink / hardlink / not_regular / compressed / skipped_journal / refused
    detail: str = ""
    matched: int = 0
    emitted: int = 0
    parsed: int = 0
    first: float | None = None   # oldest time in the file (UTC epoch, any line)
    last: float | None = None
    cut_lines: int = 0
    inode: int | None = None      # sync reads: the file's inode / size when it was looked at
    size: int | None = None
    consumed: int | None = None   # sync reads: bytes of the slice fully handled (whole lines / closed records)
    start: int | None = None      # sync reads: the byte offset the slice began at

    @property
    def truncated(self) -> bool:
        return self.matched > self.emitted


@dataclass
class Record:
    kind: str                 # "file" | "journal"
    ts: float                 # UTC epoch
    text: str = ""            # file line (multi-line records joined with \x1f)
    path: str | None = None
    entry: dict[str, Any] | None = None   # journal JSON
    match: str | None = None
    zone_assumed: bool = False


@dataclass
class LogRead:
    source: str
    family: str | None = None
    tz_name: str | None = None
    tz_offset: str | None = None
    now: float | None = None
    has_journal: bool = False
    gaps: list[str] = field(default_factory=list)
    files: list[FileRead] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    journal_errors: dict[str, str] = field(default_factory=dict)
    journal_truncated: set[str] = field(default_factory=set)
    journal_counts: dict[str, int] = field(default_factory=dict)
    records: list[Record] = field(default_factory=list)
    truncated: bool = False
    since: float | None = None
    until: float | None = None
    via: str = "ssh"                  # how it was read: ssh / subagent
    container: str | None = None      # systemd-detect-virt -c, if the machine is a container
    read_label: str | None = None     # the event "read" name's prefix ("log_read" unless a sync set it)


def _zone(tz_name: str | None, tz_offset: str | None) -> tuple[Any, bool]:
    """The machine's zone: its IANA name if this Python knows it, else the fixed
    offset `date +%z` reported (exact except across a DST change), else UTC
    (assumed)."""
    if tz_name:
        try:
            from zoneinfo import ZoneInfo

            return ZoneInfo(tz_name.strip()), False
        except Exception:  # noqa: BLE001 -- unknown name / no tzdata: fall back to the offset
            pass
    m = re.fullmatch(r"([+-])(\d\d)(\d\d)", (tz_offset or "").strip())
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))), False
    return timezone.utc, True


_EPOCH = datetime(1970, 1, 1)


def wall_to_utc(pseudo: float, zone: Any) -> float:
    """A local wall-clock pseudo-epoch -> UTC epoch, in `zone`."""
    naive = _EPOCH + timedelta(seconds=float(pseudo))
    return naive.replace(tzinfo=zone).timestamp()


def _num(text: str) -> float | None:
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def parse_output(source: str, stdout: str, since: float | None, until: float | None, *,
                 max_lines: int = DEFAULT_MAX_LINES) -> LogRead:
    """Turn either transport's output into a LogRead: records sorted newest first,
    exactly inside [since, until], at most `max_lines` (then `truncated`)."""
    out = LogRead(source=source, since=since, until=until)
    pending: list[tuple[int, int, str, str, str]] = []
    pending_stats: list[list[str]] = []
    journal_rows: list[tuple[str, str]] = []
    files: dict[tuple[int, int], FileRead] = {}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        tag = cols[0]
        if tag == "M" and len(cols) >= 3:
            key, val = cols[1], "\t".join(cols[2:])
            if key == "family":
                out.family = val if val in catalog.FAMILIES else None
            elif key == "tz_name":
                out.tz_name = val.strip() or None
            elif key == "tz_offset":
                out.tz_offset = val.strip() or None
            elif key == "now":
                out.now = _num(val)
            elif key == "journal":
                out.has_journal = val.strip() == "1"
            elif key == "gap":
                out.gaps.append(val)
            elif key == "container":
                out.container = None if val.strip() in ("", "none") else val.strip()
        elif tag == "F" and len(cols) >= 6 and cols[1].isdigit() and cols[2].isdigit():
            fr = FileRead(index=int(cols[1]), slot=int(cols[2]), path=cols[3], status=cols[4],
                          detail="" if cols[5] == "-" else cols[5])
            if cols[5].isdigit():
                fr.size = int(cols[5])
            if len(cols) >= 7 and cols[6].isdigit():
                fr.inode = int(cols[6])
            if len(cols) >= 8 and cols[7].isdigit():
                fr.start = int(cols[7])
            files[(fr.index, fr.slot)] = fr
            out.files.append(fr)
        elif tag == "L" and len(cols) >= 6 and cols[1].isdigit() and cols[2].isdigit():
            pending.append((int(cols[1]), int(cols[2]), cols[3], cols[4], "\t".join(cols[5:])))
        elif tag == "S" and len(cols) >= 11:
            pending_stats.append(cols)
        elif tag == "R" and len(cols) >= 3:
            out.skipped.append(cols[2])
        elif tag == "J" and len(cols) >= 3:
            journal_rows.append((cols[1], "\t".join(cols[2:])))
        elif tag == "JT" and len(cols) >= 2:
            out.journal_truncated.add(cols[1])
        elif tag == "JE" and len(cols) >= 3:
            out.journal_errors[cols[1]] = "\t".join(cols[2:]).strip()

    zone, assumed = _zone(out.tz_name, out.tz_offset)

    def to_utc(kind: str, value: str) -> float | None:
        v = _num(value)
        if v is None:
            return None
        return v if kind == "E" else wall_to_utc(v, zone)

    for cols in pending_stats:
        fr = files.get((int(cols[1]), int(cols[2]))) if cols[1].isdigit() and cols[2].isdigit() else None
        if fr is None:
            continue
        fr.matched, fr.emitted = int(_num(cols[3]) or 0), int(_num(cols[4]) or 0)
        fr.first = to_utc(cols[5], cols[6]) if cols[5] else None
        fr.last = to_utc(cols[7], cols[8]) if cols[7] else None
        fr.parsed, fr.cut_lines = int(_num(cols[9]) or 0), int(_num(cols[10]) or 0)
        if len(cols) >= 12:
            fr.consumed = int(_num(cols[11]) or 0)

    lo = since if since is not None else float("-inf")
    hi = until if until is not None else float("inf")
    records: list[Record] = []
    for idx, slot, kind, value, text in pending:
        ts = to_utc(kind, value)
        if ts is None or not lo <= ts <= hi + 0.999999:
            continue
        fr = files.get((idx, slot))
        records.append(Record(kind="file", ts=ts, text=text, path=fr.path if fr else None,
                              zone_assumed=assumed and kind == "W"))
    journal_keys: set[tuple[int, str]] = set()
    per_match: dict[str, list[Record]] = {}
    for match, raw in journal_rows:
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        try:
            ts = int(entry.get("__REALTIME_TIMESTAMP")) / 1_000_000
        except (TypeError, ValueError):
            continue
        if not lo <= ts <= hi + 0.999999:
            continue
        per_match.setdefault(match, []).append(Record(kind="journal", ts=ts, entry=entry, match=match))
    for match, recs in per_match.items():
        # journalctl was asked for one line more than the cap: seeing it means the
        # window held more (subagent.reads.window_args).
        if len(recs) > max_lines:
            out.journal_truncated.add(match)
            recs = recs[:max_lines]
        out.journal_counts[match] = len(recs)
        for r in recs:
            msg = r.entry.get("MESSAGE") if r.entry else None
            if isinstance(msg, str):
                journal_keys.add((int(r.ts), " ".join(msg.split())[:200]))
        records.extend(recs)
    # A file line the journal already has (same second, same message) is the same
    # event written twice (rsyslog copies the journal into /var/log): keep the
    # journal's, which carries more fields.
    if journal_keys:
        records = [r for r in records if r.kind != "file" or not _dup_of_journal(r, journal_keys)]
    records.sort(key=lambda r: r.ts, reverse=True)
    any_file_trunc = any(fr.truncated for fr in out.files)
    if len(records) > max_lines:
        records = records[:max_lines]
        out.truncated = True
    out.truncated = out.truncated or any_file_trunc or bool(out.journal_truncated)
    out.records = records
    return out


_SYSLOG_HEAD = re.compile(r"^(?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ (?P<msg>.*)$")


def _dup_of_journal(rec: Record, keys: set[tuple[int, str]]) -> bool:
    m = _SYSLOG_HEAD.match(rec.text)
    if not m:
        return False
    rest = m.group("msg")
    _prog, sep, msg = rest.partition(": ")
    if not sep:
        return False
    return (int(rec.ts), " ".join(msg.split())[:200]) in keys


# --------------------------------------------------------------------------
# Incremental sync (phase A.0): read FORWARD from a saved position
# --------------------------------------------------------------------------
SYNC_CHUNK_BYTES = 2 * 1024 * 1024        # most bytes of one file handled per sync round
SYNC_FIRST_TAIL_BYTES = 2 * 1024 * 1024   # a first sync of a file starts this far from its end
SYNC_MAX_RECORDS = 400000
SYNC_JOURNAL_MAX_LINES = 200000
SYNC_JOURNAL_MAX_BYTES = 16 * 1024 * 1024
# systemd's cursor: s=<seqnum id>;i=<seqnum>;b=<boot id>;m=<monotonic>;t=<realtime>;x=<xor hash>.
# Checked before one is ever placed in a command (verified on systemd 249 and 252).
CURSOR_RE = re.compile(r"^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};t=[0-9a-f]{1,16};"
                       r"x=[0-9a-f]{1,16}$")


def valid_cursor(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 160 and bool(CURSOR_RE.fullmatch(value))


def cursor_realtime(cursor: str) -> float | None:
    """The wall-clock time (UTC epoch) a journal cursor's `t=` field holds."""
    m = re.search(r";t=([0-9a-f]+);", cursor or "")
    return int(m.group(1), 16) / 1000000 if m else None


def journal_sync_argv(match: str, after_cursor: str | None, since: float | None,
                      prefix: list[str] | tuple[str, ...] = ()) -> list[str]:
    """journalctl for one closed match, FORWARD from a saved cursor (or from `since` on a
    first sync). No -n: it is version-dependent (it can mean the newest N), so the caller
    caps the lines itself. No --cursor-file: that would write a file on the monitored machine."""
    args = [*prefix, "journalctl", "--no-pager", "-o", "json", "--output-fields=" + ",".join(JOURNAL_FIELDS),
            *catalog.JOURNAL_MATCHES[match]]
    if after_cursor is not None:
        if not valid_cursor(after_cursor):
            raise ValueError("not a journal cursor")
        args.append("--after-cursor=" + after_cursor)
    elif since is not None:
        args += ["--since", f"@{int(since)}"]
    return args


# One awk keeps entry lines, labels journalctl's own complaints, and stops at a byte cap.
_JOURNAL_SYNC_AWK = (r'''/^\{/ { b += length($0) + 1; if (b > cap) { print "JT"; exit } print "J\t" $0; next } '''
                     r'''{ gsub(/\t/, " "); print "JE\t" substr($0, 1, 300) }''')


def build_journal_sync_script(match: str, after_cursor: str | None, since: float | None, lines: int, *,
                              journal_prefix: str = "sudo -n", max_bytes: int = SYNC_JOURNAL_MAX_BYTES) -> str:
    """The read-only script for one journal sync over SSH: the oldest entry the journal
    still holds (so a vacuumed hole shows), then up to `lines`+1 entries after the cursor."""
    jp = _checked_prefix(journal_prefix)
    prefix = jp.split() if jp else []
    main = journal_sync_argv(match, after_cursor, since, prefix)
    oldest = [*prefix, "journalctl", "--no-pager", "-o", "json", "--output-fields=MESSAGE"]
    return "\n".join([
        "LC_ALL=C; export LC_ALL",
        "printf 'M\\tnow\\t%s\\n' \"$(date +%s)\"",
        "KR_HAVE_J=0; command -v journalctl >/dev/null 2>&1 && KR_HAVE_J=1",
        "printf 'M\\tjournal\\t%s\\n' \"$KR_HAVE_J\"",
        "if [ \"$KR_HAVE_J\" = 1 ]; then",
        f"  {shlex.join(oldest)} 2>/dev/null | head -n 1 | awk '{{ print \"O\\t\" $0 }}'",
        f"  {shlex.join(main)} 2>&1 | head -n {int(lines) + 1} | awk -v cap={int(max_bytes)} "
        f"{shlex.quote(_JOURNAL_SYNC_AWK)}",
        "fi",
        "exit 0",
    ]) + "\n"


@dataclass
class JournalSync:
    have_journal: bool = False
    now: float | None = None
    oldest_ts: float | None = None            # the oldest entry the journal still holds (any source)
    entries: list[dict[str, Any]] = field(default_factory=list)   # forward order
    byte_capped: bool = False                 # the output byte cap stopped the stream early
    errors: list[str] = field(default_factory=list)
    via: str = "ssh"


def parse_journal_sync(stdout: str) -> JournalSync:
    out = JournalSync()
    for line in stdout.split("\n"):
        cols = line.split("\t", 2)
        tag = cols[0]
        if tag == "M" and len(cols) == 3:
            if cols[1] == "journal":
                out.have_journal = cols[2].strip() == "1"
            elif cols[1] == "now":
                out.now = _num(cols[2])
        elif tag == "O" and len(cols) >= 2:
            try:
                out.oldest_ts = int(json.loads(line.split("\t", 1)[1]).get("__REALTIME_TIMESTAMP")) / 1000000
            except (ValueError, TypeError, AttributeError):
                pass
        elif tag == "J" and len(cols) >= 2:
            try:
                entry = json.loads(line.split("\t", 1)[1])
            except ValueError:
                continue
            if isinstance(entry, dict):
                out.entries.append(entry)
        elif tag == "JT":
            out.byte_capped = True
        elif tag == "JE" and len(cols) >= 2:
            out.errors.append(line.split("\t", 1)[1].strip())
    return out


_SYNC_FN = r'''
kr_state() {  # path idx slot -> sets _INO _SIZE, or prints the reason and returns 1
  if [ -L "$1" ]; then printf 'F\t%s\t%s\t%s\tsymlink\t-\n' "$2" "$3" "$1"; return 1; fi
  if [ ! -e "$1" ]; then
    _p=${1%/*}
    if [ -d "$_p" ] && { [ ! -x "$_p" ] || [ ! -r "$_p" ]; }; then printf 'F\t%s\t%s\t%s\tunreadable\tdirectory\n' "$2" "$3" "$1"
    else printf 'F\t%s\t%s\t%s\tmissing\t-\n' "$2" "$3" "$1"; fi
    return 1
  fi
  if [ ! -f "$1" ]; then printf 'F\t%s\t%s\t%s\tnot_regular\t-\n' "$2" "$3" "$1"; return 1; fi
  _nl=$(stat -c %h "$1" 2>/dev/null || echo 1)
  if [ "${_nl:-1}" -gt 1 ]; then printf 'F\t%s\t%s\t%s\thardlink\t%s\n' "$2" "$3" "$1" "$_nl"; return 1; fi
  if [ ! -r "$1" ]; then printf 'F\t%s\t%s\t%s\tunreadable\t-\n' "$2" "$3" "$1"; return 1; fi
  _INO=$(stat -c %i "$1" 2>/dev/null); _SIZE=$(stat -c %s "$1" 2>/dev/null)
  case "$_INO$_SIZE" in ""|*[!0-9]*) printf 'F\t%s\t%s\t%s\tunreadable\tstat\n' "$2" "$3" "$1"; return 1;; esac
  return 0
}
kr_slice() {  # idx slot path fmt off n skipfirst : one slice [off, off+n) through the extractor
  printf 'F\t%s\t%s\t%s\tread\t%s\t%s\t%s\n' "$1" "$2" "$3" "$_SIZE" "$_INO" "$5"
  if [ "$6" -le 0 ]; then printf 'S\t%s\t%s\t0\t0\t\t\t\t\t0\t0\t0\n' "$1" "$2"; return; fi
  tail -c +$(($5 + 1)) "$3" | head -c "$6" | KR_FMT="$4" awk -v idx="$1" -v slot="$2" -v lo="$KR_LO" -v hi=-1 \
      -v tzs="$KR_TZS" -v ynow="$KR_Y" -v mnow="$KR_M" -v maxl="$KR_MAXL" -v maxb="$KR_MAXB" -v lmax="$KR_LMAX" \
      -v margin="$KR_MARGIN" -v chunk="$6" -v skip1="$7" "$KR_AWK"
  _I2=$(stat -c %i "$3" 2>/dev/null)
  [ "$_I2" = "$_INO" ] || printf 'F\t%s\t%s\t%s\tchanged\t-\n' "$1" "$2" "$3"
}
kr_sync() {  # idx path fmt saved_ino saved_off     (KR_KEEP set by the caller)
  kr_state "$2" "$1" 0 || return
  _cur_ino=$_INO; _cur_size=$_SIZE
  if [ -z "$4" ]; then                               # first sync: the tail of the file
    _off=$((_cur_size - KR_FIRST)); _skip=1; [ "$_off" -le 0 ] && { _off=0; _skip=0; }
    _n=$((_cur_size - _off)); [ "$_n" -gt "$KR_CHUNK" ] && _n=$KR_CHUNK
    kr_slice "$1" 0 "$2" "$3" "$_off" "$_n" "$_skip"
  elif [ "$4" = "$_cur_ino" ]; then
    if [ "$5" -gt "$_cur_size" ]; then
      printf 'F\t%s\t0\t%s\ttruncated\t%s\t%s\n' "$1" "$2" "$_cur_size" "$_cur_ino"
    else
      _n=$((_cur_size - $5)); [ "$_n" -gt "$KR_CHUNK" ] && _n=$KR_CHUNK
      kr_slice "$1" 0 "$2" "$3" "$5" "$_n" 0
    fi
  else                                               # rotated: find the file that had the saved inode
    _found=""
    for _g in "$2.0" "$2.1" "$2"-[0-9]*; do
      case "$_g" in *.gz|*.xz|*.bz2|*.zst|*.lz4) continue;; esac
      [ -f "$_g" ] && [ ! -L "$_g" ] && [ "$(stat -c %i "$_g" 2>/dev/null)" = "$4" ] && _found="$_g"
    done
    printf 'F\t%s\t0\t%s\tcurrent\t%s\t%s\n' "$1" "$2" "$_cur_size" "$_cur_ino"
    if [ -n "$_found" ] && kr_state "$_found" "$1" 1; then
      _n=$((_SIZE - $5)); [ "$_n" -lt 0 ] && _n=0; [ "$_n" -gt "$KR_CHUNK" ] && _n=$KR_CHUNK
      kr_slice "$1" 1 "$_found" "$3" "$5" "$_n" 0
    else
      printf 'F\t%s\t1\t%s\trotated_lost\t-\n' "$1" "$2"
    fi
  fi
}
'''


def build_file_sync_script(source: str, positions: dict[int, tuple[int | None, int]], *, floor: float | None,
                           root: str = "") -> str:
    """The read-only script that reads a source's classic files FORWARD from saved
    positions {file index: (inode, byte offset)} over SSH. A file with no saved
    position (inode None) is read from its tail. Every value placed in the script is an
    int, or comes from the catalog. `floor` (UTC epoch) keeps lines older than it out
    of the result (a first sync's look-back)."""
    src = catalog.SYNC_SOURCES[source]
    root = _checked_root(root)
    lo = -1 if floor is None else int(floor)
    parts: list[str] = [
        "LC_ALL=C; export LC_ALL",
        catalog.FAMILY_SH.replace("/etc/os-release", f"{root}/etc/os-release"),
        "printf 'M\\tfamily\\t%s\\n' \"$FAMILY\"",
        f"printf 'M\\ttz_name\\t%s\\n' \"$( (cat {root}/etc/timezone 2>/dev/null || readlink {root}/etc/localtime "
        "2>/dev/null | sed 's|.*zoneinfo/||') | head -1)\"",
        "KR_TZS=$(date +%z); printf 'M\\ttz_offset\\t%s\\n' \"$KR_TZS\"",
        "printf 'M\\tnow\\t%s\\n' \"$(date +%s)\"",
        "KR_YM=$(date '+%Y %m'); KR_Y=${KR_YM% *}; KR_M=$(echo \"${KR_YM#* }\" | sed 's/^0//')",
        f"KR_LO={lo}; KR_MAXL={SYNC_MAX_RECORDS}; KR_MAXB={SYNC_CHUNK_BYTES * 3}; KR_LMAX={LINE_MAX_BYTES}; "
        f"KR_MARGIN={WALL_MARGIN_SECONDS}; KR_CHUNK={SYNC_CHUNK_BYTES}; KR_FIRST={SYNC_FIRST_TAIL_BYTES}",
        f"KR_AWK={shlex.quote(AWK)}",
        _SYNC_FN,
        "case \"$FAMILY\" in",
    ]
    for family in catalog.FAMILIES:
        body: list[str] = []
        for i, spec in enumerate(src.files.get(family, ())):
            if i not in positions:
                continue
            ino, off = positions[i]
            ino_s = "" if ino is None else str(int(ino))
            body.append(f"KR_KEEP={shlex.quote(spec.keep)}; export KR_KEEP; "
                        f"kr_sync {i} {shlex.quote(root + spec.path)} {spec.fmt} '{ino_s}' {int(off)}")
        parts.append(f"{family})\n" + ("\n".join(body) if body else ":") + "\n;;")
    parts.append("*) printf 'M\\tgap\\t%s\\n' 'unknown Linux distribution: no log paths are known for it' ;;")
    parts.append("esac")
    parts.append("exit 0")
    return "\n".join(parts) + "\n"
