"""Facts about named files: hashes, type, packer marker, entropy, package checksum (E.4).

Read-only. The paths come from Kratos's own snapshots of the machine (the core refuses
anything else before sending; the agent refuses a path its own reads didn't list), at
most ``MAX_PATHS`` per read, each absolute, without NUL or newline, at most 4096 bytes.
They travel as base64 of their raw bytes: in the agent's read parameters, or inside the
SSH script text on standard input -- never on a command line.

Two ways to read that print the SAME records, one parser (``parse_output``):

  - ``build_script()`` -- a fixed POSIX sh + awk script for SSH, run AS THE SSH USER;
  - ``facts_output()`` -- the sub-agent's read in stdlib Python, as root, every file
    opened through the hardened opener (kratos.logsources.hostfiles: no symlink in the
    path, regular file, one hard link, not swapped mid-open).

Per file: size, mode, owner uid, mtime, inode, link count, SHA-256, SHA-1 (only for the
CIRCL lookup -- never an identity), MD5 (on Debian, whose package database records MD5s;
elsewhere only when the owning package does),
the type from the first bytes (elf32 / elf64 / script / other -- never the bytes), and,
for files no package owns, a packer marker in the first 64 KiB and the byte entropy of
the first MiB. Package ownership and the package's own checksum for the path come from
the machine's package database (dpkg md5sums, the rpm database, apk's installed db).

Records are tab-separated and name a file by its INDEX in the request, so no path ever
needs escaping on the way back:

  M  now|uid|family  <value>
  F  <idx> <status> <size> <mode> <uid> <mtime> <inode> <nlink> <sha256> <sha1> <md5> <type> <packer> <entropy>
  OWN <idx> <package>
  PK  <idx> <algo> <digest>          algo: md5 | md5c (a dpkg conffile) | sha1 | sha256 | sha384 | sha512 | apk-q1
  PC  <idx> <package> <path>         a file no package owns, identical to that file of that package
  OWNSRC / OWNERR  (as the persistence read)
  END

Status: ok | missing | link | hardlink | not_regular | not_program | unreadable |
too_large | time | refused | changed | not_listed. "-" stands for a value not read.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import stat
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # in the agent bundle: sibling modules
    from . import catalog, hostfiles, persistence  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.adapters import persistence
        from kratos.logsources import catalog, hostfiles
    except ImportError:  # run directly
        import catalog  # type: ignore[no-redef]
        import hostfiles  # type: ignore[no-redef]
        import persistence  # type: ignore[no-redef]

MAX_PATHS = 500
MAX_PATH_BYTES = 4096
HEAD_BYTES = 4096                  # the type is read from this much (never sent)
PACKER_BYTES = 64 * 1024           # a packer marker is looked for in this much
ENTROPY_BYTES = 1024 * 1024        # the entropy is computed over this much
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_RUN_BYTES = 2048 * 1024 * 1024
DEFAULT_SECONDS = 120
OUTPUT_CAP_BYTES = 512 * 1024
STATUSES = ("ok", "missing", "link", "hardlink", "not_regular", "not_program", "unreadable", "too_large", "time",
            "refused", "changed", "not_listed")
# The closed packer-marker list: (marker bytes, name). Only markers checked against a real
# sample of the packer go here (E.4 §5.1): UPX writes "UPX!" in its loader header.
PACKERS: Tuple[Tuple[bytes, str], ...] = ((b"UPX!", "upx"),)
_PROC_EXE = re.compile(rb"^/proc/([1-9][0-9]{0,6})/exe$")
_PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,127}$")
# The merged-/usr aliases: top-level links a distribution itself makes (root-owned). A path
# under one is read through its real folder; any other link in a path is refused.
USRMERGE_LINKS = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")
RPM_ALGOS = {"1": "md5", "2": "sha1", "8": "sha256", "9": "sha384", "10": "sha512"}
_SO_RE = re.compile(rb"(\.so(\.[0-9][0-9.]*)?|\.ko(\.(xz|zst|gz))?)$")


class RequestError(ValueError):
    """A path list that is not allowed (shape only)."""


# --------------------------------------------------------------------------- the request
def encode_paths(paths: List[bytes]) -> List[str]:
    return [base64.b64encode(p).decode("ascii") for p in paths]


def check_path(raw: bytes) -> bytes:
    if not isinstance(raw, bytes) or not raw.startswith(b"/"):
        raise RequestError("must be an absolute path")
    if b"\x00" in raw or b"\n" in raw:
        raise RequestError("must not contain NUL or a newline")
    if len(raw) > MAX_PATH_BYTES:
        raise RequestError("longer than 4096 bytes")
    if any(part in (b".", b"..") for part in raw.split(b"/")):
        raise RequestError("must not contain '.' or '..'")
    return raw


def decode_paths(value: Any) -> List[bytes]:
    """The agent's validator: a list of base64 strings -> checked raw paths."""
    if not isinstance(value, list) or not value or len(value) > MAX_PATHS:
        raise RequestError(f"must be a list of 1-{MAX_PATHS} paths")
    out = []
    for item in value:
        if not isinstance(item, str) or len(item) > 6000:
            raise RequestError("each path must be a base64 string")
        try:
            raw = base64.b64decode(item.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            raise RequestError("each path must be valid base64") from None
        out.append(check_path(raw))
    return out


def is_program_or_library(mode: int, name: bytes) -> bool:
    """A file Kratos may hash: any execute or setuid/setgid bit, or a shared-library or
    kernel-module name. Configuration and data files are not candidates."""
    return bool(mode & 0o6111) or bool(_SO_RE.search(name))


# --------------------------------------------------------------------------- shared pieces
def classify(head: bytes) -> str:
    if head[:4] == b"\x7fELF" and len(head) >= 5:
        return {1: "elf32", 2: "elf64"}.get(head[4], "other")
    if head[:2] == b"#!":
        return "script"
    return "other"


def packers_in(data: bytes) -> str:
    found = [name for marker, name in PACKERS if marker in data[:PACKER_BYTES]]
    return ",".join(found) or "-"


def entropy(data: bytes) -> str:
    """Byte entropy in bits per byte, "%.3f" -- the awk program computes the same sum in
    the same order (byte values 0..255) so both transports print the same text."""
    n = len(data)
    if n == 0:
        return "0.000"
    counts = [data.count(bytes((b,))) for b in range(256)]
    e = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            e -= p * math.log(p)
    return "%.3f" % (e / math.log(2))


def _usrmerge_real(raw: bytes, root: bytes, is_link: Callable[[bytes], Optional[bytes]]) -> bytes:
    rel = raw[len(root):] if root and raw.startswith(root) else raw
    parts = rel.split(b"/")
    if len(parts) > 2 and parts[1].decode("ascii", "replace") in USRMERGE_LINKS:
        target = is_link(root + b"/" + parts[1])
        if target is not None and target.rstrip(b"/") in (b"usr/" + parts[1], b"/usr/" + parts[1]):
            return root + b"/usr/" + b"/".join(parts[1:])
    return raw


# --------------------------------------------------------------------------- SSH
_SH = r"""
LC_ALL=C; export LC_ALL
TAB=$(printf '\t')
NL='
'
@FAMILY_SH@
printf 'M\tfamily\t%s\n' "$FAMILY"
printf 'M\tnow\t%s\n' "$(date +%s)"
printf 'M\tuid\t%s\n' "$(id -u)"
START=$(date +%s)
# The paths, NUL-separated, base64 on standard input (part of this script); no path ever
# contains a newline (the caller refuses those), so one per line from here on.
LIST=$(printf '%s' '@PATHS@' | base64 -d 2>/dev/null | tr '\0' '\n' | awk '{ print NR - 1 "\t" $0 }')
# merged /usr: a path under /bin, /lib, ... is read through /usr/... when that top-level
# entry is the distribution's own link to it
kr_real() {
  _p=$1
  _rest=${_p#@RAWROOT@/}
  _top=${_rest%%/*}
  case "$_top" in
    @MERGED@)
      if [ -L "@RAWROOT@/$_top" ] && [ "$_rest" != "$_top" ]; then
        _t=$(readlink "@RAWROOT@/$_top" 2>/dev/null)
        case "$_t" in "usr/$_top"|"/usr/$_top"|"usr/$_top/"|"/usr/$_top/") _p="@RAWROOT@/usr/$_rest" ;; esac
      fi ;;
  esac
  printf '%s' "$_p"
}
REAL=$(printf '%s\n' "$LIST" | while IFS="$TAB" read -r _i _p; do
  [ -n "$_p" ] || continue
  printf '%s\t%s\n' "$_i" "$(kr_real "$_p")"
done)
WANT=$(printf '%s\n' "$REAL" | cut -f2- | grep '^/')
@OWNERSHIP@
OWNIDX=$( { printf '%s\n' "$REAL"; printf '==OWN==\n'; printf '%s\n' "$OWNOUT"; } | awk -F'\t' '
  $0 == "==OWN==" { o = 1; next }
  !o { if (!($2 in idx)) idx[$2] = $1; else idx[$2] = idx[$2] " " $1; next }
  $1 == "OWN" && ($2 in idx) { n = split(idx[$2], a, " "); for (i = 1; i <= n; i++) print a[i] "\t" $3 }')
printf '%s\n' "$OWNIDX" | grep -v '^$' | sed 's/^/OWN	/'
# the package's own checksum for each owned path
PKS=""
case "$FAMILY" in
debian)
  _files=$(printf '%s\n' "$OWNIDX" | cut -f2 | grep -E '^[A-Za-z0-9][A-Za-z0-9+._:~-]*$' | sort -u | while IFS= read -r _k; do
    [ -r "@RAWROOT@/var/lib/dpkg/info/$_k.md5sums" ] && printf '%s\n' "@RAWROOT@/var/lib/dpkg/info/$_k.md5sums"
  done)
  if [ -n "$_files" ]; then
    PKS=$( { printf '%s\n' "$REAL"; printf '==OWN==\n'; printf '%s\n' "$OWNIDX"; } | awk -F'\t' -v root=@ROOTV@ '
      function alt(p) { if (p ~ /^usr\/(lib|bin|sbin|lib64)\//) return substr(p, 5); if (p ~ /^(lib|bin|sbin|lib64)\//) return "usr/" p; return "" }
      NR == FNR && $0 == "==OWN==" { o = 1; next }
      NR == FNR && !o { rel = substr($2, length(root) + 2); path[$1] = rel; next }
      NR == FNR { pk[$1] = $2; next }
      FNR == 1 { pkg = FILENAME; sub(/.*\//, "", pkg); sub(/[.]md5sums$/, "", pkg)
                 for (i in pk) if (pk[i] == pkg) { want[pkg SUBSEP path[i]] = want[pkg SUBSEP path[i]] " " i
                   a = alt(path[i]); if (a != "") want[pkg SUBSEP a] = want[pkg SUBSEP a] " " i } }
      { d = substr($0, 1, 32); f = substr($0, 35); k = pkg SUBSEP f
        if (k in want) { n = split(want[k], ix, " "); for (j = 1; j <= n; j++) print "PK\t" ix[j] "\tmd5\t" d } }' - $_files 2>/dev/null)
  fi ;;
rhel)
  PKS=$(printf '%s\n' "$OWNIDX" | cut -f2 | grep -E '^[A-Za-z0-9][A-Za-z0-9+._:~-]*$' | sort -u | while IFS= read -r _k; do
    _al=$(rpm -q --qf '%{FILEDIGESTALGO}\n' "$_k" 2>/dev/null | head -n 1)
    rpm -q --qf '[%{FILEDIGESTS}\t%{FILENAMES}\n]' "$_k" 2>/dev/null | awk -F'\t' -v k="$_k" -v al="$_al" '{ print k "\t" al "\t" $1 "\t" $2 }'
  done | { printf '%s\n' "$REAL"; printf '==OWN==\n'; printf '%s\n' "$OWNIDX"; printf '==RPM==\n'; cat; } | awk -F'\t' -v root=@ROOTV@ '
    function alt(p) { if (p ~ /^\/usr\/(lib|bin|sbin|lib64)\//) return substr(p, 5); if (p ~ /^\/(lib|bin|sbin|lib64)\//) return "/usr" p; return "" }
    $0 == "==OWN==" { s = 1; next } $0 == "==RPM==" { s = 2; next }
    s == 0 { path[$1] = substr($2, length(root) + 1); next }
    s == 1 { want[$2 SUBSEP path[$1]] = want[$2 SUBSEP path[$1]] " " $1; a = alt(path[$1]); if (a != "") want[$2 SUBSEP a] = want[$2 SUBSEP a] " " $1; next }
    { k = $1 SUBSEP $4; if ((k in want) && $3 != "") { al = $2; m = (al == "2") ? "sha1" : (al == "8") ? "sha256" : (al == "9") ? "sha384" : (al == "10") ? "sha512" : "md5"
        n = split(want[k], ix, " "); for (j = 1; j <= n; j++) print "PK\t" ix[j] "\t" m "\t" tolower($3) } }')
  ;;
alpine)
  if [ -r @ROOT@/lib/apk/db/installed ]; then
    PKS=$( { printf '%s\n' "$REAL"; printf '==OWN==\n'; printf '%s\n' "$OWNIDX"; printf '==APK==\n'; cat @ROOT@/lib/apk/db/installed; } | awk -F'\t' -v root=@ROOTV@ '
      function alt(p) { if (p ~ /^\/usr\/(lib|bin|sbin|lib64)\//) return substr(p, 5); if (p ~ /^\/(lib|bin|sbin|lib64)\//) return "/usr" p; return "" }
      $0 == "==OWN==" { s = 1; next } $0 == "==APK==" { s = 2; next }
      s == 0 { path[$1] = substr($2, length(root) + 1); next }
      s == 1 { want[$2 SUBSEP path[$1]] = want[$2 SUBSEP path[$1]] " " $1; a = alt(path[$1]); if (a != "") want[$2 SUBSEP a] = want[$2 SUBSEP a] " " $1; next }
      /^P:/ { pkg = substr($0, 3); next } /^F:/ { dir = substr($0, 3); cur = ""; next }
      /^R:/ { cur = pkg SUBSEP "/" dir "/" substr($0, 3); next }
      /^Z:/ && cur != "" { if (cur in want) { n = split(want[cur], ix, " "); for (j = 1; j <= n; j++) print "PK\t" ix[j] "\tapk-q1\t" substr($0, 3) } cur = "" }')
  fi ;;
esac
# a dpkg configuration file is not in md5sums: its recorded checksum is in the status file
if [ "$FAMILY" = debian ] && [ -r @RAWROOT@/var/lib/dpkg/status ]; then
  PKS="$PKS$NL$( { printf '%s\n' "$REAL"; printf '==ST==\n'; cat @RAWROOT@/var/lib/dpkg/status; } | awk -F'\t' -v root=@ROOTV@ '
    $0 == "==ST==" { s = 1; FS = " "; next }
    !s { k = substr($2, length(root) + 1); idx[k] = (k in idx) ? idx[k] " " $1 : $1; next }
    /^Conffiles:/ { c = 1; next } /^[^ ]/ { c = 0 }
    c && /^ \// && ($1 in idx) && $2 ~ /^[0-9a-f]+$/ && length($2) == 32 { n = split(idx[$1], a, " "); for (j = 1; j <= n; j++) print "PK\t" a[j] "\tmd5c\t" $2 }')"
fi
[ -n "$PKS" ] && printf '%s\n' "$PKS" | grep '^PK	'
MD5IDX=" $(printf '%s\n' "$PKS" | awk -F'\t' '$3 == "md5" || $3 == "md5c" { printf "%s ", $2 }') "
OWNED=" $(printf '%s\n' "$OWNIDX" | cut -f1 | tr '\n' ' ') "
USED=0
kr_dash() { printf 'F\t%s\t%s\t%s\n' "$1" "$2" "$3"; }
kr_facts() {
  _i=$1; _p=$2
  _proc=0
  case "$_p" in
    /proc/*/exe) _pid=${_p#/proc/}; _pid=${_pid%/exe}
      case "$_pid" in ''|*[!0-9]*) ;; *) _proc=1 ;; esac ;;
  esac
  if [ $_proc = 0 ]; then
    if [ -L "$_p" ]; then kr_dash "$_i" link "-	-	-	-	-	-	-	-	-	-	-	-"; return; fi
    _d=${_p%/*}; [ -n "$_d" ] || _d=/
    _phys=$(cd "$_d" 2>/dev/null && pwd -P)
    if [ -z "$_phys" ]; then
      if [ -e "$_d" ]; then kr_dash "$_i" unreadable "-	-	-	-	-	-	-	-	-	-	-	-"
      else kr_dash "$_i" missing "-	-	-	-	-	-	-	-	-	-	-	-"; fi
      return
    fi
    [ "$_phys" = "$_d" ] || { kr_dash "$_i" link "-	-	-	-	-	-	-	-	-	-	-	-"; return; }
  fi
  [ -e "$_p" ] || { kr_dash "$_i" missing "-	-	-	-	-	-	-	-	-	-	-	-"; return; }
  if [ $_proc = 0 ] && [ ! -f "$_p" ]; then kr_dash "$_i" not_regular "-	-	-	-	-	-	-	-	-	-	-	-"; return; fi
  _st=$(stat -L -c '%s	%a	%u	%Y	%i	%h' -- "$_p" 2>/dev/null)
  [ -n "$_st" ] || { kr_dash "$_i" unreadable "-	-	-	-	-	-	-	-	-	-	-	-"; return; }
  _sz=${_st%%	*}
  _mode=$(printf '%s' "$_st" | cut -f2); _nl=$(printf '%s' "$_st" | cut -f6)
  if [ $_proc = 0 ] && [ "$_nl" != 1 ]; then kr_dash "$_i" hardlink "$_st	-	-	-	-	-	-"; return; fi
  _name=${_p##*/}
  if ! printf '%s\n' "$_mode" | awk '{ m = 0; for (i = 1; i <= length($0); i++) m = m * 8 + substr($0, i, 1); exit !(int(m / 64) % 8 % 2 || int(m / 8) % 8 % 2 || m % 8 % 2 || int(m / 512) % 8 >= 2) }'; then
    case "$_name" in
      *.so|*.so.[0-9]*|*.ko|*.ko.xz|*.ko.zst|*.ko.gz) ;;
      *) kr_dash "$_i" not_program "$_st	-	-	-	-	-	-"; return ;;
    esac
  fi
  [ -r "$_p" ] || { kr_dash "$_i" unreadable "$_st	-	-	-	-	-	-"; return; }
  _now=$(date +%s)
  [ $((_now - START)) -lt @SECONDS@ ] || { kr_dash "$_i" time "$_st	-	-	-	-	-	-"; return; }
  if [ "$_sz" -gt @MAXFILE@ ] && [ $((USED + _sz)) -gt @RUNBYTES@ ]; then kr_dash "$_i" too_large "$_st	-	-	-	-	-	-"; return; fi
  USED=$((USED + _sz))
  _s256=$(sha256sum < "$_p" 2>/dev/null | cut -c1-64); _s1=$(sha1sum < "$_p" 2>/dev/null | cut -c1-40)
  _m5=-
  case "$FAMILY$MD5IDX" in debian*|*" $_i "*) _m5=$(md5sum < "$_p" 2>/dev/null | cut -c1-32) ;; esac
  case "$OWNED" in
    *" $_i "*) _ty=-; _pk=-; _en=- ;;
    *) _tpe=$(od -An -v -tu1 -N@PACKB@ < "$_p" 2>/dev/null | awk '
         { for (i = 1; i <= NF; i++) { b = $i + 0; n++; if (n <= 5) h[n] = b
             if (p3 == 85 && p2 == 80 && p1 == 88 && b == 33) upx = 1; p3 = p2; p2 = p1; p1 = b } }
         END { t = "other"
           if (h[1] == 127 && h[2] == 69 && h[3] == 76 && h[4] == 70) t = (h[5] == 1) ? "elf32" : (h[5] == 2) ? "elf64" : "other"
           else if (h[1] == 35 && h[2] == 33) t = "script"
           printf "%s\t%s\n", t, (upx ? "upx" : "-") }')
       _ty=$(printf '%s' "$_tpe" | cut -f1); _pk=$(printf '%s' "$_tpe" | cut -f2)
       # entropy needs awk's log(); an awk built without math leaves it unread ("-")
       _en=$(od -An -v -tu1 -N@ENTB@ < "$_p" 2>/dev/null | awk '
         { for (i = 1; i <= NF; i++) { c[$i + 0]++; n++ } }
         END { e = 0; for (b = 0; b < 256; b++) if (c[b] > 0) { q = c[b] / n; e -= q * log(q) }
           printf "%.3f\n", (n ? e / log(2) : 0) }' 2>/dev/null)
       [ -n "$_en" ] || _en=- ;;
  esac
  [ -n "$_s256" ] || { kr_dash "$_i" unreadable "$_st	-	-	-	-	-	-"; return; }
  _st2=$(stat -L -c '%s	%a	%u	%Y	%i	%h' -- "$_p" 2>/dev/null)
  [ "$_st2" = "$_st" ] || { kr_dash "$_i" changed "$_st	-	-	-	-	-	-"; return; }
  printf 'F\t%s\tok\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$_i" "$_st" "$_s256" "$_s1" "$_m5" "$_ty" "$_pk" "$_en"
}
FOUT=$(printf '%s\n' "$REAL" | while IFS="$TAB" read -r _i _p; do
  [ -n "$_i" ] || continue
  kr_facts "$_i" "$_p"
done)
printf '%s\n' "$FOUT"
# a file no package owns whose content is identical to a file an installed package ships
UNOWNED=$(printf '%s\n' "$FOUT" | awk -F'\t' -v owned="$OWNED" '$1 == "F" && $3 == "ok" && index(owned, " " $2 " ") == 0 { print $2 "\t" $10 "\t" $11 "\t" $12 }')
if [ -n "$UNOWNED" ]; then
  case "$FAMILY" in
  debian)
    _pc=$( { printf '%s\n' "$UNOWNED"; printf '==MD5==\n'; for _f in @RAWROOT@/var/lib/dpkg/info/*.md5sums; do [ -r "$_f" ] && printf '==F==%s\n' "${_f##*/}" && cat "$_f"; done; } | awk -F'\t' '
      $0 == "==MD5==" { s = 1; next }
      !s { if ($4 != "-") w[$4] = (($4 in w) ? w[$4] " " : "") $1; next }
      /^==F==/ { pkg = substr($0, 6); sub(/[.]md5sums$/, "", pkg); next }
      { d = substr($0, 1, 32); if (d in w) { n = split(w[d], ix, " "); for (j = 1; j <= n; j++) if (cnt[ix[j]]++ < 3) print "PC\t" ix[j] "\t" pkg "\t/" substr($0, 35) } }')
    [ -n "$_pc" ] && printf '%s\n' "$_pc" ;;
  rhel)
    _pc=$( { printf '%s\n' "$UNOWNED"; printf '==RPM==\n'; rpm -qa --qf '[%{FILEDIGESTS}\t%{FILENAMES}\t%{=NAME}\n]' 2>/dev/null; } | awk -F'\t' '
      $0 == "==RPM==" { s = 1; next }
      !s { w[$2] = (($2 in w) ? w[$2] " " : "") $1; if ($4 != "-") w[$4] = (($4 in w) ? w[$4] " " : "") $1; next }
      { d = tolower($1); if (d != "" && (d in w)) { n = split(w[d], ix, " "); for (j = 1; j <= n; j++) if (cnt[ix[j]]++ < 3) print "PC\t" ix[j] "\t" $3 "\t" $2 } }')
    [ -n "$_pc" ] && printf '%s\n' "$_pc" ;;
  alpine)
    [ -r @RAWROOT@/lib/apk/db/installed ] && { printf '%s\n' "$UNOWNED"; printf '==APK==\n'; cat @RAWROOT@/lib/apk/db/installed; } | awk -F'\t' '
      function q1(hex,   b64, i, n, v, out, c1, c2, c3) {
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; n = 0
        for (i = 1; i <= length(hex); i += 2) { v = index("0123456789abcdef", substr(hex, i, 1)) - 1
          v = v * 16 + index("0123456789abcdef", substr(hex, i + 1, 1)) - 1; by[++n] = v }
        out = ""
        for (i = 1; i <= n; i += 3) { c1 = by[i]; c2 = (i + 1 <= n) ? by[i + 1] : 0; c3 = (i + 2 <= n) ? by[i + 2] : 0
          out = out substr(b64, int(c1 / 4) + 1, 1) substr(b64, (c1 % 4) * 16 + int(c2 / 16) + 1, 1)
          out = out ((i + 1 <= n) ? substr(b64, (c2 % 16) * 4 + int(c3 / 64) + 1, 1) : "=")
          out = out ((i + 2 <= n) ? substr(b64, c3 % 64 + 1, 1) : "=") }
        return "Q1" out }
      $0 == "==APK==" { s = 1; next }
      !s { k = q1($3); w[k] = ((k in w) ? w[k] " " : "") $1; next }
      /^P:/ { pkg = substr($0, 3); next } /^F:/ { dir = substr($0, 3); next } /^R:/ { f = substr($0, 3); next }
      /^Z:/ { d = substr($0, 3); if (d in w) { n = split(w[d], ix, " "); for (j = 1; j <= n; j++) if (cnt[ix[j]]++ < 3) print "PC\t" ix[j] "\t" pkg "\t/" dir "/" f } }' ;;
  esac
fi
"""


def build_script(paths: List[bytes], *, root: str = "", max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 run_bytes: int = DEFAULT_RUN_BYTES, seconds: int = DEFAULT_SECONDS) -> str:
    """The SSH read for `paths` (checked raw bytes). Every interpolated value is a number,
    a constant from this file, or base64 (the paths) -- so nothing in a path can reach the
    shell as code. `root` exists for tests only (a fake tree)."""
    for p in paths:
        check_path(p)
    if not paths or len(paths) > MAX_PATHS:
        raise RequestError(f"1-{MAX_PATHS} paths")
    blob = base64.b64encode(b"\x00".join(paths)).decode("ascii")
    r = root.rstrip("/")
    q = persistence._sh_q
    own = (persistence.OWNERSHIP_SH.replace("@ROOT@", q(r) if r else "").replace("@ROOTV@", q(r) if r else "''"))
    body = (_SH.replace("@FAMILY_SH@", catalog.FAMILY_SH.replace("/etc/os-release", f"{r}/etc/os-release"))
            .replace("@OWNERSHIP@", own)
            .replace("@PATHS@", blob)
            .replace("@MERGED@", "|".join(USRMERGE_LINKS))
            .replace("@ROOTV@", q(r) if r else "''")
            .replace("@ROOT@", q(r) if r else "")
            .replace("@RAWROOT@", r)
            .replace("@SECONDS@", str(int(seconds)))
            .replace("@MAXFILE@", str(int(max_file_bytes)))
            .replace("@RUNBYTES@", str(int(run_bytes)))
            .replace("@ENTB@", str(ENTROPY_BYTES))
            .replace("@PACKB@", str(PACKER_BYTES)))
    return "{\n" + body + "printf 'END\\n'\n} | head -c " + str(OUTPUT_CAP_BYTES) + "\nexit 0\n"


# --------------------------------------------------------------------------- agent
Runner = Callable[[List[str], float, int], Dict[str, Any]]


def _open_proc_exe(raw: bytes) -> Tuple[int, os.stat_result]:
    """The running image of a process through /proc/<pid>/exe (it stays readable after the
    file was deleted). Only ever this exact shape; the result must be a regular file."""
    try:
        fd = os.open(raw, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        raise hostfiles.FileRefused("missing", "") from None
    except OSError as e:
        raise hostfiles.FileRefused("unreadable", e.strerror or str(e)) from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise hostfiles.FileRefused("not_regular", "")
    return fd, st


def _readlink(path: bytes) -> Optional[bytes]:
    try:
        return os.readlink(path) if os.path.islink(path) else None
    except OSError:
        return None


def _pkg_digests(family: Optional[str], wanted: Dict[int, Tuple[bytes, str]], root: str,
                 run: Optional[Runner]) -> List[str]:
    """PK lines: the owning package's checksum for each owned index -- the same joins the
    script does. wanted: idx -> (real path bytes, package)."""
    out: List[str] = []
    r = root.rstrip("/")

    def rel(p: bytes) -> str:
        s = os.fsdecode(p)
        return s[len(r):] if r and s.startswith(r) else s

    by_pkg: Dict[str, Dict[str, List[int]]] = {}
    for idx, (p, pkg) in wanted.items():
        if not _PKG_NAME.match(pkg):
            continue
        k = rel(p)
        d = by_pkg.setdefault(pkg, {})
        for cand in [k] + persistence.usrmerge_alternates(k):
            d.setdefault(cand, []).append(idx)
    if family == "debian":
        for pkg, want in sorted(by_pkg.items()):
            try:
                with open(f"{r}/var/lib/dpkg/info/{pkg}.md5sums", "rb") as fh:
                    text = fh.read(16 * 1024 * 1024).decode("utf-8", "surrogateescape")
            except OSError:
                continue
            for line in text.split("\n"):
                if len(line) < 35:
                    continue
                key = "/" + line[34:]
                for idx in want.get(key, []):
                    out.append(f"PK\t{idx}\tmd5\t{line[:32]}")
    elif family == "rhel" and run is not None:
        for pkg, want in sorted(by_pkg.items()):
            try:
                al = (run(["rpm", "-q", "--qf", "%{FILEDIGESTALGO}\\n", pkg], 30, 4096).get("stdout") or "")
                algo = RPM_ALGOS.get(al.strip().split("\n")[0].strip(), "md5")
                res = run(["rpm", "-q", "--qf", "[%{FILEDIGESTS}\\t%{FILENAMES}\\n]", pkg], 60, 16 * 1024 * 1024)
            except Exception:  # noqa: BLE001 -- a package the rpm database can't describe: no checksum
                continue
            for line in (res.get("stdout") or "").split("\n"):
                digest, _, name = line.partition("\t")
                for idx in want.get(name, []) if digest else []:
                    out.append(f"PK\t{idx}\t{algo}\t{digest.lower()}")
    elif family == "alpine":
        try:
            with open(f"{r}/lib/apk/db/installed", "rb") as fh:
                text = fh.read(64 * 1024 * 1024).decode("utf-8", "surrogateescape")
        except OSError:
            return out
        pkg, d, cur = "", "", None
        for line in text.split("\n"):
            if line.startswith("P:"):
                pkg = line[2:]
            elif line.startswith("F:"):
                d, cur = line[2:], None
            elif line.startswith("R:"):
                cur = (pkg, "/" + d + "/" + line[2:])
            elif line.startswith("Z:") and cur is not None:
                for idx in by_pkg.get(cur[0], {}).get(cur[1], []):
                    out.append(f"PK\t{idx}\tapk-q1\t{line[2:]}")
                cur = None
    out.sort(key=lambda s: (int(s.split("\t")[1]), s))
    return out


def _conffile_digests(real: List[bytes], root: str) -> List[str]:
    """PK idx md5c <md5>: a dpkg configuration file's recorded checksum (the status file's
    Conffiles lines -- md5sums doesn't list them)."""
    r = root.rstrip("/")
    want: Dict[str, List[int]] = {}
    for i, p in enumerate(real):
        k = os.fsdecode(p)
        want.setdefault(k[len(r):] if r and k.startswith(r) else k, []).append(i)
    out: List[str] = []
    try:
        with open(f"{r}/var/lib/dpkg/status", "rb") as fh:
            text = fh.read(64 * 1024 * 1024).decode("utf-8", "surrogateescape")
    except OSError:
        return out
    inside = False
    for line in text.split("\n"):
        if line.startswith("Conffiles:"):
            inside = True
            continue
        if line[:1] != " ":
            inside = False
        if inside and line.startswith(" /"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] in want and re.fullmatch(r"[0-9a-f]{32}", parts[1]):
                out += [f"PK\t{i}\tmd5c\t{parts[1]}" for i in want[parts[0]]]
    return out


def _package_copies(family: Optional[str], f_lines: List[str], owned: set, root: str,
                    run: Optional[Runner]) -> List[str]:
    """PC idx <package> <path>: a file no package owns whose content is identical to a file an
    installed package ships (its recorded checksum) -- at most three per file, in the order the
    script finds them."""
    unowned: List[Tuple[int, str, str, str]] = []
    for ln in f_lines:
        c = ln.split("\t")
        if len(c) >= 15 and c[2] == "ok" and int(c[1]) not in owned:
            unowned.append((int(c[1]), c[9], c[10], c[11]))
    if not unowned:
        return []
    r = root.rstrip("/")
    out: List[str] = []
    count: Dict[int, int] = {}

    def hit(ixs: List[int], pkg: str, path: str) -> None:
        for i in ixs:
            if count.get(i, 0) < 3:
                count[i] = count.get(i, 0) + 1
                out.append(f"PC\t{i}\t{pkg}\t{path}")

    if family == "debian":
        w: Dict[str, List[int]] = {}
        for i, _s256, _s1, m5 in unowned:
            if m5 != "-":
                w.setdefault(m5, []).append(i)
        d = f"{r}/var/lib/dpkg/info"
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".md5sums"))
        except OSError:
            names = []
        for n in names:
            try:
                with open(os.path.join(d, n), "rb") as fh:
                    lines = fh.read(16 * 1024 * 1024).decode("utf-8", "surrogateescape").split("\n")
            except OSError:
                continue
            for line in lines:
                if line[:32] in w:
                    hit(w[line[:32]], n[:-len(".md5sums")], "/" + line[34:])
    elif family == "rhel" and run is not None:
        w = {}
        for i, s256, _s1, m5 in unowned:
            w.setdefault(s256, []).append(i)
            if m5 != "-":
                w.setdefault(m5, []).append(i)
        try:
            res = run(["rpm", "-qa", "--qf", "[%{FILEDIGESTS}\\t%{FILENAMES}\\t%{=NAME}\\n]"], 60, 64 * 1024 * 1024)
        except Exception:  # noqa: BLE001 -- no rpm answer: no copies found, nothing else changes
            res = {}
        for line in (res.get("stdout") or "").split("\n"):
            c = line.split("\t")
            if len(c) >= 3 and c[0].lower() in w:
                hit(w[c[0].lower()], c[2], c[1])
    elif family == "alpine":
        w = {}
        for i, _s256, s1, _m5 in unowned:
            w.setdefault("Q1" + base64.b64encode(bytes.fromhex(s1)).decode(), []).append(i)
        try:
            with open(f"{r}/lib/apk/db/installed", "rb") as fh:
                text = fh.read(64 * 1024 * 1024).decode("utf-8", "surrogateescape")
        except OSError:
            return out
        pkg = dirn = f = ""
        for line in text.split("\n"):
            if line.startswith("P:"):
                pkg = line[2:]
            elif line.startswith("F:"):
                dirn = line[2:]
            elif line.startswith("R:"):
                f = line[2:]
            elif line.startswith("Z:") and line[2:] in w:
                hit(w[line[2:]], pkg, "/" + dirn + "/" + f)
    return out


def facts_output(paths: List[bytes], *, root: str = "", run: Optional[Runner] = None,
                 is_credential: Callable[[str], bool] = lambda p: False,
                 listed: Callable[[bytes], bool] = lambda p: True,
                 max_file_bytes: int = DEFAULT_MAX_FILE_BYTES, run_bytes: int = DEFAULT_RUN_BYTES,
                 seconds: float = DEFAULT_SECONDS) -> Dict[str, Any]:
    """The read on the agent: the same records build_script prints. `listed(path)` says
    whether this agent's own reads listed the path recently (reads.py keeps that memory);
    a path it didn't is refused ("not_listed"). `root` is for tests only."""
    start = time.monotonic()
    family = persistence._os_family(root)
    out: List[str] = [f"M\tfamily\t{family or 'unknown'}", f"M\tnow\t{int(time.time())}", f"M\tuid\t{os.getuid()}"]
    rb = os.fsencode(root.rstrip("/")) if root else b""
    real: List[bytes] = [_usrmerge_real(p, rb, _readlink) for p in paths]
    want = {os.fsdecode(p) for p in real if not _PROC_EXE.match(p)}
    owners, own_lines = persistence._ownership(family, want, root.rstrip("/"), run)
    out += own_lines
    owned: Dict[int, str] = {}
    for i, p in enumerate(real):
        pkg = owners.get(os.fsdecode(p))
        if pkg:
            owned[i] = pkg
            out.append(f"OWN\t{i}\t{pkg}")
    pks = _pkg_digests(family, {i: (real[i], pkg) for i, pkg in owned.items()}, root, run)
    if family == "debian":
        pks += _conffile_digests(real, root)
    out += pks
    md5_idx = {int(x.split("\t")[1]) for x in pks if x.split("\t")[2] in ("md5", "md5c")}
    used = 0
    dash12 = "\t".join(["-"] * 12)
    for i, (asked, p) in enumerate(zip(paths, real)):
        def say(status: str, st: Optional[os.stat_result] = None) -> None:
            stat_part = (f"{st.st_size}\t{oct(st.st_mode & 0o7777)[2:]}\t{st.st_uid}\t{int(st.st_mtime)}\t"
                         f"{st.st_ino}\t{st.st_nlink}\t" + "\t".join(["-"] * 6)) if st is not None else dash12
            out.append(f"F\t{i}\t{status}\t{stat_part}")

        proc = bool(_PROC_EXE.match(p))
        text = os.fsdecode(p)
        if not proc and is_credential(text):
            say("refused")
            continue
        if not listed(asked):
            say("not_listed")
            continue
        try:
            fd, st = _open_proc_exe(p) if proc else hostfiles.open_log_file(text)
        except hostfiles.FileRefused as e:
            status = {"symlink": "link", "hardlink": "hardlink", "not_regular": "not_regular", "missing": "missing",
                      "changed": "changed"}.get(e.status, "unreadable")
            if status in ("hardlink", "unreadable") and not proc:
                try:
                    lst = os.stat(p, follow_symlinks=False)
                except OSError:
                    lst = None
                if lst is not None and stat.S_ISREG(lst.st_mode):
                    if status == "unreadable" and not is_program_or_library(lst.st_mode, p.rsplit(b"/", 1)[-1]):
                        status = "not_program"
                    say(status, lst)
                    continue
            say(status)
            continue
        try:
            if not proc and not is_program_or_library(st.st_mode, p.rsplit(b"/", 1)[-1]):
                say("not_program", st)
                continue
            if time.monotonic() - start >= seconds:
                say("time", st)
                continue
            if st.st_size > max_file_bytes and used + st.st_size > run_bytes:
                say("too_large", st)
                continue
            used += st.st_size
            h256, h1 = hashlib.sha256(), hashlib.sha1()
            h5 = hashlib.md5() if (family == "debian" or i in md5_idx) else None
            head = b""
            while True:
                b = os.read(fd, 1024 * 1024)
                if not b:
                    break
                if len(head) < ENTROPY_BYTES:
                    head += b[:ENTROPY_BYTES - len(head)]
                h256.update(b)
                h1.update(b)
                if h5 is not None:
                    h5.update(b)
            after = os.fstat(fd)
            if (after.st_size, after.st_mtime, after.st_ino) != (st.st_size, st.st_mtime, st.st_ino):
                say("changed", st)
                continue
            if i in owned:
                ty, pk, en = "-", "-", "-"
            else:
                ty, pk, en = classify(head[:HEAD_BYTES]), packers_in(head), entropy(head)
            out.append(f"F\t{i}\tok\t{st.st_size}\t{oct(st.st_mode & 0o7777)[2:]}\t{st.st_uid}\t{int(st.st_mtime)}\t"
                       f"{st.st_ino}\t{st.st_nlink}\t{h256.hexdigest()}\t{h1.hexdigest()}\t"
                       f"{h5.hexdigest() if h5 is not None else '-'}\t{ty}\t{pk}\t{en}")
        finally:
            os.close(fd)
    out += _package_copies(family, [ln for ln in out if ln.startswith("F\t")], set(owned), root, run)
    out.append("END")
    text = "\n".join(out) + "\n"
    return {"returncode": 0, "stdout": text[:OUTPUT_CAP_BYTES], "stderr": "", "truncated": len(text) > OUTPUT_CAP_BYTES}


# --------------------------------------------------------------------------- one parser
def _int(v: str) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_output(stdout: str, count: int) -> Dict[str, Any]:
    """Both transports' records -> {family, now, reader_uid, complete, ownership, files:
    {idx: {...}}}. `count` is how many paths were asked for; an index outside it is
    ignored (a read can't add files)."""
    inv: Dict[str, Any] = {"family": None, "now": None, "reader_uid": None, "complete": False, "files": {},
                           "ownership": {"source": None, "error": None}}
    files: Dict[int, Dict[str, Any]] = inv["files"]

    def rec(i: Optional[int]) -> Optional[Dict[str, Any]]:
        if i is None or not 0 <= i < count:
            return None
        return files.setdefault(i, {"idx": i})

    for raw in stdout.split("\n"):
        c = raw.split("\t")
        tag = c[0]
        if tag == "M" and len(c) >= 3:
            if c[1] == "family":
                inv["family"] = c[2] if c[2] in catalog.FAMILIES else None
            elif c[1] == "now":
                inv["now"] = _int(c[2])
            elif c[1] == "uid":
                inv["reader_uid"] = _int(c[2])
        elif tag == "F" and len(c) >= 15:
            r = rec(_int(c[1]))
            if r is None or c[2] not in STATUSES:
                continue
            r["status"] = c[2]
            for key, v in zip(("size", "mode", "uid", "mtime", "inode", "nlink"), c[3:9]):
                r[key] = (v if key == "mode" else _int(v)) if v != "-" else None
            for key, v, pat in (("sha256", c[9], r"[0-9a-f]{64}"), ("sha1", c[10], r"[0-9a-f]{40}"),
                                ("md5", c[11], r"[0-9a-f]{32}")):
                r[key] = v if re.fullmatch(pat, v) else None
            r["type"] = c[12] if c[12] in ("elf32", "elf64", "script", "other") else None
            r["packers"] = [p for p in c[13].split(",") if p in {n for _m, n in PACKERS}]
            try:
                r["entropy"] = float(c[14]) if c[14] != "-" else None
            except ValueError:
                r["entropy"] = None
        elif tag == "OWN" and len(c) >= 3:
            r = rec(_int(c[1]))
            if r is not None and _PKG_NAME.match(c[2]):
                r["package"] = c[2]
        elif tag == "PK" and len(c) >= 4:
            r = rec(_int(c[1]))
            if r is not None and c[2] in ("md5", "md5c", "sha1", "sha256", "sha384", "sha512", "apk-q1"):
                r.setdefault("pkg_digests", []).append({"algo": c[2], "digest": c[3].strip()})
                r["pkg_digests"].sort(key=lambda d: (d["algo"], d["digest"]))
        elif tag == "PC" and len(c) >= 4:
            r = rec(_int(c[1]))
            if r is not None and _PKG_NAME.match(c[2]) and c[3].startswith("/"):
                copies = r.setdefault("package_copy", [])
                if len(copies) < 3 and {"package": c[2], "path": c[3]} not in copies:
                    copies.append({"package": c[2], "path": c[3]})
                    copies.sort(key=lambda d: (d["package"], d["path"]))
        elif tag == "OWNSRC" and len(c) >= 2:
            inv["ownership"]["source"] = c[1]
        elif tag == "OWNERR" and len(c) >= 2:
            inv["ownership"]["error"] = c[1]
        elif tag == "END":
            inv["complete"] = True
    return inv


def apk_q1_to_hex(value: str) -> Optional[str]:
    """apk's `Q1<base64 sha1>` -> hex SHA-1."""
    if not value.startswith("Q1"):
        return None
    try:
        raw = base64.b64decode(value[2:].encode("ascii"), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw.hex() if len(raw) == 20 else None
