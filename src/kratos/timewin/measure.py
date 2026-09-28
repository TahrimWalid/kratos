"""
Exhaustive, target-side measurement of authentication activity over a time window
(docs/time_window_design.md §2F, validated by E13: 1,000,000 events -> per-IP table in
1.8 s / 85 KB, vs 831 MB raw).

Measurements vs samples: the COUNTS here cover every matching event in the window (no
line cap), computed on the target by a POSIX-sh + portable-awk script and returned as a
few KB of totals. A handful of raw lines come back only as clearly-labelled SAMPLES
(newest-first plus the first line of each distinct failing source). The model is never
asked to count log lines itself -- the E25/"47 failed logins" live runs showed it can't.

Portability: the script is plain `sh` + awk with no gawk-only features (no match()
capture arrays, no mktime/strftime/asort) so it runs under mawk (Debian/Ubuntu), gawk
(RHEL) and BusyBox awk (Alpine); `timeout`/`mktemp` are used when present and degrade
gracefully when not (both are absent on a stock Alpine image).

Event definitions mirror adapters/auth_log_parse.py::classify_auth_message EXACTLY, so
the correlation engine sees the same event types whichever path produced them; a test
(tests/test_timewin_measure.py) runs both classifiers over the same lines and requires
identical results. Bursts use the same greedy sliding-window algorithm as
adapters/auth_log_patterns.py::_detect_bursts (per event type, 3-in-5-minutes).

Kratos's own SSH sessions are excluded from the SSH success/disconnect/other counts by
source IP (`$SSH_CONNECTION` on the target) and reported separately (E22: Kratos writes
sshd lines on every host it inspects). Failures from that IP are NEVER excluded.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any

FAILURE_TYPES = ("ssh_failed_login", "sudo_auth_failure", "sudo_pam_auth_failure")
SAMPLE_NEWEST = 20
SAMPLE_FIRST_PER_IP = 30
BURST_WINDOW_SECONDS = 300
BURST_THRESHOLD = 3
DEFAULT_TIME_BUDGET_SECONDS = 90

# Classifier + aggregator. Input: `journalctl -o short-unix` lines
#   "<epoch.usec> <host> <prog>[pid]: <message>"
# Outputs (tab-separated): CNT, SELF, HR, JUMP, SAMPLE, FIRSTIP, DONE; failure events are
# also written as "F <epoch> <type> <ip> <user>" to the file named by -v ffile.
_AWK_LIB = r'''
# Full precision for every number turned into text: awk's default CONVFMT/OFMT is "%.6g",
# which renders an epoch like 1790547006.8 as "1.79055e+09" (an hour off). POSIX, all awks.
BEGIN { CONVFMT = "%.6f"; OFMT = "%.6f" }
# --- exact emulation of auth_log_parse.classify_auth_message (regex SEARCH semantics) ---
function ipv4_at(s) { return match(s, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) ? substr(s, 1, RLENGTH) : "" }
function tok_at(s,   i) { i = index(s, " "); return i ? substr(s, 1, i - 1) : s }   # \S+ at position 1 ("" if s starts with a space)
function user_from_ip(s, lead, allow_invalid,   i, t, rest, u) {
  # lead (invalid user\s+)? USER " from " IPv4   -> sets U, IP
  rest = s
  while ((i = index(rest, lead)) > 0) {
    t = substr(rest, i + length(lead)); rest = substr(rest, i + 1)
    if (allow_invalid && substr(t, 1, 13) == "invalid user " ) {
      u = t; sub(/^invalid user +/, "", u)
      if (try_user_ip(u)) return 1
    }
    if (try_user_ip(t)) return 1
  }
  return 0
}
function try_user_ip(t,   u, ip) {
  u = tok_at(t); if (u == "") return 0
  if (substr(t, length(u) + 1, 6) != " from ") return 0
  ip = ipv4_at(substr(t, length(u) + 7)); if (ip == "") return 0
  U = u; IP = ip; return 1
}
function word_ok(c) { return c ~ /[A-Za-z0-9_]/ }
function ssh_pam_failure(msg,   i, t, off, j, u, r, k, ip) {
  # authentication failure.*?user=(\S+).*?rhost=(IPv4)
  i = index(msg, "authentication failure"); if (!i) return 0
  t = substr(msg, i + 22); off = 0
  while ((j = index(substr(t, off + 1), "user=")) > 0) {
    off += j; u = tok_at(substr(t, off + 5))
    if (u != "") {
      r = substr(t, off + 5 + length(u)); k = 0
      while ((j = index(substr(r, k + 1), "rhost=")) > 0) { k += j; ip = ipv4_at(substr(r, k + 6)); if (ip != "") { U = u; IP = ip; return 1 } }
    }
  }
  return 0
}
function sudo_pam_failure(msg,   i, t, off, j, u, last) {
  # pam_unix\(sudo:auth\): authentication failure;.*\buser=(\S+)  (greedy -> LAST word-boundary user=)
  i = index(msg, "pam_unix(sudo:auth): authentication failure;"); if (!i) return 0
  t = substr(msg, i + length("pam_unix(sudo:auth): authentication failure;")); off = 0; last = ""
  while ((j = index(substr(t, off + 1), "user=")) > 0) {
    off += j; u = tok_at(substr(t, off + 5))
    if (u != "" && (off == 1 || !word_ok(substr(t, off - 1, 1)))) last = u
  }
  if (last == "") return 0
  U = last; return 1
}
function classify(prog, msg,   t) {
  U = ""; IP = ""; TYPE = ""
  if (index(prog, "sshd") > 0) {
    if (user_from_ip(msg, "Failed password for ", 1)) { TYPE = "ssh_failed_login"; return }
    if (user_from_ip(msg, "Failed publickey for ", 1)) { TYPE = "ssh_failed_login"; return }
    if (ssh_pam_failure(msg)) { TYPE = "ssh_failed_login"; return }
    if (match(msg, /Accepted [^ ]+ for /)) {
      t = substr(msg, RSTART + RLENGTH)
      if (try_user_ip(t)) { TYPE = "ssh_success_login"; return }
    }
    U = ""; IP = ""
    if (user_from_ip(msg, "Invalid user ", 0)) { TYPE = "ssh_failed_login"; return }
    if ((t = index(msg, "Disconnected from ")) > 0) {
      IP = ipv4_at(substr(msg, t + 18)); if (IP != "") { TYPE = "ssh_disconnect"; return }
    }
    IP = ""; TYPE = "ssh_other"; return
  }
  if (prog == "sudo") {
    if (sudo_pam_failure(msg)) { TYPE = "sudo_pam_auth_failure"; return }
    if (match(msg, /[^ ]+ *: *[0-9]+ +incorrect password attempts *; *./)) { U = tok_at(substr(msg, RSTART)); sub(/:.*/, "", U); TYPE = "sudo_auth_failure"; return }
    if (match(msg, /pam_unix\(sudo:session\): session opened for user [^ ]+\(uid=[0-9]+\) by \((uid=)?[0-9]+\)/)) { TYPE = "sudo_session_open"; return }
    if (match(msg, /pam_unix\(sudo:session\): session closed for user [^ ]/)) { TYPE = "sudo_session_close"; return }
    if (match(msg, /[^ ]+ *: *TTY=.*; *PWD=.*; *USER=[^ ]+ *; *COMMAND=./)) { U = tok_at(substr(msg, RSTART)); sub(/:.*/, "", U); TYPE = "sudo_command"; return }
    TYPE = "sudo_other"; return
  }
  TYPE = "auth_other"
}
'''

# journald path: `journalctl -o short-unix` lines "<epoch.usec> <host> <prog>[pid]: <message>"
_JOURNAL_MAIN = r'''
{
  t = $1 + 0
  if (t <= 0) next
  # journalctl's --since/--until seek assumes time-ordered journal files; after a backwards
  # clock jump they are not (live E25b: out-of-window lines came back and were counted).
  # So every event is checked against the window HERE, and the earliest timestamp seen at
  # all is reported (the journal's first line is not its earliest after a jump).
  if (allmin == 0 || t < allmin) allmin = t
  if (prev > 0 && t < prev - 60) print "JUMP\t" prev "\t" t
  prev = t
  if (t < ws || (we > 0 && t >= we)) next
  prog = $3
  sub(/\[[0-9]+\]:$/, "", prog); sub(/:$/, "", prog)
  p = index($0, " " $3 " "); msg = substr($0, p + length($3) + 2)
  classify(prog, msg)
  lines++
  if (t > maxt) maxt = t
  if (mint == 0 || t < mint) mint = t
  self = (kip != "" && IP == kip && (TYPE == "ssh_success_login" || TYPE == "ssh_disconnect" || TYPE == "ssh_other"))
  selfsudo = (TYPE == "sudo_command" && kuser != "" && U == kuser && msg ~ selfcmd)
  if (self || selfsudo) { selfn[TYPE]++; next }
  key = TYPE "\t" (IP == "" ? "-" : IP) "\t" (U == "" ? "-" : U)
  c[key]++; if (!(key in f)) f[key] = t; l[key] = t
  h = int(t / 3600) * 3600; hc[h "\t" TYPE]++
  if (TYPE == "ssh_failed_login" || TYPE == "sudo_auth_failure" || TYPE == "sudo_pam_auth_failure")
    printf "F\t%.6f\t%s\t%s\t%s\n", t, TYPE, (IP == "" ? "-" : IP), (U == "" ? "-" : U) > ffile
  line = msg; gsub(/\t/, " ", line); if (length(line) > 200) line = substr(line, 1, 200)
  ring[ringi % nsample] = t "\t" (IP == "" ? "-" : IP) "\t" prog ": " line; ringi++
  if (IP != "" && TYPE == "ssh_failed_login" && !(IP in seenip) && nfirst < maxfirst) { seenip[IP] = 1; nfirst++; print "FIRSTIP\t" t "\t" IP "\t" prog ": " line }
}
END {
  for (k in c) print "CNT\t" k "\t" c[k] "\t" f[k] "\t" l[k]
  for (k in hc) print "HR\t" k "\t" hc[k]
  for (k in selfn) print "SELF\t" k "\t" selfn[k]
  n = (ringi < nsample) ? ringi : nsample
  for (i = ringi - n; i < ringi; i++) print "SAMPLE\t" ring[i % nsample]
  printf "DONE\t%d\t%.6f\t%.6f\t%.6f\n", lines, mint, maxt, allmin
}
'''

_CLASSIFY_AWK = _AWK_LIB + _JOURNAL_MAIN

# ---------------------------------------------------------------------------
# Classic syslog files (auth.log / secure / messages, incl. rotated .N, .N.gz and
# dateext -YYYYMMDD[.gz]) -- used for hosts without journald (Alpine) and for the part of
# a window older than the journal (design §2E, E17-E21). Timestamps in these files are
# LOCAL wall-clock and, in RFC3164/BusyBox format, have NO YEAR. Awk can't do timezone
# math portably, so lines are placed on a "pseudo-epoch" (local wall-clock seconds since
# 1970, pure arithmetic) and Kratos converts pseudo -> UTC with the target's zone.
# ---------------------------------------------------------------------------
_CIVIL_AWK = r"""
function dfc(y, m, d,   era, yoe, doy, doe) {   # days from civil (H. Hinnant), pure arithmetic
  y -= (m <= 2); era = int((y >= 0 ? y : y - 399) / 400); yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}
function mon(name) { return (index("JanFebMarAprMayJunJulAugSepOctNovDec", substr(name, 1, 3)) + 2) / 3 }
function iso_fields(s,   z, sign, oh, om) {
  # 2026-09-27T22:12:52[.123][+00:00|Z] -> sets Y M D HH MI SS and TZOFF (seconds, 0 if none)
  Y = substr(s, 1, 4) + 0; M = substr(s, 6, 2) + 0; D = substr(s, 9, 2) + 0
  HH = substr(s, 12, 2) + 0; MI = substr(s, 15, 2) + 0; SS = substr(s, 18, 2) + 0
  TZOFF = 0; HASOFF = 0
  z = substr(s, 20); sub(/^[.,][0-9]+/, "", z)
  if (z == "Z") { HASOFF = 1 }
  else if (z ~ /^[+-][0-9][0-9]:?[0-9][0-9]$/) { sign = (substr(z, 1, 1) == "-") ? -1 : 1; gsub(/:/, "", z)
    oh = substr(z, 2, 2) + 0; om = substr(z, 4, 2) + 0; TZOFF = sign * (oh * 3600 + om * 60); HASOFF = 1 }
}
"""

# pass 1 over one file: how many year rollovers (big month decreases) and the last month
_CLASSIC_PASS1 = _CIVIL_AWK + r"""
$1 ~ /^[A-Z][a-z][a-z]$/ && $2 ~ /^[0-9]+$/ { m = mon($1); if (m < 1) next
  if (pm && pm - m >= 6) r++; pm = m; last = m }
END { printf "%d %d\n", r + 0, last + 0 }
"""

# pass 2: classify + aggregate. -v r=<rollovers> ylast=<year of last line> lo/hi (pseudo
# bounds, with margin) gran=<60|3600> file=<name> ffile=<failure events out>
_CLASSIC_MAIN = _CIVIL_AWK + r"""
{
  if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {           # RFC3339 (rsyslog high-precision)
    iso_fields($1); host = $2; progtok = $3
    ps = dfc(Y, M, D) * 86400 + HH * 3600 + MI * 60 + SS
    exact = HASOFF; off = TZOFF
  } else if ($1 ~ /^[A-Z][a-z][a-z]$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) {
    m = mon($1); if (m < 1) next
    if (pm && pm - m >= 6) k++; pm = m
    yr = ylast - (r - k)
    split($3, tt, ":"); ps = dfc(yr, m, $2 + 0) * 86400 + tt[1] * 3600 + tt[2] * 60 + tt[3]
    host = $4; progtok = $5
    if ($5 ~ /^[a-z0-9]+\.[a-z]+$/) progtok = $6                       # BusyBox: "host facility.level prog[pid]:"
    exact = 0; off = 0
  } else next
  # Files are chronological: once safely past the window end, or past the point where the
  # journal takes over (dedup: classic lines there are never used), stop reading.
  if (ps > stop + 120) exit
  if (ps < lo || ps > hi) next
  prog = progtok; sub(/\[[0-9]+\]:$/, "", prog); sub(/:$/, "", prog)
  if (index(prog, "sshd") == 0 && prog != "sudo") next
  p = index($0, " " progtok " "); msg = substr($0, p + length(progtok) + 2)
  classify(prog, msg)
  if (kip != "" && IP == kip && (TYPE == "ssh_success_login" || TYPE == "ssh_disconnect" || TYPE == "ssh_other")) {
    cself[TYPE]++; next        # Kratos's own sessions (E22) -- same rule as the journald path
  }
  n++
  key = (exact ? "X" : "L") "\t" int(ps / gran) * gran "\t" off "\t" TYPE "\t" (IP == "" ? "-" : IP)
  c[key]++
  if (U != "" && TYPE == "ssh_failed_login") cu[U]++
  if (TYPE == "ssh_failed_login" || TYPE == "sudo_auth_failure" || TYPE == "sudo_pam_auth_failure")
    printf "F\t%d\t%s\t%s\t%s\n", ps - (exact ? off : 0), TYPE, (IP == "" ? "-" : IP), (U == "" ? "-" : U) > ffile
  if (mn == 0 || ps < mn) mn = ps
  if (ps > mx) mx = ps
  line = msg; gsub(/\t/, " ", line); if (length(line) > 160) line = substr(line, 1, 160)
  tail[ti % 60] = ps "\t" line; ti++
}
END {
  for (x in c) print "CM\t" x "\t" c[x]
  for (x in cu) print "CU\t" x "\t" cu[x]
  for (x in cself) print "SELF\t" x "\t" cself[x]
  nt = (ti < 60) ? ti : 60
  for (j = ti - nt; j < ti; j++) print "CT\t" file "\t" tail[j % 60]
  printf "CDONE\t%s\t%d\t%d\t%d\n", file, n, mn, mx
}
"""

# fail2ban.log: "2026-09-27 22:12:55,123 fail2ban.actions [123]: NOTICE [sshd] Ban 1.2.3.4"
_FAIL2BAN_AWK = _CIVIL_AWK + r"""
$1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ && ($0 ~ / Ban / || $0 ~ / Unban /) {
  split($1, d, "-"); split(substr($2, 1, 8), t, ":")
  ps = dfc(d[1] + 0, d[2] + 0, d[3] + 0) * 86400 + t[1] * 3600 + t[2] * 60 + t[3]
  if (ps < lo || ps > hi) next
  jail = "-"; if (match($0, /\[[^]]+\] (Ban|Unban) /)) { jail = substr($0, RSTART + 1); sub(/\].*/, "", jail) }
  act = ($0 ~ / Unban /) ? "unban" : "ban"
  ip = $NF
  print "FB\t" ps "\t" act "\t" jail "\t" ip
}
"""

# Greedy sliding-window bursts over time-sorted failure events -- the streaming
# equivalent of auth_log_patterns._detect_bursts (i advances past a burst, else by one;
# overlapping bursts of the same type merge). Emits
# BURST <type> <start> <end> <count> <top ips "ip:n,ip:n"> <top users>
_BURST_AWK = r'''
# Ties break by key (string order): mawk, gawk and BusyBox iterate arrays in different
# orders, and the top-5 lists must be identical whichever awk the target has.
function top5(arr,   k, best, bk, out, used, j) {
  out = ""
  for (j = 0; j < 5; j++) { best = -1; bk = ""
    for (k in arr) if (!(k in used) && (arr[k] > best || (arr[k] == best && k < bk))) { best = arr[k]; bk = k }
    if (bk == "") break; used[bk] = 1; out = out (out == "" ? "" : ",") bk ":" best }
  return out
}
function emit(type, s, e, n,   k) {
  if (open[type] && s <= pe[type] + 1) { pe[type] = e; pn[type] += n; for (k in wip) bip[type, k] += wip[k]; for (k in wus) bus[type, k] += wus[k]; return }
  flush(type); open[type] = 1; ps[type] = s; pe[type] = e; pn[type] = n
  for (k in wip) bip[type, k] = wip[k]; for (k in wus) bus[type, k] = wus[k]
}
function flush(type,   k, ti, tu, parts) {
  if (!open[type]) return
  for (k in bip) { split(k, parts, SUBSEP); if (parts[1] == type) { ti[parts[2]] = bip[k]; delete bip[k] } }
  for (k in bus) { split(k, parts, SUBSEP); if (parts[1] == type) { tu[parts[2]] = bus[k]; delete bus[k] } }
  printf "BURST\t%s\t%.6f\t%.6f\t%d\t%s\t%s\n", type, ps[type], pe[type], pn[type], top5(ti), top5(tu)
  open[type] = 0
}
function evaluate(type,   i, j, cnt, k) {
  # try the window starting at queue head of `type`
  i = qh[type]; cnt = qt[type] - i
  if (cnt >= thr) {
    delete wip; delete wus
    for (j = i; j < qt[type]; j++) { if (qip[type, j] != "-") wip[qip[type, j]]++; if (qus[type, j] != "-") wus[qus[type, j]]++ }
    emit(type, qtime[type, i], qtime[type, qt[type] - 1], cnt)
    for (j = i; j < qt[type]; j++) { delete qtime[type, j]; delete qip[type, j]; delete qus[type, j] }
    qh[type] = qt[type]; return 1
  }
  delete qtime[type, i]; delete qip[type, i]; delete qus[type, i]; qh[type] = i + 1; return 0
}
$1 == "F" {
  t = $2 + 0; type = $3
  if (!(type in qh)) { qh[type] = 0; qt[type] = 0 }
  while (qt[type] > qh[type] && t - qtime[type, qh[type]] > win) evaluate(type)
  qtime[type, qt[type]] = t; qip[type, qt[type]] = $4; qus[type, qt[type]] = $5; qt[type]++
}
END {
  for (type in qh) { while (qt[type] > qh[type]) evaluate(type); flush(type) }
}
'''


CLASSIC_GLOBS = ("/var/log/auth.log*", "/var/log/secure*", "/var/log/messages*")
FAIL2BAN_GLOB = "/var/log/fail2ban.log*"
# pseudo (local wall-clock) bounds are widened by this much on each side; Kratos filters
# exactly after converting to UTC (a zone offset is at most 14 h; DST adds one more).
_PSEUDO_MARGIN_SECONDS = 3 * 86400


def _classic_section(since_epoch: float, until_epoch: float | None, sudo: str, gran: int,
                     globs: tuple[str, ...] = CLASSIC_GLOBS, f2b_glob: str = FAIL2BAN_GLOB) -> str:
    """sh fragment: parse classic syslog files + fail2ban.log (see _CLASSIC_MAIN)."""
    lo = int(since_epoch) - _PSEUDO_MARGIN_SECONDS
    hi = int(until_epoch if until_epoch is not None else 4102444800) + _PSEUDO_MARGIN_SECONDS
    lib_main = shlex.quote(_AWK_LIB + _CLASSIC_MAIN)
    pass1 = shlex.quote(_CLASSIC_PASS1)
    f2b = shlex.quote(_FAIL2BAN_AWK)
    burst = shlex.quote(_BURST_AWK)
    globs = " ".join(globs)
    return f"""
printf 'META\\ttz_name\\t%s\\n' "$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null | sed 's|.*zoneinfo/||')"
printf 'META\\ttz_offset\\t%s\\n' "$(date +%z)"
SUDO={shlex.quote(sudo)}
# STOP (local pseudo-epoch): past this, classic lines are never needed -- the window end,
# or where the journal begins (plus the current UTC offset; the awk adds a 2 h margin).
STOP={hi}
if [ -n "${{HEADINT:-}}" ]; then
  # the zone's offset AT the journal's first entry (exact across DST), not today's
  TZS=$(date -d "@$HEADINT" +%z 2>/dev/null || date +%z)
  TZSEC=$(( $(echo "$TZS" | cut -c1)1 * ( $(echo "$TZS" | cut -c2-3 | sed 's/^0//')0 / 10 * 3600 + $(echo "$TZS" | cut -c4-5 | sed 's/^0//')0 / 10 * 60 ) ))
  STOP=$(( HEADINT + TZSEC ))
  printf 'META\\tclassic_stop_offset\\t%s\\n' "$TZSEC"
fi
FL=$(mktemp 2>/dev/null || echo "/tmp/kratos_fl.$$"); FFC=$(mktemp 2>/dev/null || echo "/tmp/kratos_ffc.$$"); : > "$FFC"
for f in {globs}; do [ -f "$f" ] || continue
  printf '%s %s\\n' "$(stat -c %Y "$f" 2>/dev/null || date -r "$f" +%s)" "$f"; done | sort -rn > "$FL"
while read -r MT F; do
  case "$F" in *.gz) CAT="gzip -dc" ;; *) CAT="cat" ;; esac
  if ! $SUDO $CAT "$F" >/dev/null 2>&1; then printf 'META\\tclassic_unreadable\\t%s\\n' "$F"; continue; fi
  RL=$($SUDO $CAT "$F" 2>/dev/null | awk {pass1}); R=${{RL% *}}; LASTM=${{RL#* }}
  YM=$(date -d "@$MT" '+%Y %m' 2>/dev/null || date '+%Y %m'); YMT=${{YM% *}}; MMT=$(echo "${{YM#* }}" | sed 's/^0//')
  YLAST=$YMT; if [ "$LASTM" -gt "$MMT" ]; then YLAST=$((YMT - 1)); fi
  printf 'CFILE\\t%s\\t%s\\t%s\\t%s\\n' "$F" "$MT" "$R" "$YLAST"
  $SUDO $CAT "$F" 2>/dev/null | awk -v r="$R" -v ylast="$YLAST" -v lo={lo} -v hi={hi} -v gran={int(gran)} \\
      -v file="$F" -v ffile="$FFC" -v kip="$KIP" -v stop="$STOP" {lib_main}
done < "$FL"
sort -n -k2,2 "$FFC" | awk -v win={BURST_WINDOW_SECONDS} -v thr={BURST_THRESHOLD} {burst} | sed 's/^BURST/CBURST/'
for f in {f2b_glob}; do [ -f "$f" ] || continue
  case "$f" in *.gz) CAT="gzip -dc" ;; *) CAT="cat" ;; esac
  $SUDO $CAT "$f" 2>/dev/null | awk -v lo={lo} -v hi={hi} {f2b}
done
rm -f "$FL" "$FFC"
"""


def build_script(
    since_epoch: float,
    until_epoch: float | None,
    *,
    journalctl_prefix: str = "sudo -n",
    kratos_user: str = "",
    self_command_regex: str = "COMMAND=/usr/bin/(journalctl|sshd|fail2ban-client|ufw|lsof|ps|date|nft|iptables|cat|ss|find|stat|gzip)",
    time_budget: int = DEFAULT_TIME_BUDGET_SECONDS,
    classic_granularity: int = 60,
    classic_globs: tuple[str, ...] = CLASSIC_GLOBS,
    fail2ban_glob: str = FAIL2BAN_GLOB,
) -> str:
    """The sh script run on the target. `since`/`until` are TARGET-clock epochs (the
    caller has already applied the measured clock offset). `classic_granularity` is the
    bucket size (seconds) for classic-log counts: 60 for short windows, 3600 for long ones."""
    s = int(since_epoch)
    until_arg = f" --until @{int(until_epoch) + 1}" if until_epoch is not None else ""
    jc = f"{journalctl_prefix} journalctl".strip()
    classic_fn = _classic_section(since_epoch, until_epoch, journalctl_prefix, classic_granularity,
                                  classic_globs, fail2ban_glob)
    classic = "kratos_classic"  # called from each fallback point; defined once below
    return f"""set -u
kratos_classic() {{
{classic_fn}
}}
KIP=$(echo "${{SSH_CONNECTION:-}}" | awk '{{print $1}}')
printf 'META\\tkratos_ip\\t%s\\n' "$KIP"
printf 'META\\tnow\\t%s\\n' "$(date +%s)"
if ! command -v journalctl >/dev/null 2>&1; then printf 'META\\tjournald\\tabsent\\n'
{classic}
exit 0; fi
J="{jc}"
if ! $J --no-pager -q -n 1 >/dev/null 2>&1; then printf 'META\\tjournald\\tunreadable\\n'
{classic}
exit 0; fi
printf 'META\\tjournald\\tpresent\\n'
printf 'META\\tjournal_head\\t%s\\n' "$($J --no-pager -q -o short-unix 2>/dev/null | head -n 1 | cut -d' ' -f1)"
$J --no-pager -q --list-boots 2>/dev/null | tail -n 50 | while read -r idx rest; do
  b0=$($J --no-pager -q -o short-unix -b "$idx" 2>/dev/null | head -n 1 | cut -d' ' -f1)
  b1=$($J --no-pager -q -o short-unix -b "$idx" -r -n 1 2>/dev/null | cut -d' ' -f1)
  printf 'BOOT\\t%s\\t%s\\t%s\\n' "$idx" "$b0" "$b1"
done
FF=$(mktemp 2>/dev/null || echo "/tmp/kratos_measure.$$")
: > "$FF"
TO=""
if command -v timeout >/dev/null 2>&1; then TO="timeout {int(time_budget)}"; else printf 'META\\tbudget\\tunavailable\\n'; fi
JOUT=$(mktemp 2>/dev/null || echo "/tmp/kratos_jout.$$")
jscan() {{
  # $1 = extra journalctl args (time seek); the awk filters every event by time itself
  $TO $J --no-pager -q -o short-unix _COMM=sshd _COMM=sshd-session _COMM=sudo $1 2>/dev/null \
    | awk -v kip="$KIP" -v kuser={shlex.quote(kratos_user)} -v selfcmd={shlex.quote(self_command_regex)} \
          -v ffile="$FF" -v nsample={SAMPLE_NEWEST} -v maxfirst={SAMPLE_FIRST_PER_IP} -v ws={s} -v we={int(until_epoch) + 1 if until_epoch is not None else 0} \
          {shlex.quote(_CLASSIFY_AWK)} > "$JOUT"
  RC=$?
}}
# --since only narrows the read; the END bound is enforced by the awk (an --until seek on a
# journal that is out of time order can stop before in-window lines -- see the E25b test)
jscan "--since @{s}"
JRESCAN=0
if grep -q '^JUMP' "$JOUT"; then
  # clock went backwards somewhere: time-seeking is unreliable, rescan everything
  : > "$FF"; jscan ""; JRESCAN=1
  printf 'META\\tjournal_rescanned\\tclock_jump\\n'
fi
ALLMIN=$(grep '^DONE' "$JOUT" | cut -f5 | cut -d. -f1)
cat "$JOUT"; rm -f "$JOUT"
printf 'META\\trc\\t%s\\n' "$RC"
sort -n -k2,2 "$FF" | awk -v win={BURST_WINDOW_SECONDS} -v thr={BURST_THRESHOLD} {shlex.quote(_BURST_AWK)}
rm -f "$FF"
$J --no-pager -q -o short-unix _COMM=sshd _COMM=sshd-session _COMM=sudo -n 60 2>/dev/null \
  | awk '{{ t = $1; p = index($0, " " $3 " "); m = substr($0, p + length($3) + 2); gsub(/\t/, " ", m); print "JT\t" t "\t" substr(m, 1, 160) }}'
HEADINT=$($J --no-pager -q -o short-unix 2>/dev/null | head -n 1 | cut -d. -f1)
if [ "$JRESCAN" = 1 ] && [ -n "$ALLMIN" ] && [ "$ALLMIN" -gt 0 ] && [ "$ALLMIN" -lt "${{HEADINT:-$ALLMIN}}" ]; then
  # after a clock jump the first journal line is not the earliest -- the full scan knows
  HEADINT=$ALLMIN
  printf 'META\\tjournal_head\\t%s\\n' "$ALLMIN"
fi
if [ -n "$HEADINT" ] && [ "$HEADINT" -le {s} ]; then printf 'META\\tclassic\\tskipped_covered\\n'; exit 0; fi
{classic}
"""


@dataclass
class Measurement:
    requested_start: float
    requested_end: float
    clock_offset: float
    counts: dict[str, int] = field(default_factory=dict)
    by_ip: dict[str, dict[str, Any]] = field(default_factory=dict)  # failures per source IP
    by_user: dict[str, int] = field(default_factory=dict)            # failed-login users
    sudo_fail_users: dict[str, int] = field(default_factory=dict)
    sudo_users: dict[str, int] = field(default_factory=dict)
    hourly: dict[float, dict[str, int]] = field(default_factory=dict)  # Kratos-clock hour -> type -> n
    bursts: list[dict[str, Any]] = field(default_factory=list)
    samples: list[dict[str, Any]] = field(default_factory=list)
    first_per_ip: list[dict[str, Any]] = field(default_factory=list)
    self_excluded: dict[str, int] = field(default_factory=dict)
    kratos_ip: str | None = None
    journald: str = "unknown"
    journal_head: float | None = None
    boots: list[tuple[float, float]] = field(default_factory=list)
    clock_jumps: list[tuple[float, float]] = field(default_factory=list)
    timed_out: bool = False
    budget_unavailable: bool = False
    lines: int = 0
    last_event: float | None = None
    # classic syslog / fail2ban (design §2E)
    tz_name: str | None = None
    tz_offset: str | None = None
    classic_status: str = "not_needed"          # not_needed | skipped_covered | used | none_found
    classic_files: list[dict[str, Any]] = field(default_factory=list)
    classic_unreadable: list[str] = field(default_factory=list)
    classic_span: tuple[float, float] | None = None   # Kratos-clock span the classic lines covered
    classic_granularity: int = 60
    classic_offset_note: str | None = None
    classic_stop_offset: float | None = None
    journal_rescanned: bool = False
    fail2ban: list[dict[str, Any]] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)

    # -- coverage -----------------------------------------------------------
    def coverage(self) -> dict[str, Any]:
        """What part of the requested window the counts actually cover (Kratos clock):
        the union of the sources that were really read -- journald (from its first entry)
        and classic syslog files (the span their lines cover) -- minus reboot gaps."""
        req = self.requested_end - self.requested_start
        problems: list[str] = []
        spans: list[tuple[float, float]] = []
        if self.journald == "present":
            head = (self.journal_head - self.clock_offset) if self.journal_head is not None else self.requested_start
            j_end = self.requested_end
            if self.timed_out and self.last_event is not None:
                j_end = min(j_end, self.last_event - self.clock_offset)
                problems.append(f"counting hit the time budget; journal events after {_iso(j_end)} were not counted")
            spans.append((head, j_end))
        else:
            problems.append(f"journald {self.journald} on the target" +
                            (" -- used classic log files instead" if self.classic_span else " -- no journal data"))
        if self.classic_span:
            spans.append(self.classic_span)
        if self.classic_unreadable:
            problems.append(f"could not read {', '.join(self.classic_unreadable)} (permissions?)")
        if self.classic_offset_note:
            problems.append(self.classic_offset_note)
        if self.classic_status == "used" and self.classic_granularity > 60:
            problems.append("classic-log counts are bucketed per hour at the window edges")
        clipped = sorted((max(a, self.requested_start), min(b, self.requested_end)) for a, b in spans)
        merged: list[list[float]] = []
        for a, b in clipped:
            if b <= a:
                continue
            if merged and a <= merged[-1][1] + 120:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        if not merged:
            return {"percent": 0.0, "covered_start": None, "covered_end": None,
                    "problems": problems or ["no log data found for this window"]}
        if merged[0][0] > self.requested_start + 60:
            problems.append(f"the target's logs only go back to {_iso(merged[0][0])} (retention); "
                            "nothing before that exists")
        for (a1, b1), (a2, b2) in zip(merged, merged[1:]):
            problems.append(f"no log data between {_iso(b1)} and {_iso(a2)}")
        gap_seconds = 0.0
        for a, b in self.boot_gaps():
            for ma, mb in merged:
                ov = max(0.0, min(b, mb) - max(a, ma))
                if ov > 0:
                    gap_seconds += ov
                    problems.append(f"no logging while the target was down/rebooting: {_iso(max(a, ma))} -> {_iso(min(b, mb))}")
        if self.clock_jumps:
            problems.append(f"the target's clock jumped backwards {len(self.clock_jumps)} time(s) -- the journal was "
                            + ("rescanned in full and every event filtered by its own timestamp; " if self.journal_rescanned else "")
                            + "event times near those jumps are unreliable")
        covered = sum(b - a for a, b in merged) - gap_seconds
        pct = round(100.0 * max(0.0, covered) / req, 1) if req > 0 else 0.0
        return {"percent": min(pct, 100.0), "covered_start": _iso(merged[0][0]), "covered_end": _iso(merged[-1][1]),
                "problems": problems, "sources": list(self.sources_used)}

    def boot_gaps(self) -> list[tuple[float, float]]:
        """(end of one boot, start of the next) in Kratos clock -- time with no journal."""
        b = sorted(self.boots)
        return [(b[i][1] - self.clock_offset, b[i + 1][0] - self.clock_offset)
                for i in range(len(b) - 1) if b[i + 1][0] - b[i][1] > 60]

    # -- summaries -----------------------------------------------------------
    def failed_logins(self) -> int:
        return int(self.counts.get("ssh_failed_login", 0))

    def as_auth_stats(self) -> dict[str, Any]:
        """Same shape as auth_log_parse.compute_basic_stats (what correlate_findings reads)."""
        def top(d: dict[str, int], key: str) -> list[dict[str, Any]]:
            return [{key: k, "count": v} for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:5]]
        return {
            "total_events": sum(self.counts.values()),
            "events_by_type": dict(self.counts),
            "top_failed_login_ips": [{"ip": ip, "count": d["count"]}
                                     for ip, d in sorted(self.by_ip.items(), key=lambda kv: -kv[1]["count"])[:5]],
            "top_failed_login_users": top(self.by_user, "user"),
            "top_sudo_users": top(self.sudo_users, "user"),
            "top_sudo_auth_fail_users": top(self.sudo_fail_users, "user"),
            "top_sudo_pam_auth_fail_users": [],
            "measurement": "exhaustive",
        }

    def as_auth_patterns(self) -> dict[str, Any]:
        return {
            "source_events_file": None,
            "generated_at": _iso(self.requested_end),
            "params": {"window_minutes": BURST_WINDOW_SECONDS // 60, "threshold": BURST_THRESHOLD,
                       "event_types": list(FAILURE_TYPES), "measurement": "exhaustive"},
            "bursts": [{"event_type": b["event_type"], "start": b["start"], "end": b["end"], "count": b["count"],
                        "top_users": b["top_users"], "top_source_ips": b["top_source_ips"],
                        "context_minutes_before": BURST_WINDOW_SECONDS // 60, "context_excerpt_file": None}
                       for b in self.bursts],
        }


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _pairs(s: str, key: str) -> list[dict[str, Any]]:
    out = []
    for part in (s or "").split(","):
        if ":" in part:
            k, _, v = part.rpartition(":")
            try:
                out.append({key: k, "count": int(v)})
            except ValueError:
                continue
    return out


def parse_output(stdout: str, requested_start: float, requested_end: float, clock_offset: float,
                 classic_granularity: int = 60) -> Measurement:
    """Turn the script's tab-separated output into a Measurement. All times are converted
    from the TARGET clock back to Kratos's clock (subtract `clock_offset`); classic-log
    local times are converted to UTC with the target's zone first (see _merge_classic)."""
    m = Measurement(requested_start, requested_end, clock_offset, classic_granularity=classic_granularity)
    classic: dict[str, list[list[str]]] = {"CM": [], "CU": [], "CT": [], "JT": [], "CDONE": [], "CBURST": [], "FB": [], "CFILE": []}
    for line in stdout.splitlines():
        p = line.split("\t")
        tag = p[0]
        try:
            if tag in classic:
                classic[tag].append(p)
            elif tag == "META":
                if p[1] == "kratos_ip":
                    m.kratos_ip = p[2] or None
                elif p[1] == "journald":
                    m.journald = p[2]
                elif p[1] == "journal_head" and p[2]:
                    m.journal_head = float(p[2])
                elif p[1] == "rc":
                    m.timed_out = p[2] == "124"
                elif p[1] == "budget":
                    m.budget_unavailable = True
                elif p[1] == "tz_name":
                    m.tz_name = p[2].strip() or None
                elif p[1] == "tz_offset":
                    m.tz_offset = p[2].strip() or None
                elif p[1] == "classic":
                    m.classic_status = p[2]
                elif p[1] == "journal_rescanned":
                    m.journal_rescanned = True
                elif p[1] == "classic_stop_offset":
                    m.classic_stop_offset = float(p[2])
                elif p[1] == "classic_unreadable":
                    m.classic_unreadable.append(p[2])
            elif tag == "BOOT" and p[2] and p[3]:
                m.boots.append((float(p[2]), float(p[3])))
            elif tag == "CNT":
                _add_count(m, p[1], p[2], p[3], int(p[4]), float(p[5]) - clock_offset, float(p[6]) - clock_offset)
            elif tag == "HR":
                hour = float(p[1]) - clock_offset
                m.hourly.setdefault(hour, {})[p[2]] = m.hourly.setdefault(hour, {}).get(p[2], 0) + int(p[3])
            elif tag == "SELF":
                m.self_excluded[p[1]] = m.self_excluded.get(p[1], 0) + int(p[2])
            elif tag == "JUMP":
                m.clock_jumps.append((float(p[1]) - clock_offset, float(p[2]) - clock_offset))
            elif tag == "SAMPLE":
                m.samples.append({"time": _iso(float(p[1]) - clock_offset), "ip": None if p[2] == "-" else p[2],
                                  "line": p[3] if len(p) > 3 else ""})
            elif tag == "FIRSTIP":
                m.first_per_ip.append({"time": _iso(float(p[1]) - clock_offset), "ip": p[2], "line": p[3] if len(p) > 3 else ""})
            elif tag == "BURST":
                m.bursts.append(_burst(p, lambda x: x - clock_offset))
            elif tag == "DONE":
                m.lines = int(p[1])
                m.last_event = float(p[3]) if float(p[3]) > 0 else None
        except (IndexError, ValueError):
            continue  # a malformed line never aborts the whole measurement
    if m.journald == "present":
        m.sources_used.append("journald")
    _merge_classic(m, classic)
    m.samples.sort(key=lambda s: s["time"] or "", reverse=True)
    return m


def _add_count(m: Measurement, etype: str, ip: str, user: str, n: int, first: float, last: float) -> None:
    m.counts[etype] = m.counts.get(etype, 0) + n
    if etype == "ssh_failed_login":
        if ip != "-":
            d = m.by_ip.setdefault(ip, {"count": 0, "first": first, "last": last, "users": 0})
            d["count"] += n
            d["first"], d["last"] = min(d["first"], first), max(d["last"], last)
            d["users"] += 1
        if user != "-":
            m.by_user[user] = m.by_user.get(user, 0) + n
    elif etype == "sudo_command" and user != "-":
        m.sudo_users[user] = m.sudo_users.get(user, 0) + n
    elif etype in ("sudo_auth_failure", "sudo_pam_auth_failure") and user != "-":
        m.sudo_fail_users[user] = m.sudo_fail_users.get(user, 0) + n


def _burst(p: list[str], conv) -> dict[str, Any]:
    return {"event_type": p[1], "start": _iso(conv(float(p[2]))), "end": _iso(conv(float(p[3]))),
            "count": int(p[4]), "top_source_ips": _pairs(p[5] if len(p) > 5 else "", "ip"),
            "top_users": _pairs(p[6] if len(p) > 6 else "", "user")}


def _target_zone(m: Measurement):
    from datetime import timedelta, timezone as _tz

    from kratos.utils.timeutil import zone_from_name

    z = zone_from_name(m.tz_name) if m.tz_name else None
    if z is not None:
        return z
    off = m.tz_offset or "+0000"
    try:
        sign = -1 if off.startswith("-") else 1
        return _tz(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
    except (ValueError, IndexError):
        return _tz.utc


def _merge_classic(m: Measurement, rec: dict[str, list[list[str]]]) -> None:
    """Fold classic syslog + fail2ban records into `m` (design §2E): convert local wall
    time to UTC with the target's zone -- calibrated against journald when both logs hold
    the same events (E16: a log daemon can keep writing an OLD timezone) -- and use classic
    lines only for time the journal does not cover (E18: never double count)."""
    from datetime import datetime, timedelta
    from statistics import median

    from kratos.timewin.windows import localize

    if not (rec["CM"] or rec["CDONE"] or rec["FB"]):
        if m.journald != "present" and m.classic_status == "not_needed":
            m.classic_status = "none_found"
        return
    tz = _target_zone(m)
    epoch0 = datetime(1970, 1, 1)
    override: float | None = None

    # calibration: identical message text in the newest classic lines and the journal
    # Only messages that occur exactly once in BOTH tails pair up unambiguously ("session
    # closed for user root" repeats constantly and would pair the wrong lines).
    jt: dict[str, list[float]] = {}
    for p in rec["JT"]:
        if len(p) >= 3:
            jt.setdefault(p[2], []).append(float(p[1]))
    newest = max(rec["CFILE"], key=lambda p: float(p[2]), default=None) if rec["CFILE"] else None
    ct: dict[str, list[float]] = {}
    for p in rec["CT"]:
        if len(p) >= 4 and (newest is None or p[1] == newest[1]):
            ct.setdefault(p[3], []).append(float(p[2]))
    diffs = [ct[msg][0] - jt[msg][0] for msg in ct if len(ct[msg]) == 1 and len(jt.get(msg, [])) == 1]
    if diffs:
        measured = round(median(diffs) / 60.0) * 60.0          # local - utc, seconds
        ref = jt[next(iter(jt))][0]
        zone_off = datetime.fromtimestamp(ref, tz).utcoffset().total_seconds()
        if abs(measured - zone_off) >= 900:
            override = round(measured / 900.0) * 900.0
            stop_note = ""
            if m.classic_stop_offset is not None and abs(override - m.classic_stop_offset) > 120:
                stop_note = (" The classic scan stopped where the journal begins, computed with the system zone, "
                             "so classic lines up to "
                             f"{abs(override - m.classic_stop_offset) / 3600:g} h before the journal may be missing.")
            m.classic_offset_note = (
                f"classic log times are written at UTC{override / 3600:+g}h, not the target's current zone "
                f"({m.tz_name or m.tz_offset}); used the measured offset -- older lines may differ if the log "
                "daemon's timezone changed while they were written." + stop_note)
    elif m.journald != "present":
        m.classic_offset_note = (f"classic log times assumed to be in the target's zone ({m.tz_name or m.tz_offset}); "
                                 "no journal to cross-check against")

    def real(pseudo: float, exact_off: float | None = None) -> float:
        if exact_off is not None:
            target_epoch = pseudo - exact_off
        elif override is not None:
            target_epoch = pseudo - override
        else:
            target_epoch, _ = localize(epoch0 + timedelta(seconds=pseudo), tz)
        return target_epoch - m.clock_offset

    cutoff = (m.journal_head - m.clock_offset) if (m.journald == "present" and m.journal_head is not None) else None
    used = 0
    span_lo, span_hi = None, None
    for p in rec["CDONE"]:
        try:
            n, mn, mx = int(p[2]), float(p[3]), float(p[4])
        except (IndexError, ValueError):
            continue
        if n <= 0:
            continue
        m.classic_files.append({"file": p[1], "lines": n})
        a, b = real(mn), real(mx)
        if cutoff is not None:
            b = min(b, cutoff)
        if b > a:
            span_lo = a if span_lo is None else min(span_lo, a)
            span_hi = b if span_hi is None else max(span_hi, b)
    for p in rec["CM"]:
        try:
            exact, bucket, off, etype, ip, n = p[1], float(p[2]), float(p[3]), p[4], p[5], int(p[6])
        except (IndexError, ValueError):
            continue
        t = real(bucket, off if exact == "X" else None)
        if not (m.requested_start <= t < m.requested_end) or (cutoff is not None and t >= cutoff):
            continue
        used += n
        _add_count(m, etype, ip, "-", n, t, t + m.classic_granularity)
        hour = int(t // 3600) * 3600.0
        m.hourly.setdefault(hour, {})[etype] = m.hourly.setdefault(hour, {}).get(etype, 0) + n
    if used:
        for p in rec["CU"]:  # users: classic-scan totals within the pseudo bounds (approximate at edges)
            try:
                m.by_user[p[1]] = m.by_user.get(p[1], 0) + int(p[2])
            except (IndexError, ValueError):
                continue
        for p in rec["CBURST"]:
            b = _burst(p, real)
            start_epoch = datetime.fromisoformat(b["start"]).timestamp()
            if m.requested_start <= start_epoch < m.requested_end and (cutoff is None or start_epoch < cutoff):
                m.bursts.append(b)
        m.classic_status = "used"
        m.sources_used.append("classic syslog files")
    elif m.classic_status == "not_needed":
        m.classic_status = "none_in_window"
    if span_lo is not None:
        m.classic_span = (span_lo, span_hi)
    for p in rec["FB"]:
        try:
            t = real(float(p[1]))
        except (IndexError, ValueError):
            continue
        if m.requested_start <= t < m.requested_end:
            m.fail2ban.append({"time": _iso(t), "action": p[2], "jail": p[3], "ip": p[4]})
    if m.fail2ban:
        m.sources_used.append("fail2ban.log")
