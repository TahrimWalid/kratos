"""Hardening facts of a Linux machine -- the `hardening_facts` read (E.2 §3.3).

A CLOSED list of facts, nothing outside it, no value outside each fact's type:

- sysctl values for a closed key list, read from ``/proc/sys``;
- ``stat`` (mode, owner, group, type) of a closed file list -- never their content;
- mount type and options of a closed mount-point list (``/proc/self/mounts``);
- ``/etc/login.defs`` values for a closed key list;
- PAM: which modules appear in a closed list of stacks, with their control words and
  only allow-listed arguments (flags and numeric ``key=`` values -- never a path);
- password-quality and lockout settings (``pwquality.conf``, ``faillock.conf``), closed keys;
- time synchronisation (``timedatectl show`` properties, chrony's leap status);
- kernel modules that should not load: ``install``/``blacklist`` lines, loaded, shipped;
- services from a closed list: loaded / enabled / active (systemd or OpenRC);
- auditd: enabled, rule count, watched paths and rule keys from closed lists;
- MAC: AppArmor enabled and profile counts, SELinux mode;
- banner files: size and whether they show OS details -- not their content;
- the SSH server's effective settings (``sshd -T``) for a closed key list (user lists as
  a count only) and how many ``Match`` blocks its configuration has;
- the firewall's default input policy (ufw's own config, nftables/iptables listings).

One fixed POSIX sh script (``build_script``) prints tab-separated records. Over SSH it
runs AS THE SSH USER, with ``sudo -n`` only for the three listings the setup checklist
already pins (``sshd -T``, ``auditctl -s``/``-l``, ``nft list ruleset``, ``iptables -L -n``);
the sub-agent runs the SAME script through ``sh -s`` as root (its ``hardening_facts``
read). One parser (``parse_output``) reads both, and types every value -- a value of the
wrong shape becomes "unexpected", never carried. Nothing is judged here: the checks are
Kratos's (``kratos.compliance.checks``).

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import re
import shlex
from typing import Any

OUTPUT_CAP_BYTES = 512 * 1024
DEFAULT_BUDGET_SECONDS = 60
FORMAT = "1"

SYSCTL_KEYS: tuple[str, ...] = (
    "kernel.randomize_va_space", "kernel.yama.ptrace_scope", "kernel.kptr_restrict", "kernel.dmesg_restrict",
    "fs.suid_dumpable", "fs.protected_hardlinks", "fs.protected_symlinks",
    "net.ipv4.ip_forward",
    "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects", "net.ipv4.conf.default.secure_redirects",
    "net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.tcp_syncookies",
    "net.ipv6.conf.all.forwarding",
    "net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra",
    "net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects",
    "net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route",
)
STAT_PATHS: tuple[str, ...] = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/ssh/sshd_config", "/etc/crontab",
    "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d",
    "/etc/cron.allow", "/etc/issue", "/etc/issue.net", "/etc/motd", "/etc/sudoers",
)
MOUNT_POINTS: tuple[str, ...] = ("/tmp", "/var/tmp", "/dev/shm", "/home")
LOGIN_DEFS_KEYS: tuple[str, ...] = ("PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "UMASK", "ENCRYPT_METHOD")
PAM_STACKS: tuple[str, ...] = ("common-auth", "common-password", "common-account", "system-auth", "password-auth",
                               "sshd")
PAM_FLAG_ARGS: tuple[str, ...] = ("nullok", "nullok_secure", "yescrypt", "sha512", "md5", "bigcrypt", "blowfish",
                                  "use_authtok", "try_first_pass", "use_first_pass", "preauth", "authfail",
                                  "authsucc", "enforce_for_root", "even_deny_root", "silent", "remember",
                                  "audit", "shadow")
PAM_KEY_ARGS: tuple[str, ...] = ("minlen", "deny", "unlock_time", "remember", "retry", "minclass", "dcredit",
                                 "ucredit", "lcredit", "ocredit", "maxrepeat", "maxsequence", "difok", "rounds",
                                 "fail_interval", "root_unlock_time")
SEC_CONF_KEYS: dict[str, tuple[str, ...]] = {
    "pwquality": ("minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit", "maxrepeat", "maxsequence",
                  "difok", "dictcheck", "enforcing", "enforce_for_root"),
    "faillock": ("deny", "unlock_time", "fail_interval", "even_deny_root", "root_unlock_time"),
}
TIME_PROPS: tuple[str, ...] = ("NTP", "NTPSynchronized", "CanNTP")
MODULES: tuple[str, ...] = ("cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "squashfs", "udf", "usb-storage",
                            "dccp", "sctp", "rds", "tipc")
# systemd unit names (without .service unless another suffix is given) and OpenRC names.
SERVICES: tuple[str, ...] = (
    "avahi-daemon", "cups", "nfs-server", "rpcbind", "xinetd", "vsftpd", "tftpd-hpa", "tftp.socket", "snmpd",
    "rsync", "slapd", "named", "bind9", "dnsmasq", "smbd", "smb", "squid", "dovecot", "autofs", "bluetooth",
    "ypserv", "isc-dhcp-server", "dhcpd", "telnet.socket", "rsh.socket", "rlogin.socket", "apport",
    "auditd", "chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd", "ntpsec", "cron", "crond", "rsyslog",
    "systemd-journald", "apparmor", "ufw", "firewalld", "nftables", "fail2ban", "sshd", "ssh",
)
AUDIT_WATCH_PATHS: tuple[str, ...] = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
                                      "/etc/security/opasswd", "/etc/sudoers", "/etc/sudoers.d", "/var/log/lastlog",
                                      "/var/run/faillock", "/var/log/faillog", "/etc/apparmor", "/etc/apparmor.d",
                                      "/etc/selinux", "/etc/localtime", "/etc/hosts", "/etc/issue")
AUDIT_KEYS: tuple[str, ...] = ("identity", "time-change", "system-locale", "MAC-policy", "logins", "session",
                               "perm_mod", "access", "mounts", "delete", "scope", "actions", "modules",
                               "privileged", "sudo_log_file", "usermod", "kernel_modules")
BANNER_FILES: tuple[str, ...] = ("/etc/issue", "/etc/issue.net", "/etc/motd")
SSHD_KEYS: tuple[str, ...] = (
    "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords",
    "maxauthtries", "x11forwarding", "loglevel", "ignorerhosts", "hostbasedauthentication", "permituserenvironment",
    "clientaliveinterval", "clientalivecountmax", "logingracetime", "maxstartups", "maxsessions", "usepam",
    "banner", "disableforwarding", "gssapiauthentication", "allowtcpforwarding", "ciphers", "macs",
    "kexalgorithms",
)
# These name accounts: the read sends only how many entries each has.
SSHD_COUNT_KEYS: tuple[str, ...] = ("allowusers", "allowgroups", "denyusers", "denygroups")

_WORD = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,128}$")
for _name in (*SYSCTL_KEYS, *STAT_PATHS, *MOUNT_POINTS, *LOGIN_DEFS_KEYS, *PAM_STACKS, *PAM_FLAG_ARGS, *PAM_KEY_ARGS,
              *TIME_PROPS, *MODULES, *SERVICES, *AUDIT_WATCH_PATHS, *AUDIT_KEYS, *BANNER_FILES, *SSHD_KEYS,
              *SSHD_COUNT_KEYS, *(k for v in SEC_CONF_KEYS.values() for k in v)):
    assert _WORD.fullmatch(_name), _name


def _words(items: tuple[str, ...]) -> str:
    return " ".join(items)


# One awk program: a PAM stack -> PAM<TAB>stack<TAB>type<TAB>control<TAB>module<TAB>args,
# with the control's [..] form kept as one word (spaces -> ','), the module as its file
# name, and only allow-listed arguments.
AWK_PAM = r"""
BEGIN {
  nf = split(flags, F, " "); for (i = 1; i <= nf; i++) FL[F[i]] = 1
  nk = split(keys, K, " "); for (i = 1; i <= nk; i++) KY[K[i]] = 1
}
/^[ \t]*#/ { next }
NF == 0 { next }
$1 ~ /^@include$/ { if ($2 ~ /^[a-z0-9_-]+$/) print "PAMINC\t" stack "\t" $2; next }
{
  t = $1; sub(/^-/, "", t)
  if (t != "auth" && t != "account" && t != "password" && t != "session") next
  i = 2; c = $2
  if (substr(c, 1, 1) == "[") {
    while (index(c, "]") == 0 && i < NF) { i++; c = c "," $i }
  }
  gsub(/[\t ]/, ",", c)
  if (length(c) > 120) c = "other"
  i++; m = $i; sub(/.*\//, "", m)
  if (m !~ /^pam_[a-z0-9_]+\.so$/) m = "other"
  a = ""
  for (j = i + 1; j <= NF; j++) {
    w = $j; e = index(w, "=")
    if (e == 0) { if (w in FL) a = a (a == "" ? "" : ",") w }
    else {
      k = substr(w, 1, e - 1); v = substr(w, e + 1)
      if ((k in KY) && v ~ /^-?[0-9]{1,6}$/) a = a (a == "" ? "" : ",") k "=" v
    }
  }
  print "PAM\t" stack "\t" t "\t" c "\t" m "\t" a
}
"""

# One awk program: `key = value` files (pwquality/faillock) -> SEC<TAB>file<TAB>key<TAB>value
# for the closed key list; the last setting wins (in input order: main file, then drop-ins).
AWK_KEYVAL = r"""
BEGIN { n = split(keys, K, " "); for (i = 1; i <= n; i++) W[K[i]] = 1 }
/^[ \t]*#/ { next }
{
  line = $0; sub(/^[ \t]+/, "", line)
  e = index(line, "="); if (e == 0) { k = line; v = "1" } else { k = substr(line, 1, e - 1); v = substr(line, e + 1) }
  gsub(/[ \t]/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", v)
  if ((k in W) && v ~ /^-?[0-9A-Za-z_]{0,16}$/) val[k] = v
}
END { for (i = 1; i <= n; i++) if (K[i] in val) print "SEC\t" file "\t" K[i] "\t" val[K[i]] }
"""

# One awk program: login.defs -> LDEF<TAB>key<TAB>value (closed keys; the last wins).
AWK_LOGIN_DEFS = r"""
BEGIN { n = split(keys, K, " "); for (i = 1; i <= n; i++) W[K[i]] = 1 }
/^[ \t]*#/ { next }
($1 in W) && NF >= 2 { val[$1] = $2 }
END { for (i = 1; i <= n; i++) if (K[i] in val) print "LDEF\t" K[i] "\t" val[K[i]] }
"""

# One awk program: modprobe configuration -> MODCONF<TAB>module<TAB>install<TAB>blacklisted
# (install: false|true|other|none). Module names: '-' and '_' are the same to modprobe.
AWK_MODPROBE = r"""
BEGIN { n = split(mods, M, " "); for (i = 1; i <= n; i++) { k = M[i]; gsub(/-/, "_", k); N[k] = M[i] } }
/^[ \t]*#/ { next }
$1 == "install" && NF >= 3 {
  k = $2; gsub(/-/, "_", k)
  if (k in N) { t = $3; sub(/.*\//, "", t); inst[k] = (t == "false" || t == "true") ? t : "other" }
  next
}
$1 == "blacklist" && NF >= 2 { k = $2; gsub(/-/, "_", k); if (k in N) bl[k] = 1 }
END {
  for (i = 1; i <= n; i++) {
    k = M[i]; gsub(/-/, "_", k)
    print "MODCONF\t" M[i] "\t" ((k in inst) ? inst[k] : "none") "\t" ((k in bl) ? "yes" : "no")
  }
}
"""

# One awk program: /proc/self/mounts -> MOUNT<TAB>point<TAB>fstype<TAB>options for the
# closed mount points (the last line for a point is the one in effect), NOMOUNT otherwise.
AWK_MOUNTS = r"""
BEGIN { n = split(points, P, " "); for (i = 1; i <= n; i++) W[P[i]] = 1 }
($2 in W) { fs[$2] = $3; op[$2] = $4 }
END {
  for (i = 1; i <= n; i++) {
    p = P[i]
    if (p in fs) print "MOUNT\t" p "\t" fs[p] "\t" op[p]; else print "NOMOUNT\t" p
  }
}
"""

# One awk program: `auditctl -l` -> AUDITRULES<TAB>count, AUDITW<TAB>path (watched for
# writes), AUDITK<TAB>key -- for the closed path and key lists only.
AWK_AUDIT_RULES = r"""
BEGIN {
  np = split(paths, P, " "); for (i = 1; i <= np; i++) WP[P[i]] = 1
  nk = split(keys, K, " "); for (i = 1; i <= nk; i++) WK[K[i]] = 1
  n = 0
}
/^No rules/ { next }
/^-[aw] / || /^-A / {
  n++
  for (i = 1; i <= NF; i++) {
    if ($i == "-w" && i < NF && ($(i + 1) in WP)) seenp[$(i + 1)] = 1
    if ($i ~ /^dir=/ || $i ~ /^path=/) { v = $i; sub(/^[a-z]+=/, "", v); if (v in WP) seenp[v] = 1 }
    if ($i == "-k" && i < NF && ($(i + 1) in WK)) seenk[$(i + 1)] = 1
    if ($i ~ /^key=/) { v = $i; sub(/^key=/, "", v); gsub(/"/, "", v); if (v in WK) seenk[v] = 1 }
  }
}
END {
  print "AUDITRULES\t" n
  for (i = 1; i <= np; i++) if (P[i] in seenp) print "AUDITW\t" P[i]
  for (i = 1; i <= nk; i++) if (K[i] in seenk) print "AUDITK\t" K[i]
}
"""

# One awk program: `sshd -T` -> SSHD<TAB>key<TAB>value for the closed key list, and
# SSHD<TAB>key<TAB>N (a count of entries) for the account-list keys.
AWK_SSHD = r"""
BEGIN {
  n = split(keys, K, " "); for (i = 1; i <= n; i++) W[K[i]] = 1
  m = split(counts, C, " "); for (i = 1; i <= m; i++) CW[C[i]] = 1
}
{
  k = tolower($1)
  if (k in W) { v = $2; for (i = 3; i <= NF; i++) v = v " " $i; if (length(v) > 600) v = substr(v, 1, 600); val[k] = v }
  else if (k in CW) cnt[k] += NF - 1
}
END {
  for (i = 1; i <= n; i++) if (K[i] in val) print "SSHD\t" K[i] "\t" val[K[i]]
  for (i = 1; i <= m; i++) print "SSHD\t" C[i] "\t" ((C[i] in cnt) ? cnt[C[i]] : 0)
}
"""

# One awk program: `nft list ruleset` -> NFTIN<TAB>policy for every base chain hooked on input.
AWK_NFT = r"""
/hook input/ {
  p = "accept"
  if (match($0, /policy [a-z]+/)) { p = substr($0, RSTART + 7, RLENGTH - 7) }
  print "NFTIN\t" p
}
"""

_SH = r"""
LC_ALL=C; export LC_ALL
R=@ROOT@
printf 'HFACTS\t@FORMAT@\n'
for _f in "$R/etc/os-release" "$R/usr/lib/os-release"; do
  if [ -r "$_f" ]; then
    grep -E '^(ID|ID_LIKE|VERSION_ID|PRETTY_NAME)=' "$_f" 2>/dev/null | head -n 8 | while IFS= read -r _l; do
      printf 'OS\t%s\n' "$_l"
    done
    break
  fi
done
printf 'UID\t%s\n' "$(id -u 2>/dev/null)"
_virt=none
if [ -e "$R/run/.containerenv" ] || [ -e "$R/.dockerenv" ]; then _virt=container; fi
if [ -z "$R" ] && command -v systemd-detect-virt >/dev/null 2>&1; then
  _c=$(systemd-detect-virt --container 2>/dev/null)
  case "$_c" in ''|none) ;; *) _virt=container ;; esac
fi
printf 'VIRT\t%s\n' "$_virt"

# sysctl values
for _k in @SYSCTL@; do
  _p="$R/proc/sys/$(printf '%s' "$_k" | tr . /)"
  if [ -r "$_p" ]; then
    _val=$(head -c 64 "$_p" 2>/dev/null | head -n 1 | tr '\t' ' ')
    printf 'SYSCTL\t%s\t%s\n' "$_k" "$_val"
  elif [ -e "$_p" ]; then
    printf 'SYSCTLX\t%s\tunreadable\n' "$_k"
  else
    printf 'SYSCTLX\t%s\tmissing\n' "$_k"
  fi
done

# file modes and owners -- never the content
for _f in @STAT@; do
  if [ -e "$R$_f" ] || [ -L "$R$_f" ]; then
    _s=$(stat -c '%a|%u|%g|%U|%G|%F' "$R$_f" 2>/dev/null)
    if [ -n "$_s" ]; then printf 'STAT\t%s\t%s\n' "$_f" "$_s"; else printf 'STATX\t%s\tunreadable\n' "$_f"; fi
  else
    printf 'STATX\t%s\tmissing\n' "$_f"
  fi
done

# mount options
if [ -r "$R/proc/self/mounts" ]; then
  awk -v points="@MOUNTS@" '@AWK_MOUNTS@' "$R/proc/self/mounts"
else
  printf 'GAP\tmounts\tunreadable\n'
fi

# login.defs
if [ -r "$R/etc/login.defs" ]; then
  awk -v keys="@LDEFS@" '@AWK_LDEFS@' "$R/etc/login.defs"
else
  printf 'GAP\tlogin_defs\tmissing\n'
fi

# PAM stacks
for _s in @PAM@; do
  _f="$R/etc/pam.d/$_s"
  if [ -r "$_f" ]; then
    printf 'PAMSTACK\t%s\tpresent\n' "$_s"
    awk -v stack="$_s" -v flags="@PAMFLAGS@" -v keys="@PAMKEYS@" '@AWK_PAM@' "$_f"
  elif [ -e "$_f" ]; then
    printf 'PAMSTACK\t%s\tunreadable\n' "$_s"
  else
    printf 'PAMSTACK\t%s\tmissing\n' "$_s"
  fi
done
_files=""
for _f in "$R/etc/security/pwquality.conf" "$R"/etc/security/pwquality.conf.d/*.conf; do [ -r "$_f" ] && _files="$_files $_f"; done
if [ -n "$_files" ]; then
  # shellcheck disable=SC2086
  cat $_files 2>/dev/null | awk -v file=pwquality -v keys="@PWQKEYS@" '@AWK_KEYVAL@'
  printf 'SECFILE\tpwquality\tpresent\n'
else
  printf 'SECFILE\tpwquality\tmissing\n'
fi
if [ -r "$R/etc/security/faillock.conf" ]; then
  awk -v file=faillock -v keys="@FLKEYS@" '@AWK_KEYVAL@' "$R/etc/security/faillock.conf"
  printf 'SECFILE\tfaillock\tpresent\n'
else
  printf 'SECFILE\tfaillock\tmissing\n'
fi

# time synchronisation
if [ -z "$R" ] && command -v timedatectl >/dev/null 2>&1; then
  timedatectl show @TIMEPROPS@ 2>/dev/null | head -n 6 | while IFS='=' read -r _k _v; do
    printf 'TIME\t%s\t%s\n' "$_k" "$_v"
  done
fi
if [ -z "$R" ] && command -v chronyc >/dev/null 2>&1; then
  _l=$(chronyc -n tracking 2>/dev/null | grep '^Leap status' | head -n 1 | sed 's/^[^:]*: *//')
  [ -n "$_l" ] && printf 'TIME\tchrony_leap\t%s\n' "$_l"
fi

# kernel modules that should not load
cat "$R"/etc/modprobe.d/*.conf "$R"/lib/modprobe.d/*.conf "$R"/usr/lib/modprobe.d/*.conf "$R"/run/modprobe.d/*.conf 2>/dev/null \
  | awk -v mods="@MODULES@" '@AWK_MODPROBE@'
_krel=$(uname -r 2>/dev/null)
_dep="$R/lib/modules/$_krel/modules.dep"
[ -r "$_dep" ] || _dep="$R/usr/lib/modules/$_krel/modules.dep"
for _m in @MODULES@; do
  _u=$(printf '%s' "$_m" | tr - _)
  _ld=no
  if [ -r "$R/proc/modules" ] && grep -q "^$_u " "$R/proc/modules" 2>/dev/null; then _ld=yes; fi
  if [ -r "$_dep" ]; then
    if grep -q -e "/$_m\.ko" -e "/$_u\.ko" "$_dep" 2>/dev/null; then _av=yes; else _av=no; fi
  else
    _av=unknown
  fi
  printf 'MOD\t%s\t%s\t%s\n' "$_m" "$_ld" "$_av"
done

# services
if [ -z "$R" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  printf 'INIT\tsystemd\n'
  _units=""
  for _u in @SERVICES@; do
    case "$_u" in *.*) _units="$_units $_u" ;; *) _units="$_units $_u.service" ;; esac
  done
  # shellcheck disable=SC2086
  systemctl show -p Id -p LoadState -p UnitFileState -p ActiveState $_units 2>/dev/null \
    | grep -E '^(Id|LoadState|UnitFileState|ActiveState)=' | head -n 400 | while IFS= read -r _l; do
      printf 'SVCRAW\t%s\n' "$_l"
    done
elif [ -z "$R" ] && command -v rc-service >/dev/null 2>&1; then
  printf 'INIT\topenrc\n'
  _boot=$(rc-update show 2>/dev/null)
  for _u in @SERVICES@; do
    case "$_u" in *.*) continue ;; esac
    if [ -x "/etc/init.d/$_u" ]; then
      if printf '%s\n' "$_boot" | grep -q "^ *$_u |"; then _e=enabled; else _e=disabled; fi
      if rc-service "$_u" status >/dev/null 2>&1; then _a=active; else _a=inactive; fi
      printf 'SVC\t%s\tloaded\t%s\t%s\n' "$_u" "$_e" "$_a"
    else
      printf 'SVC\t%s\tnot-found\tnone\tinactive\n' "$_u"
    fi
  done
else
  printf 'INIT\tunknown\n'
fi

# auditd
if [ -z "$R" ] && command -v auditctl >/dev/null 2>&1; then
  if _o=$($SUDO auditctl -s 2>/dev/null); then
    printf '%s\n' "$_o" | grep -E '^(enabled|pid) [0-9]+$' | head -n 2 | while read -r _k _v; do
      printf 'AUDIT\t%s\t%s\n' "$_k" "$_v"
    done
    if _o=$($SUDO auditctl -l 2>/dev/null); then
      printf '%s\n' "$_o" | awk -v paths="@AUDITPATHS@" -v keys="@AUDITKEYS@" '@AWK_AUDIT@'
    else
      printf 'GAP\taudit_rules\tunreadable\n'
    fi
  else
    printf 'GAP\taudit\tunreadable\n'
  fi
elif [ -z "$R" ]; then
  printf 'AUDIT\tinstalled\tno\n'
fi

# mandatory access control
if [ -r "$R/sys/module/apparmor/parameters/enabled" ]; then
  printf 'MAC\tapparmor_enabled\t%s\n' "$(head -c 4 "$R/sys/module/apparmor/parameters/enabled" | tr -d '\n')"
  if _o=$(cat "$R/sys/kernel/security/apparmor/profiles" 2>/dev/null); then
    printf '%s\n' "$_o" | awk 'BEGIN { t = 0; e = 0 } NF > 0 { t++; if (index($0, "(enforce)")) e++ } END { print "MAC\tapparmor_profiles\t" t "\t" e }'
  else
    printf 'GAP\tapparmor_profiles\tunreadable\n'
  fi
fi
if [ -z "$R" ] && command -v getenforce >/dev/null 2>&1; then
  printf 'MAC\tselinux_mode\t%s\n' "$(getenforce 2>/dev/null | head -n 1)"
fi
if [ -r "$R/etc/selinux/config" ]; then
  grep -E '^(SELINUX|SELINUXTYPE)=' "$R/etc/selinux/config" 2>/dev/null | tail -n 2 | while IFS='=' read -r _k _v; do
    printf 'MAC\tselinux_config_%s\t%s\n' "$_k" "$_v"
  done
fi

# banner files: size, and whether they show OS details (\m \r \s \v)
for _f in @BANNERS@; do
  if [ -r "$R$_f" ] && [ -f "$R$_f" ]; then
    _n=$(wc -c < "$R$_f" 2>/dev/null | tr -d ' ')
    _o=$(grep -c '\\[mrsv]' "$R$_f" 2>/dev/null)
    printf 'BANNER\t%s\t%s\t%s\n' "$_f" "${_n:-0}" "${_o:-0}"
  else
    printf 'BANNER\t%s\tmissing\t0\n' "$_f"
  fi
done

# the SSH server's effective settings
if [ -z "$R" ]; then
  if [ -n "$SSHD_T" ] && _o=$($SSHD_T 2>/dev/null) && [ -n "$_o" ]; then
    printf 'SSHDSTATE\tok\n'
    printf '%s\n' "$_o" | awk -v keys="@SSHDKEYS@" -v counts="@SSHDCOUNTS@" '@AWK_SSHD@'
  elif [ -e /etc/ssh/sshd_config ]; then
    printf 'SSHDSTATE\tunavailable\n'
  else
    printf 'SSHDSTATE\tnot_installed\n'
  fi
fi
_m=$(cat "$R/etc/ssh/sshd_config" "$R"/etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -c -i '^[[:space:]]*match[[:space:]]')
printf 'SSHDMATCH\t%s\n' "${_m:-0}"

# journald: where it keeps the logs (Storage= in its config, last setting wins) -- no log content
_s=$(cat "$R/etc/systemd/journald.conf" "$R"/usr/lib/systemd/journald.conf.d/*.conf "$R"/etc/systemd/journald.conf.d/*.conf 2>/dev/null \
  | grep -E '^[[:space:]]*Storage=' | tail -n 1 | cut -d= -f2 | tr -d ' "' | head -c 16)
printf 'JOURNALD\tstorage\t%s\n' "$_s"
if [ -d "$R/var/log/journal" ]; then printf 'JOURNALD\tvar_log_journal\tyes\n'; else printf 'JOURNALD\tvar_log_journal\tno\n'; fi

# firewall: the default input policy
if [ -r "$R/etc/ufw/ufw.conf" ]; then
  _e=$(grep -E '^ENABLED=' "$R/etc/ufw/ufw.conf" 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d '"' | head -c 8)
  printf 'FW\tufw_enabled\t%s\n' "$_e"
fi
if [ -r "$R/etc/default/ufw" ]; then
  _e=$(grep -E '^DEFAULT_INPUT_POLICY=' "$R/etc/default/ufw" 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d '"' | head -c 8)
  printf 'FW\tufw_input_policy\t%s\n' "$_e"
fi
if [ -r "$R/etc/firewalld/firewalld.conf" ]; then
  _e=$(grep -E '^DefaultZone=' "$R/etc/firewalld/firewalld.conf" 2>/dev/null | tail -n 1 | cut -d= -f2 | head -c 32)
  printf 'FW\tfirewalld_zone\t%s\n' "$_e"
fi
if [ -z "$R" ] && command -v nft >/dev/null 2>&1; then
  if _o=$($SUDO nft list ruleset 2>/dev/null); then
    printf 'FW\tnft_read\tok\n'
    printf '%s\n' "$_o" | awk '@AWK_NFT@' | head -n 32
  else
    printf 'FW\tnft_read\tunreadable\n'
  fi
fi
if [ -z "$R" ] && command -v iptables >/dev/null 2>&1; then
  if _o=$($SUDO iptables -L -n 2>/dev/null); then
    _p=$(printf '%s\n' "$_o" | grep '^Chain INPUT (policy ' | head -n 1 | sed 's/^Chain INPUT (policy \([A-Z]*\).*/\1/')
    printf 'FW\tiptables_input\t%s\n' "$_p"
  else
    printf 'FW\tiptables_read\tunreadable\n'
  fi
fi
printf 'END\n'
"""


def build_script(sudo: str = "sudo -n", root: str = "") -> str:
    """The fixed read. `sudo` is the privilege prefix for the pinned listings (`sudo -n`
    over SSH, empty for the root agent). `root` prefixes every FILE path (tests point it
    at a fake tree; commands are then skipped)."""
    subs = {
        "@ROOT@": shlex.quote(root), "@FORMAT@": FORMAT,
        "@SYSCTL@": _words(SYSCTL_KEYS), "@STAT@": _words(STAT_PATHS), "@MOUNTS@": _words(MOUNT_POINTS),
        "@LDEFS@": _words(LOGIN_DEFS_KEYS), "@PAM@": _words(PAM_STACKS), "@PAMFLAGS@": _words(PAM_FLAG_ARGS),
        "@PAMKEYS@": _words(PAM_KEY_ARGS), "@PWQKEYS@": _words(SEC_CONF_KEYS["pwquality"]),
        "@FLKEYS@": _words(SEC_CONF_KEYS["faillock"]), "@TIMEPROPS@": " ".join(f"-p {p}" for p in TIME_PROPS),
        "@MODULES@": _words(MODULES), "@SERVICES@": _words(SERVICES), "@AUDITPATHS@": _words(AUDIT_WATCH_PATHS),
        "@AUDITKEYS@": _words(AUDIT_KEYS), "@BANNERS@": _words(BANNER_FILES), "@SSHDKEYS@": _words(SSHD_KEYS),
        "@SSHDCOUNTS@": _words(SSHD_COUNT_KEYS),
        "@AWK_MOUNTS@": AWK_MOUNTS, "@AWK_LDEFS@": AWK_LOGIN_DEFS, "@AWK_PAM@": AWK_PAM,
        "@AWK_KEYVAL@": AWK_KEYVAL, "@AWK_MODPROBE@": AWK_MODPROBE, "@AWK_AUDIT@": AWK_AUDIT_RULES,
        "@AWK_SSHD@": AWK_SSHD, "@AWK_NFT@": AWK_NFT,
    }
    for awk in (AWK_MOUNTS, AWK_LOGIN_DEFS, AWK_PAM, AWK_KEYVAL, AWK_MODPROBE, AWK_AUDIT_RULES, AWK_SSHD, AWK_NFT):
        assert "'" not in awk, "awk programs travel inside single quotes"
    head = (f"SUDO={shlex.quote(sudo)}\n"
            'if [ -n "$SUDO" ]; then SSHD_T="$SUDO sshd -T"; else SSHD_T=""\n'
            '  for _b in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do [ -x "$_b" ] && { SSHD_T="$_b -T"; break; }; done\n'
            'fi\n')
    body = _SH
    for k, v in subs.items():
        body = body.replace(k, v)
    return head + body


# --------------------------------------------------------------------------- parsing
_INT_RE = re.compile(r"^-?[0-9]{1,12}$")
_MODE_RE = re.compile(r"^[0-7]{1,4}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:,@+/= -]{0,600}$")
_TYPES = {"regular file": "file", "regular empty file": "file", "directory": "dir", "symbolic link": "link"}
_SYSTEMD_UNIT_STATES = {"enabled", "enabled-runtime", "disabled", "static", "masked", "masked-runtime", "indirect",
                        "generated", "transient", "alias", "linked", "linked-runtime", "bad", ""}
_ACTIVE = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}


def _int(v: str) -> int | None:
    return int(v) if _INT_RE.fullmatch(v.strip()) else None


def _unit_name(unit_id: str) -> str:
    return unit_id[:-len(".service")] if unit_id.endswith(".service") else unit_id


def parse_output(stdout: str) -> dict[str, Any]:
    """Every record typed. Unknown record kinds and out-of-list keys are dropped; a value
    of the wrong shape is kept as {"unexpected": True} so a check says "unexpected value"
    rather than guessing. `complete` is False when the END marker is missing (cut off)."""
    out: dict[str, Any] = {
        "format": None, "os": {}, "uid": None, "virt": "none", "sysctl": {}, "stat": {}, "mounts": {},
        "login_defs": {}, "pam": {}, "pam_includes": {}, "sec": {"pwquality": {}, "faillock": {}},
        "sec_files": {}, "time": {}, "modules": {}, "init": "unknown", "services": {}, "audit": {},
        "mac": {}, "banners": {}, "journald": {}, "sshd": {}, "sshd_state": None, "sshd_match_blocks": None, "firewall": {},
        "gaps": {}, "complete": False, "unexpected": 0,
    }
    sysctl_ok, stat_ok, mods = set(SYSCTL_KEYS), set(STAT_PATHS), set(MODULES)
    svc_ok = {s if "." in s else s for s in SERVICES}
    raw_units: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    nft_policies: list[str] = []
    for line in (stdout or "").splitlines():
        f = line.split("\t")
        tag = f[0]
        try:
            if tag == "HFACTS":
                out["format"] = f[1] if len(f) > 1 else None
            elif tag == "OS" and len(f) > 1 and "=" in f[1]:
                k, _, v = f[1].partition("=")
                v = v.strip().strip('"').strip("'")
                if k in ("ID", "ID_LIKE", "VERSION_ID", "PRETTY_NAME") and _VALUE_RE.fullmatch(v):
                    out["os"][k] = v[:120]
            elif tag == "UID" and len(f) > 1:
                out["uid"] = _int(f[1])
            elif tag == "VIRT" and len(f) > 1 and f[1] in ("none", "container"):
                out["virt"] = f[1]
            elif tag == "SYSCTL" and len(f) > 2 and f[1] in sysctl_ok:
                n = _int(f[2])
                out["sysctl"][f[1]] = n if n is not None else {"unexpected": True}
                out["unexpected"] += n is None
            elif tag == "SYSCTLX" and len(f) > 2 and f[1] in sysctl_ok and f[2] in ("missing", "unreadable"):
                out["sysctl"][f[1]] = {"absent": f[2]}
            elif tag == "STAT" and len(f) > 2 and f[1] in stat_ok:
                parts = f[2].split("|")
                if len(parts) == 6 and _MODE_RE.fullmatch(parts[0]) and _int(parts[1]) is not None \
                        and _int(parts[2]) is not None:
                    out["stat"][f[1]] = {"mode": int(parts[0], 8), "uid": int(parts[1]), "gid": int(parts[2]),
                                         "user": parts[3] if _NAME_RE.fullmatch(parts[3]) else "?",
                                         "group": parts[4] if _NAME_RE.fullmatch(parts[4]) else "?",
                                         "type": _TYPES.get(parts[5].strip(), "other")}
                else:
                    out["stat"][f[1]] = {"unexpected": True}
                    out["unexpected"] += 1
            elif tag == "STATX" and len(f) > 2 and f[1] in stat_ok and f[2] in ("missing", "unreadable"):
                out["stat"][f[1]] = {"absent": f[2]}
            elif tag == "MOUNT" and len(f) > 3 and f[1] in MOUNT_POINTS:
                opts = [o for o in f[3].split(",") if re.fullmatch(r"[A-Za-z0-9_=.:-]{1,64}", o)]
                out["mounts"][f[1]] = {"fstype": f[2] if _NAME_RE.fullmatch(f[2]) else "?",
                                       "options": sorted(set(opts))}
            elif tag == "NOMOUNT" and len(f) > 1 and f[1] in MOUNT_POINTS:
                out["mounts"][f[1]] = None
            elif tag == "LDEF" and len(f) > 2 and f[1] in LOGIN_DEFS_KEYS:
                v = f[2].strip()
                out["login_defs"][f[1]] = v if re.fullmatch(r"[A-Za-z0-9_-]{1,32}", v) else {"unexpected": True}
            elif tag == "PAMSTACK" and len(f) > 2 and f[1] in PAM_STACKS and f[2] in ("present", "missing",
                                                                                      "unreadable"):
                out["pam"].setdefault(f[1], {"state": f[2], "lines": []})["state"] = f[2]
            elif tag == "PAMINC" and len(f) > 2 and f[1] in PAM_STACKS:
                out["pam_includes"].setdefault(f[1], []).append(f[2][:64])
            elif tag == "PAM" and len(f) > 5 and f[1] in PAM_STACKS:
                args = [a for a in f[5].split(",") if a and (a in PAM_FLAG_ARGS or (
                    "=" in a and a.split("=", 1)[0] in PAM_KEY_ARGS and _int(a.split("=", 1)[1]) is not None))]
                stack = out["pam"].setdefault(f[1], {"state": "present", "lines": []})
                if len(stack["lines"]) < 64:
                    stack["lines"].append({"type": f[2] if f[2] in ("auth", "account", "password", "session")
                                           else "?", "control": f[3][:120],
                                           "module": f[4] if re.fullmatch(r"pam_[a-z0-9_]+\.so|other", f[4]) else
                                           "other", "args": args})
            elif tag == "SEC" and len(f) > 3 and f[1] in SEC_CONF_KEYS and f[2] in SEC_CONF_KEYS[f[1]]:
                out["sec"][f[1]][f[2]] = f[3][:16]
            elif tag == "SECFILE" and len(f) > 2 and f[1] in SEC_CONF_KEYS:
                out["sec_files"][f[1]] = f[2] == "present"
            elif tag == "TIME" and len(f) > 2 and (f[1] in TIME_PROPS or f[1] == "chrony_leap"):
                v = f[2].strip()
                out["time"][f[1]] = v[:32] if re.fullmatch(r"[A-Za-z ]{1,32}", v) else "unexpected"
            elif tag == "MODCONF" and len(f) > 3 and f[1] in mods:
                m = out["modules"].setdefault(f[1], {})
                m["install"] = f[2] if f[2] in ("false", "true", "other", "none") else "other"
                m["blacklisted"] = f[3] == "yes"
            elif tag == "MOD" and len(f) > 3 and f[1] in mods:
                m = out["modules"].setdefault(f[1], {"install": "none", "blacklisted": False})
                m["loaded"] = f[2] == "yes"
                m["shipped"] = {"yes": True, "no": False}.get(f[3])
            elif tag == "INIT" and len(f) > 1 and f[1] in ("systemd", "openrc", "unknown"):
                out["init"] = f[1]
            elif tag == "SVCRAW" and len(f) > 1 and "=" in f[1]:
                k, _, v = f[1].partition("=")
                if k == "Id":
                    if cur:
                        raw_units.append(cur)
                    cur = {"Id": v}
                elif cur:
                    cur[k] = v
            elif tag == "SVC" and len(f) > 4 and f[1] in svc_ok:
                out["services"][f[1]] = {"load": "loaded" if f[2] == "loaded" else "not-found",
                                         "enabled": f[3] if f[3] in ("enabled", "disabled", "none") else "?",
                                         "active": f[4] if f[4] in ("active", "inactive") else "inactive"}
            elif tag == "AUDIT" and len(f) > 2:
                if f[1] == "installed":
                    out["audit"]["installed"] = f[2] != "no"
                elif f[1] in ("enabled", "pid") and _int(f[2]) is not None:
                    out["audit"][f[1]] = int(f[2])
                    out["audit"]["installed"] = True
            elif tag == "AUDITRULES" and len(f) > 1 and _int(f[1]) is not None:
                out["audit"]["rules"] = int(f[1])
            elif tag == "AUDITW" and len(f) > 1 and f[1] in AUDIT_WATCH_PATHS:
                out["audit"].setdefault("watched", []).append(f[1])
            elif tag == "AUDITK" and len(f) > 1 and f[1] in AUDIT_KEYS:
                out["audit"].setdefault("keys", []).append(f[1])
            elif tag == "MAC" and len(f) > 2:
                if f[1] == "apparmor_enabled":
                    out["mac"]["apparmor_enabled"] = f[2].strip().upper().startswith("Y")
                elif f[1] == "apparmor_profiles" and len(f) > 3 and _int(f[2]) is not None and _int(f[3]) is not None:
                    out["mac"]["apparmor_profiles"] = int(f[2])
                    out["mac"]["apparmor_enforce"] = int(f[3])
                elif f[1] == "selinux_mode" and f[2].strip() in ("Enforcing", "Permissive", "Disabled"):
                    out["mac"]["selinux_mode"] = f[2].strip().lower()
                elif f[1] == "selinux_config_SELINUX" and f[2].strip() in ("enforcing", "permissive", "disabled"):
                    out["mac"]["selinux_config"] = f[2].strip()
                elif f[1] == "selinux_config_SELINUXTYPE" and _NAME_RE.fullmatch(f[2].strip()):
                    out["mac"]["selinux_type"] = f[2].strip()
            elif tag == "BANNER" and len(f) > 3 and f[1] in BANNER_FILES:
                out["banners"][f[1]] = (None if f[2] == "missing" else
                                        {"size": _int(f[2]) or 0, "os_details": (_int(f[3]) or 0) > 0})
            elif tag == "SSHDSTATE" and len(f) > 1 and f[1] in ("ok", "unavailable", "not_installed"):
                out["sshd_state"] = f[1]
            elif tag == "SSHD" and len(f) > 2 and (f[1] in SSHD_KEYS or f[1] in SSHD_COUNT_KEYS):
                v = f[2].strip()
                if f[1] in SSHD_COUNT_KEYS:
                    out["sshd"][f[1]] = _int(v) or 0
                elif re.fullmatch(r"[A-Za-z0-9@.,:+_ /-]{0,600}", v):
                    out["sshd"][f[1]] = v.lower() if f[1] not in ("banner",) else v
                else:
                    out["sshd"][f[1]] = {"unexpected": True}
                    out["unexpected"] += 1
            elif tag == "SSHDMATCH" and len(f) > 1:
                out["sshd_match_blocks"] = _int(f[1])
            elif tag == "FW" and len(f) > 2:
                v = f[2].strip()
                if f[1] in ("ufw_enabled", "ufw_input_policy", "firewalld_zone", "iptables_input", "nft_read",
                            "iptables_read") and re.fullmatch(r"[A-Za-z0-9_-]{0,32}", v):
                    out["firewall"][f[1]] = v
            elif tag == "JOURNALD" and len(f) > 2 and f[1] in ("storage", "var_log_journal"):
                v = f[2].strip()
                out["journald"][f[1]] = v.lower() if re.fullmatch(r"[A-Za-z]{0,16}", v) else "unexpected"
            elif tag == "NFTIN" and len(f) > 1 and re.fullmatch(r"[a-z]{1,12}", f[1]):
                nft_policies.append(f[1])
            elif tag == "GAP" and len(f) > 2 and re.fullmatch(r"[a-z_]{1,32}", f[1]):
                out["gaps"][f[1]] = f[2][:32]
            elif tag == "END":
                out["complete"] = True
        except (IndexError, ValueError):
            out["unexpected"] += 1
    if cur:
        raw_units.append(cur)
    for u in raw_units:
        name = _unit_name(u.get("Id", ""))
        if name not in svc_ok:
            continue
        load = u.get("LoadState", "")
        state = u.get("UnitFileState", "")
        out["services"][name] = {"load": "loaded" if load == "loaded" else "not-found",
                                 "enabled": state if state in _SYSTEMD_UNIT_STATES else "?",
                                 "active": u.get("ActiveState") if u.get("ActiveState") in _ACTIVE else "inactive"}
    if nft_policies:
        out["firewall"]["nft_input_policies"] = nft_policies[:32]
    return out
