"""Kratos's compliance checks: a closed table (E.2 §3.5).

Each check is code over typed facts (kratos.compliance.facts) returning pass, fail,
unknown (with the reason Kratos couldn't tell) or na (Kratos's check doesn't apply on
this machine, said so -- never a silent pass). Kratos never runs a framework's own
scripts: where ComplianceAsCode has a rule Kratos doesn't check, the report lists it as
"not checked by Kratos" with the rule id.

`cac_rules` are the ComplianceAsCode rule ids the check gives an answer for; the CIS
section numbers per product come from the vendored control files (kratos.compliance.cac),
so one check answers the same rule in every product's benchmark. `iso` and `nis2` are
Kratos's own advisory mapping (frameworks.py).

`fix` is a copy-safe command or config line a PERSON runs (display only; Kratos never
runs it). `remote_access` marks checks about reaching the machine from outside (COMP-001
rises to medium on an internet-exposed machine). `linked_rules`: a failure of this check
is already one of these findings -- the report links to it and COMP-001 doesn't count it
again. `in_finding=False`: shown in the report, never part of COMP-001 (Kratos's own
features, not the machine's hardening).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from kratos.compliance.facts import Facts

PASS, FAIL, UNKNOWN, NA = "pass", "fail", "unknown", "na"


@dataclass(frozen=True)
class Result:
    status: str              # pass | fail | unknown | na
    found: str               # what Kratos saw, in plain words
    reason: str = ""         # unknown / na: why
    note: str = ""           # e.g. "Match blocks present: checked the defaults only"


@dataclass(frozen=True)
class Check:
    id: str
    family: str
    text: str                                    # Kratos's own words: what this check tests
    facts: tuple[str, ...]
    predicate: Callable[[Facts], Result]
    fix: str
    cac_rules: tuple[str, ...] = ()
    iso: tuple[str, ...] = ()
    nis2: tuple[str, ...] = ()
    remote_access: bool = False
    linked_rules: tuple[str, ...] = ()
    in_finding: bool = True
    os_families: tuple[str, ...] = ("debian", "rhel", "alpine", "other")
    tags: tuple[str, ...] = field(default_factory=tuple)
    # A pass is trusted from an incomplete read of its source (the part it needs was read in
    # full): the reboot check reads the kernel facts, which don't need vulnerability data.
    trust_incomplete: bool = False


def _unexpected(v: Any) -> bool:
    return isinstance(v, dict) and v.get("unexpected")


def _hard_gap(f: Facts) -> Result | None:
    src = f.get("hardening")
    if src is None:
        return Result(UNKNOWN, "", "Kratos has no hardening read of this machine yet")
    return None


def _in_container(f: Facts) -> bool:
    return f.h().get("virt") == "container"


# --------------------------------------------------------------------------- sysctl
def _sysctl(key: str, ok: tuple[int, ...], want: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        v = (f.h().get("sysctl") or {}).get(key)
        if v is None:
            return Result(UNKNOWN, "", f"{key} was not in the read")
        if isinstance(v, dict) and v.get("absent"):
            if key.startswith("net.ipv6.") and v["absent"] == "missing":
                return Result(NA, "IPv6 is off on this machine", "IPv6 is off, so this IPv6 setting doesn't apply")
            return Result(UNKNOWN, "", f"{key} is {v['absent']} on this machine")
        if _unexpected(v):
            return Result(UNKNOWN, "", f"{key} has an unexpected value")
        return Result(PASS if v in ok else FAIL, f"{key} = {v} (expected {want})")
    return pred


def _sysctl_fix(key: str, value: int) -> str:
    return (f"sudo sysctl -w {key}={value} && printf '%s\\n' '{key} = {value}' | "
            "sudo tee -a /etc/sysctl.d/60-hardening.conf")


# --------------------------------------------------------------------------- file modes
def _perm(path: str, max_mode: int, users: tuple[str, ...], groups: tuple[str, ...],
          optional: bool = False) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        st = (f.h().get("stat") or {}).get(path)
        if st is None:
            return Result(UNKNOWN, "", f"{path} was not in the read")
        if st.get("absent") == "missing":
            if optional:
                return Result(NA, f"{path} doesn't exist", f"{path} doesn't exist on this machine")
            return Result(UNKNOWN, "", f"{path} doesn't exist")
        if st.get("absent") or _unexpected(st):
            return Result(UNKNOWN, "", f"{path} couldn't be read")
        mode, user, group = int(st["mode"]), str(st["user"]), str(st["group"])
        bad = []
        if mode & ~max_mode & 0o7777:
            bad.append(f"mode {mode:o} allows more than {max_mode:o}")
        if user not in users:
            bad.append(f"owner {user}")
        if group not in groups:
            bad.append(f"group {group}")
        found = f"{path}: mode {mode:o}, owner {user}, group {group}"
        return Result(FAIL if bad else PASS, found + (f" ({'; '.join(bad)})" if bad else ""))
    return pred


def _perm_fix(path: str, mode: int, user: str, group: str) -> str:
    return f"sudo chown {user}:{group} {path} && sudo chmod {mode:o} {path}"


# --------------------------------------------------------------------------- mounts
def _mount(point: str, option: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        mounts = f.h().get("mounts") or {}
        if point not in mounts:
            return Result(UNKNOWN, "", "the mount table couldn't be read")
        m = mounts.get(point)
        if m is None:
            return Result(NA, f"{point} is not a separate mount",
                          f"{point} is not a separate mount, so its mount options don't apply (the 'separate "
                          "partition' item decides)")
        opts = m.get("options") or []
        return Result(PASS if option in opts else FAIL, f"{point} is mounted with: {','.join(opts) or '(none)'}")
    return pred


def _mount_fix(point: str, option: str) -> str:
    return (f"add {option} to the options of {point} in /etc/fstab, then: sudo mount -o remount,{option} {point}")


# --------------------------------------------------------------------------- modules
def _module(name: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        if _in_container(f):
            return Result(NA, "a container", "kernel modules belong to the host, not this container")
        m = (f.h().get("modules") or {}).get(name)
        if not m or "loaded" not in m:
            return Result(UNKNOWN, "", "the module state wasn't in the read")
        if m.get("loaded"):
            return Result(FAIL, f"the {name} module is loaded now")
        blocked = m.get("install") in ("false", "true")
        if blocked:
            return Result(PASS, f"{name} can't be loaded (install {m['install']})")
        if m.get("shipped") is False:
            return Result(PASS, f"{name} is not part of this kernel")
        if m.get("shipped") is None:
            return Result(UNKNOWN, "", "the kernel's module list couldn't be read")
        extra = " (a blacklist line alone doesn't stop a direct load)" if m.get("blacklisted") else ""
        return Result(FAIL, f"{name} could be loaded: no 'install {name} /bin/false' line{extra}")
    return pred


def _module_fix(name: str) -> str:
    return (f"printf '%s\\n' 'install {name} /bin/false' 'blacklist {name}' | "
            f"sudo tee /etc/modprobe.d/{name}.conf")


# --------------------------------------------------------------------------- services
_ALIASES = {"chrony": ("chrony", "chronyd"), "named": ("named", "bind9"), "smb": ("smbd", "smb"),
            "ntp": ("ntp", "ntpd", "ntpsec"), "cron": ("cron", "crond"), "sshd": ("ssh", "sshd"),
            "dhcpd": ("isc-dhcp-server", "dhcpd"), "tftp": ("tftpd-hpa", "tftp.socket")}


def _units(f: Facts, names: tuple[str, ...]) -> tuple[str, list[dict[str, Any]]]:
    h = f.h()
    svcs = h.get("services") or {}
    return str(h.get("init") or "unknown"), [dict(svcs[n], name=n) for n in names if n in svcs]


def _svc_off(names: tuple[str, ...], label: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        init, units = _units(f, names)
        if init == "unknown":
            return Result(UNKNOWN, "", "Kratos couldn't tell how services are started on this machine")
        loaded = [u for u in units if u.get("load") == "loaded"]
        on = [u["name"] for u in loaded if u.get("active") in ("active", "activating", "reloading")
              or str(u.get("enabled")).startswith("enabled")]
        if on:
            return Result(FAIL, f"{label} is running or enabled ({', '.join(on)})")
        if loaded:
            return Result(PASS, f"{label} is installed but off")
        return Result(PASS, f"{label} is not installed")
    return pred


def _svc_on(names: tuple[str, ...], label: str, absent_na: str = "") -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        init, units = _units(f, names)
        if init == "unknown":
            return Result(UNKNOWN, "", "Kratos couldn't tell how services are started on this machine")
        loaded = [u for u in units if u.get("load") == "loaded"]
        if not loaded:
            if absent_na:
                return Result(NA, f"{label} is not installed", absent_na)
            return Result(FAIL, f"{label} is not installed")
        good = [u for u in loaded if u.get("active") == "active" and str(u.get("enabled")) in (
            "enabled", "enabled-runtime", "static", "alias", "indirect", "generated")]
        if good:
            return Result(PASS, f"{label} is enabled and running ({good[0]['name']})")
        u = loaded[0]
        return Result(FAIL, f"{label} is {u.get('active')} and {u.get('enabled') or 'not enabled'}")
    return pred


def _svc_off_fix(names: tuple[str, ...]) -> str:
    return " ; ".join(f"sudo systemctl disable --now {n if '.' in n else n + '.service'}" for n in names[:2])


# --------------------------------------------------------------------------- packages (inventory)
def _pkg(names: tuple[str, ...], want_installed: bool, label: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        src = f.get("inventory")
        if src is None or not src.data.get("names"):
            return Result(UNKNOWN, "", "Kratos has no installed-package list for this machine yet")
        have = sorted(set(names) & set(src.data["names"]))
        if want_installed:
            return Result(PASS if have else FAIL, f"{label} {'is' if have else 'is not'} installed"
                          + (f" ({', '.join(have)})" if have else ""))
        return Result(FAIL if have else PASS, f"{label} {'is' if have else 'is not'} installed"
                      + (f" ({', '.join(have)})" if have else ""))
    return pred


def _pkg_remove_fix(names: tuple[str, ...], fam: str = "debian") -> str:
    return f"sudo apt purge {names[0]}   # or: sudo dnf remove {names[0]}"


# --------------------------------------------------------------------------- sshd
_WEAK_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256",
                 "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se"}
_WEAK_MACS_PREFIX = ("hmac-md5", "hmac-sha1", "umac-64", "hmac-ripemd160")
_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
SSHD_SUDOERS_LINE = "<login> ALL=(ALL) NOPASSWD: /usr/sbin/sshd -T"


def _sshd(test: Callable[[dict[str, Any]], tuple[bool, str] | None]) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        h = f.h()
        state = h.get("sshd_state")
        if state == "not_installed":
            return Result(NA, "no SSH server installed", "this machine has no SSH server")
        if state != "ok":
            return Result(UNKNOWN, "", "the SSH server's settings (sshd -T) couldn't be read: add the line "
                          f"'{SSHD_SUDOERS_LINE}' from the setup checklist, or read this machine through its "
                          "sub-agent")
        note = ""
        if (h.get("sshd_match_blocks") or 0) > 0:
            note = "Match blocks present: checked the defaults only"
        try:
            got = test(h.get("sshd") or {})
        except _NotBuiltIn as e:
            return Result(NA, f"{e} is not built into this SSH server", f"this SSH server has no {e} option", note)
        if got is None:
            return Result(UNKNOWN, "", "the setting wasn't in sshd -T's output", note)
        ok, found = got
        return Result(PASS if ok else FAIL, found, note=note)
    return pred


class _NotBuiltIn(Exception):
    """sshd -T has no such option: this SSH server was built without the feature."""


def _eq(key: str, want: str, absent: str = "") -> Callable[[dict[str, Any]], tuple[bool, str] | None]:
    """`absent`: "pass" (an option not built in can't be on) or "na" (doesn't apply)."""
    def t(s: dict[str, Any]) -> tuple[bool, str] | None:
        v = s.get(key)
        if v is None and absent == "pass":
            return (True, f"{key}: not built into this SSH server, so it can't be on")
        if v is None and absent == "na":
            raise _NotBuiltIn(key)
        if v is None or _unexpected(v):
            return None
        return (str(v) == want, f"{key} {v} (expected {want})")
    return t


def _int_le(key: str, hi: int, lo: int = 0) -> Callable[[dict[str, Any]], tuple[bool, str] | None]:
    def t(s: dict[str, Any]) -> tuple[bool, str] | None:
        v = s.get(key)
        try:
            n = int(str(v))
        except (TypeError, ValueError):
            return None
        return (lo <= n <= hi, f"{key} {n} (expected {lo}-{hi})" if lo else f"{key} {n} (expected at most {hi})")
    return t


def _maxstartups(s: dict[str, Any]) -> tuple[bool, str] | None:
    v = str(s.get("maxstartups") or "")
    parts = v.split(":")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) == 1:
        nums = [nums[0], 100, nums[0]]
    if len(nums) != 3:
        return None
    ok = nums[0] <= 10 and nums[1] <= 30 and nums[2] <= 60
    return (ok, f"maxstartups {v} (expected 10:30:60 or stricter)")


def _idle(s: dict[str, Any]) -> tuple[bool, str] | None:
    try:
        i, c = int(str(s.get("clientaliveinterval"))), int(str(s.get("clientalivecountmax")))
    except (TypeError, ValueError):
        return None
    return (i > 0 and c > 0, f"clientaliveinterval {i}, clientalivecountmax {c} (expected both above 0)")


def _limit_users(s: dict[str, Any]) -> tuple[bool, str] | None:
    n = sum(int(s.get(k) or 0) for k in ("allowusers", "allowgroups", "denyusers", "denygroups"))
    return (n > 0, "AllowUsers/AllowGroups/DenyUsers/DenyGroups: " + ("set" if n else "none set"))


def _algos(key: str, bad: Callable[[str], bool], what: str) -> Callable[[dict[str, Any]], tuple[bool, str] | None]:
    def t(s: dict[str, Any]) -> tuple[bool, str] | None:
        v = s.get(key)
        if not isinstance(v, str) or not v:
            return None
        weak = [a for a in v.split(",") if a and bad(a)]
        return (not weak, f"no weak {what} offered" if not weak else f"weak {what} offered: {', '.join(weak[:6])}")
    return t


def _banner(s: dict[str, Any]) -> tuple[bool, str] | None:
    v = s.get("banner")
    if v is None:
        return None
    return (str(v).lower() not in ("none", ""), "a login banner is set" if str(v).lower() != "none"
            else "no login banner")


def _loglevel(s: dict[str, Any]) -> tuple[bool, str] | None:
    v = s.get("loglevel")
    if not isinstance(v, str):
        return None
    return (v.upper() in ("INFO", "VERBOSE"), f"loglevel {v.upper()} (expected INFO or VERBOSE)")


def _sshd_fix(line: str) -> str:
    return (f"printf '%s\\n' '{line}' | sudo tee /etc/ssh/sshd_config.d/60-hardening.conf "
            "&& sudo sshd -t && sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd")


# --------------------------------------------------------------------------- login.defs / PAM
def _ldef(key: str, test: Callable[[str], bool], want: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        h = f.h()
        if (h.get("gaps") or {}).get("login_defs") == "missing":
            return Result(NA, "no /etc/login.defs", "this machine has no /etc/login.defs")
        v = (h.get("login_defs") or {}).get(key)
        if v is None:
            return Result(FAIL, f"{key} is not set in /etc/login.defs (expected {want})")
        if _unexpected(v):
            return Result(UNKNOWN, "", f"{key} has an unexpected value")
        return Result(PASS if test(str(v)) else FAIL, f"{key} {v} (expected {want})")
    return pred


def _num(fn: Callable[[int], bool]) -> Callable[[str], bool]:
    def t(v: str) -> bool:
        try:
            return fn(int(v, 8) if v.startswith("0") and len(v) > 1 else int(v))
        except ValueError:
            return False
    return t


def _umask_ok(v: str) -> bool:
    try:
        return int(v, 8) & 0o027 == 0o027
    except ValueError:
        return False


def _auth_stacks(f: Facts) -> list[str]:
    fam = f.family()
    return ["system-auth", "password-auth"] if fam == "rhel" else ["common-auth"]


def _pam_lines(f: Facts, stacks: list[str]) -> tuple[list[dict[str, Any]] | None, str]:
    pam = f.h().get("pam") or {}
    out: list[dict[str, Any]] = []
    for s in stacks:
        st = pam.get(s)
        if st is None:
            return None, f"the PAM stack {s} wasn't in the read"
        if st.get("state") == "unreadable":
            return None, f"the PAM stack {s} couldn't be read"
        out += st.get("lines") or []
    return out, ""


def _pam_no_nullok(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if f.family() == "alpine":
        return Result(NA, "Alpine", "this check reads the Debian/RHEL PAM stacks")
    lines, why = _pam_lines(f, _auth_stacks(f) + (["common-password"] if f.family() == "debian" else []))
    if lines is None:
        return Result(UNKNOWN, "", why)
    bad = [ln for ln in lines if ln.get("module") == "pam_unix.so" and
           ({"nullok", "nullok_secure"} & set(ln.get("args") or []))]
    return Result(FAIL if bad else PASS, "pam_unix allows empty passwords (nullok)" if bad else
                  "pam_unix doesn't allow empty passwords")


def _pam_faillock(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if f.family() == "alpine":
        return Result(NA, "Alpine", "this check reads the Debian/RHEL PAM stacks")
    lines, why = _pam_lines(f, _auth_stacks(f))
    if lines is None:
        return Result(UNKNOWN, "", why)
    lock = [ln for ln in lines if ln.get("module") in ("pam_faillock.so", "pam_tally2.so")]
    if not lock:
        return Result(FAIL, "no failed-login lockout (pam_faillock) in the login stack")
    deny = None
    for ln in lock:
        for a in ln.get("args") or []:
            if a.startswith("deny="):
                deny = int(a.split("=", 1)[1])
    if deny is None:
        v = (f.h().get("sec") or {}).get("faillock", {}).get("deny")
        deny = int(v) if v and str(v).lstrip("-").isdigit() else 3     # pam_faillock's built-in default is 3
    return Result(PASS if 0 < deny <= 5 else FAIL, f"lockout after {deny} failed logins (expected 1-5)")


def _pam_pwquality(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if f.family() == "alpine":
        return Result(NA, "Alpine", "this check reads the Debian/RHEL PAM stacks")
    stacks = ["system-auth", "password-auth"] if f.family() == "rhel" else ["common-password"]
    lines, why = _pam_lines(f, stacks)
    if lines is None:
        return Result(UNKNOWN, "", why)
    pq = [ln for ln in lines if ln.get("module") == "pam_pwquality.so"]
    if not pq:
        return Result(FAIL, "no password-quality check (pam_pwquality) when passwords are set")
    minlen = None
    for ln in pq:
        for a in ln.get("args") or []:
            if a.startswith("minlen="):
                minlen = int(a.split("=", 1)[1])
    if minlen is None:
        v = (f.h().get("sec") or {}).get("pwquality", {}).get("minlen")
        minlen = int(v) if v and str(v).isdigit() else 8          # pwquality's built-in default
    return Result(PASS if minlen >= 14 else FAIL, f"minimum password length {minlen} (expected at least 14)")


def _pam_hash(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if f.family() == "alpine":
        return Result(NA, "Alpine", "this check reads the Debian/RHEL PAM stacks")
    stacks = ["system-auth", "password-auth"] if f.family() == "rhel" else ["common-password"]
    lines, why = _pam_lines(f, stacks)
    if lines is None:
        return Result(UNKNOWN, "", why)
    unix = [ln for ln in lines if ln.get("module") == "pam_unix.so" and ln.get("type") == "password"]
    if not unix:
        return Result(UNKNOWN, "", "no pam_unix password line in the stack")
    algos = {a for ln in unix for a in ln.get("args") or [] if a in ("sha512", "yescrypt", "md5", "bigcrypt",
                                                                       "blowfish")}
    good = bool(algos & {"sha512", "yescrypt"}) and not (algos & {"md5", "bigcrypt"})
    return Result(PASS if good else FAIL, f"passwords are hashed with {', '.join(sorted(algos)) or 'the default'} "
                  "(expected sha512 or yescrypt)")


# --------------------------------------------------------------------------- audit, logs, time, MAC
def _audit_running(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if _in_container(f):
        return Result(NA, "a container", "auditd can't run inside a container; the host's audit covers it")
    a = f.h().get("audit") or {}
    gaps = f.h().get("gaps") or {}
    if "audit" in gaps:
        return Result(UNKNOWN, "", "auditd's status needs root: read this machine through its sub-agent, or add "
                      "'<login> ALL=(ALL) NOPASSWD: /usr/sbin/auditctl -s' from the setup checklist")
    if a.get("installed") is False:
        return Result(FAIL, "auditd is not installed")
    if int(a.get("enabled") or 0) >= 1 and int(a.get("pid") or 0) > 0:
        return Result(PASS, f"auditing is on (enabled {a.get('enabled')}, auditd running)")
    return Result(FAIL, f"auditing is off (enabled {a.get('enabled', '?')})")


_IDENTITY = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/security/opasswd")


def _audit_identity(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if _in_container(f):
        return Result(NA, "a container", "auditd can't run inside a container")
    a = f.h().get("audit") or {}
    gaps = f.h().get("gaps") or {}
    if "audit" in gaps or "audit_rules" in gaps:
        return Result(UNKNOWN, "", "auditd's rules need root: read this machine through its sub-agent, or add "
                      "'<login> ALL=(ALL) NOPASSWD: /usr/sbin/auditctl -l' from the setup checklist")
    if a.get("installed") is False or "rules" not in a:
        return Result(FAIL, "auditd is not running, so nothing is watched")
    missing = [p for p in _IDENTITY if p not in (a.get("watched") or [])]
    return Result(FAIL if missing else PASS, "changes to account files are audited" if not missing else
                  f"not watched for changes: {', '.join(missing)}")


def _audit_immutable(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if _in_container(f):
        return Result(NA, "a container", "auditd can't run inside a container")
    a = f.h().get("audit") or {}
    if "audit" in (f.h().get("gaps") or {}):
        return Result(UNKNOWN, "", "auditd's status needs root: read this machine through its sub-agent")
    if a.get("installed") is False or "enabled" not in a:
        return Result(FAIL, "auditd is not running")
    return Result(PASS if int(a["enabled"]) == 2 else FAIL, f"audit rules {'are' if a['enabled'] == 2 else 'are not'}"
                  " locked until reboot (enabled 2)")


def _journald(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if f.h().get("init") == "openrc":
        return Result(NA, "no systemd", "this machine doesn't use systemd's journal")
    j = f.h().get("journald") or {}
    if not j:
        return Result(UNKNOWN, "", "journald's settings were not in the read")
    storage = str(j.get("storage") or "")
    if storage == "persistent" or (storage in ("", "auto") and j.get("var_log_journal") == "yes"):
        return Result(PASS, f"the journal is kept on disk (Storage={storage or 'auto'}, /var/log/journal exists)")
    if storage == "unexpected":
        return Result(UNKNOWN, "", "journald's Storage= has an unexpected value")
    return Result(FAIL, f"the journal is not kept across reboots (Storage={storage or 'auto'}, no /var/log/journal)")


def _time_sync(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if _in_container(f):
        return Result(NA, "a container", "the clock belongs to the host, not this container")
    t = f.h().get("time") or {}
    if t.get("NTPSynchronized") == "yes" or t.get("chrony_leap") == "Normal":
        return Result(PASS, "the clock is synchronised")
    init, units = _units(f, ("chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd", "ntpsec"))
    active = [u["name"] for u in units if u.get("load") == "loaded" and u.get("active") == "active"]
    if t.get("NTPSynchronized") == "no" or t.get("chrony_leap") in ("Not synchronised", "Unsynchronised"):
        return Result(FAIL, "the clock is not synchronised" + (f" ({', '.join(active)} running)" if active else ""))
    if active:
        return Result(UNKNOWN, "", f"{', '.join(active)} is running but Kratos couldn't read whether it is in sync")
    if init == "unknown":
        return Result(UNKNOWN, "", "Kratos couldn't read the time services")
    return Result(FAIL, "no time synchronisation service is running")


def _apparmor(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    if _in_container(f):
        return Result(NA, "a container", "AppArmor is the host's")
    mac = f.h().get("mac") or {}
    if "apparmor_enabled" not in mac:
        return Result(FAIL, "AppArmor is not available in this kernel")
    if not mac["apparmor_enabled"]:
        return Result(FAIL, "AppArmor is turned off")
    n = mac.get("apparmor_profiles")
    return Result(PASS, "AppArmor is on" + (f" ({n} profiles, {mac.get('apparmor_enforce')} enforcing)"
                                             if n is not None else ""))


def _selinux(enforcing: bool) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        gap = _hard_gap(f)
        if gap:
            return gap
        mac = f.h().get("mac") or {}
        mode = mac.get("selinux_mode")
        if mode is None:
            return Result(UNKNOWN, "", "SELinux's mode couldn't be read (getenforce)")
        ok = mode == "enforcing" if enforcing else mode != "disabled"
        return Result(PASS if ok else FAIL, f"SELinux is {mode}")
    return pred


# --------------------------------------------------------------------------- firewall
def _fw(f: Facts) -> dict[str, Any]:
    return f.h().get("firewall") or {}


def _firewall_default_deny(f: Facts) -> Result:
    gap = _hard_gap(f)
    ca = f.get("config_audit")
    row = (ca.data.get("firewall") if ca else None) or {}
    if gap:
        if str(row.get("status")) == "FAIL":
            return Result(FAIL, "the config audit found no active firewall")
        return gap
    fw = _fw(f)
    deny = {"drop", "reject", "deny"}
    reasons = []
    if fw.get("ufw_enabled", "").lower() == "yes" and fw.get("ufw_input_policy", "").lower() in deny:
        return Result(PASS, f"ufw is on with incoming traffic denied by default ({fw['ufw_input_policy']})")
    nft = [p.lower() for p in fw.get("nft_input_policies") or []]
    if nft and any(p in deny for p in nft):
        return Result(PASS, "an nftables input chain drops by default")
    if str(fw.get("iptables_input", "")).lower() in deny:
        return Result(PASS, f"iptables' INPUT chain drops by default ({fw['iptables_input']})")
    _init, units = _units(f, ("firewalld",))
    if any(u.get("active") == "active" for u in units if u.get("load") == "loaded"):
        zone = fw.get("firewalld_zone", "")
        if zone.lower() in ("trusted",):
            return Result(FAIL, "firewalld is on but its default zone accepts everything (trusted)")
        return Result(PASS, f"firewalld is on (default zone {zone or 'public'})")
    readable = fw.get("nft_read") == "ok" or "iptables_input" in fw
    if fw.get("ufw_enabled", "").lower() == "no":
        reasons.append("ufw is off")
    if readable:
        reasons.append("no input chain drops by default")
        return Result(FAIL, "no firewall denies incoming traffic by default (" + "; ".join(reasons) + ")")
    if str(row.get("status")) == "FAIL":
        return Result(FAIL, "the config audit found no active firewall")
    return Result(UNKNOWN, "", "the firewall rules need root to read: read this machine through its sub-agent, or "
                  "add the 'nft list ruleset' / 'iptables -L -n' lines from the setup checklist")


def _ufw_enabled(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    fw = _fw(f)
    if "ufw_enabled" not in fw:
        return Result(NA, "ufw is not installed", "this machine doesn't use ufw")
    on = fw["ufw_enabled"].lower() == "yes"
    return Result(PASS if on else FAIL, f"ufw is {'on' if on else 'off'}")


def _nft_default_deny(f: Facts) -> Result:
    gap = _hard_gap(f)
    if gap:
        return gap
    fw = _fw(f)
    if fw.get("ufw_enabled", "").lower() == "yes":
        return Result(NA, "ufw is this machine's firewall", "this machine's firewall is ufw, not nftables directly")
    if fw.get("nft_read") != "ok":
        return Result(UNKNOWN, "", "nftables' rules need root to read: read this machine through its sub-agent")
    pols = [p.lower() for p in fw.get("nft_input_policies") or []]
    if not pols:
        return Result(FAIL, "nftables has no input chain")
    return Result(PASS if all(p == "drop" for p in pols) else FAIL, f"nftables input policies: {', '.join(pols)}")


# --------------------------------------------------------------------------- reused reads
def _fresh_snapshot(f: Facts, name: str) -> Any:
    src = f.get(name)
    return src.data if src is not None else None


def _signal_rules(doc: Any) -> set[str]:
    return {str(s.get("rule")) for s in (doc or {}).get("signals") or [] if isinstance(s, dict)}


def _no_rule(source: str, rule: str, ok: str, bad: str, need_complete: bool = True) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        src = f.get(source)
        if src is None:
            return Result(UNKNOWN, "", f"Kratos has no recent {src_label(source)} of this machine")
        if rule in _signal_rules(src.data):
            return Result(FAIL, bad)
        if need_complete and not src.complete:
            return Result(UNKNOWN, "", f"the {src_label(source)} was incomplete")
        return Result(PASS, ok)
    return pred


def src_label(name: str) -> str:
    from kratos.compliance.facts import SOURCES
    return SOURCES.get(name, name)


def _kev(f: Facts) -> Result:
    src = f.get("packages")
    if src is None:
        return Result(UNKNOWN, "", "Kratos has no recent package read of this machine")
    act = [str(x) for x in src.data.get("act_now_packages") or []]
    if act:
        return Result(FAIL, f"packages with known-exploited vulnerabilities and a fix: {', '.join(act[:5])}")
    if src.data.get("index_built_at") is None and not src.data.get("selector"):
        return Result(UNKNOWN, "", "no vulnerability data for this system")
    if not src.complete:
        return Result(UNKNOWN, "", "the package read was incomplete (see PKG-004)")
    return Result(PASS, "no installed package has a known-exploited vulnerability with a fix")


def _config_row(name: str, ok: str, bad: str) -> Callable[[Facts], Result]:
    def pred(f: Facts) -> Result:
        src = f.get("config_audit")
        if src is None:
            return Result(UNKNOWN, "", "Kratos has no recent config audit of this machine")
        row = src.data.get(name)
        if not isinstance(row, dict):
            return Result(UNKNOWN, "", f"the config audit didn't report {name}")
        st = str(row.get("status") or "").upper()
        detail = str(row.get("detail") or "")[:200]
        if st == "PASS":
            return Result(PASS, ok)
        if st == "FAIL":
            return Result(FAIL, bad + (f" ({detail})" if detail else ""))
        return Result(UNKNOWN, "", detail or f"the config audit couldn't tell ({st or 'no status'})")
    return pred


def _uid0(f: Facts) -> Result:
    src = f.get("privileged")
    if src is None:
        return Result(UNKNOWN, "", "Kratos has no recent privileged-accounts read of this machine")
    accts = src.data.get("accounts") or {}
    zero = sorted(str(a.get("user")) for a in accts.values() if isinstance(a, dict) and a.get("uid") == 0)
    if not zero:
        return Result(UNKNOWN, "", "the privileged-accounts read listed no UID 0 account")
    return Result(PASS if zero == ["root"] else FAIL, "only root has UID 0" if zero == ["root"] else
                  f"accounts with UID 0: {', '.join(zero)}")


def _sealing(f: Facts) -> Result:
    src = f.get("log_integrity")
    if src is None:
        return Result(UNKNOWN, "", "Kratos has no recent log-integrity check of this machine")
    seal = src.data.get("seal")
    if not seal:
        return Result(FAIL, "journal sealing isn't set up for this machine in Kratos")
    st = str((seal or {}).get("status") or "")
    return Result(PASS if st in ("ok", "verified", "sealed") else FAIL, f"journal sealing: {st or 'set up'}")


# --------------------------------------------------------------------------- the table
_NET_ISO, _NET_NIS = ("8.20", "8.9"), ("6.7", "6.3", "21(2)(e)")
_KERN_ISO, _KERN_NIS = ("8.9",), ("6.3", "21(2)(e)")
_FILE_ISO, _FILE_NIS = ("8.3", "8.9"), ("6.3", "11")
_SVC_ISO, _SVC_NIS = ("8.21", "8.9"), ("6.3", "6.7")
_AUTH_ISO, _AUTH_NIS = ("8.5", "5.17"), ("11.6", "21(2)(i)")
_SSH_ISO, _SSH_NIS = ("8.5", "8.21"), ("11.6", "6.7", "21(2)(i)")
_CRYPTO_ISO, _CRYPTO_NIS = ("8.24",), ("9", "21(2)(h)")
_LOG_ISO, _LOG_NIS = ("8.15", "8.16"), ("3.2", "21(2)(b)")
_PATCH_ISO, _PATCH_NIS = ("8.8",), ("6.6", "6.10", "21(2)(e)")
# login.defs and the PAM stacks Kratos reads are the shadow-utils / Linux-PAM setup of Debian and RHEL.
_SHADOW_FAMILIES = ("debian", "rhel")

_SYSCTLS: tuple[tuple[str, tuple[int, ...], str, int, bool], ...] = (
    # key, ok values, expected (words), fix value, network?
    ("kernel.randomize_va_space", (2,), "2", 2, False),
    ("kernel.yama.ptrace_scope", (1, 2, 3), "1 or more", 1, False),
    ("kernel.kptr_restrict", (1, 2), "1 or 2", 1, False),
    ("kernel.dmesg_restrict", (1,), "1", 1, False),
    ("fs.suid_dumpable", (0,), "0", 0, False),
    ("fs.protected_hardlinks", (1,), "1", 1, False),
    ("fs.protected_symlinks", (1,), "1", 1, False),
    ("net.ipv4.ip_forward", (0,), "0 (unless this machine routes traffic)", 0, True),
    ("net.ipv4.conf.all.accept_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.default.accept_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.all.secure_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.default.secure_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.all.send_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.default.send_redirects", (0,), "0", 0, True),
    ("net.ipv4.conf.all.accept_source_route", (0,), "0", 0, True),
    ("net.ipv4.conf.default.accept_source_route", (0,), "0", 0, True),
    ("net.ipv4.conf.all.rp_filter", (1,), "1", 1, True),
    ("net.ipv4.conf.default.rp_filter", (1,), "1", 1, True),
    ("net.ipv4.conf.all.log_martians", (1,), "1", 1, True),
    ("net.ipv4.conf.default.log_martians", (1,), "1", 1, True),
    ("net.ipv4.icmp_echo_ignore_broadcasts", (1,), "1", 1, True),
    ("net.ipv4.icmp_ignore_bogus_error_responses", (1,), "1", 1, True),
    ("net.ipv4.tcp_syncookies", (1,), "1", 1, True),
    ("net.ipv6.conf.all.forwarding", (0,), "0 (unless this machine routes traffic)", 0, True),
    ("net.ipv6.conf.all.accept_ra", (0,), "0", 0, True),
    ("net.ipv6.conf.default.accept_ra", (0,), "0", 0, True),
    ("net.ipv6.conf.all.accept_redirects", (0,), "0", 0, True),
    ("net.ipv6.conf.default.accept_redirects", (0,), "0", 0, True),
    ("net.ipv6.conf.all.accept_source_route", (0,), "0", 0, True),
    ("net.ipv6.conf.default.accept_source_route", (0,), "0", 0, True),
)

_PERMS: tuple[tuple[str, int, tuple[str, ...], tuple[str, ...], str, bool], ...] = (
    # path, max mode, owners, groups, CaC rule stem, optional
    ("/etc/passwd", 0o644, ("root",), ("root",), "etc_passwd", False),
    ("/etc/group", 0o644, ("root",), ("root",), "etc_group", False),
    ("/etc/shadow", 0o640, ("root",), ("root", "shadow"), "etc_shadow", False),
    ("/etc/gshadow", 0o640, ("root",), ("root", "shadow"), "etc_gshadow", True),
    ("/etc/ssh/sshd_config", 0o600, ("root",), ("root",), "sshd_config", True),
    ("/etc/crontab", 0o600, ("root",), ("root",), "crontab", True),
    ("/etc/cron.hourly", 0o700, ("root",), ("root",), "cron_hourly", True),
    ("/etc/cron.daily", 0o700, ("root",), ("root",), "cron_daily", True),
    ("/etc/cron.weekly", 0o700, ("root",), ("root",), "cron_weekly", True),
    ("/etc/cron.monthly", 0o700, ("root",), ("root",), "cron_monthly", True),
    ("/etc/cron.d", 0o700, ("root",), ("root",), "cron_d", True),
    ("/etc/cron.allow", 0o640, ("root",), ("root", "crontab"), "cron_allow", True),
    ("/etc/issue", 0o644, ("root",), ("root",), "etc_issue", True),
    ("/etc/issue.net", 0o644, ("root",), ("root",), "etc_issue_net", True),
)

_MOUNTS = (("/tmp", "tmp"), ("/var/tmp", "var_tmp"), ("/dev/shm", "dev_shm"), ("/home", "home"))
_MOUNT_OPTS = {"/tmp": ("nodev", "nosuid", "noexec"), "/var/tmp": ("nodev", "nosuid", "noexec"),
               "/dev/shm": ("nodev", "nosuid", "noexec"), "/home": ("nodev", "nosuid")}

_SERVICES_OFF: tuple[tuple[str, tuple[str, ...], str, tuple[str, ...]], ...] = (
    # check id stem, units, label, CaC rules
    ("avahi", ("avahi-daemon",), "Avahi (mDNS)", ("service_avahi-daemon_disabled",)),
    ("cups", ("cups",), "CUPS printing", ("service_cups_disabled",)),
    ("nfs", ("nfs-server",), "the NFS server", ("service_nfs_disabled",)),
    ("rpcbind", ("rpcbind",), "rpcbind", ("service_rpcbind_disabled",)),
    ("xinetd", ("xinetd",), "xinetd", ("service_xinetd_disabled",)),
    ("vsftpd", ("vsftpd",), "the vsftpd FTP server", ("service_vsftpd_disabled",)),
    ("tftp", ("tftpd-hpa", "tftp.socket"), "a TFTP server", ("service_tftp_disabled",)),
    ("snmpd", ("snmpd",), "the SNMP agent", ("service_snmpd_disabled",)),
    ("rsync", ("rsync",), "the rsync daemon", ("service_rsyncd_disabled",)),
    ("slapd", ("slapd",), "the LDAP server", ("service_slapd_disabled",)),
    ("named", ("named", "bind9"), "the DNS server (BIND)", ("service_named_disabled",)),
    ("dnsmasq", ("dnsmasq",), "dnsmasq", ("service_dnsmasq_disabled",)),
    ("samba", ("smbd", "smb"), "the Samba server", ("service_smb_disabled",)),
    ("squid", ("squid",), "the Squid proxy", ("service_squid_disabled",)),
    ("dovecot", ("dovecot",), "the Dovecot mail server", ("service_dovecot_disabled",)),
    ("autofs", ("autofs",), "autofs", ("service_autofs_disabled",)),
    ("bluetooth", ("bluetooth",), "Bluetooth", ("service_bluetooth_disabled",)),
    ("ypserv", ("ypserv",), "the NIS server", ("service_ypserv_disabled",)),
    ("dhcpd", ("isc-dhcp-server", "dhcpd"), "a DHCP server", ("service_dhcpd_disabled",)),
    ("apport", ("apport",), "apport crash reporting", ("service_apport_disabled",)),
    ("telnet", ("telnet.socket",), "a telnet server", ()),
    ("rsh", ("rsh.socket", "rlogin.socket"), "an rsh/rlogin server", ()),
)

_PACKAGES_OFF: tuple[tuple[str, tuple[str, ...], str, tuple[str, ...]], ...] = (
    ("telnet_client", ("telnet", "inetutils-telnet"), "the telnet client", ("package_telnet_removed",)),
    ("rsh_client", ("rsh-client", "rsh-redone-client", "rsh"), "the rsh client", ("package_rsh_removed",)),
    ("nis_client", ("nis", "ypbind"), "the NIS client", ("package_nis_removed",)),
    ("talk_client", ("talk",), "the talk client", ("package_talk_removed",)),
    ("xinetd_pkg", ("xinetd",), "xinetd", ("package_xinetd_removed",)),
    ("tftp_server_pkg", ("tftpd-hpa", "tftp-server", "atftpd"), "a TFTP server", ("package_tftp-server_removed",)),
    ("avahi_pkg", ("avahi-daemon", "avahi"), "Avahi", ("package_avahi_removed",)),
)


def _build() -> tuple[Check, ...]:
    out: list[Check] = []
    for key, ok, want, fixv, net in _SYSCTLS:
        out.append(Check(
            id="sysctl." + key, family="kernel network settings" if net else "kernel settings",
            text=f"the kernel setting {key} is {want}", facts=("hardening",), predicate=_sysctl(key, ok, want),
            fix=_sysctl_fix(key, fixv), cac_rules=("sysctl_" + key.replace(".", "_"),),
            iso=_NET_ISO if net else _KERN_ISO, nis2=_NET_NIS if net else _KERN_NIS))
    for path, mode, users, groups, stem, optional in _PERMS:
        out.append(Check(
            id="perm." + path, family="file permissions",
            text=f"{path} is owned by {users[0]}:{'/'.join(groups)} with mode {mode:o} or stricter",
            facts=("hardening",), predicate=_perm(path, mode, users, groups, optional),
            fix=_perm_fix(path, mode, users[0], groups[0]),
            cac_rules=(f"file_permissions_{stem}", f"file_owner_{stem}", f"file_groupowner_{stem}"),
            iso=_FILE_ISO, nis2=_FILE_NIS))
    out.append(Check(
        id="perm./etc/sudoers", family="file permissions", text="/etc/sudoers is owned by root:root, mode 440",
        facts=("hardening",), predicate=_perm("/etc/sudoers", 0o440, ("root",), ("root",)),
        fix=_perm_fix("/etc/sudoers", 0o440, "root", "root"), iso=("8.2", "8.9"), nis2=("11.3",)))
    for point, stem in _MOUNTS:
        for opt in _MOUNT_OPTS[point]:
            out.append(Check(
                id=f"mount.{point}.{opt}", family="mount options", text=f"{point} is mounted {opt}",
                facts=("hardening",), predicate=_mount(point, opt), fix=_mount_fix(point, opt),
                cac_rules=(f"mount_option_{stem}_{opt}",), iso=("8.9",), nis2=("6.3",)))
    for mod in ("cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "squashfs", "udf", "usb-storage", "dccp", "sctp",
                "rds", "tipc"):
        out.append(Check(
            id=f"module.{mod}", family="kernel modules", text=f"the {mod} kernel module can't be loaded",
            facts=("hardening",), predicate=_module(mod), fix=_module_fix(mod),
            cac_rules=(f"kernel_module_{mod}_disabled",), iso=("8.9",) + (("7.10",) if mod == "usb-storage" else ()),
            nis2=("6.3",)))
    for stem, units, label, rules in _SERVICES_OFF:
        out.append(Check(
            id=f"service.{stem}.off", family="services", text=f"{label} is not running",
            facts=("hardening",), predicate=_svc_off(units, label), fix=_svc_off_fix(units),
            cac_rules=rules, iso=_SVC_ISO, nis2=_SVC_NIS))
    for stem, names, label, rules in _PACKAGES_OFF:
        out.append(Check(
            id=f"package.{stem}.absent", family="installed software", text=f"{label} is not installed",
            facts=("inventory",), predicate=_pkg(names, False, label), fix=_pkg_remove_fix(names),
            cac_rules=rules, iso=("8.19", "8.21"), nis2=("6.3",)))
    out += [
        Check("package.sudo.present", "installed software", "sudo is installed (so admin work is logged per person)",
              ("inventory",), _pkg(("sudo",), True, "sudo"), "sudo apt install sudo   # or: sudo dnf install sudo",
              ("package_sudo_installed",), ("8.2",), ("11.3",)),
        Check("package.aide.present", "installed software", "a file-integrity tool (AIDE) is installed",
              ("inventory",), _pkg(("aide",), True, "AIDE"), "sudo apt install aide   # or: sudo dnf install aide",
              ("package_aide_installed",), ("8.9", "8.16"), ("6.9",)),
        # --- SSH server
        Check("sshd.root_login", "SSH server", "the SSH server refuses root logins (PermitRootLogin no)",
              ("hardening",), _sshd(_eq("permitrootlogin", "no")), _sshd_fix("PermitRootLogin no"),
              ("sshd_disable_root_login",), _SSH_ISO + ("8.2",), _SSH_NIS + ("11.3",), remote_access=True),
        Check("sshd.password_auth", "SSH server", "the SSH server doesn't accept passwords (keys only)",
              ("hardening",), _sshd(_eq("passwordauthentication", "no")), _sshd_fix("PasswordAuthentication no"),
              (), _SSH_ISO, _SSH_NIS, remote_access=True, linked_rules=("CORR-SSH-001", "CORR-SSH-002")),
        Check("sshd.empty_passwords", "SSH server", "the SSH server refuses empty passwords",
              ("hardening",), _sshd(_eq("permitemptypasswords", "no")), _sshd_fix("PermitEmptyPasswords no"),
              ("sshd_disable_empty_passwords",), _SSH_ISO, _SSH_NIS, remote_access=True),
        Check("sshd.max_auth_tries", "SSH server", "the SSH server allows at most 4 password tries per connection",
              ("hardening",), _sshd(_int_le("maxauthtries", 4, 1)), _sshd_fix("MaxAuthTries 4"),
              ("sshd_set_max_auth_tries",), _SSH_ISO, _SSH_NIS),
        Check("sshd.loglevel", "SSH server", "the SSH server logs at INFO or VERBOSE",
              ("hardening",), _sshd(_loglevel), _sshd_fix("LogLevel VERBOSE"),
              ("sshd_set_loglevel_info", "sshd_set_loglevel_verbose"), _LOG_ISO, _LOG_NIS),
        Check("sshd.ignore_rhosts", "SSH server", "the SSH server ignores .rhosts files",
              ("hardening",), _sshd(_eq("ignorerhosts", "yes")), _sshd_fix("IgnoreRhosts yes"),
              ("sshd_disable_rhosts",), _SSH_ISO, _SSH_NIS),
        Check("sshd.hostbased", "SSH server", "the SSH server refuses host-based logins",
              ("hardening",), _sshd(_eq("hostbasedauthentication", "no")), _sshd_fix("HostbasedAuthentication no"),
              ("disable_host_auth",), _SSH_ISO, _SSH_NIS),
        Check("sshd.user_env", "SSH server", "the SSH server doesn't let users set its environment",
              ("hardening",), _sshd(_eq("permituserenvironment", "no")), _sshd_fix("PermitUserEnvironment no"),
              ("sshd_do_not_permit_user_env",), _SSH_ISO, _SSH_NIS),
        Check("sshd.use_pam", "SSH server", "the SSH server uses PAM (so lockouts and account rules apply)",
              ("hardening",), _sshd(_eq("usepam", "yes", absent="na")), _sshd_fix("UsePAM yes"),
              ("sshd_enable_pam",), _AUTH_ISO, _AUTH_NIS),
        Check("sshd.banner", "SSH server", "the SSH server shows a login banner",
              ("hardening",), _sshd(_banner), _sshd_fix("Banner /etc/issue.net"),
              ("sshd_enable_warning_banner_net",), ("8.5",), ("11.6",)),
        Check("sshd.idle_timeout", "SSH server", "idle SSH sessions are checked and closed",
              ("hardening",), _sshd(_idle), _sshd_fix("ClientAliveInterval 15") + "  # and: ClientAliveCountMax 3",
              ("sshd_set_idle_timeout", "sshd_set_keepalive"), _SSH_ISO, _SSH_NIS),
        Check("sshd.login_grace", "SSH server", "an unauthenticated SSH connection is dropped within 60 seconds",
              ("hardening",), _sshd(_int_le("logingracetime", 60, 1)), _sshd_fix("LoginGraceTime 60"),
              ("sshd_set_login_grace_time",), _SSH_ISO, _SSH_NIS),
        Check("sshd.maxstartups", "SSH server", "the SSH server limits unauthenticated connections (10:30:60)",
              ("hardening",), _sshd(_maxstartups), _sshd_fix("MaxStartups 10:30:60"),
              ("sshd_set_maxstartups",), _SSH_ISO, _SSH_NIS),
        Check("sshd.max_sessions", "SSH server", "at most 10 sessions per SSH connection",
              ("hardening",), _sshd(_int_le("maxsessions", 10, 1)), _sshd_fix("MaxSessions 10"),
              ("sshd_set_max_sessions",), _SSH_ISO, _SSH_NIS),
        Check("sshd.forwarding", "SSH server", "SSH forwarding (ports, X11, agent) is off",
              ("hardening",), _sshd(_eq("disableforwarding", "yes")), _sshd_fix("DisableForwarding yes"),
              ("sshd_disable_forwarding",), _SSH_ISO, _SSH_NIS),
        Check("sshd.gssapi", "SSH server", "the SSH server doesn't use GSSAPI logins",
              ("hardening",), _sshd(_eq("gssapiauthentication", "no", absent="pass")), _sshd_fix("GSSAPIAuthentication no"),
              ("sshd_disable_gssapi_auth",), _SSH_ISO, _SSH_NIS),
        Check("sshd.limit_users", "SSH server", "SSH logins are limited to listed users or groups",
              ("hardening",), _sshd(_limit_users), _sshd_fix("AllowGroups <your-ssh-group>"),
              ("sshd_limit_user_access",), _SSH_ISO + ("8.2",), _SSH_NIS + ("11.2",)),
        Check("sshd.ciphers", "SSH server", "the SSH server offers no weak ciphers",
              ("hardening",), _sshd(_algos("ciphers", lambda a: a in _WEAK_CIPHERS or a.endswith("-cbc"), "ciphers")),
              _sshd_fix("Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc"),
              ("sshd_use_strong_ciphers",), _CRYPTO_ISO, _CRYPTO_NIS),
        Check("sshd.macs", "SSH server", "the SSH server offers no weak MACs",
              ("hardening",), _sshd(_algos("macs", lambda a: a.startswith(_WEAK_MACS_PREFIX) or "-96" in a, "MACs")),
              _sshd_fix("MACs -hmac-md5*,hmac-sha1*,umac-64*"),
              ("sshd_use_strong_macs",), _CRYPTO_ISO, _CRYPTO_NIS),
        Check("sshd.kex", "SSH server", "the SSH server offers no weak key exchanges",
              ("hardening",), _sshd(_algos("kexalgorithms", lambda a: a in _WEAK_KEX, "key exchanges")),
              _sshd_fix("KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
                        "diffie-hellman-group-exchange-sha1"),
              ("sshd_use_strong_kex",), _CRYPTO_ISO, _CRYPTO_NIS),
        # --- passwords and PAM
        Check("logindefs.pass_max_days", "passwords", "passwords expire within 365 days (PASS_MAX_DAYS)",
              ("hardening",), _ldef("PASS_MAX_DAYS", _num(lambda n: 0 < n <= 365), "1-365"),
              "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs",
              ("accounts_maximum_age_login_defs",), _AUTH_ISO, _AUTH_NIS, os_families=_SHADOW_FAMILIES),
        Check("logindefs.pass_min_days", "passwords", "passwords can't be changed again within a day (PASS_MIN_DAYS)",
              ("hardening",), _ldef("PASS_MIN_DAYS", _num(lambda n: n >= 1), "1 or more"),
              "sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs",
              ("accounts_minimum_age_login_defs",), _AUTH_ISO, _AUTH_NIS, os_families=_SHADOW_FAMILIES),
        Check("logindefs.pass_warn_age", "passwords", "users are warned 7 days before a password expires",
              ("hardening",), _ldef("PASS_WARN_AGE", _num(lambda n: n >= 7), "7 or more"),
              "sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs",
              ("accounts_password_warn_age_login_defs",), _AUTH_ISO, _AUTH_NIS, os_families=_SHADOW_FAMILIES),
        Check("logindefs.encrypt_method", "passwords", "new passwords are hashed with SHA512 or yescrypt",
              ("hardening",), _ldef("ENCRYPT_METHOD", lambda v: v.upper() in ("SHA512", "YESCRYPT"),
                                    "SHA512 or YESCRYPT"),
              "sudo sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs",
              ("set_password_hashing_algorithm_logindefs",), _CRYPTO_ISO + ("8.5",), _CRYPTO_NIS + ("11.6",),
              os_families=_SHADOW_FAMILIES),
        Check("logindefs.umask", "passwords", "new files are not readable by others by default (UMASK 027)",
              ("hardening",), _ldef("UMASK", _umask_ok, "027 or stricter"),
              "sudo sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs",
              ("accounts_umask_etc_login_defs",), ("8.3", "8.9"), ("6.3",), os_families=_SHADOW_FAMILIES),
        Check("pam.no_nullok", "passwords", "PAM doesn't accept empty passwords (no nullok)",
              ("hardening",), _pam_no_nullok,
              "remove 'nullok' from the pam_unix lines (Debian/Ubuntu: sudo pam-auth-update; RHEL: authselect)",
              ("no_empty_passwords_unix", "no_empty_passwords"), _AUTH_ISO, _AUTH_NIS, remote_access=False),
        Check("pam.faillock", "passwords", "accounts lock after at most 5 failed logins",
              ("hardening",), _pam_faillock,
              "enable pam_faillock (Ubuntu: sudo pam-auth-update --enable faillock; RHEL: sudo authselect "
              "enable-feature with-faillock) and set deny = 5 in /etc/security/faillock.conf",
              ("accounts_passwords_pam_faillock_deny",), _AUTH_ISO, _AUTH_NIS),
        Check("pam.pwquality", "passwords", "new passwords must be at least 14 characters",
              ("hardening",), _pam_pwquality,
              "install libpam-pwquality (RHEL: it is the default) and set minlen = 14 in /etc/security/pwquality.conf",
              ("accounts_password_pam_minlen",), _AUTH_ISO, _AUTH_NIS),
        Check("pam.hashing", "passwords", "PAM hashes passwords with sha512 or yescrypt",
              ("hardening",), _pam_hash, "add 'yescrypt' (or 'sha512') to the pam_unix password line",
              ("set_password_hashing_algorithm_systemauth", "set_password_hashing_algorithm_passwordauth"),
              _CRYPTO_ISO, _CRYPTO_NIS),
        # --- logging, audit, time, MAC
        Check("auditd.running", "audit and logs", "auditd is running and auditing is on",
              ("hardening",), _audit_running, "sudo apt install auditd && sudo systemctl enable --now auditd",
              ("service_auditd_enabled",), _LOG_ISO, _LOG_NIS),
        Check("auditd.identity_rules", "audit and logs", "changes to account files are audited",
              ("hardening",), _audit_identity,
              "printf '%s\\n' '-w /etc/passwd -p wa -k identity' '-w /etc/group -p wa -k identity' "
              "'-w /etc/shadow -p wa -k identity' '-w /etc/gshadow -p wa -k identity' "
              "'-w /etc/security/opasswd -p wa -k identity' | sudo tee /etc/audit/rules.d/50-identity.rules "
              "&& sudo augenrules --load",
              ("audit_rules_usergroup_modification_passwd", "audit_rules_usergroup_modification_group",
               "audit_rules_usergroup_modification_shadow", "audit_rules_usergroup_modification_gshadow",
               "audit_rules_usergroup_modification_opasswd"), _LOG_ISO, _LOG_NIS),
        Check("auditd.immutable", "audit and logs", "audit rules are locked until the next reboot (-e 2)",
              ("hardening",), _audit_immutable,
              "printf '%s\\n' '-e 2' | sudo tee /etc/audit/rules.d/99-finalize.rules && sudo augenrules --load",
              ("audit_rules_immutable",), _LOG_ISO, _LOG_NIS),
        Check("journald.persistent", "audit and logs", "the system journal is kept on disk across reboots",
              ("hardening",), _journald,
              "sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal "
              "&& sudo systemctl restart systemd-journald",
              ("journald_storage",), _LOG_ISO, _LOG_NIS),
        Check("time.synchronised", "time", "the clock is synchronised with a time source",
              ("hardening",), _time_sync,
              "sudo timedatectl set-ntp true   # or install and enable chrony",
              (), ("8.17",), ("3.2",)),
        Check("mac.apparmor", "access control", "AppArmor is enabled", ("hardening",), _apparmor,
              "sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor",
              ("grub2_enable_apparmor",), ("8.9", "8.7"), ("6.3", "6.9"), os_families=("debian",)),
        Check("mac.selinux_on", "access control", "SELinux is not disabled", ("hardening",), _selinux(False),
              "set SELINUX=enforcing in /etc/selinux/config and reboot (relabel first if it was disabled)",
              ("selinux_not_disabled",), ("8.9", "8.7"), ("6.3", "6.9"), os_families=("rhel",)),
        Check("mac.selinux_enforcing", "access control", "SELinux is enforcing", ("hardening",), _selinux(True),
              "sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
              ("selinux_state",), ("8.9", "8.7"), ("6.3", "6.9"), os_families=("rhel",)),
        # --- firewall
        Check("firewall.default_deny", "firewall", "a firewall denies incoming traffic by default",
              ("hardening", "config_audit"), _firewall_default_deny,
              "Ubuntu/Debian: sudo ufw allow OpenSSH && sudo ufw default deny incoming && sudo ufw enable ; "
              "RHEL family: sudo systemctl enable --now firewalld",
              (), ("8.20",), ("6.7", "21(2)(e)"), remote_access=True, linked_rules=("CONT-004",)),
        Check("firewall.ufw_enabled", "firewall", "ufw is enabled", ("hardening",), _ufw_enabled,
              "sudo ufw allow OpenSSH && sudo ufw enable", ("service_ufw_enabled",), ("8.20",), ("6.7",),
              os_families=("debian",)),
        Check("firewall.nft_default_deny", "firewall", "nftables' input chains drop by default",
              ("hardening",), _nft_default_deny, "set 'policy drop;' on your nftables input chain (keep SSH allowed)",
              ("nftables_ensure_default_deny_policy",), ("8.20",), ("6.7",), os_families=("debian",)),
        Check("firewall.firewalld_enabled", "firewall", "firewalld is enabled and running", ("hardening",),
              _svc_on(("firewalld",), "firewalld"), "sudo systemctl enable --now firewalld",
              ("service_firewalld_enabled",), ("8.20",), ("6.7",), os_families=("rhel",)),
        # --- reused reads
        Check("accounts.uid0_only_root", "accounts", "only root has UID 0", ("privileged",), _uid0,
              "give the extra UID 0 account its own UID (sudo usermod -u <new-uid> <account>) or remove it",
              ("accounts_no_uid_except_zero",), ("8.2",), ("11.3", "21(2)(i)")),
        Check("persistence.no_unowned_setuid", "programs", "no setuid/setgid program that no package installed",
              ("persistence",), _no_rule("persistence", "PERSIST-003", "no setuid program from outside the packages",
                                         "a setuid/setgid program no package installed (see PERSIST-003)"),
              "see PERSIST-003 for the file and what to do", (), ("8.18", "8.7"), ("6.9",),
              linked_rules=("PERSIST-003",)),
        Check("persistence.no_ld_preload", "programs", "nothing forces every program to load a library "
              "(/etc/ld.so.preload)", ("persistence",),
              _no_rule("persistence", "PERSIST-004", "no /etc/ld.so.preload entries",
                       "every program loads an extra library (see PERSIST-004)"),
              "see PERSIST-004", (), ("8.7",), ("6.9",), linked_rules=("PERSIST-004",)),
        Check("packages.no_kev", "updates", "no installed package has a known-exploited vulnerability with a fix",
              ("packages",), _kev, "see PKG-001 for the packages and the upgrade command", (), _PATCH_ISO,
              _PATCH_NIS, linked_rules=("PKG-001",)),
        Check("packages.no_pending_reboot", "updates", "the running kernel is the newest installed one",
              ("packages",), _no_rule("packages", "PKG-003", "no reboot pending for a newer kernel",
                                      "a newer kernel is installed than the one running (see PKG-003)",
                                      need_complete=False),
              "reboot the machine at a convenient time (see PKG-003)", (), _PATCH_ISO, _PATCH_NIS,
              linked_rules=("PKG-003",), trust_incomplete=True),
        Check("updates.automatic", "updates", "security updates are installed automatically", ("config_audit",),
              _config_row("unattended_upgrades", "automatic security updates are on",
                          "automatic security updates are off"),
              "Ubuntu/Debian: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
              (), _PATCH_ISO, _PATCH_NIS),
        Check("files.no_world_writable_etc", "file permissions", "nothing under /etc is writable by everyone",
              ("config_audit",), _config_row("world_writable_etc", "nothing under /etc is world-writable",
                                             "world-writable files under /etc"),
              "find /etc -xdev -type f -perm -0002 -exec sudo chmod o-w {} +", (), ("8.3", "8.9"), ("6.3",)),
        Check("kratos.log_sealing", "audit and logs", "Kratos verifies the machine's journal seals (Forward Secure "
              "Sealing)", ("log_integrity",), _sealing,
              "set up journal sealing: `kratos seal set-key <machine>` (see the GUIDE, 'Log sealing')",
              (), ("8.15",), ("3.2",), in_finding=False),
    ]
    ids = [c.id for c in out]
    assert len(ids) == len(set(ids)), "check ids must be unique"
    return tuple(out)


CHECKS: tuple[Check, ...] = _build()
BY_ID: dict[str, Check] = {c.id: c for c in CHECKS}


def applicable(family: str) -> list[Check]:
    return [c for c in CHECKS if family in c.os_families]


def evaluate(check: Check, facts: Facts) -> Result:
    """Run one check. A crash is never a pass: it becomes unknown with the reason."""
    if facts.family() not in check.os_families and facts.get("hardening") is not None:
        return Result(NA, "", f"this check is for {', '.join(check.os_families)} systems")
    try:
        return check.predicate(facts)
    except Exception as e:  # noqa: BLE001 -- a broken fact is "couldn't tell", never a crash or a pass
        return Result(UNKNOWN, "", f"unexpected fact shape ({type(e).__name__})")
