"""
Named, read-only probes -- how Kratos investigates a target through its
sub-agent when it can't (or won't) SSH in (docs/subagent_read_routing.md).

ONE closed set of reads, shipped as code. Core may only NAME a probe and pass
parameters; every parameter goes through a closed validator here, on the
agent, before anything runs. No command text, script, path list or rule text
is ever accepted from the wire -- the commands below are fixed in this file
(or built here from validated values), run with ``shell=False`` and a fixed
environment, read-only, with a per-probe timeout and output cap.

This file has TWO users, by design, so the two transports can't drift apart:
  - the agent (``agent.py``) runs ``run_probe`` for a signed read_request;
  - core's SSH path (``kratos.adapters.ssh_remote``) builds its commands with
    the SAME builders (``journal_fetch_argv``, ``journal_auth_argv``,
    ``lsof_argv``, ``config_audit_script``, ...) and parses both transports'
    output with the SAME parsers.
Raw-output probes return ``{returncode, stdout, stderr}`` exactly as the SSH
path would see them, so core runs one parser for both.

Reads never touch the execution channel, its ceiling or ``execution_enabled``.

Stdlib-only, no kratos-internal imports (deployed as a sibling of agent.py --
see protocol.py). The measurement script builder lives in kratos.timewin and
ships in the bundle as the sibling ``measure.py``.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import shlex
import stat
import subprocess
import threading
import time
from typing import Any, Callable

try:  # in the agent bundle: sibling modules
    from . import measure, privileged_accounts  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:  # core side (the same files)
        from kratos.adapters import privileged_accounts
        from kratos.timewin import measure
    except ImportError:  # `python3 subagent/agent.py` run directly
        import measure  # type: ignore[no-redef]
        import privileged_accounts  # type: ignore[no-redef]

READ_API_VERSION = 1

TRUSTED_BIN_DIRS: tuple[str, ...] = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
READ_ENV: dict[str, str] = {"PATH": ":".join(TRUSTED_BIN_DIRS), "LANG": "C", "LC_ALL": "C"}

STDERR_CAP_BYTES = 4000
MEASURE_BUDGET_SECONDS = measure.DEFAULT_TIME_BUDGET_SECONDS


class ReadParamError(ValueError):
    """A probe parameter failed its validator -- the request is refused."""


# ---------------------------------------------------------------------------
# Shared command builders (SSH path + agent)
# ---------------------------------------------------------------------------
AUTH_COMMS: dict[str, tuple[str, ...]] = {
    # OpenSSH >= 9.8 logs per-connection auth events from `sshd-session`, not
    # `sshd` (see ssh_remote.fetch_journalctl_auth_entries). Repeating a field
    # ORs it in journalctl.
    "sshd": ("sshd", "sshd-session"),
    "sudo": ("sudo",),
}

CRITICAL_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab",
)


def window_args(since_epoch: float | None, until_epoch: float | None, lines: int) -> list[str]:
    """journalctl args for "the NEWEST `lines` entries in [since, until]".

    Always absolute epochs (`@<epoch>`), never a relative string the target would
    interpret on its own clock/timezone. Always `--reverse -n <lines+1>`: plain
    `--since X -n N` returns the OLDEST N entries after X on systemd 249 (Ubuntu
    22.04) but the newest N on systemd 255 -- confirmed live on both -- so relying
    on `-n` alone silently dropped the most recent activity (including an in-
    progress brute force) whenever the window held more than N lines. `--reverse`
    makes it newest-first on every version; the one extra entry is how truncation
    is detected (the caller drops it and flags the window as not fully covered)."""
    args: list[str] = []
    if since_epoch is not None:
        args += ["--since", f"@{int(since_epoch)}"]
    if until_epoch is not None:
        args += ["--until", f"@{int(until_epoch)}"]
    return args + ["--reverse", "-n", str(int(lines) + 1)]


def journal_fetch_argv(unit: str | None, since_epoch: float | None, until_epoch: float | None,
                       lines: int, prefix: list[str] | tuple[str, ...] = ()) -> list[str]:
    parts = [*prefix, "journalctl", "--no-pager", "-o", "json"]
    if unit:
        # Match on BOTH _SYSTEMD_UNIT and _COMM: sshd is commonly logged under a
        # per-connection scope unit, never the literal "sshd.service" (see
        # ssh_remote.fetch_journalctl_entries for the live incident).
        base = unit[: -len(".service")] if unit.endswith(".service") else unit
        parts += [f"_SYSTEMD_UNIT={unit}", "+", f"_COMM={base}"]
    return parts + window_args(since_epoch, until_epoch, lines)


def journal_auth_argv(identifier: str, since_epoch: float | None, until_epoch: float | None,
                      lines: int, prefix: list[str] | tuple[str, ...] = ()) -> list[str]:
    comms = AUTH_COMMS[identifier]
    return [*prefix, "journalctl", "--no-pager", "-o", "json", *(f"_COMM={c}" for c in comms),
            *window_args(since_epoch, until_epoch, lines)]


def lsof_argv(pid: int | None) -> list[str]:
    argv = ["lsof", "-n", "-P"]
    if pid is not None:
        argv += ["-p", str(int(pid))]
    return argv


PS_ARGV: list[str] = ["ps", "aux"]
CLOCK_COMMAND = "date +%s.%N"


def file_hash_script(paths: tuple[str, ...] = CRITICAL_PATHS) -> str:
    quoted = " ".join(shlex.quote(p) for p in paths)
    return (
        f"for f in {quoted}; do "
        'if [ ! -f "$f" ]; then printf \'MISSING\\t%s\\n\' "$f"; '
        'elif [ ! -r "$f" ]; then printf \'UNREADABLE\\t%s\\n\' "$f"; '
        "else printf 'PRESENT\\t%s\\t%s\\n' \"$f\" \"$(sha256sum \"$f\" | cut -d' ' -f1)\"; "
        "fi; done"
    )


def parse_hash_lines(stdout: str, unreadable_marker: str) -> dict[str, str | None]:
    hashes: dict[str, str | None] = {}
    for line in stdout.strip().splitlines():
        cols = line.split("\t")
        if cols[0] == "PRESENT" and len(cols) == 3 and cols[2]:
            hashes[cols[1]] = cols[2]
        elif cols[0] == "MISSING" and len(cols) == 2:
            hashes[cols[1]] = None
        elif cols[0] == "UNREADABLE" and len(cols) == 2:
            hashes[cols[1]] = unreadable_marker
    return hashes


def parse_check_lines(stdout: str) -> list[dict[str, str]]:
    """`check<TAB>STATUS<TAB>detail` lines (config audit, setup probe)."""
    checks = []
    for line in stdout.strip().splitlines():
        cols = line.split("\t", 2)
        if len(cols) != 3:
            continue
        check_id, status, detail = cols
        checks.append({"check": check_id, "status": status, "detail": detail})
    return checks


# `$SUDO` is "sudo -n" over SSH (an unprivileged SSH user reads these through
# passwordless sudo) and empty for an agent that already runs as root.
_CONFIG_AUDIT_BODY = r"""
prl=$($SUDO sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')
if [ -z "$prl" ]; then
  printf 'ssh_root_login\tUNKNOWN\tCould not determine effective PermitRootLogin (%s unavailable)\n' "$SSHD_T"
elif [ "$prl" = "no" ]; then
  printf 'ssh_root_login\tPASS\tRoot login is disabled (PermitRootLogin no)\n'
elif [ "$prl" = "without-password" ] || [ "$prl" = "prohibit-password" ]; then
  printf 'ssh_root_login\tPASS\tRoot login only allowed via key, not password (PermitRootLogin %s)\n' "$prl"
else
  printf 'ssh_root_login\tFAIL\tRoot login permitted (PermitRootLogin %s)\n' "$prl"
fi

pa=$($SUDO sshd -T 2>/dev/null | grep -i '^passwordauthentication' | awk '{print $2}')
if [ -z "$pa" ]; then
  printf 'ssh_password_auth\tUNKNOWN\tCould not determine effective PasswordAuthentication (%s unavailable)\n' "$SSHD_T"
elif [ "$pa" = "no" ]; then
  printf 'ssh_password_auth\tPASS\tKey-only authentication enforced (PasswordAuthentication no)\n'
else
  printf 'ssh_password_auth\tWARN\tPassword authentication is enabled (PasswordAuthentication %s); key-only is stronger\n' "$pa"
fi

fw_found=0
if command -v ufw >/dev/null 2>&1; then
  fw_found=1
  ufw_status=$($SUDO ufw status 2>/dev/null | head -1)
  if echo "$ufw_status" | grep -qi 'active'; then
    printf 'firewall\tPASS\tufw is active (%s)\n' "$ufw_status"
  else
    printf 'firewall\tFAIL\tufw installed but not active (%s)\n' "$ufw_status"
  fi
elif command -v nft >/dev/null 2>&1; then
  fw_found=1
  nft_rules=$($SUDO nft list ruleset 2>/dev/null | wc -l)
  if [ "$nft_rules" -gt 0 ]; then
    printf 'firewall\tPASS\tnftables has %s rule line(s) configured\n' "$nft_rules"
  else
    printf 'firewall\tFAIL\tnftables installed but no rules configured\n'
  fi
elif command -v iptables >/dev/null 2>&1; then
  fw_found=1
  ipt_rules=$($SUDO iptables -L -n 2>/dev/null | grep -vc '^Chain\|^target\|^$')
  if [ "$ipt_rules" -gt 0 ]; then
    printf 'firewall\tPASS\tiptables has %s active rule(s)\n' "$ipt_rules"
  else
    printf 'firewall\tFAIL\tiptables installed but no rules configured\n'
  fi
fi
if [ "$fw_found" -eq 0 ]; then
  printf 'firewall\tUNKNOWN\tNo firewall tool found on target (ufw/nft/iptables not installed)\n'
fi

ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null)
ww_count=$(printf '%s' "$ww" | grep -c . || true)
if [ "$ww_count" -eq 0 ]; then
  printf 'world_writable_etc\tPASS\tNo world-writable files found under /etc\n'
else
  ww_sample=$(printf '%s' "$ww" | head -5 | tr '\n' ',')
  printf 'world_writable_etc\tFAIL\t%s world-writable file(s) found under /etc, e.g. %s\n' "$ww_count" "$ww_sample"
fi

if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
  enabled=$(systemctl is-enabled unattended-upgrades.service 2>/dev/null || echo unknown)
  if [ "$enabled" = "enabled" ]; then
    printf 'unattended_upgrades\tPASS\tunattended-upgrades installed and service enabled\n'
  else
    printf 'unattended_upgrades\tWARN\tunattended-upgrades installed but service state is: %s\n' "$enabled"
  fi
else
  printf 'unattended_upgrades\tFAIL\tunattended-upgrades package is not installed\n'
fi

f2b_installed=0
if command -v fail2ban-client >/dev/null 2>&1 || dpkg -l fail2ban 2>/dev/null | grep -q '^ii'; then
  f2b_installed=1
fi

if [ "$f2b_installed" -eq 0 ]; then
  printf 'fail2ban_status\tFAIL\tfail2ban is not installed\n'
else
  f2b_active=$(systemctl is-active fail2ban 2>/dev/null || echo inactive)
  if [ "$f2b_active" != "active" ]; then
    printf 'fail2ban_status\tFAIL\tfail2ban is installed but the service is not active (status: %s)\n' "$f2b_active"
  else
    jails=$($SUDO fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p')
    ssh_jail=""
    if echo "$jails" | grep -qiw 'sshd'; then
      ssh_jail="sshd"
    elif echo "$jails" | grep -qiw 'ssh'; then
      ssh_jail="ssh"
    fi
    if [ -z "$ssh_jail" ]; then
      printf 'fail2ban_status\tWARN\tfail2ban is installed and active but no SSH-specific jail is configured (jails: %s)\n' "${jails:-none}"
    else
      maxretry=$($SUDO fail2ban-client get "$ssh_jail" maxretry 2>/dev/null)
      bantime=$($SUDO fail2ban-client get "$ssh_jail" bantime 2>/dev/null)
      printf 'fail2ban_status\tPASS\tfail2ban active with SSH jail "%s" (maxretry=%s, bantime=%ss) -- reported as-is, not checked against any specific target values\n' "$ssh_jail" "${maxretry:-unknown}" "${bantime:-unknown}"
    fi
  fi
fi
"""


def config_audit_script(sudo: str = "sudo -n") -> str:
    """The config-audit script with its privilege prefix fixed at the top
    (`sudo -n` over SSH, empty for a root agent). Verdict lines only -- the
    raw `sshd -T` output never leaves the target."""
    sshd_t = f"{sudo} sshd -T".strip()
    return f"SUDO={shlex.quote(sudo)}\nSSHD_T={shlex.quote(sshd_t)}\n" + _CONFIG_AUDIT_BODY


_YARA_STRING_MATCH_RE = re.compile(r"^0x[0-9a-fA-F]+:")


def parse_yara_output(stdout: str, include_content: bool = True) -> list[dict[str, Any]]:
    """Parse `yara -s` output. A string-match line ("0xOFFSET:$id: content") has
    no leading whitespace, so it's told apart from a rule line ("Rule /path")
    by its ^0x[hex]: prefix (a rule identifier can never start with "0x").
    `include_content=False` drops the matched bytes -- the agent never sends
    them (docs/subagent_read_routing.md D4)."""
    matches: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if _YARA_STRING_MATCH_RE.match(line) and current is not None:
            parts = line.split(":", 2)
            if len(parts) == 3:
                offset, identifier, content = parts
                entry = {"offset": offset, "identifier": identifier.strip()}
                if include_content:
                    entry["matched"] = content.strip()
                current["strings"].append(entry)
        else:
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            current = {"rule": parts[0], "file": parts[1], "strings": []}
            matches.append(current)
    return matches


# ---------------------------------------------------------------------------
# Parameter validators -- closed, type-strict, never coerce
# ---------------------------------------------------------------------------
_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:+\-]{0,63}$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
EPOCH_MIN = 946684800      # 2000-01-01
EPOCH_MAX = 4102444800     # 2100-01-01


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v  # not NaN


def v_epoch(v: Any) -> float:
    if not _is_number(v) or not (EPOCH_MIN <= v <= EPOCH_MAX):
        raise ReadParamError(f"must be a Unix time between {EPOCH_MIN} and {EPOCH_MAX}")
    return float(v)


def v_int_range(lo: int, hi: int) -> Callable[[Any], int]:
    def check(v: Any) -> int:
        if type(v) is not int or not (lo <= v <= hi):
            raise ReadParamError(f"must be a whole number from {lo} to {hi}")
        return v
    return check


def v_enum(*allowed: Any) -> Callable[[Any], Any]:
    def check(v: Any) -> Any:
        if type(v) not in (str, int) or v not in allowed:
            raise ReadParamError(f"must be one of {', '.join(map(str, allowed))}")
        return v
    return check


def v_unit(v: Any) -> str:
    if not isinstance(v, str) or not _UNIT_RE.fullmatch(v):
        raise ReadParamError("must be a systemd unit or program name (letters, digits, @._:+-, at most 64)")
    return v


def v_user(v: Any) -> str:
    if not isinstance(v, str) or (v and not _USER_RE.fullmatch(v)):
        raise ReadParamError("must be a Linux user name")
    return v


def v_ip(v: Any) -> str:
    import ipaddress

    if not isinstance(v, str):
        raise ReadParamError("must be an IP address")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ReadParamError("must be an IP address") from None


def v_scan_path(v: Any) -> str:
    """Shape only here; the agent re-checks it against the scan roots on its
    own filesystem (symlinks resolved) in `_resolve_scan_path`."""
    if not isinstance(v, str) or not v.startswith("/") or len(v) > 1024 or "\x00" in v:
        raise ReadParamError("must be an absolute path")
    if any(part == ".." for part in v.split("/")):
        raise ReadParamError("must not contain '..'")
    return v


# probe -> {param: (validator, required, default)}
_P = tuple
PARAM_SPECS: dict[str, dict[str, _P]] = {
    "clock": {},
    "journal_fetch": {
        "unit": (v_unit, False, None),
        "since": (v_epoch, False, None),
        "until": (v_epoch, False, None),
        "lines": (v_int_range(1, 5000), True, None),
    },
    "journal_auth": {
        "identifier": (v_enum(*AUTH_COMMS), True, None),
        "since": (v_epoch, False, None),
        "until": (v_epoch, False, None),
        "lines": (v_int_range(1, 2000), True, None),
    },
    "open_files": {"pid": (v_int_range(1, 4194304), False, None)},
    "processes": {},
    "file_hashes": {},
    "config_audit": {},
    "capabilities": {},
    "yara_scan": {
        "path": (v_scan_path, True, None),
        "ruleset": (v_enum("all", "bundled", "local"), False, "all"),
    },
    "measure_auth": {
        "start": (v_epoch, True, None),
        "end": (v_epoch, False, None),
        "granularity": (v_enum(60, 3600), True, None),
        "exclude_user": (v_user, False, ""),
        "exclude_ip": (v_ip, False, None),
    },
    "privileged_accounts": {"since": (v_epoch, True, None)},
}

READ_PROBES: tuple[str, ...] = tuple(PARAM_SPECS)

# Agent-side wall-clock limit per probe, and the cap on what it sends back.
PROBE_TIMEOUT_SECONDS: dict[str, float] = {
    "clock": 5, "journal_fetch": 30, "journal_auth": 30, "open_files": 30, "processes": 15,
    "file_hashes": 15, "config_audit": 45, "capabilities": 20, "yara_scan": 180,
    "measure_auth": MEASURE_BUDGET_SECONDS + 60, "privileged_accounts": 30,
}
OUTPUT_CAP_BYTES: dict[str, int] = {
    "journal_fetch": 4 * 1024 * 1024, "journal_auth": 3 * 1024 * 1024,
    "open_files": 4 * 1024 * 1024, "processes": 2 * 1024 * 1024,
    "config_audit": 256 * 1024, "measure_auth": 4 * 1024 * 1024, "privileged_accounts": 1024 * 1024,
}
MAX_YARA_MATCHES = 2000
MAX_YARA_FILES = 20000
MAX_YARA_FILE_BYTES = 64 * 1024 * 1024


def validate_params(probe: str, params: Any) -> dict[str, Any]:
    """Closed validation: unknown probe, unknown key, missing required key or a
    value failing its validator all raise ReadParamError. Returns the clean
    params with defaults filled in."""
    spec = PARAM_SPECS.get(probe)
    if spec is None:
        raise ReadParamError(f"unknown probe {probe!r}")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ReadParamError("params must be an object")
    unknown = sorted(set(params) - set(spec))
    if unknown:
        raise ReadParamError(f"{probe}: unknown parameter(s) {', '.join(map(str, unknown))}")
    clean: dict[str, Any] = {}
    for name, (check, required, default) in spec.items():
        if name not in params or params[name] is None:
            if required:
                raise ReadParamError(f"{probe}: {name} is required")
            clean[name] = default
            continue
        try:
            clean[name] = check(params[name])
        except ReadParamError as e:
            raise ReadParamError(f"{probe}: {name} {e}") from None
    if probe in ("journal_fetch", "journal_auth", "measure_auth"):
        lo, hi = (clean.get("since"), clean.get("until")) if probe != "measure_auth" else (clean["start"], clean.get("end"))
        if lo is not None and hi is not None and hi < lo:
            raise ReadParamError(f"{probe}: the window ends before it starts")
    return clean


# ---------------------------------------------------------------------------
# YARA scope (agent side) -- D4: closed roots, credential paths never scanned
# ---------------------------------------------------------------------------
SCAN_ROOTS: tuple[str, ...] = (
    "/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/srv", "/opt", "/var/www",
    "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/etc/systemd/system", "/etc/init.d", "/etc/profile.d",
)
# Never walked into (directory names) / never scanned (file names, suffixes).
_CREDENTIAL_DIRS = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".password-store", ".docker", ".gcloud",
    "gcloud", ".vault-token", "keyrings", ".local/share/keyrings",
})
_CREDENTIAL_FILES = frozenset({
    "shadow", "gshadow", "shadow-", "gshadow-", "sudoers", ".netrc", ".pgpass", ".git-credentials",
    ".my.cnf", "authorized_keys", "known_hosts", "credentials", ".env", ".vault-token",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
})
_CREDENTIAL_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx", ".keystore", ".asc", ".gpg")
LOCAL_YARA_DIR = "/etc/kratos-subagent/yara"


def is_credential_path(path: str) -> bool:
    parts = [p for p in path.split("/") if p]
    if any(p in _CREDENTIAL_DIRS for p in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    low = name.lower()
    return (name in _CREDENTIAL_DIRS or low in _CREDENTIAL_FILES or low.endswith(_CREDENTIAL_SUFFIXES)
            or low.startswith(("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")))


def _resolve_scan_path(path: str) -> str:
    real = os.path.realpath(path)
    if not os.path.exists(real):
        raise ReadParamError(f"yara_scan: {path} does not exist on this box")
    for root in SCAN_ROOTS:
        r = os.path.realpath(root)
        if real == r or real.startswith(r.rstrip("/") + "/"):
            if is_credential_path(real):
                raise ReadParamError(f"yara_scan: {path} is a credential location and is never scanned")
            return real
    raise ReadParamError("yara_scan: path must be inside one of the scan roots: " + ", ".join(SCAN_ROOTS))


# ---------------------------------------------------------------------------
# Running things (agent side)
# ---------------------------------------------------------------------------
def resolve_binary(name: str) -> str | None:
    for d in TRUSTED_BIN_DIRS:
        p = f"{d}/{name}"
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


class ProbeTimeout(Exception):
    pass


class ProbeMissing(Exception):
    pass


def run_capped(argv: list[str], *, timeout: float, cap: int, stdin_text: str | None = None) -> dict[str, Any]:
    """Run a fixed argv (binary resolved inside the trusted dirs, never $PATH),
    reading at most `cap` bytes of stdout. Past the cap the process is killed
    and the output cut at the last full line (`truncated: True`); past
    `timeout` it is killed and ProbeTimeout raised. Never a shell string."""
    exe = resolve_binary(argv[0]) if not argv[0].startswith("/") else argv[0]
    if exe is None:
        raise ProbeMissing(f"{argv[0]} is not installed")
    proc = subprocess.Popen(
        [exe, *argv[1:]], stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(READ_ENV), cwd="/",
        start_new_session=True, close_fds=True,
    )
    if stdin_text is not None:
        def feed() -> None:
            try:
                proc.stdin.write(stdin_text.encode("utf-8"))  # type: ignore[union-attr]
                proc.stdin.close()  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass
        threading.Thread(target=feed, daemon=True).start()
    out = bytearray()
    err = bytearray()
    truncated = False
    deadline = time.monotonic() + timeout
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, "out")  # type: ignore[arg-type]
    sel.register(proc.stderr, selectors.EVENT_READ, "err")  # type: ignore[arg-type]
    open_streams = 2
    try:
        while open_streams:
            left = deadline - time.monotonic()
            if left <= 0:
                _kill(proc)
                raise ProbeTimeout(f"timed out after {int(timeout)}s")
            for key, _ in sel.select(timeout=min(left, 1.0)):
                chunk = os.read(key.fileobj.fileno(), 65536)  # type: ignore[union-attr]
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                if key.data == "out":
                    out += chunk
                    if len(out) > cap:
                        truncated = True
                        del out[cap:]
                        _kill(proc)
                        open_streams = 0
                        break
                elif len(err) < STDERR_CAP_BYTES:
                    err += chunk[: STDERR_CAP_BYTES - len(err)]
        try:
            rc = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill(proc)
            raise ProbeTimeout(f"timed out after {int(timeout)}s") from None
    finally:
        sel.close()
        for s in (proc.stdout, proc.stderr):
            try:
                s.close()  # type: ignore[union-attr]
            except OSError:
                pass
    text = out.decode("utf-8", "replace")
    if truncated:
        cut = text.rfind("\n")
        text = text[: cut + 1] if cut >= 0 else ""
        rc = 0  # killed on purpose: what was read is a valid (partial) result
    return {"returncode": rc, "stdout": text, "stderr": err.decode("utf-8", "replace"), "truncated": truncated}


KILL_GRACE_SECONDS = 2.0


def _kill(proc: subprocess.Popen) -> None:
    """Stop the probe's whole process group: TERM first, so a probe script's
    cleanup trap removes its temp files, then KILL whatever is left."""
    for sig, wait in ((15, KILL_GRACE_SECONDS), (9, 5.0)):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill() if sig == 9 else proc.terminate()
            except OSError:
                pass
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _is_root() -> bool:
    return os.geteuid() == 0


def _sudo() -> str:
    # A root agent needs no sudo; an unprivileged one reads through passwordless
    # sudo where the box's admin allowed it (exactly like the SSH user).
    return "" if _is_root() else "sudo -n"


_JOURNAL_GROUPS = {"systemd-journal", "adm", "wheel"}


def _in_journal_group() -> bool:
    try:
        import grp

        return bool({grp.getgrgid(g).gr_name for g in os.getgroups()} & _JOURNAL_GROUPS)
    except (KeyError, ImportError, OSError):
        return False


def journal_prefix() -> list[str]:
    """How this agent reads the system journal. Plain journalctl as a user
    outside the journal groups silently HIDES other users' entries (sshd/PAM
    auth failures included) -- the bug the SSH path's `sudo -n` exists for. So
    such an agent uses `sudo -n` too: if that isn't allowed the read fails
    loudly instead of coming back quietly incomplete."""
    return [] if _is_root() or _in_journal_group() else ["sudo", "-n"]


def _shell() -> str:
    return resolve_binary("bash") or resolve_binary("sh") or "/bin/sh"


_JOURNAL_KEEP = ("__REALTIME_TIMESTAMP", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM", "MESSAGE", "PRIORITY")


def _trim_journal(stdout: str) -> str:
    """Keep only the fields Kratos parses (less data leaves the box)."""
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(raw, dict):
            out.append(json.dumps({k: raw[k] for k in _JOURNAL_KEEP if k in raw}, separators=(",", ":")))
    return "\n".join(out) + ("\n" if out else "")


# ---------------------------------------------------------------------------
# The probes
# ---------------------------------------------------------------------------
def _p_clock(p: dict[str, Any]) -> dict[str, Any]:
    return {"returncode": 0, "stdout": f"{time.time():.6f}\n", "stderr": "", "truncated": False}


def _p_journal_fetch(p: dict[str, Any]) -> dict[str, Any]:
    r = run_capped(journal_fetch_argv(p["unit"], p["since"], p["until"], p["lines"], prefix=journal_prefix()),
                   timeout=PROBE_TIMEOUT_SECONDS["journal_fetch"], cap=OUTPUT_CAP_BYTES["journal_fetch"] * 4)
    r["stdout"] = _trim_journal(r["stdout"])
    return _cap_after_trim(r, OUTPUT_CAP_BYTES["journal_fetch"])


def _p_journal_auth(p: dict[str, Any]) -> dict[str, Any]:
    r = run_capped(journal_auth_argv(p["identifier"], p["since"], p["until"], p["lines"], prefix=journal_prefix()),
                   timeout=PROBE_TIMEOUT_SECONDS["journal_auth"], cap=OUTPUT_CAP_BYTES["journal_auth"] * 4)
    r["stdout"] = _trim_journal(r["stdout"])
    return _cap_after_trim(r, OUTPUT_CAP_BYTES["journal_auth"])


def _cap_after_trim(r: dict[str, Any], cap: int) -> dict[str, Any]:
    if len(r["stdout"].encode("utf-8")) > cap:
        text = r["stdout"].encode("utf-8")[:cap].decode("utf-8", "ignore")
        r["stdout"] = text[: text.rfind("\n") + 1]
        r["truncated"] = True
    return r


def _p_open_files(p: dict[str, Any]) -> dict[str, Any]:
    return run_capped(lsof_argv(p["pid"]), timeout=PROBE_TIMEOUT_SECONDS["open_files"],
                      cap=OUTPUT_CAP_BYTES["open_files"])


def _p_processes(p: dict[str, Any]) -> dict[str, Any]:
    return run_capped(PS_ARGV, timeout=PROBE_TIMEOUT_SECONDS["processes"], cap=OUTPUT_CAP_BYTES["processes"])


def hash_file(path: str) -> str:
    """'PRESENT\\t<path>\\t<sha256>' / 'MISSING\\t<path>' / 'UNREADABLE\\t<path>' --
    the same lines file_hash_script prints over SSH."""
    import hashlib

    try:
        st = os.stat(path)
    except FileNotFoundError:
        return f"MISSING\t{path}"
    except OSError:
        return f"UNREADABLE\t{path}"
    if not stat.S_ISREG(st.st_mode):
        return f"MISSING\t{path}"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return f"PRESENT\t{path}\t{h.hexdigest()}"
    except OSError:
        return f"UNREADABLE\t{path}"


def _p_file_hashes(p: dict[str, Any]) -> dict[str, Any]:
    lines = [hash_file(path) for path in CRITICAL_PATHS]
    return {"returncode": 0, "stdout": "\n".join(lines) + "\n", "stderr": "", "truncated": False}


def _p_config_audit(p: dict[str, Any]) -> dict[str, Any]:
    return run_capped([_shell(), "-s"], timeout=PROBE_TIMEOUT_SECONDS["config_audit"],
                      cap=OUTPUT_CAP_BYTES["config_audit"], stdin_text=config_audit_script(_sudo()))


def _p_measure_auth(p: dict[str, Any]) -> dict[str, Any]:
    script = measure.build_script(
        p["start"], p["end"], journalctl_prefix=" ".join(journal_prefix()),
        kratos_user=p["exclude_user"], classic_granularity=p["granularity"], kratos_ip=p["exclude_ip"],
    )
    sh = resolve_binary("sh") or "/bin/sh"
    return run_capped([sh, "-s"], timeout=PROBE_TIMEOUT_SECONDS["measure_auth"],
                      cap=OUTPUT_CAP_BYTES["measure_auth"], stdin_text=script)


def _p_privileged_accounts(p: dict[str, Any]) -> dict[str, Any]:
    """Who can become root, and account/group changes since `since` -- the same
    script the SSH path runs (kratos.adapters.privileged_accounts), with a root
    agent reading sudoers directly."""
    script = privileged_accounts.build_script(int(p["since"]), " ".join(journal_prefix()) + " " if journal_prefix() else "",
                                              sudo=_sudo())
    sh = resolve_binary("sh") or "/bin/sh"
    return run_capped([sh, "-s"], timeout=PROBE_TIMEOUT_SECONDS["privileged_accounts"],
                      cap=OUTPUT_CAP_BYTES["privileged_accounts"], stdin_text=script)


def _quick(argv: list[str], timeout: float = 8) -> tuple[int | None, str]:
    try:
        r = run_capped(argv, timeout=timeout, cap=64 * 1024)
        return r["returncode"], (r["stdout"] + r["stderr"])
    except ProbeMissing:
        return None, "not installed"
    except (ProbeTimeout, OSError) as e:
        return -1, str(e)


def _p_capabilities(p: dict[str, Any]) -> dict[str, Any]:
    """What this agent can actually read -- the sub-agent edition of the SSH
    setup probe, same {check, status, detail} rows."""
    rows: list[dict[str, str]] = []

    def add(check: str, status: str, detail: str) -> None:
        rows.append({"check": check, "status": status, "detail": detail})

    import pwd

    try:
        who = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        who = str(os.geteuid())
    if _is_root():
        add("agent_privilege", "PASS", "The sub-agent runs as root -- it can read every log and process")
    else:
        add("agent_privilege", "INFO", f"The sub-agent runs as {who} -- reads are limited to what {who} can see")
    sudo = [] if _is_root() else ["sudo", "-n"]

    if resolve_binary("journalctl") is None:
        add("journalctl_access", "FAIL", "No journalctl on this box -- log reads fall back to classic log files where possible")
    else:
        if _is_root() or _in_journal_group():
            add("journalctl_access", "PASS", "Can read the full system journal")
        else:
            rc, _ = _quick(["sudo", "-n", "journalctl", "--no-pager", "-q", "-n", "1"])
            if rc == 0:
                add("journalctl_access", "PASS", f"Reads the system journal through sudo -n (as {who})")
            else:
                add("journalctl_access", "FAIL", f"{who} can't read the full system journal -- add it to the "
                                                 "systemd-journal group (or allow sudo -n journalctl)")

    rc, _ = _quick([*sudo, "sshd", "-T"]) if (sudo or resolve_binary("sshd")) else (None, "")
    if rc == 0:
        add("sshd_config", "PASS", "Can read the effective sshd configuration")
    else:
        add("sshd_config", "FAIL", "Cannot run sshd -T -- the config audit will report SSH settings as UNKNOWN")

    fw = next((b for b in ("ufw", "nft", "iptables") if resolve_binary(b)), None)
    if fw is None:
        add("firewall_status", "UNKNOWN", "No ufw/nft/iptables on this box")
    else:
        argv = {"ufw": ["ufw", "status"], "nft": ["nft", "list", "ruleset"], "iptables": ["iptables", "-L", "-n"]}[fw]
        rc, _ = _quick([*sudo, *argv])
        add("firewall_status", "PASS" if rc == 0 else "FAIL",
            f"Can read {fw} status" if rc == 0 else f"Cannot read {fw} status -- the config audit will report the firewall as UNKNOWN")

    if resolve_binary("fail2ban-client"):
        rc, out = _quick([*sudo, "fail2ban-client", "status"])
        add("fail2ban_status", "PASS" if rc == 0 else "WARN",
            "Can read fail2ban status" if rc == 0 else "fail2ban-client failed (is the fail2ban service running?)")
    else:
        add("fail2ban_status", "UNKNOWN", "fail2ban is not installed")

    yara = resolve_binary("yara")
    if yara is None:
        add("yara_installed", "FAIL", "yara is not installed -- YARA scans will not run (install the yara package)")
    else:
        rc, out = _quick(["yara", "--version"])
        version = out.strip().splitlines()[0] if out.strip() else "?"
        add("yara_installed", "PASS", f"yara {version} found")
    rules, problems = yara_rule_files("all")
    add("yara_rules", "PASS" if rules else "WARN",
        f"{len(rules)} rule file(s) available" + (f"; ignored: {'; '.join(problems)}" if problems else ""))
    add("lsof_installed", "PASS" if resolve_binary("lsof") else "FAIL",
        "lsof found" if resolve_binary("lsof") else "lsof is not installed -- open-file reads will not run")

    tz = "unknown"
    try:
        with open("/etc/timezone", encoding="utf-8") as f:
            tz = f.read().strip() or tz
    except OSError:
        try:
            tz = os.readlink("/etc/localtime").split("zoneinfo/", 1)[-1]
        except OSError:
            pass
    add("target_timezone", "INFO", f"Box timezone: {tz} (journald timestamps are absolute UTC regardless)")
    return {"checks": rows, "read_probes": list(READ_PROBES)}


def bundled_rules_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")


def _rule_files_in(directory: str, trusted_only: bool) -> tuple[list[str], list[str]]:
    files: list[str] = []
    problems: list[str] = []
    try:
        names = sorted(os.listdir(directory))
        dst = os.stat(directory)
    except FileNotFoundError:
        return [], []
    except OSError as e:
        return [], [f"{directory}: unreadable ({e})"]
    allowed = {0, os.geteuid()}
    if trusted_only and (dst.st_uid not in allowed or dst.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        return [], [f"{directory}: must be owned by root and not group/world-writable -- ignored"]
    for name in names:
        if not name.endswith((".yar", ".yara")):
            continue
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{path}: not a regular file -- ignored")
            continue
        if trusted_only and (st.st_uid not in allowed or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            problems.append(f"{path}: must be owned by root and not group/world-writable -- ignored")
            continue
        files.append(path)
    return files, problems


_YARA_IMPORT_RE = re.compile(r'^\s*import\s+"', re.MULTILINE)


def _uses_yara_modules(path: str) -> bool:
    """Whether a rule file loads a YARA module (pe, elf, macho, dotnet, ...).
    Unreadable counts as yes: it is skipped rather than guessed safe."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return bool(_YARA_IMPORT_RE.search(f.read(1024 * 1024)))
    except OSError:
        return True


def yara_rule_files(ruleset: str) -> tuple[list[str], list[str]]:
    """Rules come ONLY from this box: the set shipped with the agent and/or
    the admin's own directory. Never from core (D4: core-supplied rules would
    be an oracle for file contents).

    A root agent scans files any local user can write (/tmp, /var/tmp, ...). YARA's
    modules parse file formats in depth, and most of YARA's past security bugs were
    in those parsers, so as root only module-free rules (plain string/byte
    matching) are used; the others are skipped and named (security review
    2026-10-05, finding 2)."""
    files: list[str] = []
    problems: list[str] = []
    if ruleset in ("all", "bundled"):
        f, pr = _rule_files_in(bundled_rules_dir(), trusted_only=False)
        files += f
        problems += pr
    if ruleset in ("all", "local"):
        f, pr = _rule_files_in(LOCAL_YARA_DIR, trusted_only=True)
        files += f
        problems += pr
    if _is_root():
        kept = []
        for path in files:
            if _uses_yara_modules(path):
                problems.append(f"{path}: uses a YARA module (import ...) -- skipped, because this agent runs as "
                                "root and modules parse untrusted files in depth")
            else:
                kept.append(path)
        files = kept
    return files, problems


def _walk_scan_files(top: str) -> tuple[list[str], dict[str, int], bool]:
    counts = {"skipped_credential": 0, "skipped_unreadable": 0, "skipped_large": 0}
    files: list[str] = []
    try:
        top_dev = os.stat(top).st_dev
    except OSError:
        return [], counts, False
    if os.path.isfile(top):
        return [top], counts, False

    def onerror(_e: OSError) -> None:
        counts["skipped_unreadable"] += 1

    for dirpath, dirnames, filenames in os.walk(top, onerror=onerror, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if is_credential_path(full + "/x"):
                counts["skipped_credential"] += 1
                continue
            try:
                if os.lstat(full).st_dev != top_dev:
                    continue  # stay on one filesystem
            except OSError:
                counts["skipped_unreadable"] += 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            full = os.path.join(dirpath, name)
            if is_credential_path(full):
                counts["skipped_credential"] += 1
                continue
            try:
                st = os.lstat(full)
            except OSError:
                counts["skipped_unreadable"] += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size > MAX_YARA_FILE_BYTES:
                counts["skipped_large"] += 1
                continue
            if not os.access(full, os.R_OK):
                counts["skipped_unreadable"] += 1
                continue
            files.append(full)
            if len(files) >= MAX_YARA_FILES:
                return files, counts, True
    return files, counts, False


def _p_yara_scan(p: dict[str, Any]) -> dict[str, Any]:
    path = _resolve_scan_path(p["path"])  # refuse an out-of-scope path whether or not yara exists
    if resolve_binary("yara") is None:
        raise ProbeMissing("yara is not installed on this box")
    rules, problems = yara_rule_files(p["ruleset"])
    if not rules:
        return {"status": "error", "reason": "no YARA rules on this box"
                + (f" ({'; '.join(problems)})" if problems else "")
                + f" -- the agent ships a starter set; add your own .yar files to {LOCAL_YARA_DIR} (root-owned)"}
    files, counts, file_cap = _walk_scan_files(path)
    if not files:
        return {"matches": [], "files_scanned": 0, "scan_path": path, "rule_files": [os.path.basename(r) for r in rules],
                "rule_problems": problems, "truncated": False, **counts}
    # The file list goes to yara on stdin (--scan-list /dev/stdin): nothing is
    # written to disk. -s gives offsets; the matched bytes are dropped below
    # and never leave this box.
    r = run_capped(["yara", "-w", "-s", *rules, "--scan-list", "/dev/stdin"],
                   timeout=PROBE_TIMEOUT_SECONDS["yara_scan"], cap=8 * 1024 * 1024,
                   stdin_text="\n".join(files) + "\n")
    if r["returncode"] not in (0, 1) and not r["stdout"].strip():
        detail = r["stderr"].strip().splitlines()
        msg = detail[0] if detail else f"yara exited {r['returncode']}"
        if "scan-list" in r["stderr"]:
            msg = "this box's yara is too old for list scanning (needs yara 4.0 or newer)"
        return {"status": "error", "reason": f"yara failed: {msg}"}
    matches = parse_yara_output(r["stdout"], include_content=False)
    truncated = r["truncated"] or file_cap or len(matches) > MAX_YARA_MATCHES
    for m in matches:
        m["strings"] = m["strings"][:20]
    return {
        "matches": matches[:MAX_YARA_MATCHES], "files_scanned": len(files), "scan_path": path,
        "rule_files": [os.path.basename(x) for x in rules], "rule_problems": problems,
        "truncated": truncated, "file_limit_hit": file_cap, **counts,
    }


_PROBES: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "clock": _p_clock, "journal_fetch": _p_journal_fetch, "journal_auth": _p_journal_auth,
    "open_files": _p_open_files, "processes": _p_processes, "file_hashes": _p_file_hashes,
    "config_audit": _p_config_audit, "capabilities": _p_capabilities, "yara_scan": _p_yara_scan,
    "measure_auth": _p_measure_auth, "privileged_accounts": _p_privileged_accounts,
}
assert set(_PROBES) == set(READ_PROBES)


def run_probe(probe: str, params: Any) -> dict[str, Any]:
    """Validate, run, and return a reply body for protocol.build_read_result:
    {status: ok, data} | {status: unsupported|refused|not_installed|timed_out|error, reason}.
    Never raises."""
    if probe not in _PROBES:
        return {"status": "unsupported", "reason": f"this agent has no {probe!r} read",
                "available": list(READ_PROBES)}
    try:
        clean = validate_params(probe, params)
        data = _PROBES[probe](clean)
    except ReadParamError as e:
        return {"status": "refused", "reason": str(e)}
    except ProbeMissing as e:
        return {"status": "not_installed", "reason": str(e)}
    except ProbeTimeout as e:
        return {"status": "timed_out", "reason": f"{probe} {e} on the box"}
    except Exception as e:  # noqa: BLE001 -- a probe failure is a reply, never a crash
        return {"status": "error", "reason": f"{probe} failed: {type(e).__name__}: {e}"}
    if data.get("status") == "error":
        return {"status": "error", "reason": data.get("reason") or f"{probe} failed"}
    return {"status": "ok", "data": data}
