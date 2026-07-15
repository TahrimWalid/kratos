"""
SSH remote execution against the configured Kratos target device.

Centralizes the SSH subprocess/argv-building logic so tools don't duplicate
it, plus a handful of higher-level fetchers (journalctl, open files,
processes, file hashes, config audit) built on top of it. All commands here
are fixed and parameterized (never an arbitrary caller-supplied shell
string) -- the same trust class as adapters/nmap_scan.py, not the generic
command-runner tool.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.kratos_config import (
    SSH_TARGET_HOST,
    SSH_TARGET_USER,
    SSH_TARGET_KEY_PATH,
    SSH_CONNECT_TIMEOUT_SECONDS,
    SSH_COMMAND_TIMEOUT_SECONDS,
    YARA_SCAN_TIMEOUT_SECONDS,
)


@dataclass
class SSHResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str


def target_label() -> str:
    return f"{SSH_TARGET_USER}@{SSH_TARGET_HOST}"


def _base_ssh_argv() -> list[str]:
    return [
        "ssh",
        "-i", str(SSH_TARGET_KEY_PATH),
        "-o", "BatchMode=yes",  # never prompt -- fail fast instead of hanging
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
        f"{SSH_TARGET_USER}@{SSH_TARGET_HOST}",
    ]


def run_remote_command(command: str, timeout: int | None = None) -> SSHResult:
    """Run a single command string on the target over SSH."""
    try:
        result = subprocess.run(
            _base_ssh_argv() + [command],
            capture_output=True,
            text=True,
            timeout=timeout or SSH_COMMAND_TIMEOUT_SECONDS,
        )
        return SSHResult(ok=result.returncode == 0, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr=f"SSH command timed out after {timeout or SSH_COMMAND_TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr="ssh binary not found on PATH")


def run_remote_script(script: str, timeout: int | None = None) -> SSHResult:
    """Run a multi-line script on the target via `bash -s`, fed over stdin (avoids shell-quoting a large one-liner)."""
    try:
        result = subprocess.run(
            _base_ssh_argv() + ["bash", "-s"],
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout or SSH_COMMAND_TIMEOUT_SECONDS,
        )
        return SSHResult(ok=result.returncode == 0, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr=f"SSH script timed out after {timeout or SSH_COMMAND_TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr="ssh binary not found on PATH")


# ---------------------------------------------------------------------------
# journalctl
# ---------------------------------------------------------------------------
def _parse_journal_entry(raw: dict[str, Any]) -> dict[str, Any]:
    ts_micro = raw.get("__REALTIME_TIMESTAMP")
    timestamp = None
    if ts_micro:
        try:
            timestamp = datetime.fromtimestamp(int(ts_micro) / 1_000_000).isoformat(timespec="seconds")
        except (ValueError, OSError, OverflowError):
            timestamp = None
    return {
        "timestamp": timestamp,
        "unit": raw.get("_SYSTEMD_UNIT") or raw.get("SYSLOG_IDENTIFIER"),
        "message": raw.get("MESSAGE"),
        "priority": raw.get("PRIORITY"),
    }


def fetch_journalctl_entries(unit: str | None, since: str | None, lines: int) -> SSHResult | list[dict[str, Any]]:
    # sudo -n: without it, journald's default per-user ACL silently hides
    # privileged entries (e.g. PAM/sshd authentication-failure lines) from
    # an unprivileged user's query -- confirmed live: a plain `journalctl
    # _COMM=sshd` from the SSH user returned zero "Failed password" lines
    # for a real, just-run attack, while the identical query with sudo
    # returned them correctly. -n (non-interactive): fail fast rather than
    # hang if passwordless sudo isn't configured, matching this file's
    # existing convention (see run_config_audit_checks's `sudo -n sshd -T`).
    parts = ["sudo", "-n", "journalctl", "--no-pager", "-o", "json"]
    if unit:
        # Plain `-u <unit>` filters on _SYSTEMD_UNIT only -- but daemons like
        # sshd are commonly logged under a per-connection scope unit (e.g.
        # "session-375.scope" on the real target), never the literal
        # "sshd.service" a caller would naturally pass, so `-u sshd.service`
        # silently returns zero results despite real sshd activity existing
        # (confirmed live: this happened investigating a real attack --
        # read_journalctl(unit="sshd.service") returned 0 entries while the
        # attack's real log lines were sitting right there under a
        # different unit name). Match on BOTH _SYSTEMD_UNIT and _COMM
        # (identifier, stripped of a trailing ".service") via journalctl's
        # `+` OR-separator -- the exact same two-field pattern fail2ban's
        # own sshd jail uses for the same reason (confirmed via
        # `fail2ban-client status sshd`: "Journal matches: _SYSTEMD_UNIT=
        # sshd.service + _COMM=sshd"). Can only broaden matches (OR), never
        # narrows away a real match for daemons where the literal unit name
        # IS how they're actually logged.
        base = unit[: -len(".service")] if unit.endswith(".service") else unit
        parts += [f"_SYSTEMD_UNIT={shlex.quote(unit)}", "+", f"_COMM={shlex.quote(base)}"]
    if since:
        parts += ["--since", shlex.quote(since)]
    parts += ["-n", str(int(lines))]

    result = run_remote_command(" ".join(parts))
    if not result.ok:
        return result

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(_parse_journal_entry(raw))
    return entries


def _parse_journal_entry_for_auth(raw: dict[str, Any]) -> tuple[str, str | None, str]:
    """
    Same __REALTIME_TIMESTAMP handling as _parse_journal_entry, but returns
    SYSLOG_IDENTIFIER/_COMM (e.g. "sshd", "sudo") instead of _SYSTEMD_UNIT --
    SSH sessions are logged under a generic per-connection "session-N.scope"
    unit (confirmed against the real target: _SYSTEMD_UNIT is "session-375.
    scope" for actual sshd log lines, not "sshd.service"), which is useless
    for auth-event classification, while SYSLOG_IDENTIFIER reliably says
    "sshd"/"sudo" regardless of which per-session scope logged it.
    """
    ts_micro = raw.get("__REALTIME_TIMESTAMP")
    timestamp = None
    if ts_micro:
        try:
            timestamp = datetime.fromtimestamp(int(ts_micro) / 1_000_000).isoformat(timespec="seconds")
        except (ValueError, OSError, OverflowError):
            timestamp = None
    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")
    identifier = raw.get("SYSLOG_IDENTIFIER") or raw.get("_COMM")
    return timestamp, identifier, raw.get("MESSAGE") or ""


def fetch_journalctl_auth_entries(max_lines_per_identifier: int = 500) -> tuple[list[tuple[str, str | None, str]], list[str]]:
    """
    Fetches sshd + sudo journal entries from the target over SSH, mirroring
    adapters/auth_log_parse.py::collect_journald_lines's local equivalent
    (two separate _COMM-filtered queries) instead of a generic recent-N-
    entries scan -- a generic scan can be crowded out entirely by unrelated
    service noise on a busy target (confirmed in Kratos's own live
    attack-detection testing: a 200-entry general query returned mostly
    systemd startup noise, zero sshd lines).

    Returns (entries, errors):
    - entries: (timestamp, identifier, message) tuples, ready for
      adapters/auth_log_parse.py::classify_auth_message.
    - errors: one string per _COMM query that failed (e.g. the connection
      was refused/banned mid-investigation -- see the fail2ban-collateral-
      ban finding from live testing). A partial fetch still returns
      whatever succeeded rather than discarding it, but the caller must
      surface `errors` explicitly rather than let a silently-incomplete
      auth picture look complete.
    """
    entries: list[tuple[str, str | None, str]] = []
    errors: list[str] = []
    for identifier in ("sshd", "sudo"):
        # sudo -n: see fetch_journalctl_entries above -- without it, journald's
        # per-user ACL silently hides privileged entries (confirmed live: a
        # real attack's "Failed password" lines were completely invisible to
        # an unprivileged query despite being well within the fetched window).
        result = run_remote_command(f"sudo -n journalctl --no-pager -o json _COMM={identifier} -n {int(max_lines_per_identifier)}")
        if not result.ok:
            errors.append(f"{identifier}: {(result.stderr or result.stdout).strip()}")
            continue
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append(_parse_journal_entry_for_auth(raw))
    return entries, errors


# ---------------------------------------------------------------------------
# lsof
# ---------------------------------------------------------------------------
def fetch_open_files(pid: int | None) -> SSHResult | list[dict[str, str]]:
    parts = ["lsof", "-n", "-P"]
    if pid is not None:
        parts += ["-p", str(int(pid))]

    result = run_remote_command(" ".join(parts))
    if not result.ok:
        return result

    entries = []
    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        cols = line.split(None, 8)
        if len(cols) < 9:
            continue
        command, pid_, user, fd, ftype, _device, _size_off, _node, name = cols
        entries.append({"command": command, "pid": pid_, "user": user, "fd": fd, "type": ftype, "path": name})
    return entries


# ---------------------------------------------------------------------------
# ps aux
# ---------------------------------------------------------------------------
def fetch_processes() -> SSHResult | list[dict[str, str]]:
    result = run_remote_command("ps aux")
    if not result.ok:
        return result

    entries = []
    lines = result.stdout.strip().splitlines()
    for line in lines[1:]:  # skip header
        cols = line.split(None, 10)
        if len(cols) < 11:
            continue
        user, pid, cpu, mem, _vsz, _rss, _tty, _stat, _start, _time, command = cols
        entries.append({"user": user, "pid": pid, "cpu": cpu, "mem": mem, "command": command})
    return entries


# ---------------------------------------------------------------------------
# File integrity (hashing)
# ---------------------------------------------------------------------------
CRITICAL_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab",
)


UNREADABLE_SENTINEL = "<unreadable: permission denied to SSH user>"


def fetch_file_hashes(paths: tuple[str, ...] = CRITICAL_PATHS) -> SSHResult | dict[str, str | None]:
    """
    Returns {path: sha256_hex} for files the SSH user can read, {path: None}
    for files that don't exist at all, and {path: UNREADABLE_SENTINEL} for
    files that exist but the SSH user lacks permission to read (e.g.
    /etc/sudoers is commonly 0440 root:root -- present, but not a MISSING
    file, and not a hash either). A prior version of this only tested
    existence, not readability, so a permission-denied sha256sum silently
    produced an empty string instead of a clear, distinguishable result.
    """
    quoted = " ".join(shlex.quote(p) for p in paths)
    script = (
        f"for f in {quoted}; do "
        'if [ ! -f "$f" ]; then printf \'MISSING\\t%s\\n\' "$f"; '
        'elif [ ! -r "$f" ]; then printf \'UNREADABLE\\t%s\\n\' "$f"; '
        "else printf 'PRESENT\\t%s\\t%s\\n' \"$f\" \"$(sha256sum \"$f\" | cut -d' ' -f1)\"; "
        "fi; done"
    )
    result = run_remote_command(script)
    if not result.ok:
        return result

    hashes: dict[str, str | None] = {}
    for line in result.stdout.strip().splitlines():
        cols = line.split("\t")
        if cols[0] == "PRESENT" and len(cols) == 3 and cols[2]:
            hashes[cols[1]] = cols[2]
        elif cols[0] == "MISSING" and len(cols) == 2:
            hashes[cols[1]] = None
        elif cols[0] == "UNREADABLE" and len(cols) == 2:
            hashes[cols[1]] = UNREADABLE_SENTINEL
    return hashes


# ---------------------------------------------------------------------------
# Config audit
# ---------------------------------------------------------------------------
_CONFIG_AUDIT_SCRIPT = r"""
prl=$(sudo -n sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')
if [ -z "$prl" ]; then
  printf 'ssh_root_login\tUNKNOWN\tCould not determine effective PermitRootLogin (sudo -n sshd -T unavailable)\n'
elif [ "$prl" = "no" ]; then
  printf 'ssh_root_login\tPASS\tRoot login is disabled (PermitRootLogin no)\n'
elif [ "$prl" = "without-password" ] || [ "$prl" = "prohibit-password" ]; then
  printf 'ssh_root_login\tPASS\tRoot login only allowed via key, not password (PermitRootLogin %s)\n' "$prl"
else
  printf 'ssh_root_login\tFAIL\tRoot login permitted (PermitRootLogin %s)\n' "$prl"
fi

pa=$(sudo -n sshd -T 2>/dev/null | grep -i '^passwordauthentication' | awk '{print $2}')
if [ -z "$pa" ]; then
  printf 'ssh_password_auth\tUNKNOWN\tCould not determine effective PasswordAuthentication (sudo -n sshd -T unavailable)\n'
elif [ "$pa" = "no" ]; then
  printf 'ssh_password_auth\tPASS\tKey-only authentication enforced (PasswordAuthentication no)\n'
else
  printf 'ssh_password_auth\tWARN\tPassword authentication is enabled (PasswordAuthentication %s); key-only is stronger\n' "$pa"
fi

fw_found=0
if command -v ufw >/dev/null 2>&1; then
  fw_found=1
  ufw_status=$(sudo -n ufw status 2>/dev/null | head -1)
  if echo "$ufw_status" | grep -qi 'active'; then
    printf 'firewall\tPASS\tufw is active (%s)\n' "$ufw_status"
  else
    printf 'firewall\tFAIL\tufw installed but not active (%s)\n' "$ufw_status"
  fi
elif command -v nft >/dev/null 2>&1; then
  fw_found=1
  nft_rules=$(sudo -n nft list ruleset 2>/dev/null | wc -l)
  if [ "$nft_rules" -gt 0 ]; then
    printf 'firewall\tPASS\tnftables has %s rule line(s) configured\n' "$nft_rules"
  else
    printf 'firewall\tFAIL\tnftables installed but no rules configured\n'
  fi
elif command -v iptables >/dev/null 2>&1; then
  fw_found=1
  ipt_rules=$(sudo -n iptables -L -n 2>/dev/null | grep -vc '^Chain\|^target\|^$')
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
    jails=$(sudo -n fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p')
    ssh_jail=""
    if echo "$jails" | grep -qiw 'sshd'; then
      ssh_jail="sshd"
    elif echo "$jails" | grep -qiw 'ssh'; then
      ssh_jail="ssh"
    fi
    if [ -z "$ssh_jail" ]; then
      printf 'fail2ban_status\tWARN\tfail2ban is installed and active but no SSH-specific jail is configured (jails: %s)\n' "${jails:-none}"
    else
      maxretry=$(sudo -n fail2ban-client get "$ssh_jail" maxretry 2>/dev/null)
      bantime=$(sudo -n fail2ban-client get "$ssh_jail" bantime 2>/dev/null)
      printf 'fail2ban_status\tPASS\tfail2ban active with SSH jail "%s" (maxretry=%s, bantime=%ss) -- reported as-is, not checked against any specific target values\n' "$ssh_jail" "${maxretry:-unknown}" "${bantime:-unknown}"
    fi
  fi
fi
"""


def run_config_audit_checks() -> SSHResult | list[dict[str, str]]:
    result = run_remote_script(_CONFIG_AUDIT_SCRIPT)
    if not result.ok:
        return result

    checks = []
    for line in result.stdout.strip().splitlines():
        cols = line.split("\t", 2)
        if len(cols) != 3:
            continue
        check_id, status, detail = cols
        checks.append({"check": check_id, "status": status, "detail": detail})
    return checks


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------
_YARA_STRING_MATCH_RE = re.compile(r"^0x[0-9a-fA-F]+:")


def _parse_yara_output(stdout: str) -> list[dict[str, Any]]:
    """
    Parses `yara -s` output. Confirmed by real inspection (not assumed from
    docs): string-match lines ("0xOFFSET:$id: matched content") have NO
    leading whitespace in this yara version's output -- an earlier version
    of this parser assumed indentation distinguished a rule-match line
    ("RuleName /matched/path") from a string-match line, which real output
    disproved immediately (both start at column 0). The reliable
    distinguisher instead: a YARA rule identifier can never start with
    "0x" (identifiers must start with a letter or underscore), so a line
    matching ^0x[hex]: is always a string-match continuation of the most
    recent rule-match line, never a new one. Matched string content is
    split on ':' with maxsplit=2 so arbitrary bytes in the matched content
    itself (which may include colons) don't break parsing.
    """
    matches: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if _YARA_STRING_MATCH_RE.match(line) and current is not None:
            string_parts = line.split(":", 2)
            if len(string_parts) == 3:
                offset, identifier, content = string_parts
                current["strings"].append({"offset": offset, "identifier": identifier.strip(), "matched": content.strip()})
        else:
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            rule_name, file_path = parts
            current = {"rule": rule_name, "file": file_path, "strings": []}
            matches.append(current)
    return matches


def fetch_yara_scan(scan_path: str, rules_content: str) -> SSHResult | list[dict[str, Any]]:
    """
    Runs `yara` ON THE TARGET (must be installed there -- see CLAUDE.md
    operational facts) against scan_path, a path that already exists on the
    target. rules_content (the full text of one or more concatenated .yar
    rule files, resolved on the KRATOS HOST side by the caller -- see
    agent/tools.py::tool_run_yara_scan) is pushed to a target-side temp
    file over THIS SAME SSH session via a heredoc (a random per-call
    delimiter, not a fixed one, so rule content that happens to contain a
    line matching a fixed delimiter could never truncate the heredoc
    early), scanned, then removed again on the target regardless of
    outcome -- Kratos never leaves rule files lying around on the target,
    and never pulls the SCANNED FILES' content back to the Kratos host,
    only match results (rule name, file path, offset, matched string) --
    same posture as fetch_file_hashes (compute something about target file
    content ON the target, never transfer the file itself).
    """
    delimiter = f"KRATOS_YARA_RULES_{uuid.uuid4().hex}"
    quoted_path = shlex.quote(scan_path)
    script = (
        "RULES_FILE=$(mktemp /tmp/kratos_yara_rules.XXXXXX.yar)\n"
        f"cat > \"$RULES_FILE\" << '{delimiter}'\n"
        f"{rules_content}\n"
        f"{delimiter}\n"
        f"if [ ! -e {quoted_path} ]; then\n"
        f"  echo 'KRATOS_SCAN_PATH_NOT_FOUND: {quoted_path}' >&2\n"
        "  rm -f \"$RULES_FILE\"\n"
        "  exit 3\n"
        "fi\n"
        f"if [ -d {quoted_path} ]; then YARA_FLAGS=\"-r -s\"; else YARA_FLAGS=\"-s\"; fi\n"
        f"yara $YARA_FLAGS \"$RULES_FILE\" {quoted_path}\n"
        "RC=$?\n"
        "rm -f \"$RULES_FILE\"\n"
        "exit $RC\n"
    )
    # Deliberately its own timeout, not SSH_COMMAND_TIMEOUT_SECONDS -- see
    # kratos_config.py::YARA_SCAN_TIMEOUT_SECONDS for the real-measured
    # justification. A timeout here still means the temp rules file cleanup
    # line in the script above never got to run (the whole remote script
    # was killed mid-execution) -- see the module-level SSH client-timeout
    # cleanup note for why that's still safe.
    result = run_remote_script(script, timeout=YARA_SCAN_TIMEOUT_SECONDS)
    if not result.ok:
        if result.returncode == -1 and "timed out" in result.stderr:
            # Replace run_remote_script's generic "SSH script timed out"
            # wording -- a caller/agent seeing a YARA timeout needs to know
            # this is a scan-scope problem, not a generic SSH/network issue,
            # and that the fix is a narrower scan_path, not a retry.
            return SSHResult(
                ok=False,
                returncode=-1,
                stdout="",
                stderr=(
                    f"YARA scan did not complete within {YARA_SCAN_TIMEOUT_SECONDS}s. "
                    f"scan_path={scan_path!r} is likely too broad for a single scan "
                    "(a real, unmocked test found a full recursive scan of '/' on this "
                    "target still running after 17+ real minutes). Retry with a "
                    "narrower scan_path (e.g. a specific directory like /home or /var/log, "
                    "or a single file) rather than the filesystem root."
                ),
            )
        return result
    return _parse_yara_output(result.stdout)
