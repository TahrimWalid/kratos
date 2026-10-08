"""
SSH remote execution against the configured Kratos target device.

Centralizes the SSH subprocess/argv-building logic so tools don't duplicate
it, plus a handful of higher-level fetchers (journalctl, open files,
processes, file hashes, config audit) built on top of it. All commands here
are fixed and parameterized (never an arbitrary caller-supplied shell
string) -- the same trust class as adapters/nmap_scan.py, not the generic
command-runner tool.

run_remote_command/run_remote_script below are deliberately never wrapped as
their own agent-callable @register_tool, and that's a permanent boundary,
not a "just needs wrapping" TODO -- see docs/DESIGN.md's "Execution
boundary" section for the full rationale. Kratos must never have the
capability to autonomously execute commands or change state on the target,
in any form, generic or narrowly-scoped, even behind human approval-gating.
These two functions exist only to be called internally by other tools'
fixed, read-only actions (journalctl, file hashes, config audit, etc.) --
every one of which only ever reads state, never changes it. Don't add a
general-purpose "run this command on the target" tool on top of these; that
would violate the boundary regardless of how the tool is scoped or gated.

Sub-agent routing (docs/subagent_read_routing.md): a target linked to a paired
sub-agent is read through it by the NAMED fetchers below -- each maps to one
probe in kratos.subagent.reads, which also builds the commands used here, so
both transports run the same reads and share one parser. run_remote_command/
run_remote_script stay SSH-only: their input is free command text, which must
never be sent to an agent, so for a sub-agent-only target they refuse.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import kratos_config as _kconfig
from kratos.subagent import reads as _reads
from kratos.subagent import routing as _routing
from kratos.utils.timeutil import epoch_to_utc_iso, utc_now_iso
from kratos.kratos_config import (
    SSH_TARGET_KEY_PATH,
    SSH_CONNECT_TIMEOUT_SECONDS,
    SSH_COMMAND_TIMEOUT_SECONDS,
    YARA_SCAN_TIMEOUT_SECONDS,
    get_active_target,
)


def _journalctl_prefix() -> list[str]:
    """`["sudo", "-n"]` (default) or `[]` -- see
    kratos_config.py::JOURNALCTL_USE_SUDO. Reads `_kconfig.JOURNALCTL_USE_SUDO`
    via the module itself, not a `from...import`-frozen copy -- a plain
    `from kratos.kratos_config import JOURNALCTL_USE_SUDO` binds the value at
    import time and would never see a later `monkeypatch.setattr(kratos_config,
    ...)` (see docs/DESIGN.md's "Live-switchable settings" section). No live
    REPL command flips this flag today, but there's no reason to reintroduce
    the same footgun for a value tests need to toggle mid-process."""
    return ["sudo", "-n"] if _kconfig.JOURNALCTL_USE_SUDO else []


@dataclass
class SSHResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    # Set by a sub-agent read: its output hit the agent's cap (the newest part
    # was kept), and which way the result came.
    truncated: bool = False
    via: str = "ssh"


def target_label() -> str:
    return f"{_kconfig.ssh_user_for()}@{get_active_target()}"


def _host_key_opts() -> list[str]:
    """Host-key verification options (Sprint 1 backlog #12). Read live from the
    module (not frozen imports) so a mid-process toggle takes effect, matching
    the JOURNALCTL_USE_SUDO pattern. Default is unchanged (accept-new, ssh's own
    known_hosts); an operator on an untrusted network sets
    KRATOS_SSH_STRICT_HOST_KEY_CHECKING=yes + KRATOS_SSH_KNOWN_HOSTS to enforce a
    pinned key (see pin_target_host_key)."""
    opts = ["-o", f"StrictHostKeyChecking={_kconfig.SSH_STRICT_HOST_KEY_CHECKING}"]
    if _kconfig.SSH_KNOWN_HOSTS_PATH is not None:
        opts += ["-o", f"UserKnownHostsFile={_kconfig.SSH_KNOWN_HOSTS_PATH}"]
    return opts


def _base_ssh_argv() -> list[str]:
    # Offer only Kratos's key when it exists: an agent full of other keys can
    # otherwise hit the server's MaxAuthTries ("Too many authentication
    # failures") before this one is ever tried.
    only = ["-o", "IdentitiesOnly=yes"] if Path(SSH_TARGET_KEY_PATH).exists() else []
    return [
        "ssh",
        "-i", str(SSH_TARGET_KEY_PATH),
        *only,
        "-o", "BatchMode=yes",  # never prompt -- fail fast instead of hanging
        *_host_key_opts(),
        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
        f"{_kconfig.ssh_user_for()}@{get_active_target()}",
    ]


def pin_target_host_key(target: str | None = None, known_hosts_path: Path | None = None) -> SSHResult:
    """Pin the target's SSH host key into a Kratos-owned known_hosts (backlog
    #12) via `ssh-keyscan`, so `StrictHostKeyChecking=yes` can then enforce it
    (fail closed on any unknown/changed key) instead of blind first-contact TOFU.
    This is the deliberate, operator-invoked "trust this host's key now" step —
    the one moment first contact is accepted, unlike TOFU where every first
    contact is. Appends to `known_hosts_path` (or the configured
    SSH_KNOWN_HOSTS_PATH); returns an SSHResult (ok=False if keyscan finds
    nothing or no destination file is configured)."""
    host = target or get_active_target()
    if not host:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr=_kconfig.NO_TARGET_MESSAGE)
    dest = known_hosts_path or _kconfig.SSH_KNOWN_HOSTS_PATH
    if dest is None:
        return SSHResult(ok=False, returncode=-1, stdout="",
                         stderr="No known_hosts path configured (set KRATOS_SSH_KNOWN_HOSTS) to pin a key into.")
    try:
        scan = subprocess.run(
            ["ssh-keyscan", "-T", str(SSH_CONNECT_TIMEOUT_SECONDS), host],
            capture_output=True, text=True, timeout=SSH_CONNECT_TIMEOUT_SECONDS + 5,
        )
    except subprocess.TimeoutExpired:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr=f"ssh-keyscan timed out for {host}")
    except FileNotFoundError:
        return SSHResult(ok=False, returncode=-1, stdout="", stderr="ssh-keyscan binary not found on PATH")
    keys = scan.stdout.strip()
    if not keys:
        return SSHResult(ok=False, returncode=scan.returncode, stdout="",
                         stderr=(scan.stderr.strip() or f"ssh-keyscan returned no host key for {host}"))
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("a", encoding="utf-8") as f:
        f.write(keys + "\n")
    return SSHResult(ok=True, returncode=0, stdout=f"Pinned {host} host key(s) into {dest}", stderr="")


def _no_target_result() -> SSHResult | None:
    """Every SSH call funnels through here: with no target set, say so plainly
    instead of running `ssh user@` and surfacing ssh's own confusing error."""
    if get_active_target():
        return None
    return SSHResult(ok=False, returncode=-1, stdout="", stderr=_kconfig.NO_TARGET_MESSAGE)


_SSH_ONLY_MESSAGE = (
    "not available over the sub-agent: {host} is reached only through its sub-agent, which runs "
    "Kratos's built-in reads and nothing else -- this check reads the target over SSH. Set up SSH to "
    "this box (and switch it with /target link) to use it."
)


def _ssh_blocked_result() -> SSHResult | None:
    """Free command text never goes to a sub-agent: for a sub-agent-only
    target, SSH-only callers (kept tools) are told so instead of failing
    with a confusing SSH error."""
    if _routing.is_subagent_only():
        return SSHResult(ok=False, returncode=-1, stdout="",
                         stderr=_SSH_ONLY_MESSAGE.format(host=get_active_target()), via="none")
    return None


def run_remote_command(command: str, timeout: int | None = None) -> SSHResult:
    """Run a single command string on the target over SSH."""
    if (missing := _no_target_result()) is not None:
        return missing
    if (blocked := _ssh_blocked_result()) is not None:
        return blocked
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


def run_remote_script(script: str, timeout: int | None = None, shell: str = "bash") -> SSHResult:
    """Run a multi-line script on the target via `<shell> -s`, fed over stdin (avoids
    shell-quoting a large one-liner). `shell="sh"` for POSIX scripts that must also run on
    hosts without bash (e.g. Alpine) -- timewin.measure's counter is one."""
    if (missing := _no_target_result()) is not None:
        return missing
    if (blocked := _ssh_blocked_result()) is not None:
        return blocked
    try:
        result = subprocess.run(
            _base_ssh_argv() + [shell, "-s"],
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
# SSH or sub-agent
# ---------------------------------------------------------------------------
def _ssh_unreachable(result: SSHResult) -> bool:
    """ssh's own failures (can't connect, auth refused, host key) exit 255;
    a missing ssh binary is reported as -1. A remote command's own non-zero
    exit, or a command that ran too long, is NOT a reason to switch paths."""
    return result.returncode == 255 or (result.returncode == -1 and "ssh binary not found" in result.stderr)


def _first_line(text: str, limit: int = 160) -> str:
    line = next((ln.strip() for ln in (text or "").splitlines() if ln.strip()), "")
    return line[:limit] or "no detail"


def agent_result(reply: dict[str, Any]) -> SSHResult:
    """A sub-agent raw-output reply as the SSHResult the SSH path would give,
    so one parser serves both transports."""
    if reply.get("status") == "ok" and isinstance(reply.get("data"), dict):
        data = reply["data"]
        rc = data.get("returncode") if isinstance(data.get("returncode"), int) else -1
        return SSHResult(ok=rc == 0, returncode=rc, stdout=str(data.get("stdout") or ""),
                         stderr=str(data.get("stderr") or ""), truncated=bool(data.get("truncated")),
                         via="subagent")
    return SSHResult(ok=False, returncode=-1, stdout="", via="subagent",
                     stderr=f"via the sub-agent: {reply.get('reason') or reply.get('status') or 'read failed'}")


def _route(probe: str, params: dict[str, Any], ssh_call: Any, *, agent_call: Any = None) -> Any:
    """Run one named read the right way for the active target:
    no link -> SSH, unchanged; "subagent" link -> the agent only;
    "ssh_first" -> SSH, and on an SSH connection failure the same read via
    the agent (remembered briefly so one investigation doesn't wait out the
    SSH timeout on every read). Leaves a transport note either way.
    `agent_call(link)` overrides the default raw-output conversion."""
    link = _routing.active_link()
    if link is None:
        return ssh_call()

    def via_agent() -> Any:
        if agent_call is not None:
            return agent_call(link)
        return agent_result(_routing.agent_read(link, probe, params))

    if link.mode == _routing.MODE_SUBAGENT:
        _routing.note(f"read through its sub-agent ({link.label})")
        return via_agent()
    down = _routing.ssh_down_reason(link.host)
    if down is None:
        result = ssh_call()
        if not (isinstance(result, SSHResult) and _ssh_unreachable(result)):
            return result
        down = _first_line(result.stderr)
        _routing.mark_ssh_down(link.host, down)
    out = via_agent()
    _routing.note(f"SSH to {link.host} failed ({down}); read through its sub-agent ({link.label}) instead")
    if isinstance(out, SSHResult) and not out.ok and out.via == "subagent":
        out.stderr = f"SSH failed ({down}); {out.stderr}"
    return out


# ---------------------------------------------------------------------------
# journalctl
# ---------------------------------------------------------------------------
def _parse_journal_entry(raw: dict[str, Any]) -> dict[str, Any]:
    ts_micro = raw.get("__REALTIME_TIMESTAMP")
    timestamp = None
    if ts_micro:
        try:
            # __REALTIME_TIMESTAMP is epoch microseconds -- an absolute UTC
            # instant, independent of the TARGET's own local timezone -- so
            # UTC is the correct, lossless normalization. The previous
            # datetime.fromtimestamp() (no tz) silently rebased it onto the
            # KRATOS HOST's local zone and stored it naive, which broke as
            # soon as the host and target zones differed, or the host
            # travelled between sessions.
            timestamp = epoch_to_utc_iso(int(ts_micro) / 1_000_000)
        except (ValueError, OSError, OverflowError):
            timestamp = None
    return {
        "timestamp": timestamp,
        "unit": raw.get("_SYSTEMD_UNIT") or raw.get("SYSLOG_IDENTIFIER"),
        "message": raw.get("MESSAGE"),
        "priority": raw.get("PRIORITY"),
    }


@dataclass
class JournalWindow:
    """What a journal fetch actually covered -- see _window_args. `truncated` means
    the window held MORE than the requested number of entries, so only the newest
    ones were returned and everything before `oldest_returned` (back to
    `since_epoch`) was NOT seen."""
    since_epoch: float | None
    until_epoch: float | None
    requested: int
    returned: int
    truncated: bool
    oldest_returned: str | None
    newest_returned: str | None


# ---------------------------------------------------------------------------
# Target clock offset (docs/time_window_design.md §2D)
# ---------------------------------------------------------------------------
# journald stamps entries with the TARGET's clock. If that clock is wrong, a window
# computed on Kratos's clock is misaligned: live test, target 7 min behind -> a
# "last 5 minutes" query returned 0 of 8 attack lines sent seconds earlier, and the
# investigation answered "no failed SSH login attempts". Measured once per target and
# cached briefly; callers shift window bounds by it and report it.
CLOCK_OFFSET_TTL_SECONDS = 300.0
CLOCK_OFFSET_WARN_SECONDS = 60.0
_clock_offset_cache: dict[str, tuple[float, float | None]] = {}


def measure_target_clock_offset(force: bool = False) -> float | None:
    """Seconds the target's clock is AHEAD of Kratos's (negative = behind), from
    `date +%s.%N` over SSH against the round-trip midpoint. None if it can't be
    measured (the caller then applies no correction and says so)."""
    import time as _time

    host = get_active_target()
    cached = _clock_offset_cache.get(host)
    if cached and not force and _time.time() - cached[0] < CLOCK_OFFSET_TTL_SECONDS:
        return cached[1]
    t0 = _time.time()
    result = _route("clock", {}, lambda: run_remote_command(_reads.CLOCK_COMMAND))
    t1 = _time.time()
    offset: float | None = None
    if result.ok:
        try:
            offset = float(result.stdout.strip()) - (t0 + t1) / 2
        except ValueError:
            offset = None
    _clock_offset_cache[host] = (t1, offset)
    return offset


# Shared with the sub-agent (kratos.subagent.reads) -- see its docstring for why
# every fetch is `--reverse -n <lines+1>` with absolute epochs.
_window_args = _reads.window_args


def _take_newest(raw_newest_first: list[dict[str, Any]], lines: int) -> tuple[list[dict[str, Any]], bool]:
    truncated = len(raw_newest_first) > lines
    kept = raw_newest_first[:lines]
    kept.reverse()  # back to chronological order for every consumer
    return kept, truncated


def _parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def fetch_journalctl_entries(
    unit: str | None,
    since_epoch: float | None,
    lines: int,
    until_epoch: float | None = None,
) -> SSHResult | tuple[list[dict[str, Any]], JournalWindow]:
    # sudo -n (default) or nothing at all if the target's SSH user is in the
    # systemd-journal group instead (see _journalctl_prefix, kratos_config.py
    # ::JOURNALCTL_USE_SUDO, adapters/target_setup.py). Either way, PLAIN
    # unprivileged journalctl with neither is the broken case: journald's
    # default per-user ACL silently hides privileged entries (e.g. PAM/sshd
    # authentication-failure lines) -- confirmed live: a plain `journalctl
    # _COMM=sshd` from an SSH user with neither sudo nor journal-group access
    # returned zero "Failed password" lines for a real, just-run attack,
    # while the identical query with sudo returned them correctly. -n
    # (non-interactive, sudo path only): fail fast rather than hang if
    # passwordless sudo isn't configured, matching this file's existing
    # convention (see run_config_audit_checks's `sudo -n sshd -T`).
    # unit: plain `-u <unit>` filters on _SYSTEMD_UNIT only, but daemons like
    # sshd are commonly logged under a per-connection scope unit (e.g.
    # "session-375.scope"), never the literal "sshd.service" -- confirmed live:
    # read_journalctl(unit="sshd.service") returned 0 entries while a real
    # attack's lines sat under a different unit. The shared builder matches
    # _SYSTEMD_UNIT OR _COMM (journalctl's `+`), the same two-field pattern
    # fail2ban's own sshd jail uses; it can only broaden matches.
    argv = _reads.journal_fetch_argv(unit, since_epoch, until_epoch, int(lines), prefix=_journalctl_prefix())
    agent_lines = min(int(lines), 5000)  # the agent's per-read ceiling
    params = {"unit": unit or None, "since": since_epoch, "until": until_epoch, "lines": agent_lines}
    result = _route("journal_fetch", params, lambda: run_remote_command(shlex.join(argv)))
    if not result.ok:
        return result
    if result.via == "subagent":
        lines = agent_lines

    newest_first = [_parse_journal_entry(raw) for raw in _parse_json_lines(result.stdout)]
    entries, truncated = _take_newest(newest_first, int(lines))
    truncated = truncated or result.truncated
    window = JournalWindow(
        since_epoch=since_epoch,
        until_epoch=until_epoch,
        requested=int(lines),
        returned=len(entries),
        truncated=truncated,
        oldest_returned=entries[0].get("timestamp") if entries else None,
        newest_returned=entries[-1].get("timestamp") if entries else None,
    )
    return entries, window


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
            # Absolute UTC instant -- see _parse_journal_entry for why UTC is
            # the correct normalization of journald's epoch timestamp.
            timestamp = epoch_to_utc_iso(int(ts_micro) / 1_000_000)
        except (ValueError, OSError, OverflowError):
            timestamp = None
    if timestamp is None:
        timestamp = utc_now_iso()
    identifier = raw.get("SYSLOG_IDENTIFIER") or raw.get("_COMM")
    return timestamp, identifier, raw.get("MESSAGE") or ""


def fetch_journalctl_auth_entries(
    max_lines_per_identifier: int = 500,
    since_epoch: float | None = None,
    until_epoch: float | None = None,
) -> tuple[list[tuple[str, str | None, str]], list[str], dict[str, JournalWindow]]:
    """
    Fetches sshd + sudo journal entries from the target over SSH, mirroring
    adapters/auth_log_parse.py::collect_journald_lines's local equivalent
    (two separate _COMM-filtered queries) instead of a generic recent-N-
    entries scan -- a generic scan on a busy target gets crowded out by
    unrelated service noise (systemd startup chatter, etc.) before it ever
    reaches an sshd or sudo line.

    `since_epoch`/`until_epoch`: absolute UTC bounds (resolved Kratos-side by
    kratos.utils.time_window), applied to both per-identifier queries via
    _window_args -- i.e. the NEWEST `max_lines_per_identifier` entries in the
    window, on every systemd version. (An earlier version of this docstring
    claimed plain `--since X -n N` already meant "most recent N since X"; that is
    false on systemd 249, where it returns the OLDEST N -- see _window_args.)
    None/None preserves unscoped most-recent-N behavior. This exists because this fetch runs as a background
    side-effect of every read_journalctl call (feeding correlate_findings)
    independently of the tool's own primary query -- without threading
    `since` through here too, a caller-scoped primary query (e.g. "last 24
    hours") would still silently correlate against an unscoped, unknown-age
    snapshot underneath it.

    Returns (entries, errors, windows):
    - entries: (timestamp, identifier, message) tuples, ready for
      adapters/auth_log_parse.py::classify_auth_message.
    - windows: per-identifier JournalWindow -- `truncated=True` means that
      identifier's events before `oldest_returned` were not seen, which the
      caller must surface (a silently partial window looks complete).
    - errors: one string per _COMM query that failed (e.g. the connection
      was refused/banned mid-investigation -- see the fail2ban-collateral-
      ban finding from live testing). A partial fetch still returns
      whatever succeeded rather than discarding it, but the caller must
      surface `errors` explicitly rather than let a silently-incomplete
      auth picture look complete.
    """
    entries: list[tuple[str, str | None, str]] = []
    errors: list[str] = []
    windows: dict[str, JournalWindow] = {}
    # OpenSSH >= 9.8 logs per-connection auth events (incl. "Invalid user"/"Failed
    # password") from a separate `sshd-session` process, not `sshd` -- confirmed live on
    # Rocky 9 (OpenSSH 9.9: 0 invalid-user lines under _COMM=sshd, 4 under sshd-session)
    # and Alpine 3.22. Filtering on `sshd` alone left the correlation engine blind to
    # SSH brute force on every current distro. Repeating a field ORs it in journalctl
    # (verified on systemd 249 and 252); hosts with older OpenSSH are unaffected.
    # (The comm lists live in kratos.subagent.reads.AUTH_COMMS, shared with the agent.)
    for identifier in _reads.AUTH_COMMS:
        # _journalctl_prefix(): see fetch_journalctl_entries above -- without
        # sudo OR systemd-journal group membership, journald's per-user ACL
        # silently hides privileged entries (confirmed live: a real attack's
        # "Failed password" lines were completely invisible to an
        # unprivileged query despite being well within the fetched window).
        argv = _reads.journal_auth_argv(identifier, since_epoch, until_epoch, int(max_lines_per_identifier),
                                        prefix=_journalctl_prefix())
        per_id = int(max_lines_per_identifier)
        params = {"identifier": identifier, "since": since_epoch, "until": until_epoch, "lines": min(per_id, 2000)}
        result = _route("journal_auth", params, lambda argv=argv: run_remote_command(shlex.join(argv)))
        if not result.ok:
            errors.append(f"{identifier}: {(result.stderr or result.stdout).strip()}")
            continue
        if result.via == "subagent":
            per_id = min(per_id, 2000)
        parsed = [_parse_journal_entry_for_auth(raw) for raw in _parse_json_lines(result.stdout)]
        truncated = len(parsed) > per_id or result.truncated
        kept = parsed[:per_id]
        kept.reverse()  # chronological
        entries.extend(kept)
        windows[identifier] = JournalWindow(
            since_epoch=since_epoch,
            until_epoch=until_epoch,
            requested=per_id,
            returned=len(kept),
            truncated=truncated,
            oldest_returned=kept[0][0] if kept else None,
            newest_returned=kept[-1][0] if kept else None,
        )
    return entries, errors, windows


# ---------------------------------------------------------------------------
# lsof
# ---------------------------------------------------------------------------
def fetch_open_files(pid: int | None) -> SSHResult | list[dict[str, str]]:
    argv = _reads.lsof_argv(pid)
    result = _route("open_files", {"pid": int(pid) if pid is not None else None},
                    lambda: run_remote_command(" ".join(argv)))
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
    result = _route("processes", {}, lambda: run_remote_command(" ".join(_reads.PS_ARGV)))
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
CRITICAL_PATHS: tuple[str, ...] = _reads.CRITICAL_PATHS


UNREADABLE_SENTINEL = "<unreadable: permission denied to SSH user>"
AGENT_UNREADABLE_SENTINEL = "<unreadable: permission denied to the sub-agent>"


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
    def via_agent(link: Any) -> SSHResult | dict[str, str | None]:
        if tuple(paths) != CRITICAL_PATHS:  # the agent hashes only its own fixed list
            return SSHResult(ok=False, returncode=-1, stdout="", via="subagent",
                             stderr="via the sub-agent: only Kratos's fixed critical-file list can be hashed")
        return agent_result(_routing.agent_read(link, "file_hashes", {}))

    result = _route("file_hashes", {}, lambda: run_remote_command(_reads.file_hash_script(tuple(paths))),
                    agent_call=via_agent)
    if not result.ok:
        return result
    marker = AGENT_UNREADABLE_SENTINEL if result.via == "subagent" else UNREADABLE_SENTINEL
    return _reads.parse_hash_lines(result.stdout, marker)


# ---------------------------------------------------------------------------
# Config audit
# ---------------------------------------------------------------------------
# The script itself lives in kratos.subagent.reads (shared with the agent); over
# SSH it reads sshd -T / firewall / fail2ban through `sudo -n`.
_CONFIG_AUDIT_SCRIPT = _reads.config_audit_script("sudo -n")


def run_config_audit_checks() -> SSHResult | list[dict[str, str]]:
    result = _route("config_audit", {}, lambda: run_remote_script(_CONFIG_AUDIT_SCRIPT))
    if not result.ok:
        return result
    return _reads.parse_check_lines(result.stdout)


# ---------------------------------------------------------------------------
# Target setup probe (2026-07-18) -- read-only companion to
# adapters/target_setup.py::generate_target_setup_checklist. Same trust
# class as run_config_audit_checks above (status-only commands, nothing
# mutates target state): confirms what a human actually accomplished by
# running the checklist's commands, rather than Kratos silently discovering
# a missing capability mid-investigation. Deliberately one round trip (one
# script, like _CONFIG_AUDIT_SCRIPT) instead of one SSH call per check --
# each real SSH connection setup has real, measurable latency, and this
# runs synchronously in the middle of a REPL command, not the background.
# ---------------------------------------------------------------------------
_TARGET_PROBE_SCRIPT = r"""
printf 'ssh_reachable\tPASS\tConnected as %s\n' "$(whoami)"

if groups | tr ' ' '\n' | grep -qx systemd-journal; then
  printf 'journalctl_access\tPASS\tIn systemd-journal group -- no sudo needed for journalctl\n'
elif sudo -n journalctl -n 1 >/dev/null 2>&1; then
  printf 'journalctl_access\tPASS\tsudo -n journalctl works\n'
else
  printf 'journalctl_access\tFAIL\tNeither systemd-journal group membership nor sudo -n journalctl works -- read_journalctl will silently miss privileged entries\n'
fi

if sudo -n sshd -T >/dev/null 2>&1; then
  printf 'sudo_sshd_config\tPASS\tsudo -n sshd -T works\n'
else
  printf 'sudo_sshd_config\tFAIL\tsudo -n sshd -T not permitted -- run_config_audit will report ssh_root_login/ssh_password_auth as UNKNOWN\n'
fi

if sudo -n ufw status >/dev/null 2>&1 || sudo -n nft list ruleset >/dev/null 2>&1 || sudo -n iptables -L -n >/dev/null 2>&1; then
  printf 'sudo_firewall_status\tPASS\tPasswordless sudo works for the installed firewall tool\n'
else
  printf 'sudo_firewall_status\tFAIL\tNo passwordless sudo for ufw/nft/iptables status -- run_config_audit will report firewall as UNKNOWN\n'
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  f2b_err=$(sudo -n fail2ban-client status 2>&1 >/dev/null)
  f2b_rc=$?
  if [ "$f2b_rc" -eq 0 ]; then
    printf 'sudo_fail2ban\tPASS\tsudo -n fail2ban-client works\n'
  elif printf '%s' "$f2b_err" | grep -qi 'password is required\|not allowed to run\|sorry, user'; then
    printf 'sudo_fail2ban\tFAIL\tsudo -n fail2ban-client not permitted -- run_config_audit will report fail2ban_status incompletely\n'
  else
    printf 'sudo_fail2ban\tFAIL\tsudo -n fail2ban-client IS permitted, but the command itself failed (fail2ban service is likely installed but not running -- try: sudo systemctl enable --now fail2ban) -- run_config_audit will report fail2ban_status incompletely\n'
  fi
else
  printf 'sudo_fail2ban\tUNKNOWN\tfail2ban-client not found on target\n'
fi

if command -v yara >/dev/null 2>&1; then
  printf 'yara_installed\tPASS\tyara found on target\n'
else
  printf 'yara_installed\tFAIL\tyara not installed -- run_yara_scan will fail\n'
fi

if command -v lsof >/dev/null 2>&1; then
  printf 'lsof_installed\tPASS\tlsof found on target\n'
else
  printf 'lsof_installed\tFAIL\tlsof not installed -- list_open_files will fail\n'
fi

# Target timezone (informational). Kratos reads target logs via journalctl's
# JSON __REALTIME_TIMESTAMP, which is an absolute UTC epoch regardless of this
# setting -- so target-log storage is already correct no matter what this
# says. It's surfaced only so an operator interpreting RAW TEXT log lines
# (which are printed in the target's local zone) knows which zone those are
# in. Never FAIL: a target's zone is a fact to report, not a misconfiguration.
tz_name="$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo unknown)"
printf 'target_timezone\tINFO\tTarget system timezone: %s (journald log timestamps are stored as absolute UTC regardless)\n' "$tz_name"
"""


def run_target_probe_checks() -> SSHResult | list[dict[str, str]]:
    """Read-only capability check for the CURRENTLY ACTIVE target (resolved
    via get_active_target(), same chokepoint as every other fetcher in this
    file -- no separate target parameter needed). Returns SSHResult on
    connection failure (target unreachable at all -- port 22 blocked, wrong
    host, etc.), else a list of {check, status, detail} dicts, same shape as
    run_config_audit_checks. Note the fail2ban `ignoreip` requirement from
    adapters/target_setup.py's checklist is NOT checked here -- verifying it
    needs guessing a jail name and adds fragility for one line of a larger
    checklist; left as a manual step, called out with extra emphasis in the
    checklist text itself given it's a real, previously-hit failure mode
    (Kratos's own SSH traffic getting itself banned mid-investigation)."""
    result = _route("capabilities", {}, lambda: run_remote_script(_TARGET_PROBE_SCRIPT),
                    agent_call=agent_capabilities)
    if isinstance(result, list) or not result.ok:
        return result
    return _reads.parse_check_lines(result.stdout)


def agent_capabilities(link: Any) -> SSHResult | list[dict[str, str]]:
    """The sub-agent edition of the setup probe: what the agent can read on
    its box, led by a row saying how the box is reached."""
    reply = _routing.agent_read(link, "capabilities", {})
    if reply.get("status") != "ok" or not isinstance(reply.get("data"), dict):
        return agent_result(reply)
    checks = [c for c in reply["data"].get("checks") or [] if isinstance(c, dict)]
    head = {"check": "subagent_reachable", "status": "PASS",
            "detail": f"Connected through the sub-agent on {link.label} ({_routing.MODE_LABELS[link.mode]})"}
    return [head, *checks]


# ---------------------------------------------------------------------------
# YARA scanning
# ---------------------------------------------------------------------------
_parse_yara_output = _reads.parse_yara_output  # shared with the sub-agent


class YaraMatches(list):
    """The match list, plus what a sub-agent scan reports about its own scope
    (files scanned, credential/unreadable files skipped, truncation) in
    `.scan_info` -- empty for an SSH scan."""

    scan_info: dict[str, Any]

    def __init__(self, items: Any = (), scan_info: dict[str, Any] | None = None):
        super().__init__(items)
        self.scan_info = scan_info or {}


def _yara_via_agent(link: Any, scan_path: str, custom_rules: bool) -> SSHResult | YaraMatches:
    if custom_rules:
        return SSHResult(ok=False, returncode=-1, stdout="", via="subagent", stderr=(
            "via the sub-agent: custom rules can't be sent to a sub-agent (a rule sent from Kratos could be "
            "used to read file contents back). Place them on the box in /etc/kratos-subagent/yara/ "
            "(root-owned) and scan again without rules_path."))
    reply = _routing.agent_read(link, "yara_scan", {"path": scan_path})
    if reply.get("status") != "ok" or not isinstance(reply.get("data"), dict):
        reason = reply.get("reason") or reply.get("status")
        if reply.get("status") == "refused" and "scan roots" in str(reason):
            reason = f"{reason}. Through the sub-agent YARA only scans those places."
        return SSHResult(ok=False, returncode=-1, stdout="", via="subagent", stderr=f"via the sub-agent: {reason}")
    data = reply["data"]
    info = {k: data.get(k) for k in ("files_scanned", "skipped_credential", "skipped_unreadable", "skipped_large",
                                      "truncated", "file_limit_hit", "rule_files", "rule_problems", "scan_path")}
    info["matched_content"] = "not returned through the sub-agent (rule, file and offset only)"
    return YaraMatches(data.get("matches") or [], info)


# Where malware is usually dropped or served from. A bounded default for "scan
# the system for malicious files" -- never '/' (a full recursive scan runs far
# past any practical timeout, see YARA_SCAN_TIMEOUT_SECONDS).
DEFAULT_YARA_SWEEP_PATHS: tuple[str, ...] = (
    "/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/usr/local/bin", "/usr/local/sbin",
)
_YARA_SCANNED_MARK = "KRATOS_SCANNED\t"
_YARA_ERRORS_MARK = "KRATOS_ERRORS\t"
_YARA_UNREADABLE_MARK = "KRATOS_UNREADABLE\t"
_YARA_SKIPPED_MARK = "KRATOS_SKIPPED\t"


def _yara_sweep_via_agent(link: Any, paths: tuple[str, ...], custom_rules: bool) -> SSHResult | dict[str, Any]:
    """The sweep through a sub-agent: one named yara_scan read per root (the
    agent never takes a path list), each under its own scope rules -- the box's
    own rules, credential files skipped, rule/file/offset only."""
    if custom_rules:
        return _yara_via_agent(link, "", custom_rules=True)
    matches: list[dict[str, Any]] = []
    scanned: list[str] = []
    notes: list[str] = []
    for path in paths:
        reply = _routing.agent_read(link, "yara_scan", {"path": path})
        status, reason = reply.get("status"), str(reply.get("reason") or "")
        if status == "ok" and isinstance(reply.get("data"), dict):
            data = reply["data"]
            scanned.append(path)
            matches.extend(data.get("matches") or [])
            skipped = [f"{data[k]} {label}" for k, label in (("skipped_credential", "credential file(s)"),
                                                             ("skipped_unreadable", "unreadable item(s)"),
                                                             ("skipped_large", "file(s) over 64 MB"))
                       if data.get(k)]
            if skipped:
                notes.append(f"Inside {path}, {', '.join(skipped)} were skipped.")
            if data.get("truncated"):
                notes.append(f"The scan of {path} stopped at its file or match limit.")
        elif status == "refused" and "does not exist" in reason:
            continue  # not on this box -- reported as not present
        else:
            return SSHResult(ok=False, returncode=-1, stdout="", via="subagent",
                             stderr=f"via the sub-agent: {reason or status}")
    return {"matches": matches, "scanned": scanned, "unreadable": 0, "unreadable_paths": [],
            "partially_unreadable": {}, "agent_notes": notes,
            "matched_content": "not returned through the sub-agent (rule, file and offset only)"}


def fetch_yara_sweep(paths: tuple[str, ...], rules_content: str, custom_rules: bool = False) -> SSHResult | dict[str, Any]:
    """Scan every path in `paths` that exists on the target, in one SSH call.
    Returns {"matches", "scanned", "unreadable"} -- `scanned` lists the paths
    that really existed and were scanned, `unreadable` counts files yara could
    not open as the SSH user (e.g. /root), so a clean result is never
    overstated. Same rule-file push/cleanup posture as fetch_yara_scan."""
    delimiter = f"KRATOS_YARA_RULES_{uuid.uuid4().hex}"
    quoted = " ".join(shlex.quote(p) for p in paths)
    script = (
        "command -v yara >/dev/null 2>&1 || { echo 'yara is not installed on the target' >&2; exit 4; }\n"
        "RULES_FILE=$(mktemp /tmp/kratos_yara_rules.XXXXXX.yar)\n"
        "ERR_FILE=$(mktemp /tmp/kratos_yara_err.XXXXXX)\n"
        f"cat > \"$RULES_FILE\" << '{delimiter}'\n"
        f"{rules_content}\n"
        f"{delimiter}\n"
        f"for p in {quoted}; do\n"
        "  [ -e \"$p\" ] || continue\n"
        # yara skips what it can't read SILENTLY (exit 0), so readability is
        # measured here, not inferred from yara's output.
        "  if [ ! -r \"$p\" ] || { [ -d \"$p\" ] && [ ! -x \"$p\" ]; }; then\n"
        f"    printf '{_YARA_UNREADABLE_MARK}%s\\n' \"$p\"; continue\n"
        "  fi\n"
        f"  printf '{_YARA_SCANNED_MARK}%s\\n' \"$p\"\n"
        "  yara -r -s \"$RULES_FILE\" \"$p\" 2>>\"$ERR_FILE\"\n"
        "  n=$( { find \"$p\" -type d 2>&1 >/dev/null | grep -c 'ermission denied'; } 2>/dev/null )\n"
        "  f=$( find \"$p\" -type f ! -readable 2>/dev/null | wc -l )\n"
        f"  printf '{_YARA_SKIPPED_MARK}%s\\t%s\\t%s\\n' \"$p\" \"${{n:-0}}\" \"${{f:-0}}\"\n"
        "done\n"
        f"printf '{_YARA_ERRORS_MARK}%s\\n' \"$(grep -c . \"$ERR_FILE\")\"\n"
        "rm -f \"$RULES_FILE\" \"$ERR_FILE\"\n"
        "exit 0\n"
    )
    result = _route("yara_scan", {}, lambda: run_remote_script(script, timeout=YARA_SCAN_TIMEOUT_SECONDS),
                    agent_call=lambda link: _yara_sweep_via_agent(link, paths, custom_rules))
    if isinstance(result, dict):
        return result
    if not result.ok:
        if result.returncode == -1 and "timed out" in result.stderr:
            return SSHResult(ok=False, returncode=-1, stdout="", stderr=(
                f"YARA sweep did not complete within {YARA_SCAN_TIMEOUT_SECONDS}s -- retry with a specific "
                "scan_path (one of the directories above) instead of the default sweep."))
        return result
    scanned, unreadable, body = [], 0, []
    unreadable_paths: list[str] = []
    skipped: dict[str, dict[str, int]] = {}
    for line in result.stdout.splitlines():
        if line.startswith(_YARA_SCANNED_MARK):
            scanned.append(line[len(_YARA_SCANNED_MARK):])
        elif line.startswith(_YARA_UNREADABLE_MARK):
            unreadable_paths.append(line[len(_YARA_UNREADABLE_MARK):])
        elif line.startswith(_YARA_SKIPPED_MARK):
            parts = line[len(_YARA_SKIPPED_MARK):].split("\t")
            if len(parts) == 3 and parts[1].strip().isdigit() and parts[2].strip().isdigit():
                d, f = int(parts[1]), int(parts[2])
                if d or f:
                    skipped[parts[0]] = {"unreadable_dirs": d, "unreadable_files": f}
        elif line.startswith(_YARA_ERRORS_MARK):
            tail = line[len(_YARA_ERRORS_MARK):].strip()
            unreadable = int(tail) if tail.isdigit() else 0
        else:
            body.append(line)
    return {"matches": _parse_yara_output("\n".join(body)), "scanned": scanned, "unreadable": unreadable,
            "unreadable_paths": unreadable_paths, "partially_unreadable": skipped}


def fetch_yara_scan(scan_path: str, rules_content: str, custom_rules: bool = False) -> SSHResult | list[dict[str, Any]]:
    """
    Runs `yara` ON THE TARGET (must be installed there -- see docs/DESIGN.md's
    "Target-facing tools" section) against scan_path, a path that already
    exists on the target. rules_content (the full text of one or more concatenated .yar
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
    result = _route("yara_scan", {}, lambda: run_remote_script(script, timeout=YARA_SCAN_TIMEOUT_SECONDS),
                    agent_call=lambda link: _yara_via_agent(link, scan_path, custom_rules))
    if isinstance(result, YaraMatches):
        return result
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
                    "(a full recursive scan of '/' can run well past this budget). "
                    "Retry with a narrower scan_path (e.g. a specific directory like "
                    "/home or /var/log, or a single file) rather than the filesystem root."
                ),
            )
        return result
    return _parse_yara_output(result.stdout)


# ---------------------------------------------------------------------------
# Exhaustive auth measurement (timewin.measure) -- SSH or sub-agent
# ---------------------------------------------------------------------------
# The address Kratos's own SSH sessions come from, per target, as the last SSH
# measurement saw it ($SSH_CONNECTION on the target). A measurement run by the
# sub-agent can't see that, so it is passed along to keep Kratos's own logins
# out of the counts (parity with the SSH path).
_kratos_ip_by_host: dict[str, str] = {}


def remember_kratos_ip(ip: str | None) -> None:
    if ip:
        _kratos_ip_by_host[get_active_target()] = ip


def run_auth_measurement(since_epoch: float, until_epoch: float | None, *, granularity: int,
                         kratos_user: str, timeout: int) -> SSHResult:
    """Run the target-side measurement script for one window. Over SSH the
    script is built here; through the sub-agent the agent builds the SAME
    script (its bundled copy of timewin/measure.py) from validated
    parameters -- no script text is sent."""
    from kratos.timewin.measure import build_script

    def over_ssh() -> SSHResult:
        script = build_script(since_epoch, until_epoch, journalctl_prefix=" ".join(_journalctl_prefix()),
                              kratos_user=kratos_user, classic_granularity=granularity)
        return run_remote_script(script, timeout=timeout, shell="sh")

    params = {"start": since_epoch, "end": until_epoch, "granularity": granularity, "exclude_user": kratos_user,
              "exclude_ip": _kratos_ip_by_host.get(get_active_target())}
    return _route("measure_auth", params, over_ssh)


# ---------------------------------------------------------------------------
# Privileged accounts (list_privileged_accounts) -- SSH or sub-agent
# ---------------------------------------------------------------------------
def fetch_privileged_accounts(lookback_days: int) -> SSHResult | tuple[Any, int]:
    """(inventory, since_epoch), or the failed SSHResult. Both transports run the
    same script (adapters/privileged_accounts.build_script); through the
    sub-agent it is the agent's own `privileged_accounts` read, so no script
    text is sent."""
    import time as _time

    from kratos.adapters import privileged_accounts as PA

    since = int(_time.time() - max(1, int(lookback_days)) * 86400)

    def over_ssh() -> SSHResult:
        prefix = " ".join(shlex.quote(p) for p in _journalctl_prefix())
        return run_remote_script(PA.build_script(since, prefix + " " if prefix else ""), shell="sh")

    result = _route("privileged_accounts", {"since": since}, over_ssh)
    if not result.ok:
        return result
    return PA.parse_output(result.stdout), since
