"""
Kratos general configuration: SSH target device + notification settings.

Mirrors the env-var-override-with-sensible-default pattern used in
llm_config.py, kept separate since this config is unrelated to the LLM
backend (SSH target details, ntfy topic).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from kratos import paths as _paths

# Idempotent and safe to call even if .env doesn't exist or vars are already
# set (see llm_config.py's identical call for the same reasoning) -- added
# here too rather than relying on llm_config.py having already been
# imported first in every real entry point. Without this, OTX_API_KEY/
# ABUSEIPDB_API_KEY below would silently read as unset in any context that
# imports kratos_config before anything touches llm_config.
load_dotenv(_paths.env_file())

# ---------------------------------------------------------------------------
# SSH target -- the remote device Kratos investigates over SSH.
# ---------------------------------------------------------------------------
# No default: the machine to investigate always comes from the user --
# KRATOS_SSH_HOST, the target saved at first run (default_target, see
# seed_active_target_from_config), /target, or a session's own target. An
# empty value means "none set yet"; target-facing tools say so instead of
# guessing a host.
SSH_TARGET_HOST = os.environ.get("KRATOS_SSH_HOST", "").strip()
SSH_TARGET_USER = os.environ.get("KRATOS_SSH_USER", "ubuntu")
SSH_TARGET_KEY_PATH = Path(
    os.environ.get("KRATOS_SSH_KEY_PATH", str(Path.home() / ".ssh" / "id_ed25519"))
)
SSH_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_SSH_CONNECT_TIMEOUT", "10"))
SSH_COMMAND_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_SSH_COMMAND_TIMEOUT", "30"))

# SSH host-key verification. The original behavior was
# bare TOFU: `StrictHostKeyChecking=accept-new` against the user's GLOBAL
# ~/.ssh/known_hosts, so a first-contact key was accepted blindly and pins
# weren't isolated/auditable. These two knobs let an operator move to a pinned,
# fail-closed posture on an untrusted network WITHOUT breaking the trusted lab:
#   * KRATOS_SSH_KNOWN_HOSTS -> a Kratos-owned known_hosts file (isolated from
#     the global one, so `ssh_remote.pin_target_host_key` can pin there and pins
#     are auditable). Unset -> ssh's default known_hosts (unchanged behavior).
#   * KRATOS_SSH_STRICT_HOST_KEY_CHECKING -> the OpenSSH StrictHostKeyChecking
#     value. Default "accept-new" preserves the lab's zero-friction first
#     contact; set "yes" to REJECT any host key not already pinned (the
#     untrusted-network posture — pin the key first via pin_target_host_key or
#     the target-onboarding step). A CHANGED key is rejected under BOTH values;
#     only unknown-first-contact differs. Read live via the module (not a frozen
#     import) so tests/callers can toggle mid-process, matching JOURNALCTL_USE_SUDO.
SSH_KNOWN_HOSTS_PATH = (
    Path(os.environ["KRATOS_SSH_KNOWN_HOSTS"]) if os.environ.get("KRATOS_SSH_KNOWN_HOSTS") else None
)
SSH_STRICT_HOST_KEY_CHECKING = os.environ.get("KRATOS_SSH_STRICT_HOST_KEY_CHECKING", "accept-new")

# run_yara_scan's own timeout, deliberately separate from
# SSH_COMMAND_TIMEOUT_SECONDS above -- that 30s default is right for the
# quick, bounded SSH commands it's shared by (list_open_files,
# check_file_integrity, etc.), but wrong for YARA: a recursive `yara -r -s`
# scan of `/` is a many-minutes (not tens-of-seconds) operation, genuinely
# CPU-bound rather than hung. No timeout that's still "practical" (i.e.
# doesn't let one tool call dominate an entire investigation run) can wait
# out a genuine full-root scan; 180s is sized instead for the realistic
# "broad but bounded" case an investigating agent would actually pick (e.g.
# /etc, /var/log, /home, /opt) -- 6x the shared 30s default. A true
# `scan_path='/'` still won't finish in time; that's expected, not a bug --
# it fails with a clear, scan-specific message instead of the generic,
# misleading SSH_COMMAND_TIMEOUT error a shared timeout would produce (see
# docs/DESIGN.md's "Target-facing tools and operational requirements"
# section).
YARA_SCAN_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_YARA_SCAN_TIMEOUT", "180"))

# journalctl access mode -- see adapters/target_setup.py for the
# full target-onboarding checklist this feeds into. Default True preserves
# the original, always-worked `sudo -n journalctl` path unconditionally --
# zero regression risk for any target set up before this flag existed. Set
# to "0" only after confirming (via the target-setup probe,
# adapters/ssh_remote.py::run_target_probe_checks) that the SSH user is
# really in the target's systemd-journal group -- that group grants
# journal-read access without sudo at all, a smaller blast radius than
# passwordless sudo if the SSH key ever leaks (group membership can only
# ever grant read access, never a path to root). Sudo still works fine even
# if the user is ALSO in that group, so this flag is purely a preference,
# never a requirement -- both mechanisms are supported indefinitely, not
# one deprecating the other.
JOURNALCTL_USE_SUDO = os.environ.get("KRATOS_JOURNALCTL_USE_SUDO", "1") == "1"

# ---------------------------------------------------------------------------
# Active target override -- session-lifetime, in-process only, never
# persisted by itself. Without this chokepoint, a REPL command that only
# stores/displays a value in session_state and the session DB would leave
# every SSH-based tool (via adapters/ssh_remote.py) and run_nmap_scan/
# run_vuln_scan still reading the frozen SSH_TARGET_HOST above regardless
# -- the exact live-switchable-settings bug class described in
# docs/DESIGN.md. get_active_target() is now the single chokepoint every
# target-facing tool resolves its host through -- SSH_TARGET_HOST (the
# KRATOS_SSH_HOST env var) is the fallback, and the CLI's main() seeds the
# saved default_target when that is unset (seed_active_target_from_config).
#
# Why a mutable module global, not an explicit parameter threaded through
# run_agent()/execute_tool_call(): auditing every target-facing tool shows
# run_nmap_scan/run_vuln_scan already accept their own
# `target` argument, but read_journalctl/list_open_files/list_processes/
# check_file_integrity/run_config_audit/run_yara_scan have NO target
# parameter at all today; they all reach the target exclusively through
# ssh_remote.py's target_label()/_base_ssh_argv(). Threading an explicit
# override through every one of those signatures plus run_agent()/
# execute_tool_call() would touch ~8 call chains for equivalent behavior.
# Fixing ssh_remote.py's own resolution point instead (see that module)
# covers all of them through the ONE existing shared chokepoint they already
# funnel through -- a scoped, session-lifetime config override, per the
# task's own documented fallback. Safe under this architecture because each
# `kratos` process runs exactly one REPL session serially (never multiple
# concurrent investigations in one process) -- this mutable state has zero
# visibility across separate `kratos` processes, so it cannot leak into the
# already-concurrency-tested session DB or interact with it in any way.
# ---------------------------------------------------------------------------
_active_target_override: str | None = None


NO_TARGET_MESSAGE = (
    "No target is set yet, so there is no machine to investigate. Set one with "
    "/target <host> in Kratos (or KRATOS_SSH_HOST for command-line runs)."
)


class NoTargetConfigured(RuntimeError):
    def __init__(self) -> None:
        super().__init__(NO_TARGET_MESSAGE)


def get_active_target() -> str:
    """The host being investigated, or "" when none has been set."""
    return (_active_target_override or SSH_TARGET_HOST or "").strip()


def require_active_target() -> str:
    target = get_active_target()
    if not target:
        raise NoTargetConfigured()
    return target


def set_active_target(host: str | None) -> None:
    global _active_target_override
    _active_target_override = host


# The data folder of this process (the CLI's --data-dir, the TUI's, MCP's). Set
# once at startup and by every tool dispatch; read by code with no data_dir
# parameter of its own -- the SSH/sub-agent routing in adapters/ssh_remote.py
# needs it to find the target's link and the local listener socket.
_active_data_dir: Path | None = None


def set_active_data_dir(data_dir: Path | str | None) -> None:
    global _active_data_dir
    _active_data_dir = Path(data_dir).resolve() if data_dir else None


def get_active_data_dir() -> Path | None:
    return _active_data_dir


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def remember_first_target(data_dir: Path, host: str) -> bool:
    """Save `host` as the default target for command-line and scheduled runs if
    none is saved yet (the first real target a user sets). Never overwrites a
    saved default and skips Kratos's own host. True if it saved."""
    host = (host or "").strip()
    if not host or host.lower() in _LOOPBACK_HOSTS:
        return False
    if str(load_local_config(data_dir).get("default_target") or "").strip():
        return False
    save_local_config(data_dir, default_target=host)
    return True


def seed_active_target_from_config(data_dir: Path) -> str:
    """For entry points without the TUI's boot flow (`kratos investigate`,
    `kratos run`, systemd-scheduled runs): use the target saved at first run
    unless KRATOS_SSH_HOST or an explicit override already chose one. Returns
    the resulting active target ("" if still none)."""
    if not get_active_target():
        saved = str(load_local_config(data_dir).get("default_target") or "").strip()
        if saved:
            set_active_target(saved)
    return get_active_target()


# ---------------------------------------------------------------------------
# Directory-scoped local config -- first-run trust record + persisted
# default target. One JSON file under the resolved
# data_dir (already the existing per-installation persistent storage
# location -- the session DB lives next to it), not a second, disconnected
# persistence scheme. The persisted "default_target" is what seeds
# get_active_target() above at REPL startup (see cli/repl.py::run_session)
# -- /target then overrides it further for the rest of that session, same
# mechanism, not a competing one.
# ---------------------------------------------------------------------------
_LOCAL_CONFIG_FILENAME = "kratos_local_config.json"


def _local_config_path(data_dir: Path) -> Path:
    return data_dir / _LOCAL_CONFIG_FILENAME


def load_local_config(data_dir: Path) -> dict:
    path = _local_config_path(data_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_local_config(data_dir: Path, **updates: Any) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    config = load_local_config(data_dir)
    config.update(updates)
    _local_config_path(data_dir).write_text(json.dumps(config, indent=2), encoding="utf-8")

# ---------------------------------------------------------------------------
# Notifications (ntfy) -- OFF until KRATOS_NTFY_TOPIC is set. There is no
# default topic on purpose: a topic written in this (public) source would be
# public knowledge, and an ntfy topic is unauthenticated -- anyone who knows its
# name can read every message sent to it. Each install picks its own
# (`/doctor` suggests a random one). For real deployments use a self-hosted
# ntfy (KRATOS_NTFY_BASE_URL) and/or an access token (KRATOS_NTFY_TOKEN).
# agent/notify.py reads these live, so tests and a changed environment apply.
# ---------------------------------------------------------------------------
NTFY_BASE_URL = os.environ.get("KRATOS_NTFY_BASE_URL", "https://ntfy.sh")
NTFY_TOPIC = os.environ.get("KRATOS_NTFY_TOPIC", "").strip() or None
NTFY_TOKEN = os.environ.get("KRATOS_NTFY_TOKEN", "").strip() or None
NTFY_REQUEST_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_NTFY_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Threat intel (optional, opt-in) -- see docs/DESIGN.md's "Threat-intel
# enrichment" section for the full reasoning this implements. Two
# tiers, deliberately different trust levels:
#   - cached (default, always available): AlienVault OTX pulses synced
#     locally on a schedule via update_threat_intel_cache() -- lookups
#     during an investigation read ONLY this local cache, no live call.
#   - live escalation (opt-in): AbuseIPDB, reachable ONLY when
#     THREAT_INTEL_ENABLED is True AND a human approves that SPECIFIC
#     lookup at a real-time prompt every time -- a key being configured is
#     never sufficient by itself. See agent/tools.py::tool_check_ip_reputation.
# ---------------------------------------------------------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
THREAT_INTEL_ENABLED = os.environ.get("KRATOS_THREAT_INTEL_ENABLED", "0") == "1"

# When a run_vuln_scan finds the local vulscan CVE database stale, whether to
# INTERRUPT the scan with a live "download a fresh copy now?" approval prompt.
# Default OFF: a plain investigation shouldn't be interrupted by a
# download modal it can only decline -- especially since the scan proceeds with
# the current database either way, and the upstream mirror is Cloudflare-blocked
# so the update usually fails anyway. When OFF, staleness is still ALWAYS
# reported passively (database_stale/database_age_days in the result), so nothing
# is hidden -- the visibility is preserved, only the interruption is dropped.
# Set KRATOS_VULSCAN_UPDATE_PROMPT=1 to restore the interactive update prompt.
VULSCAN_UPDATE_PROMPT = os.environ.get("KRATOS_VULSCAN_UPDATE_PROMPT", "0") == "1"
