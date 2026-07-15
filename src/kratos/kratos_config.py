"""
Kratos general configuration: SSH target device + notification settings.

Mirrors the env-var-override-with-sensible-default pattern used in
llm_config.py, kept separate since this config is unrelated to the LLM
backend (SSH target details, ntfy topic).
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Idempotent and safe to call even if .env doesn't exist or vars are already
# set (see llm_config.py's identical call for the same reasoning) -- added
# here too rather than relying on llm_config.py having already been
# imported first in every real entry point. Without this, OTX_API_KEY/
# ABUSEIPDB_API_KEY below would silently read as unset in any context that
# imports kratos_config before anything touches llm_config.
load_dotenv(Path(__file__).parent.parent.parent / ".env")

# ---------------------------------------------------------------------------
# SSH target -- the remote device Kratos investigates over SSH.
# ---------------------------------------------------------------------------
SSH_TARGET_HOST = os.environ.get("KRATOS_SSH_HOST", "10.136.28.168")
SSH_TARGET_USER = os.environ.get("KRATOS_SSH_USER", "ubuntu")
SSH_TARGET_KEY_PATH = Path(
    os.environ.get("KRATOS_SSH_KEY_PATH", str(Path.home() / ".ssh" / "id_ed25519"))
)
SSH_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_SSH_CONNECT_TIMEOUT", "10"))
SSH_COMMAND_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_SSH_COMMAND_TIMEOUT", "30"))

# run_yara_scan's own timeout, deliberately separate from
# SSH_COMMAND_TIMEOUT_SECONDS above -- that 30s default is right for the
# quick, bounded SSH commands it's shared by (list_open_files,
# check_file_integrity, etc.), but wrong for YARA: a real, unmocked timing
# run against kratos-target confirmed a recursive `yara -r -s` scan of `/`
# is a many-minutes (not tens-of-seconds) operation -- still running past 17
# real minutes, actively CPU-bound, not hung. No timeout that's still
# "practical" (i.e. doesn't let one tool call dominate an entire ~10-20 min
# investigation run) can wait out a genuine full-root scan; 180s is sized
# instead for the realistic "broad but bounded" case an investigating agent
# would actually pick (e.g. /etc, /var/log, /home, /opt) -- 6x the old
# shared 30s default. A true `scan_path='/'` still won't finish in time;
# that's expected, not a bug -- it now fails with a clear, scan-specific
# message instead of the previous generic/misleading SSH_COMMAND_TIMEOUT
# error, per CLAUDE.md's Sprint 2 closing regression findings (2026-07-14).
YARA_SCAN_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_YARA_SCAN_TIMEOUT", "180"))

# ---------------------------------------------------------------------------
# Notifications (ntfy.sh)
# ---------------------------------------------------------------------------
NTFY_BASE_URL = os.environ.get("KRATOS_NTFY_BASE_URL", "https://ntfy.sh")
NTFY_TOPIC = os.environ.get("KRATOS_NTFY_TOPIC", "kratos-alerts-n4qk9zxp2v7m")
NTFY_REQUEST_TIMEOUT_SECONDS = int(os.environ.get("KRATOS_NTFY_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Threat intel (optional, opt-in) -- see CLAUDE.md's "Decision: threat-intel
# enrichment scope" for the full moat-tension reasoning this implements. Two
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
