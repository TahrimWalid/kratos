"""
Two-tier threat-intel enrichment: AlienVault OTX pulses (default, cached,
offline-during-investigations) + AbuseIPDB (opt-in, live, approval-gated).
This module IS the implementation of CLAUDE.md's "Decision: threat-intel
enrichment scope" -- the cached/live split is that decision, not a
separate choice layered on top of it.

VirusTotal was explicitly ruled out as the primary choice: its 2026 Google
Threat Intelligence integration meaningfully restricted free-tier access, a
bad fit for a free/open-source project's ongoing viability.

Approval gating for the live tier does NOT live here. request_approval is
never called from inside an adapter anywhere in this project (every call
site is in agent/tools.py -- see run_linux_command, capture_traffic, and
run_vuln_scan's staleness-update prompt) -- this module's live-lookup
function makes the real network call unconditionally, every time it's
invoked, with zero internal gating. The decision of WHETHER to call it
(the KRATOS_THREAT_INTEL_ENABLED flag check, and the real-time human
approval prompt) lives entirely in
agent/tools.py::tool_check_ip_reputation, matching this project's
established "adapters do mechanism, tools.py does policy" convention.
"""
from __future__ import annotations

import json
from kratos.utils.timeutil import utc_now_iso
from pathlib import Path
from typing import Any

from kratos.kratos_config import OTX_API_KEY, ABUSEIPDB_API_KEY
from kratos.utils.redact import redact_secrets

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Same class as vulscan/ and llm/models/ -- runtime-managed, locally-synced
# data, not source, not committed. See .gitignore.
CACHE_DIR = _REPO_ROOT / "data" / "threat_intel_cache"
CACHE_FILE = CACHE_DIR / "otx_pulses.json"

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_IP_INDICATOR_TYPES = {"IPv4", "IPv6"}
OTX_SYNC_TIMEOUT_SECONDS = 30
ABUSEIPDB_TIMEOUT_SECONDS = 15


def update_threat_intel_cache(max_pages: int = 5) -> tuple[bool, str]:
    """
    Syncs subscribed OTX pulses via DirectConnect (GET /pulses/subscribed,
    paginated) into a local JSON cache, keyed by IP indicator for O(1)
    lookup. Mirrors adapters/vuln_scan.py::update_vulscan_db's pattern:
    build the new cache in memory / a temp file, validate, atomic replace
    -- a failed or partial sync must never corrupt or truncate the
    existing, working cache.
    """
    if not OTX_API_KEY:
        return False, "OTX_API_KEY not set -- see .env.example. Cached tier stays empty until configured."

    import requests

    all_indicators: dict[str, list[dict[str, Any]]] = {}
    url = f"{OTX_BASE_URL}/pulses/subscribed?limit=50"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        for _ in range(max(1, max_pages)):
            resp = requests.get(url, headers=headers, timeout=OTX_SYNC_TIMEOUT_SECONDS)
            resp.raise_for_status()
            data = resp.json()
            for pulse in data.get("results", []):
                pulse_id = pulse.get("id")
                pulse_name = pulse.get("name")
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") not in _IP_INDICATOR_TYPES:
                        continue
                    ip = indicator.get("indicator")
                    if not ip:
                        continue
                    all_indicators.setdefault(ip, []).append({
                        "pulse_id": pulse_id,
                        "pulse_name": pulse_name,
                        "description": indicator.get("description") or pulse.get("description") or "",
                    })
            next_url = data.get("next")
            if not next_url:
                break
            url = next_url
    except Exception as e:
        # Explicit redaction guard -- see llm_interface.py's identical
        # pattern and utils/redact.py's docstring for why this is applied
        # proactively rather than in reaction to a confirmed leak.
        return False, f"OTX sync failed: {redact_secrets(str(e), OTX_API_KEY)}"

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = CACHE_FILE.with_suffix(".json.new")
    payload = {
        "synced_at": utc_now_iso(),
        "indicator_count": len(all_indicators),
        "indicators": all_indicators,
    }
    try:
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp_path.replace(CACHE_FILE)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return True, f"Synced {len(all_indicators)} IP indicators to {CACHE_FILE}"


def lookup_ip_cache(ip: str) -> dict[str, Any] | None:
    """
    Reads ONLY the local cache file populated by update_threat_intel_cache
    -- no network call anywhere in this function, unconditionally. Returns
    None if the cache doesn't exist, is unreadable, or has no entry for ip
    (all three are the same "nothing cached" result to the caller).
    """
    if not CACHE_FILE.exists():
        return None
    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    entries = payload.get("indicators", {}).get(ip)
    if not entries:
        return None
    return {"ip": ip, "pulses": entries, "cache_synced_at": payload.get("synced_at")}


def lookup_ip_live_abuseipdb(ip: str) -> dict[str, Any] | None:
    """
    Real, live AbuseIPDB API call. Makes the network request
    UNCONDITIONALLY when called -- no flag check, no approval check, no
    internal gating of any kind. See module docstring: that decision lives
    entirely in agent/tools.py::tool_check_ip_reputation, never here.
    """
    if not ABUSEIPDB_API_KEY:
        return None
    import requests

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=ABUSEIPDB_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
    except Exception as e:
        print(f"[KRATOS] AbuseIPDB lookup failed: {redact_secrets(str(e), ABUSEIPDB_API_KEY)}")
        return None
