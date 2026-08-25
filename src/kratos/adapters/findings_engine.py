from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos import __version__ as KRATOS_VERSION
from kratos.utils.latest_file import latest_file



# ---------------------------
# Helpers: find latest files
# ---------------------------
def find_latest_inputs(data_dir: Path) -> dict[str, Path | None]:
    scans_dir = data_dir / "scans"
    logs_dir = data_dir / "logs"
    ctx_dir = data_dir / "context"
    reports_dir = data_dir / "reports"
    baseline_dir = data_dir / "baseline"

    return {
        "nmap_parsed": latest_file(scans_dir, "parsed_*.json"),
        "auth_stats": latest_file(logs_dir, "auth_stats_*.json"),
        "auth_patterns": latest_file(logs_dir, "auth_patterns_*.json"),
        "system_context": latest_file(ctx_dir, "system_context_*.json"),
        "auth_trends": latest_file(reports_dir, "auth_trends_*.json"),
        "file_integrity": latest_file(baseline_dir, "file_integrity_diff_*.json"),
    }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _extract_sudo_members(sudo_group_line: str | None) -> list[str]:
    # Example: "sudo:x:27:walid000"
    if not sudo_group_line:
        return []
    parts = sudo_group_line.split(":")
    if len(parts) < 4:
        return []
    members = parts[3].strip()
    if not members:
        return []
    return [m.strip() for m in members.split(",") if m.strip()]

def _nmap_has_ssh_exposed(nmap_parsed: dict[str, Any] | None) -> bool:
    if not nmap_parsed or not isinstance(nmap_parsed.get("hosts"), list):
        return False
    for h in nmap_parsed["hosts"]:
        for p in h.get("open_ports", []):
            port = int(p.get("port", 0) or 0)
            svc = (p.get("service") or "").lower()
            if port == 22 or "ssh" in svc:
                return True
    return False

def _context_has_ssh_exposed(system_context: dict[str, Any] | None) -> bool:
    """Check if SSH is running/listening based on system context."""
    if not system_context:
        return False
    ssh_info = system_context.get("ssh", {})
    # SSH is exposed if service is active OR listening on port 22
    if ssh_info.get("service_active"):
        return True
    listening_ports = ssh_info.get("listening_ports", [])
    return 22 in listening_ports or len(listening_ports) > 0

def _bursts_of(auth_patterns: dict[str, Any] | None, event_types: tuple[str, ...]) -> list[dict[str, Any]]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    return [b for b in auth_patterns["bursts"] if b.get("event_type") in event_types]


_SCOPE_LABELS = {
    "local_host": "LOCAL KRATOS HOST (not the monitored target)",
}


def _system_context_scope_note(system_context: dict[str, Any] | None) -> str | None:
    """
    One-line evidence tag identifying which host system_context actually
    describes. Older context files (or a manually-constructed dict without a
    'scope' field) have no scope tag -- reported as 'unlabeled/unknown' rather
    than silently assumed to be the target, since collect_system_context has
    only ever inspected Kratos's own local host.
    """
    if not system_context:
        return None
    scope = system_context.get("scope")
    label = _SCOPE_LABELS.get(scope, f"unlabeled/unknown scope ({scope!r})" if scope else "unlabeled/unknown scope")
    return f"system_context scope: {label}"


def _is_service_active(system_context: dict[str, Any] | None, unit_name: str) -> bool:
    if not system_context:
        return False
    services = (system_context.get("services") or {})
    units = services.get("units") or []
    for u in units:
        if not isinstance(u, dict):
            continue
        if u.get("unit") == unit_name and u.get("active") == "active":
            return True
    return False


def _auth_failure_count(auth_stats: dict[str, Any] | None) -> int:
    if not auth_stats:
        return 0
    by_type = auth_stats.get("events_by_type") or {}
    return int(by_type.get("sudo_auth_failure", 0)) + int(by_type.get("sudo_pam_auth_failure", 0)) + int(by_type.get("ssh_failed_login", 0))


# ---------------------------
# Findings model
# ---------------------------
@dataclass
class Finding:
    id: str
    title: str
    severity: str          # info | low | medium | high
    evidence: list[str]
    recommendation: list[str]
    playbooks: list[dict[str, Any]] = field(default_factory=list)


def _severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3}.get(sev, 0)


# Sprint 3 Phase 2 (CLI overhaul, presentation-only): plain-language, one-line
# summary per rule ID, keyed to every id="..." literal used by
# generate_findings() below. Template-based rather than LLM-generated per the
# design doc's own decision (docs/sprint3_phase1_cli_overhaul_design.md §9) --
# these rule IDs are deterministic and finite, so a static map avoids a
# non-deterministic extra LLM call for something formulaic. Kept here, next
# to the rule definitions, so a new id="..." added below is a visible,
# one-line diff away from also getting a template; GENERIC_FINDING_SUMMARY is
# the deliberate fallback for anything missed, so a forgotten template is a
# blander sentence, never a crash or a blank summary.
FINDING_SUMMARY_TEMPLATES: dict[str, str] = {
    "NET-001": "No open network ports were found in the latest scan.",
    "NET-002": "Open network ports were found — this is the system's attack surface.",
    "CTX-001": "One or more accounts with admin (sudo) rights were identified.",
    "AUTH-001": "Failed attempts to gain admin (sudo) rights were observed.",
    "AUTH-003": "Admin (sudo) session activity was observed.",
    "OBS-001": "Login failures were seen, but the services that collect logs appear to be off — some activity may be going unrecorded.",
    "AUTH-004": "A burst of login failures was observed in a short window.",
    "CORR-001": "A network-exposed SSH service combined with a burst of failed logins — a pattern consistent with a brute-force attempt.",
    "CORR-002": "A burst of failed admin (sudo) logins concentrated on a single account.",
    "CORR-SSH-001": "SSH is exposed to the network and a burst of failed logins was observed — looks like a brute-force attempt.",
    "AUTH-TREND-001": "Login failures have been trending upward across recent runs.",
    "INTEG-001": "One or more tracked files have changed since the last known-good baseline.",
    "ENV-001": "This looks like a development environment (WSL2), not a production system.",
}

GENERIC_FINDING_SUMMARY = "A security-relevant pattern was detected — see details below."


# ---------------------------
# Core: generate findings
# ---------------------------
# ---------------------------
# Deterministic offline threat-intel corroboration (Option 1, 2026-08-24)
# ---------------------------
# When correlation surfaces a suspicious SOURCE IP (a failed-login / brute-force
# / sudo-failure burst), corroborating that IP against known threat intel must
# NOT depend on the agent LLM remembering to call check_ip_reputation -- that was
# measured unreliable (~25% tool-selection on the eval's A8). The rule engine
# does it itself here, deterministically, using ONLY the OFFLINE local OTX cache
# (a plain file read -- no network call, no approval). The live AbuseIPDB tier is
# untouched and stays approval-gated. Only a real KNOWN-MALICIOUS cache hit
# changes anything (evidence line + severity raised to at least high) -- a miss
# leaves the finding exactly as it was, so there's no "not in cache" noise and no
# risk of a clean lookup reading as reassuring.
_IP_SOURCED_SUSPICIOUS_IDS = {"CORR-SSH-001", "CORR-001", "CORR-002", "AUTH-004"}
_SUSPICIOUS_BURST_TYPES = ("ssh_failed_login", "sudo_pam_auth_failure", "sudo_auth_failure")


def _suspicious_source_ips(auth_patterns: dict[str, Any] | None) -> list[str]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    ips: list[str] = []
    for b in auth_patterns["bursts"]:
        if b.get("event_type") in _SUSPICIOUS_BURST_TYPES:
            for entry in b.get("top_source_ips", []) or []:
                ip = entry.get("ip")
                if ip and ip not in ips:
                    ips.append(ip)
    return ips


def _suspicious_source_ip_counts(auth_patterns: dict[str, Any] | None) -> list[tuple[str, int]]:
    if not auth_patterns or not isinstance(auth_patterns.get("bursts"), list):
        return []
    from collections import Counter
    c: Counter = Counter()
    for b in auth_patterns["bursts"]:
        if b.get("event_type") in _SUSPICIOUS_BURST_TYPES:
            for entry in b.get("top_source_ips", []) or []:
                ip = entry.get("ip")
                if ip:
                    c[ip] += int(entry.get("count") or 0)
    return c.most_common(5)


def _surface_source_ips_in_evidence(
    findings: list["Finding"], auth_patterns: dict[str, Any] | None
) -> None:
    # Put the attacking source IP(s) directly on the finding so the final answer
    # can name them -- the burst carries top_source_ips but the finding text
    # didn't expose it, so the agent knew the burst happened but often couldn't
    # attribute it to an IP. Independent of threat-intel (fires on any burst).
    counts = _suspicious_source_ip_counts(auth_patterns)
    if not counts:
        return
    summary = ", ".join(f"{ip} ({n} events)" for ip, n in counts)
    for f in findings:
        if f.id in _IP_SOURCED_SUSPICIOUS_IDS:
            f.evidence.append(f"Source IP(s) behind this activity: {summary}.")


def _enrich_findings_with_offline_reputation(
    findings: list["Finding"], auth_patterns: dict[str, Any] | None
) -> None:
    ips = _suspicious_source_ips(auth_patterns)
    if not ips:
        return
    try:
        from kratos.adapters.threat_intel import lookup_ip_cache
    except Exception:  # noqa: BLE001 -- enrichment must never break correlation
        return
    malicious: dict[str, dict[str, Any]] = {}
    for ip in ips:
        try:
            r = lookup_ip_cache(ip)  # OFFLINE: reads only the local OTX cache file
        except Exception:  # noqa: BLE001
            r = None
        if r:
            malicious[ip] = r
    if not malicious:
        return
    for f in findings:
        if f.id not in _IP_SOURCED_SUSPICIOUS_IDS:
            continue
        for ip, r in malicious.items():
            pulses = r.get("pulses") or []
            names = ", ".join(str(p.get("pulse_name")) for p in pulses[:3] if p.get("pulse_name"))
            f.evidence.append(
                f"Threat-intel corroboration (offline OTX cache): source IP {ip} is KNOWN-MALICIOUS"
                + (f" -- {names}" if names else "")
                + " -- this corroborates a real attack; treat with raised confidence/severity."
            )
        if _severity_rank(f.severity) < _severity_rank("high"):
            f.severity = "high"


def generate_findings(
    nmap_parsed: dict[str, Any] | None,
    auth_stats: dict[str, Any] | None,
    auth_patterns: dict[str, Any] | None,
    system_context: dict[str, Any] | None,
    auth_trends: dict[str, Any] | None = None,
    file_integrity: dict[str, Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    # 1) Network exposure (Nmap)
    if nmap_parsed and isinstance(nmap_parsed.get("hosts"), list):
        hosts = nmap_parsed["hosts"]
        open_ports_total = sum(len(h.get("open_ports", [])) for h in hosts)

        if open_ports_total == 0:
            findings.append(
                Finding(
                    id="NET-001",
                    title="No open TCP ports detected in latest scan",
                    severity="info",
                    evidence=[
                        f"Source: {nmap_parsed.get('source_file', 'n/a')}",
                        "Nmap open_ports count = 0",
                    ],
                    recommendation=[
                        "If this is expected (local dev machine), no action needed.",
                        "If services should be reachable, verify firewall/service configuration and rescan.",
                    ],
                )
            )
        else:
            # Basic service hints (thesis-safe; not claiming exploitation)
            exposed = []
            for h in hosts:
                for p in h.get("open_ports", []):
                    svc = p.get("service") or "unknown"
                    exposed.append(f"{h.get('ip','?')} {p.get('protocol','tcp')}/{p.get('port')} ({svc})")

            sev = "medium"
            # If SSH exposed, keep medium (could be high in real environments, but thesis-safe defaults)
            if any("(ssh)" in e or " ssh" in e for e in exposed):
                sev = "medium"

            findings.append(
                Finding(
                    id="NET-002",
                    title="Open ports detected (attack surface present)",
                    severity=sev,
                    evidence=[
                        f"Source: {nmap_parsed.get('source_file', 'n/a')}",
                        f"Open ports total = {open_ports_total}",
                        "Exposed endpoints:",
                        *exposed[:10],
                    ],
                    recommendation=[
                        "Validate each exposed service is necessary.",
                        "Restrict access using firewall rules or bind services to trusted interfaces.",
                        "Keep exposed services updated and use strong authentication (especially SSH).",
                    ],
                )
            )

    # 2) Privilege context (sudo group)
    if system_context:
        sudo_line = (system_context.get("users") or {}).get("sudo_group")
        members = _extract_sudo_members(sudo_line)

        if members:
            findings.append(
                Finding(
                    id="CTX-001",
                    title="Sudo-capable users identified",
                    severity="info",
                    evidence=[
                        _system_context_scope_note(system_context),
                        f"sudo group line: {sudo_line}",
                        f"sudo members: {', '.join(members)}",
                    ],
                    recommendation=[
                        "Keep sudo membership minimal and reviewed.",
                        "Ensure sudo users use strong passwords and (if possible) MFA on the host environment.",
                    ],
                )
            )

    # 3) Auth behavior: sudo auth failures + bursts
    if auth_stats:
        by_type = auth_stats.get("events_by_type") or {}
        sudo_fail_count = int(by_type.get("sudo_auth_failure", 0))
        sudo_pam_fail_count = int(by_type.get("sudo_pam_auth_failure", 0))

        # Real fix (2026-07-17): auth_stats['since'] is only ever populated
        # for target-fetched data (agent/tools.py::_persist_target_auth_
        # correlation_data now stamps whatever `since` the model's
        # read_journalctl call used, or None if unstated) -- absent
        # entirely for locally-parsed auth_stats (parse_auth_log has no
        # time-window concept). Either way, state it plainly in the
        # evidence rather than letting a reader (human or the model itself)
        # silently assume these counts are scoped to whatever the
        # investigation goal asked about. This is the concrete fix for the
        # real incident where a final_answer confidently said "in the last
        # 24 hours" about a count that was actually an unscoped snapshot.
        since_value = auth_stats.get("since")
        time_window_note = (
            f"Time window: since {since_value!r}" if since_value
            else "Time window: unscoped (no time window was requested/applied to this data)"
        )

        if (sudo_fail_count + sudo_pam_fail_count) > 0:
            findings.append(
                Finding(
                    id="AUTH-001",
                    title="Sudo authentication failures observed",
                    severity="low",
                    evidence=[
                        f"sudo_pam_auth_failure events = {sudo_pam_fail_count}",
                        f"sudo_auth_failure events = {sudo_fail_count}",
                        "Source: latest auth_stats",
                        time_window_note,
                    ],
                    recommendation=[
                        "If this was a mistyped password, no action needed.",
                        "If unexpected, review sudo usage and ensure passwords are not being guessed.",
                        "Consider enabling stronger authentication or tightening sudo policy if failures repeat.",
                    ],
                    playbooks=[
                        {
                            "title": "Confirm if failures were accidental",
                            "commands": [
                                "grep -n 'authentication failure' /var/log/auth.log | tail -n 40",
                                "history | tail -n 50",
                            ],
                            "notes": [
                                "If it was a mistyped password, no action needed. If unexpected, investigate.",
                            ],
                        },
                    ],
                )
            )

        sudo_open = int(by_type.get("sudo_session_open", 0))
        sudo_close = int(by_type.get("sudo_session_close", 0))

        if (sudo_open + sudo_close) > 0:
            findings.append(
                Finding(
                    id="AUTH-003",
                    title="Sudo session activity observed",
                    severity="info",
                    evidence=[
                        f"sudo_session_open events = {sudo_open}",
                        f"sudo_session_close events = {sudo_close}",
                        "Source: latest auth_stats",
                        time_window_note,
                    ],
                    recommendation=[
                        "If this corresponds to expected admin tasks (updates/installs), no action needed.",
                        "If unexpected, review who initiated privileged actions and when they occurred.",
                    ],
                )
            )

    # Check for auth failures with inactive logging services
    failures = _auth_failure_count(auth_stats)
    if failures > 0:
        rsyslog_ok = _is_service_active(system_context, "rsyslog.service")
        journald_ok = _is_service_active(system_context, "systemd-journald.service")

        if not (rsyslog_ok or journald_ok):
            obs_001_evidence = [
                f"auth failure events = {failures}",
                "rsyslog.service active = false",
                "systemd-journald.service active = false",
                f"context snapshot = {(system_context or {}).get('collected_at', 'unknown')}",
            ]
            scope_note = _system_context_scope_note(system_context)
            if scope_note:
                obs_001_evidence.append(scope_note)
            else:
                obs_001_evidence.append(
                    "system_context: not provided in this investigation -- 'inactive' here may "
                    "simply mean service state could not be checked, not that logging is actually off"
                )
            findings.append(
                Finding(
                    id="OBS-001",
                    title="Authentication failures detected but log collection services appear inactive",
                    severity="medium",
                    evidence=obs_001_evidence,
                    recommendation=[
                        "Verify that system logging is enabled (rsyslog or journald) so security-relevant events are recorded.",
                        "If this is an embedded/stripped environment, document logging limitations in the deployment section.",
                    ],
                    playbooks=[
                        {
                            "title": "Check logging service status",
                            "commands": [
                                "systemctl status rsyslog --no-pager",
                                "systemctl status systemd-journald --no-pager",
                            ],
                            "notes": [
                                "If both are inactive, visibility is reduced and security events may not be recorded.",
                            ],
                        },
                        {
                            "title": "Inspect recent logging errors",
                            "commands": [
                                "journalctl -xe --no-pager | tail -n 80",
                                "journalctl -u rsyslog --since '30 minutes ago' --no-pager",
                                "journalctl -u systemd-journald --since '30 minutes ago' --no-pager",
                            ],
                            "notes": [
                                "Look for service crashes, permission issues, disk full, or configuration failures.",
                            ],
                        },
                    ],
                )
            )

    # Bursts (patterns)
    if auth_patterns and isinstance(auth_patterns.get("bursts"), list):
        bursts = auth_patterns["bursts"]
        # only report bursts we care about
        relevant = [
            b for b in bursts
            if b.get("event_type") in ("sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login")
        ]
        if relevant:
            # If we have bursts, raise severity
                        findings.append(
                Finding(
                    id="AUTH-004",
                    title="Burst activity detected in authentication failures",
                    severity="info",
                    evidence=[
                        f"Source: {auth_patterns.get('source_events_file', 'n/a')}",
                        f"Bursts detected = {len(relevant)}",
                        *[
                            f"{b.get('event_type')} burst: {b.get('count')} events between {b.get('start')} and {b.get('end')}"
                            for b in relevant[:5]
                        ],
                    ],
                    recommendation=[
                        "Investigate the time window(s) shown in the evidence.",
                        "For SSH bursts: consider rate-limiting, disabling password auth, or restricting by IP.",
                        "For sudo failure bursts: review local user activity and consider tightening sudo policy if unexpected.",
                    ],
                )
            )

    # ---------------------------
    # Correlation rules (Sprint next)
    # ---------------------------

    # CORR-001: SSH exposed + SSH failed-login burst
    ssh_exposed = _nmap_has_ssh_exposed(nmap_parsed)
    ssh_bursts = _bursts_of(auth_patterns, ("ssh_failed_login",))

    if ssh_exposed and ssh_bursts:
        findings.append(
            Finding(
                id="CORR-001",
                title="SSH exposure correlated with failed-login burst activity",
                severity="medium",
                evidence=[
                    "SSH appears exposed in latest scan (port 22 and/or ssh service detected).",
                    f"SSH failed-login bursts detected = {len(ssh_bursts)}",
                    *[
                        f"ssh_failed_login burst: {b.get('count')} events between {b.get('start')} and {b.get('end')}"
                        for b in ssh_bursts[:3]
                    ],
                ],
                recommendation=[
                    "If SSH must remain exposed: disable password authentication, use key-based auth, and restrict by IP if possible.",
                    "Consider rate-limiting / lockout controls (e.g., fail2ban) and monitor authentication logs.",
                    "Re-run scans and confirm only required services are exposed.",
                ],
            )
        )

    # CORR-002: Sudo failure bursts + single sudo user
    sudo_members: list[str] = []
    if system_context:
        sudo_line = (system_context.get("users") or {}).get("sudo_group")
        sudo_members = _extract_sudo_members(sudo_line)

    sudo_fail_bursts = _bursts_of(auth_patterns, ("sudo_pam_auth_failure", "sudo_auth_failure"))

    if sudo_fail_bursts and len(sudo_members) == 1:
        findings.append(
            Finding(
                id="CORR-002",
                title="Privileged authentication bursts observed on a single sudo user",
                severity="medium",
                evidence=[
                    _system_context_scope_note(system_context),
                    f"sudo group members = {', '.join(sudo_members)}",
                    f"Sudo failure bursts detected = {len(sudo_fail_bursts)}",
                    *[
                        f"{b.get('event_type')} burst: {b.get('count')} events between {b.get('start')} and {b.get('end')}"
                        for b in sudo_fail_bursts[:3]
                    ],
                ],
                recommendation=[
                    "Verify whether these failures match expected admin activity (mistyped password) in the shown time window.",
                    "If unexpected, review local user activity and consider tightening sudo policy.",
                    "Ensure the sudo user has strong authentication and avoid unnecessary sudo attempts.",
                ],
                playbooks=[
                    {
                        "title": "Review sudo activity around the burst window",
                        "commands": [
                            "grep -n 'sudo' /var/log/auth.log | tail -n 60",
                            "journalctl _COMM=sudo --since '2 hours ago' --no-pager | tail -n 80",
                        ],
                        "notes": [
                            "Confirm whether the failures match expected admin activity (mistypes) or look suspicious.",
                        ],
                    },
                    {
                        "title": "Check who has sudo access",
                        "commands": [
                            "getent group sudo",
                            "sudo -l",
                        ],
                        "notes": [
                            "Keep sudo membership minimal and reviewed.",
                        ],
                    },
                ],
            )
        )

    # CORR-SSH-001: SSH open + failed-login burst => HIGH
    # Check exposure from both nmap and system context
    ssh_from_nmap = _nmap_has_ssh_exposed(nmap_parsed)
    ssh_from_context = False
    ssh_ports = []
    
    if system_context and "ssh" in system_context:
        ssh_ctx = system_context["ssh"]
        if ssh_ctx.get("listening_ports"):
            ssh_from_context = True
            ssh_ports = ssh_ctx.get("listening_ports", [])
    
    ssh_exposed = ssh_from_nmap or ssh_from_context
    ssh_failed_bursts = _bursts_of(auth_patterns, ("ssh_failed_login",))
    
    if ssh_exposed and len(ssh_failed_bursts) > 0:
        # Build evidence based on what detected SSH
        evidence = []
        if ssh_from_nmap and ssh_from_context:
            exposure_msg = f"ssh exposed (nmap + context), ports: {ssh_ports if ssh_ports else [22]}"
        elif ssh_from_nmap:
            exposure_msg = "ssh exposed (nmap scan detected port 22 open)"
        else:
            exposure_msg = f"ssh exposed (context: listening on ports {ssh_ports})"
        
        evidence.append(exposure_msg)
        if ssh_from_context:
            # system_context's "ssh" info reflects whatever host
            # collect_system_context inspected (Kratos's own local host as of
            # this writing) -- flag that explicitly whenever it contributed
            # to this SSH-exposure verdict, so "context: listening on ports"
            # is never mistaken for the monitored target's own SSH exposure.
            scope_note = _system_context_scope_note(system_context)
            if scope_note:
                evidence.append(f"NOTE: the 'context' exposure signal above is from {scope_note}")
        evidence.append(f"ssh_failed_login bursts detected = {len(ssh_failed_bursts)}")
        
        # Summarize burst evidence (keep it minimal)
        b0 = ssh_failed_bursts[0]
        evidence.append(f"example burst: {b0.get('count', 0)} events between {b0.get('start')} and {b0.get('end')}")
        
        findings.append(
            Finding(
                id="CORR-SSH-001",
                title="SSH exposed with failed-login burst activity observed",
                severity="high",
                evidence=evidence,
                recommendation=[
                    "Confirm SSH is required on this host.",
                    "Restrict SSH access (firewall, allowlist, or bind to trusted interface/VPN).",
                    "Prefer key-based authentication; disable password auth if possible.",
                    "Monitor for continued failed logins and consider rate limiting (e.g., Fail2ban).",
                ],
                playbooks=[
                    {
                        "title": "Inspect recent SSH authentication activity",
                        "commands": [
                            "journalctl _COMM=sshd --since '2 hours ago' --no-pager | tail -n 120",
                            "grep -n 'Failed password' /var/log/auth.log | tail -n 80",
                            "grep -n 'Failed publickey' /var/log/auth.log | tail -n 80",
                        ],
                        "notes": [
                            "Confirm whether failures are expected (testing) or suspicious (repeated / unknown IPs)."
                        ],
                    },
                    {
                        "title": "Verify SSH exposure and listeners",
                        "commands": [
                            "ss -lntp | grep ':22 '",
                            "sudo ufw status verbose || true",
                            "systemctl status sshd --no-pager || systemctl status ssh --no-pager",
                        ],
                        "notes": [
                            "If SSH is not needed publicly, restrict access."
                        ],
                    }
                ]
            )
        )

    # AUTH-TREND-001: Increasing authentication failures trend
    if auth_trends:
        summary = auth_trends.get("summary", {})
        if summary.get("trigger_auth_trend_001") is True:
            direction = summary.get("direction", "unknown")
            delta = summary.get("delta", 0)
            files_compared = summary.get("files_compared", 0)
            first_val = summary.get("first_value", 0)
            last_val = summary.get("last_value", 0)
            
            findings.append(
                Finding(
                    id="AUTH-TREND-001",
                    title="Increasing authentication failures observed across recent runs",
                    severity="medium",
                    evidence=[
                        f"direction = {direction}",
                        f"delta = {delta} (from {first_val} to {last_val})",
                        f"files compared = {files_compared}",
                        f"trend source: {auth_trends.get('generated_at', 'unknown')}",
                    ],
                    recommendation=[
                        "Verify whether admin activity or testing caused the increase.",
                        "Review auth logs around the newest run timestamps to identify patterns.",
                        "If SSH bursts exist, consider rate-limiting or disabling password authentication.",
                        "Monitor for continued escalation in future runs.",
                    ],
                )
            )

    # INTEG-001: File/config integrity changes (from check_file_integrity's baseline diff)
    if file_integrity and isinstance(file_integrity.get("diff"), dict):
        diff = file_integrity["diff"]
        changed = diff.get("changed") or []
        added = diff.get("added") or []
        removed = diff.get("removed") or []

        if changed or added or removed:
            evidence = [f"Source: {file_integrity.get('checked_at', 'unknown')} (baseline: {file_integrity.get('baseline_name', 'default')})"]
            if changed:
                evidence.append(f"Changed = {len(changed)}")
                evidence.extend(f"  changed: {c.get('path')}" for c in changed[:10])
            if added:
                evidence.append(f"Added = {len(added)}")
                evidence.extend(f"  added: {a.get('path')}" for a in added[:10])
            if removed:
                evidence.append(f"Removed = {len(removed)}")
                evidence.extend(f"  removed: {r.get('path')}" for r in removed[:10])

            findings.append(
                Finding(
                    id="INTEG-001",
                    title="Tracked file(s) changed since baseline",
                    severity="medium",
                    evidence=evidence,
                    recommendation=[
                        "Confirm whether this change was an authorized/expected admin action.",
                        "If unexpected, treat as a possible tampering or persistence indicator and investigate further (recent auth activity, running processes).",
                        "Re-baseline (check_file_integrity) once the change is confirmed legitimate, so future diffs are measured from the new known-good state.",
                    ],
                )
            )

    # 4) Environment note (WSL)
    if system_context:
        rel = (system_context.get("os") or {}).get("release", "")
        if "WSL" in rel or "microsoft" in rel.lower():
            findings.append(
                Finding(
                    id="ENV-001",
                    title="Environment appears to be WSL2 (development context)",
                    severity="info",
                    evidence=[_system_context_scope_note(system_context), f"kernel release: {rel}"],
                    recommendation=[
                        "Document this environment in the thesis evaluation (some services/log formats differ from standard Linux).",
                        "Validate core functionality on a non-WSL Linux host or SBC during the deployment/testing phase if possible.",
                    ],
                )
            )

    # Surface the attacking source IP(s) on IP-sourced findings so the answer
    # can attribute the activity, then deterministically corroborate them against
    # the offline threat-intel cache (Option 1). Both are independent of whether
    # the agent chose to call check_ip_reputation.
    _surface_source_ips_in_evidence(findings, auth_patterns)
    _enrich_findings_with_offline_reputation(findings, auth_patterns)

    # Sort by severity (high -> info)
    findings.sort(key=lambda f: _severity_rank(f.severity), reverse=True)
    return findings


# ---------------------------
# Auto-discovered input staleness (Sprint 3 cleanup, 2026-07-16)
# ---------------------------
# Reference pattern: adapters/vuln_scan.py::check_vulscan_db_staleness /
# STALENESS_THRESHOLD_DAYS -- same non-blocking, mtime-based, "round number,
# stated as such" philosophy, applied here to a different question (spread
# BETWEEN several auto-discovered inputs' timestamps, not one file's age
# against now).
#
# Confirmed via real reproduction (the correlate_findings path-hallucination
# investigation) that find_latest_inputs() picks the latest file per
# category independently, with no check on how far apart those files
# actually are -- a real run silently correlated a 2-4-day-old nmap scan and
# system-context snapshot against same-day auth data, status "done", no
# warning at all. Not cosmetic: correlate_findings's own value proposition
# is corroborating a finding ACROSS data types (e.g. CORR-SSH-001 combines
# "SSH is exposed" with "a failed-login burst happened"), which only means
# what it claims if those inputs are roughly contemporaneous -- a stale
# nmap/context input mixed with fresh auth data can make a finding look
# corroborated when it's really "exposed at some point in the past, burst
# happening now," a materially weaker claim.
#
# A single, uniform threshold (not category-aware): auth data is
# effectively continuous while nmap/context data changes far less often, but
# there's no real usage data yet to calibrate a per-category-pair matrix
# against, and the codebase's own precedent (vulscan's threshold) is a
# single round number stated as operationally reasonable, not precisely
# derived -- matching that rather than inventing new machinery. 24 hours:
# short enough to catch the real multi-day-stale scenario that surfaced
# this, long enough that a single investigation collecting different
# categories a few hours apart (normal, not a problem) doesn't get flagged.
STALENESS_SPREAD_THRESHOLD_HOURS = 24


def _staleness_warning(inputs: dict[str, Path | None], auto_discovered_keys: set[str]) -> str | None:
    """
    None if fewer than 2 auto-discovered inputs are present (nothing to
    compare), or if the spread between the oldest and newest auto-discovered
    input is within STALENESS_SPREAD_THRESHOLD_HOURS. Explicitly-pinned
    inputs (in `inputs` but not in `auto_discovered_keys`) are never
    considered here -- an explicit path is the caller's own informed choice,
    not something this warning second-guesses (see module docstring above).
    """
    mtimes: dict[str, float] = {}
    for key in auto_discovered_keys:
        path = inputs.get(key)
        if path is not None:
            mtimes[key] = path.stat().st_mtime

    if len(mtimes) < 2:
        return None

    newest_key = max(mtimes, key=lambda k: mtimes[k])
    oldest_key = min(mtimes, key=lambda k: mtimes[k])
    spread_hours = (mtimes[newest_key] - mtimes[oldest_key]) / 3600
    if spread_hours <= STALENESS_SPREAD_THRESHOLD_HOURS:
        return None

    newest_ts = datetime.fromtimestamp(mtimes[newest_key]).isoformat(timespec="seconds")
    oldest_ts = datetime.fromtimestamp(mtimes[oldest_key]).isoformat(timespec="seconds")
    return (
        f"Auto-discovered inputs span {spread_hours:.1f}h (> {STALENESS_SPREAD_THRESHOLD_HOURS}h "
        f"threshold): '{newest_key}' is from {newest_ts}, '{oldest_key}' is from {oldest_ts}. This "
        "correlation mixes fresher and staler data -- treat any finding that depends on the older "
        "input(s) as reflecting that input's collection time, not necessarily the current state."
    )


# ---------------------------
# Report writing
# ---------------------------
def write_findings_report(
    data_dir: Path,
    nmap_parsed_file: Path | None = None,
    auth_stats_file: Path | None = None,
    auth_patterns_file: Path | None = None,
    system_context_file: Path | None = None,
    auth_trends_file: Path | None = None,
    file_integrity_file: Path | None = None,
) -> tuple[Path, Path]:
    """
    Generate findings report.

    Input resolution is PER-ARGUMENT, not all-or-nothing: for each of
    nmap_parsed_file, auth_stats_file, auth_patterns_file, system_context_file
    -- an explicitly-provided value is used EXACTLY as given and is never
    silently swapped for an auto-discovered file. Only arguments left as None
    are auto-discovered via find_latest_inputs(data_dir), independently of
    whether sibling arguments were also given. If an explicitly-provided path
    does not exist on disk, that specific input is recorded in the written
    report's "input_errors" (and left out of "missing_inputs"/the generated
    findings for that input) rather than silently falling back to a different
    file for that slot.

    auth_trends_file and file_integrity_file keep different semantics from
    the core four above: when all four core fields are given explicitly (the
    "transaction" pattern `kratos run` uses), an omitted auth_trends_file /
    file_integrity_file means "none for this report" -- not "please look one
    up" -- since `kratos run`'s legacy pipeline never generates either of
    these. When called with those four omitted (the plain `findings-generate`
    / agent-loop pattern), a None auth_trends_file / file_integrity_file IS
    auto-discovered like the others, preserving that existing behavior.
    """
    explicit = {
        "nmap_parsed": nmap_parsed_file,
        "auth_stats": auth_stats_file,
        "auth_patterns": auth_patterns_file,
        "system_context": system_context_file,
    }
    auto = find_latest_inputs(data_dir)

    inputs: dict[str, Path | None] = {}
    input_errors: dict[str, str] = {}
    auto_discovered_keys: set[str] = set()
    for key, explicit_value in explicit.items():
        if explicit_value is None:
            inputs[key] = auto.get(key)
            if inputs[key] is not None:
                auto_discovered_keys.add(key)
            continue
        path = Path(explicit_value)
        if path.exists():
            inputs[key] = path
        else:
            input_errors[key] = f"Explicit path does not exist: {path}"
            inputs[key] = None

    all_required_explicit = all(v is not None for v in explicit.values())

    def _resolve_optional(key: str, explicit_value: Path | None) -> None:
        if explicit_value is not None:
            path = Path(explicit_value)
            if path.exists():
                inputs[key] = path
            else:
                input_errors[key] = f"Explicit path does not exist: {path}"
                inputs[key] = None
        elif all_required_explicit:
            inputs[key] = None
        else:
            inputs[key] = auto.get(key)
            if inputs[key] is not None:
                auto_discovered_keys.add(key)

    _resolve_optional("auth_trends", auth_trends_file)
    _resolve_optional("file_integrity", file_integrity_file)

    missing = [k for k, v in inputs.items() if v is None and k not in input_errors]
    staleness_warning = _staleness_warning(inputs, auto_discovered_keys)
    # We allow partial reports; still generate report but mark missing/errored inputs.
    nmap_parsed = _read_json(inputs["nmap_parsed"]) if inputs["nmap_parsed"] else None
    auth_stats = _read_json(inputs["auth_stats"]) if inputs["auth_stats"] else None
    auth_patterns = _read_json(inputs["auth_patterns"]) if inputs["auth_patterns"] else None
    system_context = _read_json(inputs["system_context"]) if inputs["system_context"] else None
    auth_trends = _read_json(inputs["auth_trends"]) if inputs["auth_trends"] else None
    file_integrity = _read_json(inputs["file_integrity"]) if inputs["file_integrity"] else None

    findings = generate_findings(nmap_parsed, auth_stats, auth_patterns, system_context, auth_trends, file_integrity)

    # Environment detection
    env_label = "linux"
    if system_context:
        rel = (system_context.get("os") or {}).get("release", "")
        if "WSL" in rel or "microsoft" in rel.lower():
            env_label = "wsl2"

    report_obj = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "tool": {"name": "kratos", "version": KRATOS_VERSION},
        "environment": {"label": env_label},
        # Explicit, report-level flag for which host system_context describes --
        # a findings report must never present local-Kratos-host state as if
        # it were the monitored target's state without this being visible.
        "system_context_scope": (system_context or {}).get("scope") if system_context else None,
        "inputs": {k: (v.name if v else None) for k, v in inputs.items()},
        "missing_inputs": missing,
        "input_errors": input_errors,
        "staleness_warning": staleness_warning,
        "findings": [asdict(f) for f in findings],
    }

    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    out_json = reports_dir / f"findings_{ts}.json"
    out_md = reports_dir / f"findings_{ts}.md"

    out_json.write_text(json.dumps(report_obj, indent=2), encoding="utf-8")

    # Markdown report (thesis/demo friendly)
    md_lines: list[str] = []
    md_lines.append(f"# Kratos Findings Report\n")
    md_lines.append(f"- Generated at: {report_obj['generated_at']}")
    md_lines.append(f"- Inputs:")
    for k, v in report_obj["inputs"].items():
        md_lines.append(f"  - {k}: {v}")
    if missing:
        md_lines.append(f"\n> Note: Missing inputs: {', '.join(missing)}\n")
    if staleness_warning:
        md_lines.append(f"\n> **Staleness warning**: {staleness_warning}\n")

    md_lines.append("\n## Findings\n")
    if not findings:
        md_lines.append("_No findings generated._")
    else:
        for f in findings:
            md_lines.append(f"### [{f.severity.upper()}] {f.id} — {f.title}\n")
            md_lines.append("**Evidence**")
            for e in f.evidence:
                md_lines.append(f"- {e}")
            md_lines.append("\n**Recommendations**")
            for r in f.recommendation:
                md_lines.append(f"- {r}")
            
            # Add playbooks section if present
            if f.playbooks:
                md_lines.append("\n**Playbooks (verification steps)**")
                for pb in f.playbooks:
                    md_lines.append(f"- **{pb['title']}**")
                    for cmd in pb.get('commands', []):
                        md_lines.append(f"  - `{cmd}`")
                    for note in pb.get('notes', []):
                        md_lines.append(f"  - {note}")
            
            md_lines.append("")

    out_md.write_text("\n".join(md_lines).strip() + "\n", encoding="utf-8")

    return out_json, out_md
