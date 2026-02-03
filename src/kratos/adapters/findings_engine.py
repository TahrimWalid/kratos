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

    return {
        "nmap_parsed": latest_file(scans_dir, "parsed_*.json"),
        "auth_stats": latest_file(logs_dir, "auth_stats_*.json"),
        "auth_patterns": latest_file(logs_dir, "auth_patterns_*.json"),
        "system_context": latest_file(ctx_dir, "system_context_*.json"),
        "auth_trends": latest_file(reports_dir, "auth_trends_*.json"),
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


# ---------------------------
# Core: generate findings
# ---------------------------
def generate_findings(
    nmap_parsed: dict[str, Any] | None,
    auth_stats: dict[str, Any] | None,
    auth_patterns: dict[str, Any] | None,
    system_context: dict[str, Any] | None,
    auth_trends: dict[str, Any] | None = None,
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
            findings.append(
                Finding(
                    id="OBS-001",
                    title="Authentication failures detected but log collection services appear inactive",
                    severity="medium",
                    evidence=[
                        f"auth failure events = {failures}",
                        "rsyslog.service active = false",
                        "systemd-journald.service active = false",
                        f"context snapshot = {system_context.get('collected_at', 'unknown')}",
                    ],
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

    # 4) Environment note (WSL)
    if system_context:
        rel = (system_context.get("os") or {}).get("release", "")
        if "WSL" in rel or "microsoft" in rel.lower():
            findings.append(
                Finding(
                    id="ENV-001",
                    title="Environment appears to be WSL2 (development context)",
                    severity="info",
                    evidence=[f"kernel release: {rel}"],
                    recommendation=[
                        "Document this environment in the thesis evaluation (some services/log formats differ from standard Linux).",
                        "Validate core functionality on a non-WSL Linux host or SBC during the deployment/testing phase if possible.",
                    ],
                )
            )

    # Sort by severity (high -> info)
    findings.sort(key=lambda f: _severity_rank(f.severity), reverse=True)
    return findings


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
) -> tuple[Path, Path]:
    """
    Generate findings report.
    
    When called from `kratos run`, explicit file paths from the current transaction are passed.
    When called from manual `findings-generate`, uses latest files (backwards compatible).
    """
    # If explicit files not provided, fall back to "latest file" lookup
    if not all([nmap_parsed_file, auth_stats_file, auth_patterns_file, system_context_file]):
        inputs = find_latest_inputs(data_dir)
    else:
        # Use the explicit paths provided (transaction mode)
        inputs = {
            "nmap_parsed": nmap_parsed_file,
            "auth_stats": auth_stats_file,
            "auth_patterns": auth_patterns_file,
            "system_context": system_context_file,
            "auth_trends": auth_trends_file,
        }

    missing = [k for k, v in inputs.items() if v is None]
    # We allow partial reports; still generate report but mark missing inputs.
    nmap_parsed = _read_json(inputs["nmap_parsed"]) if inputs["nmap_parsed"] else None
    auth_stats = _read_json(inputs["auth_stats"]) if inputs["auth_stats"] else None
    auth_patterns = _read_json(inputs["auth_patterns"]) if inputs["auth_patterns"] else None
    system_context = _read_json(inputs["system_context"]) if inputs["system_context"] else None
    auth_trends = _read_json(inputs["auth_trends"]) if inputs["auth_trends"] else None

    findings = generate_findings(nmap_parsed, auth_stats, auth_patterns, system_context, auth_trends)

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
        "inputs": {k: (v.name if v else None) for k, v in inputs.items()},
        "missing_inputs": missing,
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
