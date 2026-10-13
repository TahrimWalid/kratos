"""The built-in checks: thin wrappers over tools Kratos already has.

Each goes through `ctx.call` (execute_tool_call in real use), so the dispatch guards,
the target checks, approval gating and event recording all still apply, and each
returns a one-line summary built from the tool's STRUCTURED result -- never from raw
log text, so the digest holds Kratos-written words and finding IDs only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kratos.collect.registry import Check, CheckContext, CheckResult, register

_LAST_24H = {"kind": "rolling", "amount": 24, "unit": "hour"}
_MAX_PORTS_SHOWN = 8


def _unwrap(res: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None, str | None]:
    """(inner result, error text, coverage_gap) of an execute_tool_call reply."""
    if not isinstance(res, dict):
        return None, "no reply", None
    inner = res.get("result") if isinstance(res.get("result"), dict) else None
    gap = None
    for src in (res, inner):
        if isinstance(src, dict) and isinstance(src.get("coverage_gap"), str):
            gap = src["coverage_gap"]
    if res.get("status") != "ok":
        return None, str(res.get("observation") or "the tool failed")[:300], gap
    if inner is not None and inner.get("status") == "error":
        return None, str(inner.get("observation") or "the tool failed")[:300], gap
    return inner or {}, None, gap


def _failed(label: str, err: str, gap: str | None, tool: str) -> CheckResult:
    return CheckResult(
        status="not_supported" if gap else "failed",
        summary="not checked (unavailable on this machine)" if gap else "could not be checked",
        coverage_gaps=[gap or f"{label}: could not be checked"], detail=err, tools=[tool])


# --------------------------------------------------------------------------- ports
def _run_ports(ctx: CheckContext) -> CheckResult:
    res = ctx.call("run_nmap_scan", {})
    inner, err, gap = _unwrap(res)
    if inner is None:
        return _failed("open ports", err or "", gap, "run_nmap_scan")
    ports: list[str] = []
    parsed_file = inner.get("parsed_json_file")
    try:
        data = json.loads(Path(str(parsed_file)).read_text(encoding="utf-8"))
        for host in data.get("hosts") or []:
            for p in host.get("open_ports") or []:
                ports.append(f"{p.get('port')}/{p.get('protocol')} {p.get('service') or 'unknown'}".strip())
    except (OSError, ValueError, TypeError):
        n = int(inner.get("open_ports_total") or 0)
        return CheckResult("ok", f"{n} open port(s)" if n else "no open ports found", tools=["run_nmap_scan"])
    if not ports:
        return CheckResult("ok", "no open ports found", tools=["run_nmap_scan"])
    shown = ", ".join(ports[:_MAX_PORTS_SHOWN]) + (f" (+{len(ports) - _MAX_PORTS_SHOWN} more)"
                                                   if len(ports) > _MAX_PORTS_SHOWN else "")
    return CheckResult("ok", f"{len(ports)} open port(s): {shown}", tools=["run_nmap_scan"])


# --------------------------------------------------------------------------- auth, last 24 h
def _run_auth_activity(ctx: CheckContext) -> CheckResult:
    res = ctx.call("measure_auth_activity", {"window": dict(_LAST_24H)})
    inner, err, gap = _unwrap(res)
    if inner is None:
        return _failed("sign-in activity", err or "", gap, "measure_auth_activity")
    counts = inner.get("counts") if isinstance(inner.get("counts"), dict) else {}
    failed = int(counts.get("ssh_failed_login") or 0)
    ips = int(inner.get("distinct_failed_login_ips") or 0)
    bursts = inner.get("bursts") if isinstance(inner.get("bursts"), list) else []
    ok_logins = int(counts.get("ssh_success_login") or 0)
    parts = []
    if failed:
        bits = f"{failed} failed SSH login(s)"
        if ips:
            bits += f" from {ips} address(es)"
        parts.append(bits)
    else:
        parts.append("no failed SSH logins")
    if bursts:
        parts.append(f"{len(bursts)} burst(s)")
    if ok_logins:
        parts.append(f"{ok_logins} accepted login(s)")
    window = inner.get("window") if isinstance(inner.get("window"), dict) else {}
    gaps: list[str] = []
    status = "ok"
    pct = window.get("coverage_percent")
    if isinstance(pct, (int, float)) and pct < 100 and window.get("problems"):
        status = "partial"
        parts.append(f"only {pct:g}% of the 24 h is covered by the logs; the rest is unknown, not clean")
    return CheckResult(status, "; ".join(parts), gaps, tools=["measure_auth_activity"])


# --------------------------------------------------------------------------- log tampering
_INTEGRITY_LABELS = {
    "file_state": "log files", "journal": "journal files", "boots": "boot history",
    "login_records": "login records", "auditd": "audit log",
}


def _run_log_integrity(ctx: CheckContext) -> CheckResult:
    res = ctx.call("check_log_integrity", {})
    inner, err, gap = _unwrap(res)
    if inner is None:
        return _failed("log tampering", err or "", gap, "check_log_integrity")
    suspicious = [str(c) for c in inner.get("suspicious_checks") or []]
    gaps = [gap] if gap else []
    status = "partial" if gaps else "ok"
    if suspicious:
        names = ", ".join(_INTEGRITY_LABELS.get(c, c) for c in suspicious)
        return CheckResult(status, f"something looks off in: {names}", gaps, tools=["check_log_integrity"])
    return CheckResult(status, "no sign of altered logs", gaps, tools=["check_log_integrity"])


# --------------------------------------------------------------------------- privileged accounts
def _run_privileged_accounts(ctx: CheckContext) -> CheckResult:
    res = ctx.call("list_privileged_accounts", {"lookback_days": 30})
    inner, err, gap = _unwrap(res)
    if inner is None:
        return _failed("privileged accounts", err or "", gap, "list_privileged_accounts")
    n = len(inner.get("privileged_accounts") or [])
    grants = len(inner.get("recent_privilege_grants") or [])
    changed = inner.get("changed_since_last_check") if isinstance(inner.get("changed_since_last_check"), dict) else {}
    added, removed = len(changed.get("added") or []), len(changed.get("removed") or [])
    parts = [f"{n} account(s) hold privileged access"]
    if grants:
        parts.append(f"{grants} recent grant(s)")
    if changed.get("previous_snapshot_at"):
        parts.append(f"{added} new and {removed} gone since the last check" if added or removed
                     else "no change since the last check")
    else:
        parts.append("first look, nothing to compare with")
    gaps = [g for g in (inner.get("evidence_gaps") or []) if isinstance(g, str)]
    if gaps:
        parts.append("some account-change history is missing")
    return CheckResult("partial" if gaps else "ok", "; ".join(parts), [], tools=["list_privileged_accounts"],
                       detail="; ".join(gaps)[:300])


# --------------------------------------------------------------------------- configuration audit
_AUDIT_NAMES = {
    "ssh_root_login": "SSH root login", "ssh_password_auth": "SSH password login", "firewall": "firewall",
    "fail2ban_status": "fail2ban", "world_writable_etc": "world-writable files in /etc",
    "unattended_upgrades": "automatic updates",
}


def _run_config_audit(ctx: CheckContext) -> CheckResult:
    res = ctx.call("run_config_audit", {})
    inner, err, gap = _unwrap(res)
    if inner is None:
        return _failed("configuration", err or "", gap, "run_config_audit")
    rows = [c for c in inner.get("checks") or [] if isinstance(c, dict)]
    by_status: dict[str, list[str]] = {}
    for c in rows:
        status = str(c.get("status") or "UNKNOWN").upper()
        name = _AUDIT_NAMES.get(str(c.get("check")), "another setting")     # fixed words, never the machine's
        by_status.setdefault(status if status in ("PASS", "FAIL", "WARN") else "UNKNOWN", []).append(name)
    if not rows:
        return CheckResult("failed", "could not be checked", ["configuration: could not be checked"],
                           tools=["run_config_audit"])
    parts = [f"{len(by_status.get('PASS', []))} of {len(rows)} settings are fine"]
    for key, word in (("FAIL", "failing"), ("WARN", "warning"), ("UNKNOWN", "could not be read")):
        if by_status.get(key):
            parts.append(f"{word}: {', '.join(sorted(set(by_status[key])))}")
    return CheckResult("ok", "; ".join(parts), tools=["run_config_audit"])


# --------------------------------------------------------------------------- registration
register(Check(
    name="ports", cost="quick", ttl_setting="collect.ttl.ports_minutes", default_ttl_minutes=60,
    run=_run_ports, inputs=("nmap_parsed",), transports=frozenset({"ssh", "agent"}), budget_seconds=40.0,
    label="open ports", order=30, short="ports"))
register(Check(
    name="auth_activity", cost="quick", ttl_setting="collect.ttl.auth_activity_minutes", default_ttl_minutes=15,
    run=_run_auth_activity, inputs=("auth_stats", "auth_patterns"), transports=frozenset({"ssh", "agent"}),
    budget_seconds=40.0, label="sign-in activity (24 h)", order=10, short="auth 24 h"))
register(Check(
    name="log_integrity", cost="quick", ttl_setting="collect.ttl.log_integrity_minutes", default_ttl_minutes=60,
    run=_run_log_integrity, inputs=("log_integrity",), transports=frozenset({"ssh", "agent"}),
    budget_seconds=40.0, label="log tampering", order=20, short="tampering"))
register(Check(
    name="privileged_accounts", cost="quick", ttl_setting="collect.ttl.privileged_accounts_minutes",
    default_ttl_minutes=60, run=_run_privileged_accounts, inputs=("privileged_accounts",),
    transports=frozenset({"ssh", "agent"}), budget_seconds=40.0, label="privileged accounts", order=40,
    short="privileged"))
register(Check(
    name="config_audit", cost="quick", ttl_setting="collect.ttl.config_audit_minutes", default_ttl_minutes=360,
    run=_run_config_audit, inputs=(), transports=frozenset({"ssh", "agent"}), budget_seconds=40.0,
    label="configuration audit", order=60, short="config"))
