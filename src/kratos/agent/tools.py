"""
Tool registry for the Kratos ReAct agent.

Each tool is a thin wrapper around an existing adapter's logic — the adapters
themselves are not modified. Handlers always return JSON-serializable dicts
(no printing to stdout), so the same handler can be called directly (as here)
or later by an LLM-driven agent loop.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import shlex
import subprocess
import time
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from kratos.adapters.nmap_scan import run_nmap_scan as _run_nmap_scan
from kratos.adapters.nmap_parse import parse_nmap_xml_to_dict as _parse_nmap_xml_to_dict
from kratos.adapters.nmap_parse import write_parsed_json as _write_parsed_json
from kratos.adapters.network_capture import capture_traffic as _capture_traffic
from kratos.adapters.system_context import write_system_context as _write_system_context
from kratos.adapters.auth_log_parse import (
    parse_auth_log_file as _parse_auth_log_file,
    classify_auth_message as _classify_auth_message,
    compute_basic_stats as _compute_basic_stats,
)
from kratos.adapters.auth_log_patterns import analyze_auth_patterns as _analyze_auth_patterns
from kratos.adapters.findings_engine import write_findings_report as _write_findings_report
from kratos.kratos_config import (
    SSH_TARGET_USER,
    THREAT_INTEL_ENABLED as _THREAT_INTEL_ENABLED,
    VULSCAN_UPDATE_PROMPT as _VULSCAN_UPDATE_PROMPT,
    get_active_target,
)
from kratos.agent import console as _console
from kratos.utils.time_window import (
    TimeBoundError as _TimeBoundError,
    epoch_to_iso_utc as _epoch_to_iso_utc,
)
from kratos.timewin.toolwin import resolve_tool_window as _resolve_tool_window
from kratos.timewin.measure import (
    DEFAULT_TIME_BUDGET_SECONDS as _MEASURE_BUDGET,
    build_script as _build_measure_script,
    parse_output as _parse_measure_output,
)
from kratos.timewin.windows import TimeIntentError as _TimeIntentError, current_context as _current_time_context
from kratos.timewin.claims import METRICS as _CLAIM_METRICS, measurement_summary as _measurement_summary
from kratos.timewin.compare import compare_measurements as _compare_measurements
from kratos.timewin.snapshots import (
    DESCRIPTIONS as _SNAPSHOT_DESCRIPTIONS,
    as_of as _snapshot_as_of,
    horizon as _snapshot_horizon,
    summarize as _snapshot_summary,
    within as _snapshots_within,
)
from kratos.utils.time_window import resolve_time_bound as _resolve_time_bound
from kratos.adapters.ssh_remote import (
    target_label as _ssh_target_label,
    fetch_journalctl_entries as _fetch_journalctl_entries,
    fetch_journalctl_auth_entries as _fetch_journalctl_auth_entries,
    measure_target_clock_offset as _measure_target_clock_offset,
    CLOCK_OFFSET_WARN_SECONDS as _CLOCK_OFFSET_WARN_SECONDS,
    fetch_open_files as _fetch_open_files,
    fetch_processes as _fetch_processes,
    fetch_file_hashes as _fetch_file_hashes,
    run_config_audit_checks as _run_config_audit_checks,
    fetch_yara_scan as _fetch_yara_scan,
    run_remote_script as _run_remote_script,
    _journalctl_prefix,
    SSHResult as _SSHResult,
)
from kratos.adapters.baseline import (
    save_file_integrity_baseline as _save_file_integrity_baseline,
    load_file_integrity_baseline as _load_file_integrity_baseline,
    diff_file_integrity as _diff_file_integrity,
    save_file_integrity_diff as _save_file_integrity_diff,
)
from kratos.adapters.vuln_scan import (
    check_vulscan_db_staleness as _check_vulscan_db_staleness,
    update_vulscan_db as _update_vulscan_db,
    run_nmap_vulscan as _run_nmap_vulscan,
    parse_vulscan_xml as _parse_vulscan_xml,
    run_nuclei_scan as _run_nuclei_scan,
    parse_nuclei_jsonl as _parse_nuclei_jsonl,
    DEFAULT_NUCLEI_TAGS as _DEFAULT_NUCLEI_TAGS,
    STALENESS_THRESHOLD_DAYS as _VULSCAN_STALENESS_THRESHOLD_DAYS,
)
from kratos.adapters.threat_intel import (
    lookup_ip_cache as _lookup_ip_cache,
    lookup_ip_live_abuseipdb as _lookup_ip_live_abuseipdb,
)
from kratos.agent.notify import send_notification as _send_notification


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, dict[str, Any]]
    handler: Callable[..., dict[str, Any]]
    requires_approval: bool = False


TOOL_REGISTRY: dict[str, Tool] = {}


def tool_reaches_approval(tool: Tool | None) -> bool:
    """True if a tool COULD pause to ask a human to approve something mid-run —
    used to EXCLUDE such tools from a headless surface (the MCP server) and to
    WARN about them in a plan preview. Two independent signals, because the
    registry flag alone is not complete (a tool may reach request_approval only
    CONDITIONALLY from inside its handler with requires_approval=False, e.g.
    run_vuln_scan's staleness prompt / check_ip_reputation's live tier): the
    registry's requires_approval, OR the handler's own source text containing a
    `request_approval(` call. Fails SAFE — a None tool (an unknown/dangling step)
    or an unreadable handler source is treated as reaching approval, never
    assumed fine because it couldn't be checked.

    Single source of truth for this check (mcp_server.py and
    tui_mk2/agent/plan_preview.py both import it). NOTE the DIFFERENT, deliberate
    sibling in agent/loop.py::_handler_self_gates — that answers the OPPOSITE
    question ("does the handler gate ITSELF, so dispatch needn't add a gate?")
    with the OPPOSITE fail-safe (False → gate at dispatch); do not merge them.
    Known limit: scans only the handler's own source, not helpers it calls — true
    for every tool that reaches request_approval today.
    """
    if tool is None:
        return True
    if tool.requires_approval:
        return True
    try:
        source = inspect.getsource(tool.handler)
    except (OSError, TypeError):
        return True
    return "request_approval(" in source


def register_tool(
    name: str,
    description: str,
    parameters: dict[str, dict[str, Any]],
    requires_approval: bool = False,
):
    """Decorator: registers `func` under `name` in TOOL_REGISTRY."""
    def decorator(func: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        TOOL_REGISTRY[name] = Tool(
            name=name,
            description=description,
            parameters=parameters,
            handler=func,
            requires_approval=requires_approval,
        )
        return func
    return decorator


# Append-only record of every request_approval() call: {"tool": name, "approved": bool}.
# execute_tool_call (agent/loop.py) uses this as a backstop to verify that a
# tool marked requires_approval=True actually consulted the approval gate
# during its call, rather than trusting the requires_approval flag alone --
# see approval_log_length()/approval_was_recorded() below.
_approval_log: list[dict[str, Any]] = []


def approval_log_length() -> int:
    return len(_approval_log)


def approval_was_recorded(tool_name: str, since_index: int) -> bool:
    """True if request_approval(tool_name, ...) was called at least once since_index."""
    return any(entry["tool"] == tool_name for entry in _approval_log[since_index:])


# Swappable presentation/decision provider for request_approval (2026-09-03,
# kratos-mk2 Textual TUI). DEFAULT is None -> the exact prior behavior below
# (render_approval_situation + a blocking input()), so the classic
# `kratos` REPL and every shell subcommand are byte-for-byte unaffected. The
# Textual TUI installs a provider that renders a modal and blocks the worker
# thread on the user's answer instead -- a blocking input() cannot drive a
# Textual modal. A provider only replaces the "show the situation and get a
# yes/no" step; the fail-safe semantics (any exception/interrupt -> denial)
# and the central _approval_log recording (which execute_tool_call's backstop
# depends on) both stay HERE, so no gate can bypass them by supplying a
# provider. See src/kratos/tui_mk2/approvals.py for the TUI's provider.
_approval_prompt_provider: "Callable[[str, dict[str, Any]], bool] | None" = None


def set_approval_prompt_provider(provider: "Callable[[str, dict[str, Any]], bool] | None") -> None:
    """Install (or clear, with None) the approval decision provider. When set,
    request_approval delegates the render+decide step to it instead of the
    built-in input() prompt. The provider must return a truthy value ONLY for
    an explicit approval; anything else (including a raised exception) is
    treated as a denial, preserving the no-force-accept invariant."""
    global _approval_prompt_provider
    _approval_prompt_provider = provider


def request_approval(tool_name: str, details: dict[str, Any]) -> bool:
    """
    Blocking human approval prompt. Every tool that executes a command or
    escalates privilege (run_linux_command, capture_traffic) MUST call this
    and check its return value before doing anything irreversible — no
    parameter, retry, or error path may skip it. Returns True only on an
    explicit (case/whitespace-insensitive) 'y' or 'yes'; Enter or anything
    else denies -- fail-safe, never force-accept.

    No TTY / interrupted input (EOFError, KeyboardInterrupt) is treated as an
    explicit denial -- fail-safe by design, not by accidental exception
    propagation into a caller's generic except clause.

    Sprint 3 Phase 2 (CLI overhaul): the print block immediately below and
    the input() prompt string are the ONLY things that changed here --
    rendering now goes through agent/console.py::render_approval_situation,
    the single shared presentation path for every approval gate (self-write
    keep, run_linux_command, capture_traffic, live threat-intel, vulscan
    staleness). Still blocks on the same input(), still no force-accept
    fallback, still the same EOFError/KeyboardInterrupt -> denial handling.

    kratos-mk2 (2026-09-03): when set_approval_prompt_provider() has installed
    a provider (the Textual TUI does), the render+decide step is delegated to
    it -- but the fail-safe (any exception -> denial) and the _approval_log
    recording below still happen here unconditionally, so the invariants hold
    regardless of provider.
    """
    if _approval_prompt_provider is not None:
        try:
            approved = bool(_approval_prompt_provider(tool_name, details))
        except (EOFError, KeyboardInterrupt):
            approved = False
        except Exception:  # noqa: BLE001 -- a broken provider must fail safe, never force-accept
            approved = False
        _approval_log.append({"tool": tool_name, "approved": approved})
        return approved

    _console.render_approval_situation(_console.get_console(), tool_name, details)

    try:
        decision = input(_console.approval_prompt_text()).strip().lower()
        # Fail-safe: ONLY an explicit yes approves; Enter/n/anything else denies.
        approved = decision in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        approved = False

    _approval_log.append({"tool": tool_name, "approved": approved})
    return approved


@register_tool(
    name="run_nmap_scan",
    description=(
        "Checks NETWORK EXPOSURE / ATTACK SURFACE: what ports and services are reachable on a "
        "host. Relevant for any question about whether a system is exposed, reachable, or "
        "vulnerable from the network -- not only when the goal explicitly says 'scan' or "
        "'ports'. Worth considering for almost any general security investigation, since "
        "exposure is one of the basic categories a thorough check covers alongside auth "
        "activity and system state. Saves both raw XML and normalized JSON under "
        "data_dir/scans/; the normalized JSON is what correlate_findings picks up automatically. "
        "Defaults to scanning the MONITORED TARGET DEVICE (the protected system, same as the "
        "SSH-based tools) -- pass target explicitly only to check a different host, e.g. "
        "'127.0.0.1' for Kratos's own local host specifically (self-monitoring, not the default)."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "target": {"type": "str|null", "description": "IP or hostname to scan. Defaults to the configured/active SSH target.", "default": None},
    },
)
def tool_run_nmap_scan(data_dir: Path, target: str | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    resolved_target = target or get_active_target()
    out_xml = _run_nmap_scan(data_dir, resolved_target)
    parsed = _parse_nmap_xml_to_dict(out_xml)
    out_json = _write_parsed_json(data_dir, parsed)

    hosts = parsed.get("hosts", [])
    return {
        "xml_file": str(out_xml),
        "parsed_json_file": str(out_json),
        "target": resolved_target,
        "host_count": len(hosts),
        "open_ports_total": sum(len(h.get("open_ports", [])) for h in hosts),
    }


@register_tool(
    name="capture_traffic",
    description=(
        "LOCAL KRATOS HOST -- not the monitored target. Checks LIVE NETWORK ACTIVITY: passively "
        "captures real traffic on Kratos's OWN host's network interfaces for a fixed duration -- "
        "NOT the SSH target's network. Relevant only when the suspected activity is on Kratos's "
        "own host; for 'is something talking to the network right now' about the monitored target "
        "device, this tool cannot see that traffic at all (it never touches the target). "
        "NON-NEGOTIABLE: escalates privilege via sudo, so this always blocks on an explicit human "
        "y/n approval prompt before running — there is no way to skip it."
    ),
    parameters={
        "duration_seconds": {"type": "int", "description": "Capture duration in seconds", "default": 60},
        "interface": {"type": "str", "description": "Network interface to capture on", "default": "any"},
    },
    requires_approval=True,
)
def tool_capture_traffic(duration_seconds: int = 60, interface: str = "any") -> dict[str, Any]:
    approved = request_approval(
        "capture_traffic",
        {
            "command": f"sudo tcpdump -i {interface} -G {duration_seconds} ...",
            "reason": f"Passively capture network traffic for {duration_seconds}s on interface '{interface}'.",
        },
    )
    if not approved:
        return {
            "status": "not_approved",
            "duration_seconds": duration_seconds,
            "interface": interface,
            "observation": "User did not approve traffic capture. Command was NOT run.",
        }

    out_file = _capture_traffic(duration_seconds=duration_seconds, interface=interface)
    if out_file is None:
        return {"status": "failed", "reason": "capture failed or tcpdump not available"}
    return {"status": "ok", "output_file": str(out_file), "duration_seconds": duration_seconds, "interface": interface}


@register_tool(
    name="collect_system_context",
    description=(
        "LOCAL KRATOS HOST -- not the monitored target. Checks SYSTEM STATE on the machine Kratos "
        "itself runs on: OS/kernel info, users, sudo membership, running services, network "
        "interfaces, SSH exposure. Relevant ONLY for questions about Kratos's own host (self-"
        "monitoring). Do NOT use this to answer 'is anything unusual running', 'who has privileged "
        "access', 'is SSH exposed', or 'is this system okay' about the monitored target device -- "
        "those are answered by the target-facing tools (read_journalctl, list_processes, "
        "list_open_files, run_config_audit), not this one. Using this tool for a target "
        "investigation will silently return Kratos's own local host state instead. Returns a "
        "compact summary; the full context is saved under data_dir/context/ (tagged "
        "'scope': 'local_host') and picked up automatically by correlate_findings, which labels "
        "any findings derived from it accordingly."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
    },
)
def tool_collect_system_context(data_dir: Path) -> dict[str, Any]:
    out_path = _write_system_context(Path(data_dir))
    ctx = json.loads(out_path.read_text(encoding="utf-8", errors="replace"))

    users = ctx.get("users") or {}
    critical_services = ctx.get("critical_services") or {}
    return {
        "context_file": str(out_path),
        "scope": ctx.get("scope", "local_host"),
        "summary": {
            "os": ctx.get("os"),
            "uptime": ctx.get("uptime"),
            "total_users": users.get("total_users"),
            "sudo_group": users.get("sudo_group"),
            "critical_services_detected": critical_services.get("detected"),
            "ssh": ctx.get("ssh"),
        },
    }


@register_tool(
    name="parse_auth_log",
    description=(
        "Checks KRATOS'S OWN LOCAL HOST authentication log (auth.log/secure/journald ON THE MACHINE "
        "KRATOS ITSELF RUNS ON) -- NOT the monitored target device. Relevant ONLY for questions "
        "about whether Kratos's own host has been targeted or compromised (self-monitoring). "
        "Do NOT use this to investigate 'the system' being protected/monitored -- that is the "
        "separate SSH target, and its authentication activity is checked with read_journalctl "
        "instead, not this tool. Using this tool for a target investigation will silently show "
        "irrelevant local data and miss the target's actual auth activity entirely."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "log_path": {"type": "path|null", "description": "Explicit log file path (optional)", "default": None},
        "source": {"type": "str", "description": "'auto', 'file', or 'journald'", "default": "auto"},
    },
)
def tool_parse_auth_log(
    data_dir: Path,
    log_path: str | Path | None = None,
    source: str = "auto",
) -> dict[str, Any]:
    resolved_log_path = Path(log_path) if log_path else None
    events_out, stats_out, stats = _parse_auth_log_file(Path(data_dir), resolved_log_path, source)
    # Also run the burst/brute-force detector on the LOCAL-host events and persist
    # auth_patterns_*.json (Sprint 1 backlog #5). Without this, parse_auth_log
    # produced only events/stats, so correlate_findings had no `bursts` to key
    # CORR-SSH-001 off — a brute force against KRATOS'S OWN HOST went undetected
    # even though the identical target-facing path (read_journalctl ->
    # _persist_target_auth_correlation_data) already runs exactly this analysis.
    # Wired the same way (a direct call, matching that path) so the two auth
    # sources stay symmetric.
    patterns_out = _analyze_auth_patterns(Path(data_dir), events_file=events_out)
    return {
        "events_file": str(events_out),
        "stats_file": str(stats_out),
        "patterns_file": str(patterns_out),
        "stats": stats,
    }


@register_tool(
    name="correlate_findings",
    description=(
        "SYNTHESIZES whatever categories of data have been collected so far (nmap/auth/context/"
        "etc) into concrete, ranked findings -- relevant once you've gathered enough evidence "
        "across the categories that matter for this goal, typically as a later step, not a "
        "substitute for collecting network/auth/system-state data in the first place. "
        "Automatically picks up the latest file each collection tool wrote for every category, "
        "including categories you never collected (it correlates whatever IS available and "
        "leaves the rest out) -- always call this with NO arguments; there is nothing else to "
        "fill in."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        # Investigation, 2026-07-16: these 6 override params exist ONLY for
        # a "pin one specific file instead of the latest" power-user case
        # that the CLI's own pipeline (cmd_run/cmd_findings_generate)
        # already serves by calling write_findings_report() directly,
        # bypassing this tool wrapper entirely -- confirmed via grep, no
        # other code path relies on the agent ever seeing them. The ReAct
        # loop has no legitimate use for them (each collection tool writes
        # exactly one fresh file per call, so "latest" already IS "the one
        # I just made"), yet a real live run showed the model fabricating
        # plausible-looking values for them anyway -- a pattern-completion
        # hallucination off OTHER tools' real Observation filenames in the
        # same conversation, not a missing-instruction problem (the
        # description/RULES already said to omit them, three ways, before
        # this fix). agent_hidden=True removes the affordance from
        # render_tools_for_prompt()'s output instead of adding yet another
        # "don't guess" instruction on top of ones already not working --
        # the model now sees a tool with nothing to fill in at all. The
        # real Python signature below, existence-check validation, and the
        # CLI's own explicit-path usage are all completely unchanged.
        "nmap_parsed_file": {"type": "path|null", "description": "Explicit parsed-Nmap JSON path (default: latest in data_dir/scans)", "default": None, "agent_hidden": True},
        "auth_stats_file": {"type": "path|null", "description": "Explicit auth stats JSON path (default: latest in data_dir/logs)", "default": None, "agent_hidden": True},
        "auth_patterns_file": {"type": "path|null", "description": "Explicit auth patterns JSON path (default: latest in data_dir/logs)", "default": None, "agent_hidden": True},
        "system_context_file": {"type": "path|null", "description": "Explicit system context JSON path (default: latest in data_dir/context)", "default": None, "agent_hidden": True},
        "auth_trends_file": {"type": "path|null", "description": "Explicit auth trends JSON path (optional)", "default": None, "agent_hidden": True},
        "file_integrity_file": {"type": "path|null", "description": "Explicit file-integrity diff JSON path (default: latest in data_dir/baseline)", "default": None, "agent_hidden": True},
    },
)
def tool_correlate_findings(
    data_dir: Path,
    nmap_parsed_file: str | Path | None = None,
    auth_stats_file: str | Path | None = None,
    auth_patterns_file: str | Path | None = None,
    system_context_file: str | Path | None = None,
    auth_trends_file: str | Path | None = None,
    file_integrity_file: str | Path | None = None,
) -> dict[str, Any]:
    data_dir = Path(data_dir)

    # write_findings_report only honors explicit *_file args when ALL FOUR
    # required ones are non-None -- if even one is left as None (very common,
    # since a caller often only has some of the inputs), it silently discards
    # every explicit path given and falls back to find_latest_inputs(data_dir)
    # instead. That means a hallucinated/wrong path would never even be read:
    # it'd just be dropped, and *whatever real file happens to be newest* in
    # data_dir gets used in its place, silently -- looks successful, but for
    # the wrong reason. Validate every explicitly-given path up front so a bad
    # path is a clear, actionable error instead of an invisible substitution.
    explicit_paths = {
        "nmap_parsed_file": nmap_parsed_file,
        "auth_stats_file": auth_stats_file,
        "auth_patterns_file": auth_patterns_file,
        "system_context_file": system_context_file,
        "auth_trends_file": auth_trends_file,
        "file_integrity_file": file_integrity_file,
    }
    missing = [(name, str(Path(value))) for name, value in explicit_paths.items() if value and not Path(value).exists()]
    if missing:
        bad = "; ".join(f"{name}='{path}'" for name, path in missing)
        return {
            "status": "error",
            "observation": (
                f"These file paths do not exist on disk: {bad}. Do not guess file paths — use the "
                "exact path from a previous tool's Observation (e.g. run_nmap_scan's parsed_json_file, "
                "collect_system_context's context_file, parse_auth_log's stats_file), or omit the "
                "argument entirely to auto-discover the latest file in data_dir."
            ),
        }

    out_json, out_md = _write_findings_report(
        data_dir,
        nmap_parsed_file=Path(nmap_parsed_file) if nmap_parsed_file else None,
        auth_stats_file=Path(auth_stats_file) if auth_stats_file else None,
        auth_patterns_file=Path(auth_patterns_file) if auth_patterns_file else None,
        system_context_file=Path(system_context_file) if system_context_file else None,
        auth_trends_file=Path(auth_trends_file) if auth_trends_file else None,
        file_integrity_file=Path(file_integrity_file) if file_integrity_file else None,
    )
    report = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
    findings = report.get("findings") or []
    return {
        "findings_json_file": str(out_json),
        "findings_md_file": str(out_md),
        "inputs_used": report.get("inputs"),
        "missing_inputs": report.get("missing_inputs"),
        "input_errors": report.get("input_errors"),
        "staleness_warning": report.get("staleness_warning"),
        "findings": findings,
        "count": len(findings),
    }


def _persist_target_auth_correlation_data(
    data_dir: Path,
    since: str | None = None,
    since_epoch: float | None = None,
    until_epoch: float | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    """
    Fetches the target's sshd/sudo journal entries over SSH and persists
    them in the exact same events/stats/patterns file shape
    parse_auth_log_file/analyze_auth_patterns already produce for the LOCAL
    host -- so correlate_findings's existing data_dir/logs auto-discovery
    picks up real target auth data automatically, with no changes needed to
    correlate_findings itself (reusing the proven local detection pathway
    rather than building a parallel one). Called unconditionally from
    tool_read_journalctl; kept as a standalone helper so a fetch failure
    here never blocks that tool's primary, model-requested query.

    `since` (real fix, 2026-07-17): threaded straight from
    tool_read_journalctl's own `since` arg into
    fetch_journalctl_auth_entries, so a time-scoped goal ("last 24 hours")
    actually produces time-scoped auth_stats/auth_patterns -- this used to
    be a silent, always-unscoped ~500-line snapshot regardless of what the
    model's primary query asked for, which is the real gap a live incident
    surfaced (a confident "in the last 24 hours" answer built on data of
    unknown real age). None (unstated goal) preserves prior behavior
    exactly. Stamped onto stats['since'] too, so anything reading the
    persisted auth_stats file later (e.g. findings_engine.py's evidence
    text) can state plainly whether a given finding was actually time-
    scoped or not, instead of silently implying it always is.
    """
    entries, fetch_errors, windows = _fetch_journalctl_auth_entries(
        since_epoch=since_epoch, until_epoch=until_epoch
    )
    target = _ssh_target_label()
    events = [
        _classify_auth_message(ts, target, identifier, msg, msg)
        for ts, identifier, msg in entries
        if msg
    ]
    stats = _compute_basic_stats(events)
    stats["source"] = f"ssh_target_journald:{target}"
    stats["since"] = since
    stats["until"] = until
    stats["since_utc"] = _epoch_to_iso_utc(since_epoch) if since_epoch is not None else None
    stats["until_utc"] = _epoch_to_iso_utc(until_epoch) if until_epoch is not None else None
    # Per-identifier coverage: a truncated identifier means events older than its
    # oldest_returned were NOT analyzed -- findings_engine states this in evidence.
    stats["coverage"] = {ident: asdict(w) for ident, w in windows.items()}
    if fetch_errors:
        stats["_fetch_errors"] = fetch_errors

    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    events_out = logs_dir / f"auth_events_{ts_tag}.json"
    stats_out = logs_dir / f"auth_stats_{ts_tag}.json"
    events_out.write_text(json.dumps([asdict(e) for e in events], indent=2), encoding="utf-8")
    stats_out.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    patterns_out = _analyze_auth_patterns(data_dir, events_file=events_out)

    return {
        "events_file": str(events_out),
        "stats_file": str(stats_out),
        "patterns_file": str(patterns_out),
        "auth_events_captured": len(events),
        "fetch_errors": fetch_errors,
        "since": since,
        "coverage": stats["coverage"],
    }


@register_tool(
    name="read_journalctl",
    description=(
        "PRIMARY tool for checking the MONITORED TARGET DEVICE's authentication activity, SSH "
        "login attempts, and general system logs (reads the target's journald over SSH -- this "
        "IS the protected system, not the local Kratos host). When an investigation goal says "
        "'check for suspicious activity on this system' or asks about login attempts/break-ins, "
        "'this system' means the target being protected, and this is the tool that actually sees "
        "it -- default to this, not parse_auth_log (which only sees Kratos's own local host and "
        "will not show anything happening on the target). Also useful more broadly for "
        "unexpected service behavior, crashes, or activity tied to a specific unit. Returns "
        "structured entries (timestamp, unit, message, priority) -- the NEWEST `lines` entries only, "
        "so it is for READING lines, not counting: for how many / when / from where / comparisons "
        "over a period use measure_auth_activity, which counts every event. Every call also fetches and "
        "persists the target's sshd/sudo auth activity in the background (using the same `since` "
        "value as this call, if given -- independent only of `unit`/`lines`) so correlate_findings "
        "can pick it up automatically, already scoped to the same time window -- no separate tool "
        "call needed for that."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "unit": {"type": "str|null", "description": "Filter to a specific systemd unit (e.g. 'sshd.service')", "default": None},
        "window": {"type": "object|str|null", "description": "PREFERRED way to scope time: a window id from the TIME CONTEXT (e.g. \"w1\") or a time intent object (see TIME CONTEXT). Kratos computes the exact instants -- never compute timestamps yourself.", "default": None},
        "since": {"type": "str|null", "description": "Legacy alternative to `window`: '<N> minutes|hours|days|weeks ago', 'today', 'yesterday', or an ISO date/time like '2026-07-05 00:00'. Prefer `window`.", "default": None},
        "until": {"type": "str|null", "description": "Legacy end bound for `since` (default: now).", "default": None},
        "lines": {"type": "int", "description": "Max number of entries to return -- always the NEWEST ones in the window. If the window holds more, the result says it was truncated and which part was not seen.", "default": 200},
    },
)
def tool_read_journalctl(
    data_dir: Path,
    unit: str | None = None,
    since: str | None = None,
    lines: int = 200,
    until: str | None = None,
    window: Any = None,
) -> dict[str, Any]:
    data_dir = Path(data_dir)
    # Resolve the window Kratos-side, BEFORE any SSH: the target is only ever sent
    # absolute epochs (never a relative string interpreted on its own clock/tz), and
    # an ambiguous/unsupported/future value is rejected here with a message the model
    # can act on, rather than being guessed at (docs/time_window_design.md §16).
    try:
        tw = _resolve_tool_window(window=window, since=since, until=until, tool="read_journalctl")
    except (_TimeBoundError, _TimeIntentError) as e:
        return {"status": "error", "observation": f"invalid time window: {e}"}
    since_epoch = tw.window.start_utc if tw else None
    until_epoch = None if (tw is None or tw.open_ended) else tw.window.end_utc

    # Shift the Kratos-clock window into the TARGET's clock (journald timestamps are
    # the target's) -- docs/time_window_design.md §2D.
    clock_offset = _measure_target_clock_offset() if (since_epoch is not None or until_epoch is not None) else None
    shift = clock_offset or 0.0
    t_since = since_epoch + shift if since_epoch is not None else None
    t_until = until_epoch + shift if until_epoch is not None else None

    auth_correlation = _persist_target_auth_correlation_data(
        data_dir, since=since, since_epoch=t_since, until_epoch=t_until, until=until
    )

    result = _fetch_journalctl_entries(unit, t_since, lines, until_epoch=t_until)
    if isinstance(result, _SSHResult):
        return {
            "status": "error",
            "observation": f"journalctl over SSH failed: {(result.stderr or result.stdout).strip()}",
            "auth_correlation_data": auth_correlation,
        }
    entries, fetch_window = result
    summary = _window_summary(fetch_window, since, until)
    summary.update(_clock_note(clock_offset, since_epoch, until_epoch))
    if tw is not None:
        summary.update({"id": tw.window.id, "label": tw.window.label, "tz": tw.window.tz,
                        "notes": tw.window.notes, "chip": tw.window.summary()})
    return {
        "status": "ok",
        "target": _ssh_target_label(),
        "unit": unit,
        "count": len(entries),
        "window": summary,
        "entries": entries,
        "auth_correlation_data": auth_correlation,
    }


def _clock_note(offset: float | None, since_epoch: float | None, until_epoch: float | None) -> dict[str, Any]:
    if since_epoch is None and until_epoch is None:
        return {}
    if offset is None:
        return {"target_clock_offset_s": None,
                "clock": "target clock offset could not be measured -- window NOT corrected for clock skew"}
    note = {"target_clock_offset_s": round(offset, 1)}
    if abs(offset) >= _CLOCK_OFFSET_WARN_SECONDS:
        direction = "behind" if offset < 0 else "ahead of"
        note["clock"] = (
            f"WARNING: the target's clock is {abs(offset) / 60:.1f} min {direction} Kratos's. The window was "
            "shifted to compensate, but entry timestamps shown are the TARGET's own clock -- "
            "state real times accordingly, and consider recommending the target fix its time sync (NTP)."
        )
    # the returned window bounds are in Kratos time (what the user asked about)
    note["since_utc"] = _epoch_to_iso_utc(since_epoch) if since_epoch is not None else None
    note["until_utc"] = _epoch_to_iso_utc(until_epoch) if until_epoch is not None else "now"
    return note


def _window_summary(window: Any, since: str | None, until: str | None) -> dict[str, Any]:
    """What this read actually covered, stated for the model in plain words -- a
    truncated window must never read as a complete one."""
    start = _epoch_to_iso_utc(window.since_epoch) if window.since_epoch is not None else None
    end = _epoch_to_iso_utc(window.until_epoch) if window.until_epoch is not None else "now"
    if window.truncated:
        note = (
            f"TRUNCATED: the window held more than {window.requested} entries, so only the newest "
            f"{window.returned} were returned (oldest returned: {window.oldest_returned}). Entries "
            f"between {start or 'the start of the journal'} and {window.oldest_returned} were NOT seen -- "
            "do not describe that part of the window as clean. Narrow the window, filter by unit, "
            "or rely on correlate_findings' counts."
        )
    else:
        note = "complete: every matching entry in the window was returned."
    return {
        "since": since, "until": until, "since_utc": start, "until_utc": end,
        "returned": window.returned, "truncated": window.truncated,
        "oldest_returned": window.oldest_returned, "newest_returned": window.newest_returned,
        "coverage": note,
    }


def _measurement_window_block(tw: Any, m: Any, clock_offset: float | None) -> dict[str, Any]:
    cov = m.coverage()
    block = {
        "id": tw.window.id, "label": tw.window.label, "tz": tw.window.tz, "notes": tw.window.notes,
        "chip": tw.window.summary(), "since_utc": _epoch_to_iso_utc(tw.window.start_utc),
        "until_utc": _epoch_to_iso_utc(tw.window.end_utc), "coverage_percent": cov["percent"],
        "covered_from": cov["covered_start"], "covered_to": cov["covered_end"], "problems": cov["problems"],
        "truncated": cov["percent"] < 100.0, "oldest_returned": cov["covered_start"],
        "coverage": ("complete: every matching event in the window was counted." if cov["percent"] >= 100.0 else
                     f"PARTIAL ({cov['percent']}%): " + "; ".join(cov["problems"]) +
                     " -- do NOT describe the uncovered part as clean; say it is unknown."),
    }
    block.update(_clock_note(clock_offset, tw.window.start_utc, tw.window.end_utc))
    return block


@register_tool(
    name="measure_auth_activity",
    description=(
        "EXHAUSTIVE COUNTS of authentication activity on the MONITORED TARGET over a time window: "
        "failed/successful SSH logins, invalid users, sudo failures/sessions/commands -- totals, per "
        "source IP (with first/last seen), per hour, brute-force bursts, and the exact coverage of the "
        "window (retention, reboots, clock problems). Counted ON the target, so it covers every event "
        "in the window with no line cap (a month of heavy attacks costs a few KB). Use this for any "
        "'how many', 'when', 'from where', 'did X happen in <period>', or comparison question; use "
        "read_journalctl only when you need to read actual log lines. Also feeds correlate_findings "
        "with the exhaustive numbers. Kratos's own SSH sessions are excluded from success counts and "
        "reported separately (failures are never excluded)."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "window": {"type": "object|str", "description": "REQUIRED: a window id from the TIME CONTEXT (e.g. \"w1\") or a time intent object. Kratos computes the exact instants."},
        "since": {"type": "str|null", "description": "Legacy alternative to `window` ('24 hours ago', '2026-07-05'). Prefer `window`.", "default": None},
        "until": {"type": "str|null", "description": "Legacy end bound for `since`.", "default": None},
    },
)
def tool_measure_auth_activity(
    data_dir: Path, window: Any = None, since: str | None = None, until: str | None = None
) -> dict[str, Any]:
    data_dir = Path(data_dir)
    try:
        tw = _resolve_tool_window(window=window, since=since, until=until, tool="measure_auth_activity")
    except (_TimeBoundError, _TimeIntentError) as e:
        return {"status": "error", "observation": f"invalid time window: {e}"}
    if tw is None:
        return {"status": "error", "observation": "measure_auth_activity needs a window: pass \"window\": "
                "{\"id\": \"w1\"} from the TIME CONTEXT, or a time intent like {\"kind\": \"rolling\", "
                "\"amount\": 24, \"unit\": \"hour\"}."}
    return _measure_window(data_dir, tw)[2]


def _measure_window(data_dir: Path, tw: Any, persist: bool = True) -> tuple[Any, dict[str, Any] | None, dict[str, Any]]:
    """Run the target-side measurement for one resolved window, persist it for
    correlate_findings, record it for Guard 7, and build the tool payload. Shared by
    measure_auth_activity and compare_periods. Returns (Measurement|None, window block,
    payload); Measurement is None on an SSH failure (payload is then the error)."""
    clock_offset = _measure_target_clock_offset()
    shift = clock_offset or 0.0
    w = tw.window
    gran = 60 if w.seconds <= 2 * 86400 else 3600  # classic-log bucket size (see measure.py)
    script = _build_measure_script(
        w.start_utc + shift, None if tw.open_ended else w.end_utc + shift,
        journalctl_prefix=" ".join(_journalctl_prefix()), kratos_user=SSH_TARGET_USER,
        classic_granularity=gran,
    )
    result = _run_remote_script(script, timeout=_MEASURE_BUDGET + 60, shell="sh")
    if not result.ok and not result.stdout.strip():
        return None, None, {"status": "error", "observation": f"measurement over SSH failed: {(result.stderr or result.stdout).strip()}"}
    m = _parse_measure_output(result.stdout, w.start_utc, w.end_utc, shift, classic_granularity=gran)
    block = _measurement_window_block(tw, m, clock_offset)
    run_ctx = _current_time_context()
    if run_ctx is not None:  # what Guard 7 verifies the final answer's numbers against
        run_ctx.measurements[w.id] = _measurement_summary(m)
        run_ctx.measurement_objects[w.id] = m
    # Persist in the exact shapes correlate_findings already reads, so its rule engine
    # works from the exhaustive counts (latest file by mtime wins). A comparison's baseline
    # windows are NOT persisted (persist=False): correlation must describe the period of
    # interest, not whichever window happened to be measured last.
    stats = m.as_auth_stats()
    stats.update({
        "source": f"ssh_target_measurement:{_ssh_target_label()}",
        "since": w.label, "since_utc": block["since_utc"], "until_utc": block["until_utc"],
        "window_id": w.id,
        "coverage": {"measurement": {"truncated": block["truncated"], "returned": m.lines,
                                     "oldest_returned": block["covered_from"]}},
    })
    stats_out = patterns_out = None
    if persist:
        logs_dir = data_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        # window id + second-resolution stamp: two windows measured in one second never
        # collide, and the stamp stays LAST (utils/latest_file.files_in_date_range reads the
        # date from the second-to-last "_" field).
        ts_tag = f"{w.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        stats_out = logs_dir / f"auth_stats_{ts_tag}.json"
        patterns_out = logs_dir / f"auth_patterns_{ts_tag}.json"
        stats_out.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        patterns_out.write_text(json.dumps(m.as_auth_patterns(), indent=2), encoding="utf-8")

    top_ips = sorted(m.by_ip.items(), key=lambda kv: -kv[1]["count"])[:10]
    return m, block, {
        "status": "ok",
        "target": _ssh_target_label(),
        "measurement": "exhaustive (every matching event in the covered window, counted on the target)",
        "window": block,
        "counts": dict(sorted(m.counts.items())),
        "failed_login_sources": [
            {"ip": ip, "failed_logins": d["count"], "first_seen": _epoch_to_iso_utc(d["first"]),
             "last_seen": _epoch_to_iso_utc(d["last"])} for ip, d in top_ips
        ],
        "distinct_failed_login_ips": len(m.by_ip),
        "top_failed_login_users": [{"user": u, "count": c} for u, c in sorted(m.by_user.items(), key=lambda kv: -kv[1])[:5]],
        "bursts": m.bursts,
        "fail2ban": {"bans": sum(1 for e in m.fail2ban if e["action"] == "ban"),
                     "unbans": sum(1 for e in m.fail2ban if e["action"] == "unban"), "events": m.fail2ban[:20]},
        "sources": {"used": m.sources_used, "journald": m.journald, "classic_logs": m.classic_status,
                    "classic_files": m.classic_files, "target_timezone": m.tz_name or m.tz_offset},
        "samples": {"note": "SAMPLE lines only -- counts above are authoritative", "newest": m.samples[:10],
                    "first_line_per_failing_ip": m.first_per_ip[:10]},
        "kratos_own_activity_excluded": {"kratos_ip": m.kratos_ip, "events": m.self_excluded},
        "persisted": {"stats_file": str(stats_out) if stats_out else None,
                      "patterns_file": str(patterns_out) if patterns_out else None},
    }


@register_tool(
    name="compare_periods",
    description=(
        "COMPARES authentication activity on the MONITORED TARGET across two or more time periods "
        "(e.g. this week vs last week, last 30 minutes vs the 30 before). Measures every period "
        "exhaustively (same engine as measure_auth_activity, reusing any measurement already taken), "
        "normalizes to a rate per day of covered time, checks coverage, and applies a statistical "
        "test so ordinary variation is reported as 'no_meaningful_change' rather than a trend. Use it "
        "for ANY comparison or trend question -- never compare numbers yourself. Cite its comparison "
        "id in a \"trend\" claim."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "metric": {"type": "str", "description": "What to compare: " + ", ".join(sorted(_CLAIM_METRICS))},
        "windows": {"type": "list", "description": "Two or more window ids (\"w1\") or time intent objects; "
                    "e.g. [\"w1\", {\"kind\": \"relative_to\", \"window\": \"w1\", \"shift\": {\"amount\": -7, \"unit\": \"day\"}}]"},
    },
)
def tool_compare_periods(data_dir: Path, metric: str, windows: Any) -> dict[str, Any]:
    data_dir = Path(data_dir)
    if metric not in _CLAIM_METRICS:
        return {"status": "error", "observation": f"unknown metric {metric!r}; use one of {', '.join(sorted(_CLAIM_METRICS))}"}
    if isinstance(windows, str):
        try:
            windows = json.loads(windows)
        except json.JSONDecodeError:
            windows = [w.strip() for w in windows.split(",") if w.strip()]
    if not isinstance(windows, list) or len(windows) < 2:
        return {"status": "error", "observation": "compare_periods needs at least two windows"}
    resolved = []
    for i, ref in enumerate(windows):
        try:
            tw = _resolve_tool_window(window=ref, tool="compare_periods")
        except (_TimeBoundError, _TimeIntentError) as e:
            return {"status": "error", "observation": f"window #{i + 1}: invalid time window: {e}"}
        if tw is None:
            return {"status": "error", "observation": f"window #{i + 1} is empty"}
        resolved.append(tw)
    if len({tw.window.id for tw in resolved}) < len(resolved):
        return {"status": "error", "observation": "the windows to compare must be different periods"}

    run_ctx = _current_time_context()
    rows = []
    for idx, tw in enumerate(resolved):
        m = run_ctx.measurement_objects.get(tw.window.id) if run_ctx else None
        if m is None:
            # only the first (period of interest) feeds correlate_findings; baselines don't
            m, _block, payload = _measure_window(data_dir, tw, persist=(idx == 0))
            if m is None:
                return payload
        summ = _measurement_summary(m)
        cov = m.coverage()
        summ["covered_seconds"] = cov["percent"] / 100.0 * tw.window.seconds
        rows.append((tw.window, summ))
    result = _compare_measurements(metric, rows)
    cid = "c1"
    if run_ctx is not None:
        n = sum(1 for k in run_ctx.measurements if k.startswith("compare:")) + 1
        cid = f"c{n}"
        allowed = {int(r["value"]) for r in result["windows"]}
        allowed |= {int(round(r["rate_per_day"])) for r in result["windows"] if r["rate_per_day"] is not None}
        allowed |= {int(round(abs(pr["rate_change_percent"]))) for pr in result["pairs"] if pr.get("rate_change_percent") is not None}
        run_ctx.measurements[f"compare:{cid}"] = {"metric": metric, "pairs": result["pairs"], "values": allowed}
    return {"status": "ok", "comparison_id": cid, **result,
            "note": "Verdicts are computed by Kratos: quote them; do not re-derive trends from the numbers."}


@register_tool(
    name="state_as_of",
    description=(
        "What the MONITORED TARGET looked like at a past time, from Kratos's OWN saved observations "
        "(scans, baselines, system snapshots, integrity checks, findings) -- for questions logs can't "
        "answer: 'was port 8080 open last week?', 'who had sudo on Monday?', 'what did the last scan "
        "before the incident show?'. Give either `at` (a point in time) or `window` (a period). Returns "
        "the nearest snapshot at or before that time and how far from it that snapshot is, or says "
        "plainly that there is no record -- it never interpolates. Categories: "
        + ", ".join(f"{k} ({v})" for k, v in _SNAPSHOT_DESCRIPTIONS.items())
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "category": {"type": "str", "description": "Snapshot category (see description)"},
        "at": {"type": "str|null", "description": "A point in time: 'now', '3 days ago', '2026-09-20 09:00' (user's timezone)", "default": None},
        "window": {"type": "object|str|null", "description": "A window id or time intent: snapshots inside it + the last one before it", "default": None},
    },
)
def tool_state_as_of(data_dir: Path, category: str, at: str | None = None, window: Any = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    if category not in _SNAPSHOT_DESCRIPTIONS:
        return {"status": "error", "observation": f"unknown category {category!r}; use one of {', '.join(_SNAPSHOT_DESCRIPTIONS)}"}
    target = get_active_target() if category not in ("integrity_baseline",) else None
    run_ctx = _current_time_context()

    def record(snap: Any) -> dict[str, Any]:
        d = snap.as_dict() | {"state": _snapshot_summary(snap)}
        sid = "s" + hashlib.sha1(snap.path.encode()).hexdigest()[:8]  # stable across runs
        d["snapshot_id"] = sid
        if run_ctx is not None:  # a "state" claim may cite it (Guard 7)
            run_ctx.measurements[f"snapshot:{sid}"] = {"values": set()}
        if snap.target is None:
            d["target_note"] = "this snapshot does not record which host it describes"
        return d

    hz = _snapshot_horizon(data_dir).get(category)
    if window not in (None, "", {}):
        try:
            tw = _resolve_tool_window(window=window, tool="state_as_of")
        except (_TimeBoundError, _TimeIntentError) as e:
            return {"status": "error", "observation": f"invalid time window: {e}"}
        w = tw.window
        inside = _snapshots_within(data_dir, category, w.start_utc, w.end_utc, target)
        before = _snapshot_as_of(data_dir, category, w.start_utc, target)
        return {"status": "ok", "category": category, "window": {"id": w.id, "chip": w.summary()},
                "snapshots_in_window": [record(x) for x in inside[-5:]], "count_in_window": len(inside),
                "last_before_window": record(before) if before else None, "history": hz,
                "note": ("no snapshot inside this window -- Kratos did not observe this during that period"
                         if not inside else "state is only known at the listed capture times, not in between")}
    try:
        t = _resolve_time_bound(at) if at else time.time()
    except _TimeBoundError as e:
        return {"status": "error", "observation": f"invalid time: {e}"}
    snap = _snapshot_as_of(data_dir, category, t, target)
    if snap is None:
        return {"status": "ok", "category": category, "requested_at": _epoch_to_iso_utc(t), "snapshot": None,
                "history": hz, "note": ("no record: Kratos has no " + category + " snapshot at or before that time"
                                        + (f" (its history starts {hz['oldest']})" if hz else ""))}
    gap = t - snap.captured_at
    return {"status": "ok", "category": category, "requested_at": _epoch_to_iso_utc(t), "snapshot": record(snap),
            "distance": f"captured {gap / 86400:.1f} days before the requested time" if gap >= 86400
            else f"captured {gap / 3600:.1f} hours before the requested time",
            "history": hz, "note": "this is what Kratos observed at the capture time; the state may have changed since"}


@register_tool(
    name="list_open_files",
    description=(
        "Checks what files/sockets are currently open on the SSH target device (not the local "
        "Kratos host), optionally filtered by PID. Relevant when investigating a specific "
        "suspicious process, an unexpected listening socket, or potential active compromise -- "
        "typically a follow-up once list_processes or network checks flag something specific to "
        "look at closer, not a first step. Returns structured entries: command, pid, user, fd, "
        "type, path. Runs as the configured SSH user without sudo, so results are limited to what "
        "that user can see."
    ),
    parameters={
        "pid": {"type": "int|null", "description": "Filter to a specific process ID", "default": None},
    },
)
def tool_list_open_files(pid: int | None = None) -> dict[str, Any]:
    result = _fetch_open_files(pid)
    if isinstance(result, _SSHResult):
        return {"status": "error", "observation": f"lsof over SSH failed: {(result.stderr or result.stdout).strip()}"}
    return {"status": "ok", "target": _ssh_target_label(), "pid": pid, "count": len(result), "entries": result}


@register_tool(
    name="list_processes",
    description=(
        "Checks RUNNING PROCESSES on the SSH target device (not the local Kratos host) via `ps "
        "aux`. Relevant whenever 'is anything unusual running', unexpected resource usage, or "
        "verifying no unfamiliar process is active could matter -- a basic system-state check "
        "worth considering for most investigations, not only when the goal explicitly asks about "
        "processes. Returns structured entries: user, pid, cpu, mem, command."
    ),
    parameters={},
)
def tool_list_processes() -> dict[str, Any]:
    result = _fetch_processes()
    if isinstance(result, _SSHResult):
        return {"status": "error", "observation": f"ps aux over SSH failed: {(result.stderr or result.stdout).strip()}"}
    return {"status": "ok", "target": _ssh_target_label(), "count": len(result), "entries": result}


@register_tool(
    name="check_file_integrity",
    description=(
        "Checks FILE/CONFIG INTEGRITY: hashes critical config paths (/etc/passwd, "
        "/etc/ssh/sshd_config, /etc/sudoers, /etc/crontab) on the SSH target device and compares "
        "against a stored baseline. Relevant for any question about unauthorized changes, "
        "tampering, or persistence mechanisms -- not only when the goal explicitly says 'file "
        "integrity'. Worth considering alongside process/network checks for a thorough compromise "
        "investigation. If no baseline exists yet for baseline_name, establishes one and reports "
        "'baseline_established' instead of a diff (this first run is a setup step, not a finding). "
        "Baselines are stored locally under data_dir/baseline/, keyed by baseline_name. The diff "
        "(if any) is also persisted so correlate_findings can pick it up automatically -- no "
        "separate tool call needed for that."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "baseline_name": {"type": "str", "description": "Name of the baseline to check/create (lets you track multiple targets/configs separately)", "default": "default"},
    },
)
def tool_check_file_integrity(data_dir: Path, baseline_name: str = "default") -> dict[str, Any]:
    data_dir = Path(data_dir)
    target = _ssh_target_label()

    current = _fetch_file_hashes()
    if isinstance(current, _SSHResult):
        return {"status": "error", "observation": f"File integrity check over SSH failed: {(current.stderr or current.stdout).strip()}"}

    existing = _load_file_integrity_baseline(data_dir, baseline_name)
    fell_back_from: str | None = None
    if existing is None:
        # A fresh baseline_name must NOT silently establish a new baseline on a
        # possibly-tampered system (that always returns "no diff" and misses real
        # changes -- a confirmed detection gap). Fall back to the most recent
        # EXISTING baseline of ANY name and diff against it; only establish a
        # brand-new baseline if truly none exists yet.
        bdir = Path(data_dir) / "baseline"
        if bdir.exists():
            candidates = sorted(
                (p for p in bdir.glob("file_integrity_*.json")
                 if not p.name.startswith("file_integrity_diff_")),
                key=lambda p: p.stat().st_mtime, reverse=True,
            )
            for cand in candidates:
                try:
                    existing = json.loads(cand.read_text(encoding="utf-8"))
                    fell_back_from = cand.stem.replace("file_integrity_", "", 1)
                    break
                except Exception:  # noqa: BLE001
                    continue
    if existing is None:
        baseline_path = _save_file_integrity_baseline(data_dir, baseline_name, target, current)
        return {
            "status": "baseline_established",
            "baseline_name": baseline_name,
            "baseline_file": str(baseline_path),
            "target": target,
            "hashes": current,
        }

    diff = _diff_file_integrity(existing.get("hashes") or {}, current)
    diff_file = _save_file_integrity_diff(data_dir, baseline_name, target, diff)
    result = {
        "status": "ok",
        "baseline_name": baseline_name,
        "target": target,
        "baseline_created_at": existing.get("created_at"),
        "diff": diff,
        "diff_file": str(diff_file),
    }
    if fell_back_from is not None:
        result["baseline_fallback"] = (
            f"No baseline named '{baseline_name}' existed; diffed against the most recent "
            f"existing baseline '{fell_back_from}' instead of establishing a new one."
        )
    return result


# Bundled starter ruleset -- see yara_rules/README.md for source/license/citation. Deliberately
# NOT a rule-management/update system: a small, real, vendored default plus a rules_path override,
# nothing more.
DEFAULT_YARA_RULES_DIR = Path(__file__).resolve().parents[3] / "yara_rules"


def _load_yara_rules_content(rules_path: Path | None) -> tuple[str, list[str]] | None:
    """
    Returns (concatenated rule text, [source filenames]), or None if no
    .yar/.yara files were found. rules_path REPLACES the bundled defaults
    entirely when given (not merged with them) -- simpler and more
    predictable than a merge, and avoids silent rule-name collisions
    between the bundled set and a custom one.
    """
    search_dir = rules_path if rules_path else DEFAULT_YARA_RULES_DIR
    if rules_path and rules_path.is_file():
        files = [rules_path]
    elif search_dir.is_dir():
        files = sorted(search_dir.glob("*.yar")) + sorted(search_dir.glob("*.yara"))
    else:
        return None
    if not files:
        return None

    parts = [f"// ---- from {f.name} ----\n{f.read_text(encoding='utf-8')}" for f in files]
    return "\n\n".join(parts), [f.name for f in files]


@register_tool(
    name="run_yara_scan",
    description=(
        "Scans a file or directory on the SSH TARGET DEVICE (not the local Kratos host) for "
        "malware/webshell signatures using YARA pattern matching. Runs the `yara` binary ON THE "
        "TARGET over SSH -- it must already be installed there; "
        "this tool does not install it. No scanned file's CONTENT is ever pulled back to the "
        "Kratos host, only match results (rule name, matched file path, offset, matched string) "
        "cross the wire -- same posture as check_file_integrity's hashing. Relevant as a targeted "
        "follow-up once a SPECIFIC suspicious file, directory, or web-server document root has "
        "already been identified (e.g. via list_open_files, list_processes, or file integrity "
        "findings) -- not a first step, and not something to call speculatively across the whole "
        "filesystem. Uses Kratos's small bundled starter ruleset (yara_rules/, sourced from the "
        "public Yara-Rules project) by default; pass rules_path to use a custom rules file or "
        "directory INSTEAD of the bundled defaults (replaces, does not merge with, the bundled "
        "set)."
    ),
    parameters={
        "scan_path": {"type": "str", "description": "File or directory path ON THE TARGET to scan."},
        "rules_path": {"type": "str|null", "description": "Local Kratos-host path to a custom .yar file or directory of .yar files, used INSTEAD of the bundled default ruleset. Omit to use the bundled defaults.", "default": None},
    },
)
def tool_run_yara_scan(scan_path: str, rules_path: str | Path | None = None) -> dict[str, Any]:
    resolved_rules_path = Path(rules_path) if rules_path else None
    loaded = _load_yara_rules_content(resolved_rules_path)
    if loaded is None:
        return {
            "status": "error",
            "observation": (
                f"No .yar/.yara rule files found at {resolved_rules_path}" if resolved_rules_path
                else f"No bundled YARA rules found at {DEFAULT_YARA_RULES_DIR} -- ruleset missing or empty."
            ),
        }
    rules_content, rule_files = loaded

    result = _fetch_yara_scan(scan_path, rules_content)
    if isinstance(result, _SSHResult):
        return {
            "status": "error",
            "observation": f"YARA scan over SSH failed: {(result.stderr or result.stdout).strip()}",
            "rules_used": rule_files,
        }
    return {
        "status": "ok",
        "target": _ssh_target_label(),
        "scan_path": scan_path,
        "rules_used": rule_files,
        "match_count": len(result),
        "matches": result,
    }


@register_tool(
    name="run_vuln_scan",
    description=(
        "Checks the SSH TARGET DEVICE (not the local Kratos host) for known vulnerabilities and "
        "web/service misconfigurations, combining two complementary scanners into one merged "
        "result: Nuclei (active, template-driven checks across HTTP/DNS/TCP/SSL/File -- strong on "
        "web/API misconfigurations and modern exploit patterns) and nmap's vulscan script "
        "(passive CVE correlation against nmap's own version-detection output, using a "
        "LOCAL/offline CVE database -- never a live external API call). Both scanners run FROM "
        "the Kratos host, reaching the target over the network -- same execution model as "
        "run_nmap_scan, NOT an SSH-remote-execution tool like run_yara_scan/list_open_files. "
        "Relevant for any question about exposed vulnerabilities, outdated software, or "
        "exploitable misconfigurations -- a natural follow-up once open ports/services are known "
        "(run_nmap_scan), though this tool performs its own version detection independently and "
        "does not require a prior scan. KNOWN GAP: neither scanner meaningfully covers OT/ICS "
        "protocols (Modbus etc.) -- a clean result is NOT proof an OT/ICS device has no "
        "vulnerabilities, do not represent it that way. The vulscan half uses a local CVE "
        "database that goes stale between manual updates -- if it's stale, the result includes a "
        "database_stale warning; if a human is available to answer, a one-time approval prompt "
        "offers to refresh it, but the scan itself always completes regardless of that answer -- "
        "staleness is a visibility concern here, not a hard stop."
    ),
    parameters={
        "data_dir": {"type": "path", "description": "Kratos data directory"},
        "target": {"type": "str|null", "description": "Target IP/hostname to scan. Defaults to the configured SSH target.", "default": None},
        "nuclei_tags": {"type": "str|null", "description": "Nuclei template tags to run, comma-separated. Defaults to a modest subset (cve,exposure,misconfig), not the full 13,000+ template set.", "default": None},
    },
)
def tool_run_vuln_scan(data_dir: Path, target: str | None = None, nuclei_tags: str | None = None) -> dict[str, Any]:
    data_dir = Path(data_dir)
    resolved_target = target or get_active_target()
    resolved_tags = nuclei_tags or _DEFAULT_NUCLEI_TAGS

    staleness = _check_vulscan_db_staleness()
    # A stale CVE database is ALWAYS reported passively (database_stale /
    # database_age_days in the result below), so its state is never hidden. The
    # INTERACTIVE "download now?" approval prompt, however, is off by default
    # (KRATOS_VULSCAN_UPDATE_PROMPT) -- it interrupted a plain investigation with
    # a modal the user can only decline, while the scan proceeds either way and
    # the upstream mirror is Cloudflare-blocked so the update usually fails. Opt
    # in to restore the prompt. See kratos_config.VULSCAN_UPDATE_PROMPT.
    if staleness["stale"] and _VULSCAN_UPDATE_PROMPT:
        age_desc = f"{staleness['age_days']} days old" if staleness["exists"] else "missing"
        approved = request_approval(
            "UPDATE VULSCAN CVE DATABASE",
            {
                "question": (
                    f"The local vulscan CVE database is stale ({age_desc}, threshold="
                    f"{_VULSCAN_STALENESS_THRESHOLD_DAYS} days). Download a fresh copy now?"
                ),
                "note": (
                    "Answer 'y' to update before scanning. Anything else -- including no answer "
                    "or an interrupted prompt -- proceeds with the CURRENT (stale) database; the "
                    "scan itself is never blocked on this answer either way."
                ),
            },
        )
        if approved:
            ok, message = _update_vulscan_db()
            print(f"[KRATOS] vulscan DB update: {'OK' if ok else 'FAILED'} -- {message}", file=sys.stderr)
            staleness = _check_vulscan_db_staleness()

    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    # nmap+vulscan runs FIRST and its own -sV port/service data is reused to
    # target Nuclei precisely -- confirmed by real testing to matter, not a
    # theoretical nicety: Nuclei's -u needs an explicit port to reach a
    # service on a non-standard port (e.g. 8080), and blindly defaulting to
    # port 80 would silently miss it. Falls back to a bare http:// probe on
    # resolved_target only if nmap found no HTTP-labeled port at all.
    nuclei_target = resolved_target
    try:
        vulscan_xml = _run_nmap_vulscan(resolved_target, data_dir)
        findings.extend(_parse_vulscan_xml(vulscan_xml))
        nmap_parsed = _parse_nmap_xml_to_dict(vulscan_xml)  # same -sV XML shape run_nmap_scan produces
        for host_entry in nmap_parsed.get("hosts", []):
            for port_entry in host_entry.get("open_ports", []):
                svc = (port_entry.get("service") or "").lower()
                if "http" not in svc:
                    continue
                port = port_entry.get("port")
                scheme = "https" if "ssl" in svc or "tls" in svc else "http"
                nuclei_target = f"{scheme}://{resolved_target}:{port}"
                break
            if nuclei_target != resolved_target:
                break
    except RuntimeError as e:
        errors.append(f"vulscan: {e}")

    try:
        nuclei_path = _run_nuclei_scan(nuclei_target, data_dir, resolved_tags)
        findings.extend(_parse_nuclei_jsonl(nuclei_path))
    except RuntimeError as e:
        errors.append(f"nuclei: {e}")

    nuclei_count = sum(1 for f in findings if f["source"] == "nuclei")
    vulscan_count = sum(1 for f in findings if f["source"] == "vulscan")

    return {
        "status": "ok" if not errors else ("partial" if findings else "error"),
        "target": resolved_target,
        "database_stale": staleness["stale"],
        "database_last_updated": staleness["last_updated"],
        "database_age_days": staleness["age_days"],
        "nuclei_finding_count": nuclei_count,
        "vulscan_finding_count": vulscan_count,
        "finding_count": len(findings),
        "findings": findings,
        "errors": errors,
    }


@register_tool(
    name="check_ip_reputation",
    description=(
        "Correlates a specific IP address against threat intelligence. USE THIS whenever an "
        "investigation has surfaced a SPECIFIC source IP tied to suspicious activity -- a "
        "failed-login or brute-force burst, a port scan, or any attack traffic attributable to an "
        "IP (e.g. the source IP on AUTH/CORR-SSH findings, or from a network capture). Checking "
        "that IP's reputation directly strengthens or weakens the finding: a known-malicious hit "
        "corroborates a real attack and should RAISE the finding's confidence/severity in your "
        "final answer, while a clean result tempers a borderline one. Worth reaching for as a "
        "standard enrichment step once a concrete suspicious IP is in view -- but only on such an "
        "IP, never a bulk/speculative sweep across every IP seen. TWO TIERS, tried in order: a "
        "LOCAL, OFFLINE cache of AlienVault OTX pulses (default -- checked first, no live network "
        "call, available regardless of configuration) and an OPT-IN live escalation via AbuseIPDB, "
        "only reachable if BOTH KRATOS_THREAT_INTEL_ENABLED=1 is set AND a human explicitly "
        "approves THIS SPECIFIC lookup at a real-time prompt -- never triggered automatically. The "
        "result's 'source' field states which tier answered: 'cache', 'live', or 'none' if neither "
        "had anything (including live disabled/declined)."
    ),
    parameters={
        "ip": {"type": "str", "description": "IP address to check."},
    },
)
def tool_check_ip_reputation(ip: str) -> dict[str, Any]:
    cached = _lookup_ip_cache(ip)
    if cached:
        return {"status": "ok", "ip": ip, "source": "cache", "result": cached}

    if not _THREAT_INTEL_ENABLED:
        return {
            "status": "ok", "ip": ip, "source": "none",
            "observation": (
                "No cached OTX data for this IP. Live escalation (AbuseIPDB) is disabled "
                "(KRATOS_THREAT_INTEL_ENABLED is not set to 1) -- enable it in .env to allow live "
                "lookups; even then, each lookup still requires a real-time human approval."
            ),
        }

    approved = request_approval(
        "LIVE THREAT-INTEL LOOKUP (AbuseIPDB)",
        {
            "ip": ip,
            "question": (
                f"No local (cached, offline) threat-intel data found for {ip}. Send this IP to "
                "AbuseIPDB (a third-party service) for a live reputation check?"
            ),
            "note": (
                "Answer 'y' to allow this ONE lookup. Anything else -- including no answer or an "
                "interrupted prompt -- denies it; no data about this IP is sent anywhere."
            ),
        },
    )
    if not approved:
        return {
            "status": "ok", "ip": ip, "source": "none",
            "observation": "No cached data, and live escalation was not approved -- no external lookup performed.",
        }

    live_result = _lookup_ip_live_abuseipdb(ip)
    if live_result is None:
        return {
            "status": "error", "ip": ip, "source": "none",
            "observation": "Live AbuseIPDB lookup failed, or ABUSEIPDB_API_KEY is not configured.",
        }
    return {"status": "ok", "ip": ip, "source": "live", "result": live_result}


@register_tool(
    name="run_config_audit",
    description=(
        "Checks HARDENING/CONFIG POSTURE on the SSH target device (not a full Lynis-style scan): "
        "SSH root login policy, SSH password-auth vs key-only, firewall active, world-writable "
        "files under /etc, unattended-upgrades enabled, fail2ban status. Relevant for 'is this "
        "system properly secured', 'is my server okay', or general hardening questions -- and "
        "worth considering as a baseline check alongside network/auth checks even when the goal "
        "doesn't explicitly mention configuration or hardening. Returns one PASS/FAIL/WARN/UNKNOWN "
        "result with a short explanation per check."
    ),
    parameters={},
)
def tool_run_config_audit() -> dict[str, Any]:
    result = _run_config_audit_checks()
    if isinstance(result, _SSHResult):
        return {"status": "error", "observation": f"Config audit over SSH failed: {(result.stderr or result.stdout).strip()}"}
    return {"status": "ok", "target": _ssh_target_label(), "checks": result}


@register_tool(
    name="send_notification",
    description=(
        "Send an alert notification via ntfy.sh (not tied to the SSH target -- an external push "
        "notification service). Never crashes the caller if ntfy is unreachable; failure is reported "
        "in the returned status instead."
    ),
    parameters={
        "message": {"type": "str", "description": "Notification body text"},
        "severity": {"type": "str", "description": "'info', 'warning', or 'critical' -- maps to ntfy priority/tag", "default": "info"},
    },
)
def tool_send_notification(message: str, severity: str = "info") -> dict[str, Any]:
    return _send_notification(message, severity)


@register_tool(
    name="run_linux_command",
    description=(
        "LOCAL KRATOS HOST -- not the monitored target. Executes an arbitrary Linux shell command "
        "ON KRATOS'S OWN HOST, not the SSH target device -- there is no way to run this against "
        "the target. NON-NEGOTIABLE: this always blocks on an explicit human y/n approval prompt "
        "before running anything — there is no way to skip it."
    ),
    parameters={
        "command": {"type": "str", "description": "The exact shell command to execute"},
        "reason": {"type": "str", "description": "Why this command needs to run"},
    },
    requires_approval=True,
)
def tool_run_linux_command(command: str, reason: str) -> dict[str, Any]:
    """
    Human-in-the-loop gated command execution.

    Hard requirement: subprocess.run is reached from exactly one place below,
    guarded by request_approval() returning True. No retry, fallback, or error
    path in this function calls subprocess without that same check passing.
    """
    if not request_approval("run_linux_command", {"command": command, "reason": reason}):
        return {
            "status": "not_approved",
            "command": command,
            "reason": reason,
            "observation": "User did not approve execution. Command was NOT run.",
        }

    try:
        result = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            timeout=60,
        )
        return {
            "status": "executed",
            "command": command,
            "reason": reason,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except Exception as e:
        return {
            "status": "error",
            "command": command,
            "reason": reason,
            "observation": f"Approved, but execution raised an error: {e}",
        }


def render_tools_for_prompt() -> str:
    """
    Human/LLM-readable listing of every registered tool (name, description,
    params) -- this is the ONLY thing the agent loop's LLM ever sees of the
    registry; TOOL_REGISTRY/tool.parameters itself stays fully intact for
    every other consumer (execute_tool_call's real **kwargs call, the CLI's
    own direct calls, tests, etc.).

    A parameter marked agent_hidden=True (investigation, 2026-07-16 -- see
    correlate_findings's override params for the motivating case) is skipped
    here but still fully present/usable in tool.parameters and the real
    Python signature -- this hides an affordance from the model's view, it
    does not remove real capability. Confirmed real, not hypothetical: a
    live run showed the model fabricating plausible-looking values for
    correlate_findings's *_file override args (which it never had a
    legitimate need to set) despite the description/RULES already saying to
    omit them -- removing the args from what the model sees at all closes
    that off structurally, rather than adding another "don't guess"
    instruction on top of ones already not working.
    """
    lines: list[str] = []
    for tool in TOOL_REGISTRY.values():
        approval_note = " [REQUIRES HUMAN APPROVAL]" if tool.requires_approval else ""
        lines.append(f"- {tool.name}{approval_note}: {tool.description}")
        for pname, pinfo in tool.parameters.items():
            if pinfo.get("agent_hidden"):
                continue
            default = pinfo.get("default", "<required>")
            lines.append(f"    - {pname} ({pinfo.get('type', 'any')}, default={default!r}): {pinfo.get('description', '')}")
    return "\n".join(lines)
