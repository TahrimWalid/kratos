from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from kratos.utils.latest_file import latest_file, files_in_date_range


_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _word_count(text: str) -> int:
    return len([w for w in text.split() if w.strip()])


def _truncate_to_words(text: str, max_words: int) -> str:
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]) + " …"


def cmd_prepare_bundle(args) -> int:
    data_dir: Path = args.data_dir
    reports_dir = data_dir / "reports"
    scans_dir = data_dir / "scans"
    logs_dir = data_dir / "logs"
    ctx_dir = data_dir / "context"
    baseline_dir = data_dir / "baseline"

    # Support date-range filtering
    since = getattr(args, "since", None)
    until = getattr(args, "until", None)
    
    # Get findings (required) — respect date range if provided
    if since or until:
        findings_files = files_in_date_range(reports_dir, "findings_*.json", since=since, until=until)
        findings_path = findings_files[-1] if findings_files else None
    else:
        findings_path = latest_file(reports_dir, "findings_*.json")
    
    if not findings_path:
        print("[KRATOS] No findings found. Run: kratos findings-generate (or kratos run)")
        return 1

    # Get optional supporting files — respect date range if provided
    if since or until:
        patterns_files = files_in_date_range(logs_dir, "auth_patterns_*.json", since=since, until=until)
        patterns_path = patterns_files[-1] if patterns_files else None
        
        nmap_files = files_in_date_range(scans_dir, "parsed_*.json", since=since, until=until)
        nmap_parsed_path = nmap_files[-1] if nmap_files else None
        
        ctx_files = files_in_date_range(ctx_dir, "system_context_*.json", since=since, until=until)
        system_context_path = ctx_files[-1] if ctx_files else None
        
        baseline_files = files_in_date_range(baseline_dir, "baseline_*.json", since=since, until=until)
        baseline_path = baseline_files[-1] if baseline_files else None
        
        trends_files = files_in_date_range(reports_dir, "auth_trends_*.json", since=since, until=until)
        trends_path = trends_files[-1] if trends_files else None
    else:
        patterns_path = latest_file(logs_dir, "auth_patterns_*.json")
        nmap_parsed_path = latest_file(scans_dir, "parsed_*.json")
        system_context_path = latest_file(ctx_dir, "system_context_*.json")
        baseline_path = latest_file(baseline_dir, "baseline_*.json")
        trends_path = latest_file(reports_dir, "auth_trends_*.json")

    findings = json.loads(findings_path.read_text(encoding="utf-8", errors="replace"))
    findings_list = findings.get("findings") or []

    env_label = ((findings.get("environment") or {}).get("label")) or "unknown"
    gen_at = findings.get("generated_at") or datetime.now().isoformat(timespec="seconds")

    # sort findings by severity then id
    def rank(f):
        sev = (f.get("severity") or "info").lower()
        return (-_SEV_ORDER.get(sev, 1), str(f.get("id") or ""))

    findings_sorted = sorted(findings_list, key=rank)

    # pull lightweight context
    sudo_members = []
    if system_context_path:
        ctx = json.loads(system_context_path.read_text(encoding="utf-8", errors="replace"))
        sudo_line = ((ctx.get("users") or {}).get("sudo_group") or "")
        parts = sudo_line.split(":")
        if len(parts) >= 4 and parts[3].strip():
            sudo_members = [u.strip() for u in parts[3].split(",") if u.strip()]

    open_ports_summary = "Unknown"
    if nmap_parsed_path:
        parsed = json.loads(nmap_parsed_path.read_text(encoding="utf-8", errors="replace"))
        hosts = parsed.get("hosts") or []
        total_open = 0
        host_lines = []
        for h in hosts:
            host = h.get("host") or h.get("address") or "unknown"
            ports = h.get("open_ports") or []
            total_open += len(ports)
            if ports:
                plist = []
                for p in ports:
                    port = p.get("port")
                    proto = p.get("protocol") or "tcp"
                    svc = (p.get("service") or "").strip()
                    plist.append(f"{port}/{proto} {svc}".strip())
                host_lines.append(f"{host}: " + ", ".join(plist))
        if total_open == 0:
            open_ports_summary = "No open TCP ports detected."
        else:
            open_ports_summary = f"Open ports total: {total_open}. " + " | ".join(host_lines)

    bursts_summary = "No patterns file found."
    if patterns_path:
        pat = json.loads(patterns_path.read_text(encoding="utf-8", errors="replace"))
        bursts = pat.get("bursts") or []
        if not bursts:
            bursts_summary = "No bursts detected in selected event types."
        else:
            lines = [f"Bursts detected: {len(bursts)}"]
            for b in bursts[:5]:  # cap
                et = b.get("event_type")
                cnt = b.get("count")
                start = b.get("start")
                end = b.get("end")
                ex = b.get("excerpt_file")
                if ex:
                    lines.append(f"- {et}: {cnt} ({start} → {end}) excerpt={ex}")
                else:
                    lines.append(f"- {et}: {cnt} ({start} → {end})")
            bursts_summary = "\n".join(lines)

    # Build bundle text
    lines = []
    lines.append("KRATOS PREPARED BUNDLE (offline / LLM-ready)")
    lines.append(f"Generated: {gen_at}")
    lines.append(f"Environment: {env_label}")
    lines.append("")
    lines.append("INPUT FILES (latest)")
    lines.append(f"- findings: {findings_path.name}")
    if patterns_path:
        lines.append(f"- patterns: {patterns_path.name}")
    if nmap_parsed_path:
        lines.append(f"- nmap_parsed: {nmap_parsed_path.name}")
    if system_context_path:
        lines.append(f"- system_context: {system_context_path.name}")
    if baseline_path:
        lines.append(f"- baseline: {baseline_path.name}")
    if trends_path:
        lines.append(f"- auth_trends: {trends_path.name}")
    lines.append("")
    lines.append("TOP FINDINGS (ordered by severity)")
    for f in findings_sorted[:10]:  # cap to keep short
        sev = (f.get("severity") or "info").upper()
        fid = f.get("id")
        title = f.get("title")
        lines.append(f"- [{sev}] {fid}: {title}")
        # include 1 evidence line max to keep clean
        ev = (f.get("evidence") or [])
        if ev:
            lines.append(f"  evidence: {ev[0]}")
    lines.append("")
    lines.append("KEY CONTEXT")
    lines.append(f"- sudo members: {', '.join(sudo_members) if sudo_members else 'unknown/none'}")
    lines.append(f"- network: {open_ports_summary}")
    lines.append("")
    lines.append("LOG PATTERNS SUMMARY")
    lines.append(bursts_summary)
    
    # Add trends summary if available
    if trends_path:
        trends = json.loads(trends_path.read_text(encoding="utf-8", errors="replace"))
        summary = trends.get("summary", {})
        lines.append("")
        lines.append("AUTH TRENDS SUMMARY")
        lines.append(f"- Direction: {summary.get('direction', 'unknown')}")
        lines.append(f"- Delta: {summary.get('delta', 0)} (from {summary.get('first', 0)} to {summary.get('last', 0)})")
        lines.append(f"- Files compared: {summary.get('files_compared', 0)}")
        lines.append(f"- AUTH-TREND-001 trigger: {summary.get('trigger_auth_trend_001', False)}")


    bundle_text = "\n".join(lines).strip() + "\n"
    bundle_text = _truncate_to_words(bundle_text, max_words=getattr(args, "max_words", 500))

    out = reports_dir / f"bundle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    out.write_text(bundle_text, encoding="utf-8")

    print(f"[KRATOS] Bundle written -> {out}")
    print(f"[KRATOS] Words: {_word_count(bundle_text)} (limit: {getattr(args, 'max_words', 500)})")
    return 0
