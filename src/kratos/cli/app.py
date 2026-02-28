import argparse
from pathlib import Path
from kratos.adapters.log_window import write_event_excerpt_from_events_file
from kratos.utils.latest_file import latest_file

from kratos.adapters.nmap_parse import (
    find_latest_nmap_xml,
    parse_nmap_xml_to_dict,
    write_parsed_json,
)

from kratos.adapters.nmap_scan import run_nmap_scan
from kratos.adapters.auth_log_parse import parse_auth_log_file
from kratos.adapters.auth_log_patterns import analyze_auth_patterns
from kratos.adapters.system_context import write_system_context
from kratos.adapters.findings_engine import write_findings_report
from kratos.adapters.logs_trends import build_auth_trends_report
from kratos.cli.logs_patterns_show import cmd_logs_patterns_show
from kratos.cli.findings_show import cmd_findings_show
from kratos.cli.baseline import cmd_baseline_create, cmd_baseline_compare
from kratos.cli.bundle import cmd_prepare_bundle
from kratos.llm_interface import analyze_findings, shutdown_llm
from kratos.llm_config import MAX_TOKENS_QUESTION

PROJECT_NAME = "kratos"
DEFAULT_DATA_DIR = Path("data")


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        out_xml = run_nmap_scan(args.data_dir, args.target)
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    print(f"[KRATOS] Scan complete -> {out_xml}")
    return 0


def cmd_scan_summary(args: argparse.Namespace) -> int:
    # Minimal summary by reusing parser output (no duplicated XML parsing)
    latest = find_latest_nmap_xml(args.data_dir)
    if latest is None:
        print("[KRATOS] No Nmap XML scans found. Run: kratos scan --target <ip>")
        return 1

    try:
        parsed = parse_nmap_xml_to_dict(latest)
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    print(f"[KRATOS] Latest scan: {latest.name}")
    for host in parsed["hosts"]:
        print(f"Host: {host['ip']}")
        ports = host["open_ports"]
        if not ports:
            print("  - No open ports found")
        else:
            for p in ports:
                details = p["service"]
                if p.get("product"):
                    details += f" ({p['product']}"
                    if p.get("version"):
                        details += f" {p['version']}"
                    details += ")"
                print(f"  - {p['protocol']}/{p['port']}: {details}")

    return 0


def cmd_scan_parse(args: argparse.Namespace) -> int:
    latest = find_latest_nmap_xml(args.data_dir)
    if latest is None:
        print("[KRATOS] No Nmap XML scans found. Run: kratos scan --target <ip>")
        return 1

    try:
        parsed = parse_nmap_xml_to_dict(latest)
        out_json = write_parsed_json(args.data_dir, parsed)
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    host_count = len(parsed["hosts"])
    open_ports_total = sum(len(h["open_ports"]) for h in parsed["hosts"])

    print(f"[KRATOS] Parsed latest scan: {latest.name}")
    print(f"[KRATOS] Hosts: {host_count}, total open ports: {open_ports_total}")
    print(f"[KRATOS] JSON written -> {out_json}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    # Backward-compatible alias
    return cmd_findings_generate(args)


def cmd_logs_parse(args: argparse.Namespace) -> int:
    # Future-proof: use getattr with defaults in case caller doesn't define these
    log_file = getattr(args, "log_file", None)
    source = getattr(args, "source", "auto")
    
    try:
        events_out, stats_out, stats = parse_auth_log_file(
            args.data_dir,
            log_file,
            source
        )
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    # Check if user-provided file was not found
    if "_warn_explicit_file_not_found" in stats:
        not_found_path = stats["_warn_explicit_file_not_found"]
        print(f"[KRATOS] WARN: Provided --log-file not found: {not_found_path} (continuing with auto-detect)")

    source_info = stats.get("source", "unknown")
    
    # Check if no logs were found
    if source_info == "none":
        print(f"[KRATOS] No supported auth log source found (auth.log/secure/journald).")
        print(f"[KRATOS] Generated empty outputs: events: {events_out.name}, stats: {stats_out.name}")
        return 0
    
    print(f"[KRATOS] Parsed auth log -> source: {source_info}")
    print(f"[KRATOS] Output files: events: {events_out.name}, stats: {stats_out.name}")
    print(f"[KRATOS] Total events: {stats.get('total_events', 0)}")

    # nice quick summary
    by_type = stats.get("events_by_type", {})
    if by_type:
        print("[KRATOS] Event types:")
        for k, v in sorted(by_type.items(), key=lambda x: (-x[1], x[0])):
            print(f"  - {k}: {v}")

    top_ips = stats.get("top_failed_login_ips", [])
    if top_ips:
        print("[KRATOS] Top failed-login IPs:")
        for item in top_ips:
            print(f"  - {item['ip']}: {item['count']}")

    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    """
    AI-powered analysis of Kratos security findings using Qwen2.5-Coder 7B.
    Loads the latest prepared bundle and explains findings in plain language.
    """
    data_dir: Path = args.data_dir
    mode = getattr(args, "mode", "summary").lower()
    question = getattr(args, "question", None)

    # Locate latest bundle; auto-generate if missing or stale
    reports_dir = data_dir / "reports"
    bundle_path = latest_file(reports_dir, "bundle_*.txt")

    class _BundleArgs:
        def __init__(self, d):
            self.data_dir = d
            self.max_words = 1000

    def _regen_bundle() -> bool:
        ret = cmd_prepare_bundle(_BundleArgs(data_dir))
        return ret == 0

    # Check if findings are newer than the bundle (stale bundle guard)
    findings_path = latest_file(reports_dir, "findings_*.json")
    if bundle_path and findings_path:
        bundle_mtime = bundle_path.stat().st_mtime
        findings_mtime = findings_path.stat().st_mtime
        if findings_mtime > bundle_mtime:
            print("[KRATOS] Findings are newer than bundle — regenerating bundle...", flush=True)
            if _regen_bundle():
                bundle_path = latest_file(reports_dir, "bundle_*.txt")
            else:
                print("[KRATOS] WARNING: Bundle regeneration failed — using stale bundle.", flush=True)

    if not bundle_path:
        print("[KRATOS] No prepared bundle found. Generating one now...", flush=True)
        if not _regen_bundle():
            print("[KRATOS] ERROR: Could not generate bundle. Run: kratos findings-generate first", flush=True)
            return 1
        bundle_path = latest_file(reports_dir, "bundle_*.txt")
        if not bundle_path:
            print("[KRATOS] ERROR: Bundle generation failed.", flush=True)
            return 1

    try:
        bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[KRATOS] ERROR reading bundle: {e}", flush=True)
        return 1

    # Build prompt
    if question:
        # Focused bundle for -q: strip boilerplate INPUT FILES section
        import re
        focused = re.sub(r"INPUT FILES.*?\n\n", "", bundle_text, flags=re.DOTALL).strip()
        prompt = (
            f"Based on this security data, answer the following question:\n\n"
            f"{question}\n\nData:\n{focused}\n\n"
            f"Be specific and grounded in the provided data only. If information is missing, say so."
        )
        response = analyze_findings(bundle_text=prompt, mode="summary",
                                    max_tokens=MAX_TOKENS_QUESTION)
    else:
        response = analyze_findings(bundle_text=bundle_text, mode=mode)

    if response is None:
        print("[KRATOS-LLM] LLM unavailable — showing raw findings instead.", flush=True)
        print("\n" + "=" * 70, flush=True)
        print("  KRATOS RAW FINDINGS  (LLM offline — no AI interpretation)", flush=True)
        print("=" * 70, flush=True)
        print(bundle_text, flush=True)
        print("=" * 70, flush=True)
        print("[KRATOS] Tip: ensure model file exists and disk has 1 GB+ free.", flush=True)
        shutdown_llm()
        return 2  # 2 = partial success: findings shown, LLM unavailable

    print("\n" + "=" * 70, flush=True)
    print("KRATOS SECURITY ANALYSIS  (powered by Qwen2.5-Coder 7B — offline)", flush=True)
    print("=" * 70, flush=True)
    print(flush=True)
    print(response, flush=True)
    print("\n" + "=" * 70, flush=True)
    print("[KRATOS-LLM] Analysis complete. Verify recommendations with actual system inspection.", flush=True)

    shutdown_llm()
    return 0


def cmd_logs_patterns(args: argparse.Namespace) -> int:
    try:
        out = analyze_auth_patterns(
            data_dir=args.data_dir,
            events_file=args.events_file,
            event_types=args.event_types,
            window_minutes=args.window_minutes,
            threshold=args.threshold,
        )
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    print(f"[KRATOS] Patterns written -> {out}")
    return 0


def cmd_logs_trends(args: argparse.Namespace) -> int:
    try:
        out_json, out_md, report = build_auth_trends_report(
            data_dir=args.data_dir,
            last_n=args.last,
            min_delta=args.min_delta,
        )
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    s = report["summary"]
    print(f"[KRATOS] Trends report JSON -> {out_json}")
    print(f"[KRATOS] Trends report MD   -> {out_md}")
    print(f"[KRATOS] Direction: {s['direction']} | Delta: {s['delta']} | AUTH-TREND-001 trigger: {s['trigger_auth_trend_001']}")
    return 0


def cmd_context_collect(args: argparse.Namespace) -> int:
    out = write_system_context(args.data_dir)
    print(f"[KRATOS] System context written -> {out}")
    return 0


def cmd_findings_generate(args: argparse.Namespace) -> int:
    out_json, out_md = write_findings_report(args.data_dir)
    print(f"[KRATOS] Findings JSON -> {out_json}")
    print(f"[KRATOS] Findings MD   -> {out_md}")
    
    # Show which context snapshot was used for traceability
    import json
    data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
    ctx_file = data.get("inputs", {}).get("system_context")
    if ctx_file:
        print(f"[KRATOS] Context snapshot used -> {ctx_file}")
    
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """
    Run the full pipeline as a single transaction.
    Each step passes its outputs directly to the next step (no "latest file" lookups).
    """
    # 1) scan + parse
    try:
        nmap_xml = run_nmap_scan(args.data_dir, args.target)
        print(f"[KRATOS] Scan complete -> {nmap_xml}")
        
        parsed = parse_nmap_xml_to_dict(nmap_xml)
        parsed_json = write_parsed_json(args.data_dir, parsed)
        
        host_count = len(parsed["hosts"])
        open_ports_total = sum(len(h["open_ports"]) for h in parsed["hosts"])
        print(f"[KRATOS] Parsed scan: {nmap_xml.name}")
        print(f"[KRATOS] Hosts: {host_count}, total open ports: {open_ports_total}")
        print(f"[KRATOS] JSON written -> {parsed_json}")
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    # 2) logs + patterns
    log_file = getattr(args, "log_file", None)
    source = getattr(args, "source", "auto")
    
    try:
        events_out, stats_out, stats = parse_auth_log_file(
            args.data_dir,
            log_file,
            source
        )
    except RuntimeError as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    # Check if user-provided file was not found
    if "_warn_explicit_file_not_found" in stats:
        not_found_path = stats["_warn_explicit_file_not_found"]
        print(f"[KRATOS] WARN: Provided --log-file not found: {not_found_path} (continuing with auto-detect)")

    source_info = stats.get("source", "unknown")
    
    # Check if no logs were found
    if source_info == "none":
        print(f"[KRATOS] No supported auth log source found (auth.log/secure/journald).")
        print(f"[KRATOS] Generated empty outputs: events: {events_out.name}, stats: {stats_out.name}")
    else:
        print(f"[KRATOS] Parsed auth log -> source: {source_info}")
        print(f"[KRATOS] Output files: events: {events_out.name}, stats: {stats_out.name}")
        print(f"[KRATOS] Total events: {stats.get('total_events', 0)}")

        # nice quick summary
        by_type = stats.get("events_by_type", {})
        if by_type:
            print("[KRATOS] Event types:")
            for k, v in sorted(by_type.items(), key=lambda x: (-x[1], x[0])):
                print(f"  - {k}: {v}")

        top_ips = stats.get("top_failed_login_ips", [])
        if top_ips:
            print("[KRATOS] Top failed-login IPs:")
            for item in top_ips:
                print(f"  - {item['ip']}: {item['count']}")
    
    # Run patterns analysis using the events file we just created
    if events_out:
        try:
            patterns_out = analyze_auth_patterns(
                data_dir=args.data_dir,
                events_file=events_out,
                event_types=getattr(args, "event_types", None),
                window_minutes=getattr(args, "window_minutes", 5),
                threshold=getattr(args, "threshold", 3),
            )
            print(f"[KRATOS] Patterns written -> {patterns_out}")
        except RuntimeError as e:
            print(f"[KRATOS] WARNING: Pattern detection failed: {e}, continuing pipeline.")
            patterns_out = None
    else:
        patterns_out = None

    # 3) context
    try:
        context_out = write_system_context(args.data_dir)
        print(f"[KRATOS] System context written -> {context_out}")
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1

    # 4) findings (uses the files we just created in this run)
    try:
        out_json, out_md = write_findings_report(
            data_dir=args.data_dir,
            nmap_parsed_file=parsed_json,
            auth_stats_file=stats_out,
            auth_patterns_file=patterns_out,
            system_context_file=context_out,
            auth_trends_file=None,  # trends not generated in run (optional)
        )
        print(f"[KRATOS] Findings JSON -> {out_json}")
        print(f"[KRATOS] Findings MD   -> {out_md}")
        
        # Show which context snapshot was used for traceability
        import json
        data = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        ctx_file = data.get("inputs", {}).get("system_context")
        if ctx_file:
            print(f"[KRATOS] Context snapshot used -> {ctx_file}")
        
        # Extract timestamp from any output file to show artifact set tag
        artifact_tag = parsed_json.stem.split('_', 1)[1] if '_' in parsed_json.stem else "unknown"
        print(f"[KRATOS] Run artifact set: {artifact_tag} (all files use this timestamp)")
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1
    
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROJECT_NAME,
        description="Kratos — Offline AI Security Assistant (thesis prototype)",
    )
    p.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Directory for storing scans/logs/context/reports (default: ./data)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    runp = sub.add_parser("run", help="Run the full pipeline (scan→logs→context→findings)")
    runp.add_argument("--target", default="127.0.0.1", help="Scan target (default: 127.0.0.1)")
    runp.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Path to auth log file (optional, auto-detect if not provided)",
    )
    runp.add_argument(
        "--source",
        choices=["auto", "file", "journald"],
        default="auto",
        help="Auth log source (default: auto)",
    )
    runp.add_argument("--threshold", type=int, default=3, help="Burst threshold (default: 3)")
    runp.add_argument("--window-minutes", type=int, default=5, help="Burst window in minutes (default: 5)")
    runp.add_argument(
        "--event-types",
        nargs="+",
        default=["sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login"],
        help="Event types to analyze (default: sudo_pam_auth_failure sudo_auth_failure ssh_failed_login)",
    )
    runp.set_defaults(func=cmd_run)

    scan = sub.add_parser("scan", help="Run an Nmap scan and save XML output")
    scan.add_argument("--target", default="127.0.0.1", help="Scan target (default: 127.0.0.1)")
    scan.set_defaults(func=cmd_scan)

    summary = sub.add_parser("scan-summary", help="Summarize the latest Nmap XML scan")
    summary.set_defaults(func=cmd_scan_summary)

    parse = sub.add_parser("scan-parse", help="Parse latest Nmap XML into normalized JSON")
    parse.set_defaults(func=cmd_scan_parse)

    logs_parse = sub.add_parser("logs-parse", help="Parse auth.log into normalized events + stats")
    logs_parse.add_argument(
        "--source",
        choices=["auto", "file", "journald"],
        default="auto",
        help="Auth log source: auto-detect (default), file, or journald",
    )
    logs_parse.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Path to auth log file (default: auto-detect /var/log/auth.log or /var/log/secure)",
    )
    logs_parse.set_defaults(func=cmd_logs_parse)
    
    logs_patterns = sub.add_parser(
        "logs-patterns",
        help="Detect bursts/patterns in parsed auth events"
    )
    logs_patterns.add_argument(
        "--events-file",
        type=Path,
        default=None,
        help="Path to auth_events_*.json (default: latest in data/logs/)",
    )
    logs_patterns.add_argument(
        "--event-types",
        nargs="+",
        default=["sudo_pam_auth_failure", "sudo_auth_failure", "ssh_failed_login"],
        help="Event types to analyze (default: sudo_pam_auth_failure sudo_auth_failure ssh_failed_login)",
    )
    logs_patterns.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Burst window in minutes (default: 5)",
    )
    logs_patterns.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum events in window to count as burst (default: 3)",
    )
    logs_patterns.set_defaults(func=cmd_logs_patterns)

    patterns_show = sub.add_parser("logs-patterns-show", help="Show latest auth pattern analysis")
    patterns_show.set_defaults(func=cmd_logs_patterns_show)

    trends = sub.add_parser("logs-trends", help="Run-to-run trend analysis over recent auth_stats files")
    trends.add_argument("--last", type=int, default=5, help="How many recent stats files to compare (default: 5)")
    trends.add_argument("--min-delta", type=int, default=2, help="Minimum increase (last-first) to trigger trend (default: 2)")
    trends.set_defaults(func=cmd_logs_trends)

    context = sub.add_parser(
        "context-collect",
        help="Collect system context (OS, users, services, network)"
    )
    context.set_defaults(func=cmd_context_collect)

    findings = sub.add_parser(
        "findings-generate",
        help="Generate correlated findings report (JSON + Markdown)"
    )
    findings.set_defaults(func=cmd_findings_generate)

    findings_show = sub.add_parser("findings-show", help="Show latest findings (optionally filter by ID)")
    findings_show.add_argument("--id", dest="finding_id", default=None, help="Filter by finding ID (e.g., CORR-002)")
    findings_show.set_defaults(func=cmd_findings_show)

    bcreate = sub.add_parser("baseline-create", help="Create a baseline snapshot (versioned JSON)")
    bcreate.set_defaults(func=cmd_baseline_create)

    bcompare = sub.add_parser("baseline-compare", help="Compare latest baseline vs current snapshot")
    bcompare.set_defaults(func=cmd_baseline_compare)

    bundle = sub.add_parser("prepare-bundle", help="Create a clean, short text bundle for offline LLM input")
    bundle.add_argument("--max-words", type=int, default=500, help="Max words in the bundle (default: 500)")
    bundle.set_defaults(func=cmd_prepare_bundle)

    analyze = sub.add_parser("analyze", help="Analyze scan/log/context data (placeholder)")
    analyze.set_defaults(func=cmd_analyze)


    chat = sub.add_parser("chat", help="AI analysis of findings via Qwen2.5-Coder 7B (offline)")
    chat.add_argument(
        "--mode",
        choices=["summary", "deep"],
        default="summary",
        help="summary = executive overview, deep = attack chains + blind spots (default: summary)",
    )
    chat.add_argument("--question", "-q", default=None, help="Ask a specific question about the findings")
    chat.set_defaults(func=cmd_chat)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    args.data_dir.mkdir(parents=True, exist_ok=True)
    return int(args.func(args))
