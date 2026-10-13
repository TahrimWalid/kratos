"""The `kratos` command-line entry point and all of its subcommands.

`main()` builds the argparse parser and dispatches. Two shapes to keep straight:

- **Bare `kratos`** (no subcommand) launches the full-screen Textual TUI — the
  primary interface. The classic prompt_toolkit REPL is retired as the default
  face and no longer has an entry here.
- **`kratos <subcommand>`** runs one of the fixed-pipeline / service commands
  defined below: `investigate`, `run`, `scan` (+ `scan-summary`/`scan-parse`),
  `logs-*`, `findings-*`, `context`, `baseline`, `chat`, `prepare-bundle`,
  `scheduled-run`, `llm-serve`, `mcp-serve`, and so on. Each `cmd_*` handler is a
  thin wrapper over an adapter or the agent; this module is the wiring, not the
  logic.

`load_kept_tools()` is called once here before dispatch so self-written tools are
registered for whichever path runs.
"""
import argparse
import os
import sys
import json
import shutil
import time
from pathlib import Path
from rich.panel import Panel
from rich.table import Table
from kratos import paths as _paths
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
from kratos.adapters.network_capture import capture_traffic
from kratos.adapters.network_aggregator import build_anomaly_report
from kratos.adapters.security_report import generate_daily_report, generate_weekly_report
from kratos.cli.logs_patterns_show import cmd_logs_patterns_show
from kratos.cli.findings_show import cmd_findings_show
from kratos.cli.baseline import cmd_baseline_create, cmd_baseline_compare
from kratos.cli.bundle import cmd_prepare_bundle
from kratos.llm_interface import analyze_findings, shutdown_llm
from kratos.llm_config import MAX_TOKENS_QUESTION
from kratos.storage.anomaly_store import AnomalyStore
from kratos.agent.loop import run_agent, DEFAULT_MAX_ITERS
from kratos.agent.self_write_loop import load_kept_tools
from kratos.agent import console as _console
from kratos.kratos_config import get_active_target
from kratos.run_context import run_scope
from kratos.llm_config import LLM_OPENAI_MODEL

PROJECT_NAME = "kratos"
DEFAULT_DATA_DIR = _paths.default_data_dir()


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


def cmd_mcp_serve(args: argparse.Namespace) -> int:
    """
    Starts the Kratos MCP server (stdio transport) -- exposes kratos_investigate/
    kratos_get_findings/kratos_list_sessions to an MCP client (e.g. Claude Desktop).
    Thin wrapper around run_agent()/SessionStore, same architecture as `kratos
    investigate`/the REPL -- Kratos's own agent loop and its own configured LLM remain
    the orchestrator regardless of how the request arrives. Read/investigate only: no
    approval-gated action is reachable through this surface. Blocking -- runs until the
    client disconnects or the process is killed. See mcp_server.py's module docstring
    for the full boundary rationale.
    """
    from kratos.mcp_server import run_stdio_server
    run_stdio_server(args.data_dir)
    return 0


def cmd_subagent_pair(args: argparse.Namespace) -> int:
    """
    Generate a one-time pairing code for a new sub-agent (capability 1 --
    read-only telemetry only; docs/subagent_architecture.md). Print the
    exact command to run ON the target -- the target-side agent is the file
    at src/kratos/subagent/{agent,protocol,collector}.py, stdlib-only and
    deployable by copying just those three files (see agent.py's module
    docstring for the deployment shape).
    """
    from kratos.storage.subagent_store import SubAgentStore

    store = SubAgentStore(args.data_dir / "kratos.db")
    result = store.create_pairing_code(name=args.name)
    print(f"[KRATOS] Pairing code: {result['code']}  (expires in {result['ttl_seconds'] // 60} min)")
    print(f"[KRATOS] On the target, with subagent/{{agent,protocol,collector,signing,whitelist}}.py copied alongside each other:")
    print(
        f"[KRATOS]   python3 -m subagent.agent --core-host {args.core_host} --core-port {args.core_port} "
        f"--pair {result['code']}"
    )
    print(f"[KRATOS] The pairing code is single-use; the agent saves a persistent token after its first successful connect.")
    print(f"[KRATOS] Easier: `kratos subagent-install --core-host {args.core_host}` emits a one-command installer instead.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Create the settings file from the bundled template if there isn't one, and
    say where Kratos keeps everything. Never overwrites an existing file."""
    from importlib.resources import files

    env_path = _paths.env_file()
    print(f"[KRATOS] {_paths.layout_note()}.")
    if env_path.exists():
        print(f"[KRATOS] Settings file already exists, left as it is: {env_path}")
    else:
        template = files("kratos").joinpath("templates/env.example").read_text(encoding="utf-8")
        _paths.write_private_text(env_path, template)
        print(f"[KRATOS] Created your settings file (readable only by you): {env_path}")
        print("[KRATOS] Open it and set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL for your model --")
        print("         or start `kratos` and add one under Settings > Models.")
    for label, path in _paths.describe()[1:]:
        print(f"         {label + ':':<18} {path}")
    from kratos.adapters.vuln_scan import vulscan_installed

    if not vulscan_installed():
        print("[KRATOS] Optional: `kratos vulscan-install` downloads the CVE list the vulnerability scan matches against.")
    return 0


def cmd_vulscan_install(args: argparse.Namespace) -> int:
    """Download nmap's vulscan script and CVE list into Kratos's data home."""
    from kratos.adapters import vuln_scan

    print("[KRATOS] Installing vulscan: the script from its repository, the CVE list built from NVD's "
          "public feeds (a couple of minutes) ...")
    ok, message = vuln_scan.install_vulscan(force=args.force, progress=lambda m: print(f"         {m}", flush=True))
    print(f"[KRATOS] {message}")
    if ok:
        status = vuln_scan.check_vulscan_db_staleness()
        if status.get("note"):
            print(f"[KRATOS] Note: {status['note']}")
    return 0 if ok else 1


def cmd_subagent_install(args: argparse.Namespace) -> int:
    """
    Emit a self-contained, one-command installer for a new sub-agent
    (capability 1 -- read-only telemetry). Creates a single-use pairing code
    (unless --code is supplied) and prints a POSIX-sh script that, run once on
    the target, writes the stdlib-only agent bundle, installs a systemd
    service (Restart=always), and connects. No PyPI, no hosting endpoint, no
    inbound port on the target. Direct execution (capability 2) is never
    enabled by this installer.
    """
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent import installer as _installer

    code = args.code
    ttl_note = ""
    if not code:
        store = SubAgentStore(args.data_dir / "kratos.db")
        result = store.create_pairing_code(name=args.name)
        code = result["code"]
        ttl_note = f"  (pairing code expires in {result['ttl_seconds'] // 60} min)"

    try:
        script = _installer.generate_installer(args.core_host, code, core_port=args.core_port,
                                               trusted_interfaces=args.trusted_interfaces)
    except _installer.InstallerError as exc:
        print(f"[KRATOS] Could not generate installer: {exc}", file=sys.stderr)
        return 1

    if args.output:
        out = Path(args.output)
        out.write_text(script, encoding="utf-8")
        print(f"[KRATOS] Installer written to {out}{ttl_note}")
        print(f"[KRATOS] 1. Make sure this core is listening:  kratos subagent-serve --host {args.core_host}")
        print(f"[KRATOS] 2. Copy {out.name} to the target and run:  sh {out.name}")
    else:
        print(script)
    return 0


def cmd_subagent_serve(args: argparse.Namespace) -> int:
    """
    Run the Kratos-core-side sub-agent listener. Blocking -- accepts OUTBOUND
    connections from paired sub-agents and never dials out to one itself (see
    core_server.py's module docstring). It receives telemetry, serves
    investigation reads, and delivers a /whitelist action only after a person
    approved it there (typed EXECUTE) for a target that opted in -- and the
    agent still refuses it unless its own execution switch and ceiling allow it.
    """
    import asyncio

    import signal

    from kratos.storage.subagent_store import SubAgentStore
    from kratos.storage.whitelist_store import WhitelistStore
    from kratos.subagent.core_server import RESTART_EXIT_CODE, CoreServer, DEFAULT_PORT
    from kratos.subagent.local_reads import socket_path

    store = SubAgentStore(args.data_dir / "kratos.db")
    # The whitelist store is what lets core push allowlists, record what each agent
    # allows, and deliver /whitelist runs (they wait in its queue for this process).
    try:
        server = CoreServer(store, host=args.host, port=args.port,
                            whitelist_store=WhitelistStore(args.data_dir / "kratos.db"),
                            read_socket_path=socket_path(args.data_dir))
    except ValueError as exc:
        print(f"[KRATOS] --host: {exc}", file=sys.stderr)
        return 2
    print(f"[KRATOS] Sub-agent telemetry server listening on {server.host} port {args.port} (Ctrl+C to stop)")

    async def _main() -> None:
        # SIGTERM (systemctl stop/restart) and Ctrl+C both shut down cleanly,
        # so connected targets are recorded as "listener stopped" at once
        # rather than looking connected until the heartbeat goes stale.
        loop = asyncio.get_running_loop()
        serve = asyncio.create_task(server.serve_forever())
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, serve.cancel)
            except (NotImplementedError, RuntimeError):
                pass
        try:
            await serve
        except asyncio.CancelledError:
            pass
        finally:
            await server.close()

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
    if server.restart_for_update:
        # A service restarting itself to load newer code: systemd starts it
        # again (EX_TEMPFAIL also counts as a failure for Restart=on-failure).
        print("\n[KRATOS] Restarting to load newer Kratos code.")
        return RESTART_EXIT_CODE
    print("\n[KRATOS] Sub-agent telemetry server stopped.")
    return 0


def cmd_snapshots(args: argparse.Namespace) -> int:
    """Kratos's own saved observations, indexed by capture time (docs/time_window_design.md
    §17). `prune` only PREVIEWS unless --apply is given -- never deletes by surprise."""
    from kratos.timewin import snapshots as S

    data_dir = Path(args.data_dir)
    if args.action == "index":
        for cat, n in sorted(S.reindex(data_dir).items()):
            print(f"[KRATOS] {cat:20s} {n}")
        return 0
    if args.action == "list":
        for cat, h in sorted(S.horizon(data_dir).items()):
            print(f"[KRATOS] {cat:20s} {h['count']:5d}  {h['oldest']}  ->  {h['newest']}")
        return 0
    plan = S.plan_retention(data_dir)
    print(f"[KRATOS] retention policy: keep all <{plan['policy']['keep_all_days']}d, daily <{plan['policy']['daily_until_days']}d, "
          f"weekly <{plan['policy']['weekly_until_days']}d, monthly after; {plan['pinned']} pinned")
    for item in plan["delete"][:50]:
        print(f"[KRATOS]   would remove {item['file']}  ({item['category']}, captured {item['captured_at']})")
    if len(plan["delete"]) > 50:
        print(f"[KRATOS]   ... and {len(plan['delete']) - 50} more")
    print(f"[KRATOS] {len(plan['delete'])} files, {plan['delete_bytes'] / 1e6:.1f} MB")
    if not args.apply:
        print("[KRATOS] preview only -- nothing deleted. Re-run with --apply to remove these files.")
        return 0
    removed = S.apply_retention(data_dir, plan)
    print(f"[KRATOS] removed {removed} files")
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    """The log lines Kratos has read from a machine, as stored events (read-only).
    Plain lines by default; --json prints one ECS document per line."""
    from kratos.events.store import MAX_LIMIT, EventStore
    from kratos.target_key import target_key
    from kratos.utils.time_window import TimeBoundError, resolve_time_bound
    from kratos.utils.timeutil import format_for_display, resolve_display_tz

    target = args.target or get_active_target()
    if not target:
        print("[KRATOS] Which machine? Pass --target <host> (or set KRATOS_SSH_HOST).", file=sys.stderr)
        return 1
    try:
        start = resolve_time_bound(args.since) if args.since else None
        end = resolve_time_bound(args.until) if args.until else None
    except TimeBoundError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 1
    store = EventStore(Path(args.data_dir) / "kratos.db")
    filters = dict(start=start, end=end, source_ip=args.ip, user=args.user, process=args.process,
                   dataset=args.dataset, action=args.action)
    events = store.query(target, **filters, limit=min(args.limit, MAX_LIMIT), newest_first=not args.oldest_first)
    if args.json:
        for e in events:
            print(json.dumps(e.to_ecs(), sort_keys=True, ensure_ascii=False))
        return 0
    total = store.count(target, **filters)
    if not events:
        known = ", ".join(t for t, _ in store.targets()) or "none yet"
        print(f"[KRATOS] No stored events for {target_key(target)} with those filters. "
              f"Machines with events: {known}.")
        return 0
    tz = resolve_display_tz(Path(args.data_dir))
    for e in events:
        when = format_for_display(e.timestamp.isoformat(), "%Y-%m-%d %H:%M:%S", tz=tz)
        who = " ".join(x for x in (f"user={e.user_name}" if e.user_name else "",
                                    f"from={e.source_ip}" if e.source_ip else "") if x)
        text = (e.message or "").replace("\n", " ")
        print(f"{when}  {e.action or e.dataset:<22} {e.outcome or '':<8} {who:<34} {text[:120]}")
    shown = f"{len(events)} of {total}" if total > len(events) else str(total)
    print(f"[KRATOS] {shown} events for {target_key(target)} (times in {getattr(tz, 'key', None) or tz}).")
    return 0


_STATE_WORDS = {"open": "open", "verified": "verified", "mitigated": "fixed (mitigated)",
                "inactive": "no recurrence (inactive)", "risk_accepted": "risk accepted",
                "false_positive": "false positive", "out_of_scope": "out of scope"}


def _findings_when(value: str | None, tz) -> str:
    from kratos.utils.timeutil import format_for_display

    return format_for_display(value, "%Y-%m-%d %H:%M", tz=tz) if value else "-"


def cmd_seal(args: argparse.Namespace) -> int:
    """`kratos seal set-key|status|verify|remove-key`: journal sealing (FSS). The
    verification key stays on this machine: it is read from stdin (never the
    command line, which other users can see in `ps`) and never printed."""
    import getpass

    from kratos import kratos_config as _kc
    from kratos.logsources import seal as SEAL
    from kratos.run_context import run_scope
    from kratos.utils.timeutil import epoch_to_utc_iso

    data_dir = Path(args.data_dir)
    action = args.seal_action
    if action == "status":
        keys = SEAL.keys_on_file(data_dir)
        if not keys:
            print("[KRATOS] No machine has journal sealing set up in Kratos (see `kratos seal set-key`).")
            return 0
        for k in keys:
            last = SEAL.latest_summary(data_dir, k["target"]) or {}
            print(f"{k['target']:<20} key set {epoch_to_utc_iso(k.get('set_at')) if k.get('set_at') else '?'} by "
                  f"{k.get('set_by') or '?'}; machine-id {k.get('machine_id') or 'not yet bound'}; "
                  f"last check: {last.get('status', 'never')} {last.get('checked_at') or ''}".rstrip())
        return 0
    target = args.target
    if action == "set-key":
        if sys.stdin.isatty():
            print("Paste the verification key journalctl --setup-keys printed, then press Enter:", file=sys.stderr)
        key = sys.stdin.readline().strip()
        try:
            path = SEAL.set_key(data_dir, target, key, set_by=f"{getpass.getuser()} (cli)")
        except SEAL.SealKeyError as e:
            print(f"[KRATOS] {e}", file=sys.stderr)
            return 1
        print(f"[KRATOS] Verification key saved for {target} in {path} (owner-only). It never leaves this machine.")
        return 0
    if action == "remove-key":
        if SEAL.remove_key(data_dir, target):
            print(f"[KRATOS] Removed the verification key for {target}; sealing can't be verified until a new one is set.")
            return 0
        print(f"[KRATOS] No verification key on file for {target}.", file=sys.stderr)
        return 1
    if action == "verify":
        if not SEAL.has_key(data_dir, target):
            print(f"[KRATOS] No verification key on file for {target} (kratos seal set-key {target}).", file=sys.stderr)
            return 1
        _kc.set_active_data_dir(data_dir)
        with run_scope("cli", target=target), _kc.pinned_target(target):
            summary = SEAL.verify(data_dir, target)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0 if summary and summary["status"] != "failed" else 1
        print(f"[KRATOS] {target}: {summary['status']}  (passed {len(summary['passed'])}, unchanged since verified "
              f"{summary['skipped_unchanged']}, failed {len(summary['failed'])}, changed archives "
              f"{len(summary['changed_archives'])}, unsealed after setup {len(summary['unsealed_after_setup'])})")
        for f in summary["failed"] + summary["changed_archives"]:
            print(f"  FAILED {f['name']}: {f['detail']}")
        for f in summary["unsealed_after_setup"]:
            print(f"  NOT SEALED {f['name']}")
        if summary.get("unverifiable"):
            print(f"  could not verify: {summary['unverifiable']}")
        for n in summary["notes"]:
            print(f"  note: {n}")
        return 1 if summary["status"] == "failed" else 0
    return 2


def _budget_value_text(value: object) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def cmd_budget(args: argparse.Namespace) -> int:
    """`kratos budget [show|set|resume]`: the model spending limits, for a machine with
    no TUI (schedules, `kratos mcp-serve`). Same settings and checks as Settings ->
    Budget; a change applies from the next model call in every Kratos process."""
    from kratos import settings_store
    from kratos.budget import breaker, limits as L, report

    data_dir = Path(args.data_dir)
    action = getattr(args, "budget_action", None) or "show"
    if action == "set":
        key = args.key if args.key.startswith("budget.") else f"budget.{args.key}"
        if key not in L.KEYS:
            print(f"[KRATOS] '{args.key}' isn't a budget limit. Limits: "
                  + ", ".join(k.removeprefix("budget.") for k in L.KEYS), file=sys.stderr)
            return 2
        try:
            settings_store.set(key, args.value, data_dir=data_dir, actor="cli")
        except settings_store.SettingError as e:
            print(f"[KRATOS] Not changed: {e}", file=sys.stderr)
            return 2
        value = _budget_value_text(settings_store.get(key, data_dir=data_dir))
        print(f"[KRATOS] {key} = {value}. Applies to the next model call, in every Kratos process.")
        return 0
    if action == "resume":
        if breaker.resume(data_dir, args.source, actor="cli"):
            print(f"[KRATOS] Resumed {args.source}.")
            return 0
        print(f"[KRATOS] {args.source} isn't paused.", file=sys.stderr)
        return 1
    t = report.today(data_dir)
    specs = {sp.key: sp for sp in settings_store.specs()}
    if getattr(args, "json", False):
        print(json.dumps({
            "day": t.day,
            "today": [{"scope": s.scope, "label": s.label, "spent": s.spent, "limit": s.limit} for s in t.scopes],
            "calls_today": t.totals.calls,
            "limits": {k: settings_store.get(k, data_dir=data_dir) for k in L.KEYS},
            "paused": [{"source": p["key"], "until": p.get("until"), "reason": p.get("reason")} for p in t.pauses],
        }, indent=2, sort_keys=True))
        return 0
    print(f"Model spending today ({t.day}), {t.totals.calls} model call{'s' if t.totals.calls != 1 else ''}:")
    for s in t.scopes:
        print(f"  {s.label}: {s.text} ({s.remaining_text})")
    print("Limits (kratos budget set <name> <value>):")
    for k in L.KEYS:
        changed = settings_store.last_change(k, data_dir=data_dir)
        who = f"  -- set by {changed[1]}" if changed else "  -- default"
        doc = specs[k].doc if k in specs else ""
        print(f"  {k.removeprefix('budget.'):<34} {_budget_value_text(settings_store.get(k, data_dir=data_dir)):<12}{who}")
        if doc:
            print(f"      {doc}")
    for p in t.pauses:
        print(f"Paused: {p['key']} {breaker.pause_text(p)} (kratos budget resume {p['key']})")
    print("Costs are estimates from list prices; your provider's bill is the real figure.")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    """`kratos findings list|show|verify|accept|fp|out-of-scope|reopen|import-reports`:
    the findings Kratos remembers across runs, and the decisions people make about them."""
    from kratos.lifecycle import decide as D, migrate as M, query as Q
    from kratos.lifecycle.keys import short
    from kratos.utils.timeutil import epoch_to_utc_iso, resolve_display_tz

    data_dir = Path(args.data_dir)
    tz = resolve_display_tz(data_dir)
    action = args.findings_action
    if action == "import-reports":
        result = M.import_reports(data_dir)
        print(f"[KRATOS] imported {result['imported']} report(s) "
              f"({result['records_created']} new finding record(s)); "
              f"{result['skipped_lifecycle']} already tracked; {result['malformed']} unreadable (skipped).")
        if result["by_source"]:
            print("[KRATOS] machine taken from: " + ", ".join(f"{k} {v}" for k, v in sorted(result["by_source"].items())))
        return 0
    M.ensure_imported(data_dir)
    if action == "list":
        target = None if args.target == "all" else (args.target or get_active_target())
        try:
            rows = Q.list_findings(data_dir, target=target, state=args.state.replace("-", "_"))
        except ValueError as e:
            print(f"[KRATOS] {e}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
            return 0
        if not rows:
            what = {"open_verified": "open or verified", "decided": "decided", "all": ""}.get(
                args.state, _STATE_WORDS.get(args.state, args.state))
            print(f"[KRATOS] No {what} findings".replace("  ", " ") + (f" for {target}." if target else "."))
        for r in rows:
            expiry = (r.get("decision") or {}).get("expires_at")
            print(f"{r['short_key']}  {_STATE_WORDS.get(r['state'], r['state']):<24} {r['severity']:<8} "
                  f"{r['rule_id']:<14} {r['target']:<16} seen {_findings_when(r['first_seen'], tz)} .. "
                  f"{_findings_when(r['last_seen'], tz)}" + (f"  until {_findings_when(expiry, tz)}" if expiry else "")
                  + f"  {r['title']}")
        hidden = Q.hidden_counts(data_dir, target)
        if args.state in ("open_verified", "open-verified") and sum(hidden.values()):
            print(f"[KRATOS] Hidden by your decisions: {sum(hidden.values())} "
                  f"(kratos findings list --state decided)")
        return 0
    if action == "show":
        try:
            rec, latest, events = Q.get_finding(data_dir, args.key)
        except LookupError as e:
            print(f"[KRATOS] {e}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps({"record": rec, "finding": latest, "history": events}, indent=2, sort_keys=True))
            return 0
        print(f"{rec['rule_id']} -- {rec['title']}")
        print(f"  key: {rec['finding_key']}  machine: {rec['target']}  severity: {rec['severity']}")
        print(f"  state: {_STATE_WORDS.get(rec['state'], rec['state'])}  seen {rec['times_seen']} time(s), "
              f"first {_findings_when(rec['first_seen'], tz)}, last {_findings_when(rec['last_seen'], tz)}, "
              f"last re-checked {_findings_when(rec['last_checked'], tz)}")
        if rec["entities"]:
            print(f"  about: {', '.join(rec['entities'])}")
        d = rec.get("decision")
        if d:
            print(f"  decision: {_STATE_WORDS.get(d['kind'])} ({D.SCOPE_WORDS.get(d['scope'])}) by "
                  f"{d['decided_by']}" + (f", owner {d['owner']}" if d.get("owner") else "")
                  + (f", until {_findings_when(d['expires_at'], tz)}" if d.get("expires_at") else "")
                  + f": {d['reason']}")
        for line in (latest.get("evidence") or [])[:12]:
            print(f"  - {line}")
        print("  history:")
        for e in events:
            move = f"{e['from_state'] or '-'} -> {e['to_state']}" if e["to_state"] else ""
            print(f"    {_findings_when(e['at'], tz)}  {e['kind']:<17} {move:<26} by {e['actor']} "
                  f"({e['interface'] or '-'}): {e['reason'] or ''}")
        return 0
    actor = D.Actor.current("cli")
    try:
        if action == "verify":
            out = D.verify(args.key, actor=actor, reason=args.reason, data_dir=data_dir)
        elif action == "reopen":
            out = D.reopen(args.key, actor=actor, reason=args.reason, data_dir=data_dir)
        elif action == "accept":
            if (args.days is None) == (args.until is None):
                raise D.DecisionError("give how long: --days N or --until DATE")
            expires = D.expiry_from_days(args.days) if args.days is not None else D.parse_expiry(args.until, tz=tz)
            out = D.accept_risk(args.key, actor=actor, reason=args.reason, owner=args.owner, expires_at=expires,
                                scope=args.scope, data_dir=data_dir)
        else:
            expires = None
            if args.days is not None:
                expires = D.expiry_from_days(args.days)
            elif args.until is not None:
                expires = D.parse_expiry(args.until, tz=tz)
            fn = D.mark_false_positive if action == "fp" else D.mark_out_of_scope
            out = fn(args.key, actor=actor, reason=args.reason, scope=args.scope, expires_at=expires,
                     data_dir=data_dir)
    except D.DecisionError as e:
        print(f"[KRATOS] Not changed: {e}", file=sys.stderr)
        return 1
    state = out.get("state") or out.get("kind")
    extra = ""
    if out.get("expires_at"):
        extra = f" until {_findings_when(epoch_to_utc_iso(out['expires_at']), tz)}"
    if out.get("scope") and out["scope"] != "key":
        extra += f" ({D.SCOPE_WORDS[out['scope']]}; {len(out.get('changed') or [])} finding(s) changed now)"
    print(f"[KRATOS] {short(out['finding_key'])}: {_STATE_WORDS.get(state, state)}{extra}.")
    return 0


def cmd_subagent_status(args: argparse.Namespace) -> int:
    """List paired sub-agent targets and their derived liveness status, plus
    a one-line summary of the latest telemetry received from each (capability
    1). Status here is derived purely from persisted last_seen recency (see
    subagent/status.py) since this is a separate process from any running
    `subagent-serve` -- it has no live-socket visibility of its own."""
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent.status import LISTENER_STALE_AFTER_SECONDS, assess_all

    store = SubAgentStore(args.data_dir / "kratos.db")
    assessed = assess_all(store)
    if not assessed:
        print("[KRATOS] No sub-agents paired yet. Run: kratos subagent-install")
        return 0
    listeners = store.live_listeners(LISTENER_STALE_AFTER_SECONDS)
    if listeners:
        from kratos.utils.build_info import current_disk_build, display_build, same_code

        lst = listeners[0]
        print(f"[KRATOS] listener: {lst['mode']} (pid {lst['pid']}, port {lst['port']}, "
              f"build {display_build(lst['build'])})")
        if lst.get("build") and not same_code(lst["build"], current_disk_build()):
            how = ("restart its service (or press L in /subagent)" if lst["mode"] == "service"
                   else "restart it")
            print(f"[KRATOS]   it runs older code than is on disk ({display_build(current_disk_build())}); {how}")
    else:
        print("[KRATOS] listener: NONE RUNNING -- targets can't check in; statuses below are unknown")
    for t, st in assessed:
        print(f"[KRATOS] {t['target_id']}  {t.get('name') or t['hostname'] or '?'}  status={st.state}  "
              f"last_seen={t['last_seen']}  -- {st.reason}")
        latest = store.get_latest_telemetry(t["target_id"])
        if latest:
            host = (latest["payload"].get("host") or {})
            disk = (latest["payload"].get("disk") or {})
            print(
                f"[KRATOS]   latest telemetry (seq={latest['seq']}, collected_at={latest['collected_at']}): "
                f"uptime={host.get('uptime_seconds')}s  disk_used_pct={disk.get('used_pct')}"
            )
    return 0


def cmd_llm_serve(args: argparse.Namespace) -> int:
    """
    Start a local model server (a GGUF model loaded once and kept in memory, or a
    local Ollama) for the self-hosted path.
    Run this in a dedicated terminal before using kratos chat for fast responses.
    """
    import subprocess
    import os as _os
    from kratos.llm_config import (
        MODEL_PATH, LLM_BACKEND, LLM_OPENAI_BASE_URL, OLLAMA_BIN, OLLAMA_QUIET, OLLAMA_DETACH,
        LLAMA_SERVER_HOST, LLAMA_SERVER_PORT,
        LLAMA_N_CTX, LLAMA_N_THREADS, LLAMA_SEED, STARTUP_TIMEOUT_SECONDS,
    )

    # The OpenAI-compatible /v1/chat/completions endpoint (the only query
    # path now -- see docs/DESIGN.md's "LLM backend" section) does not
    # honor a per-request context-length override at all: a request can
    # pass options.num_ctx and Ollama's own /api/ps will still report the
    # bare default context_length, unaffected. Context length is a
    # model-load-time concept for Ollama, not a per-completion-request one
    # in the OpenAI API shape, so the only real fix is Ollama's own
    # server-level OLLAMA_CONTEXT_LENGTH env var, set here when KRATOS
    # ITSELF starts the process (only place Kratos controls Ollama's
    # environment -- an already-running Ollama instance Kratos didn't
    # start, e.g. one managed by systemd, needs a manual restart with this
    # var set to pick it up).
    _ollama_env_ctx = _os.environ.get("OLLAMA_CONTEXT_LENGTH", str(LLAMA_N_CTX))

    backend = (LLM_BACKEND or "auto").strip().lower()
    local_model_ready = MODEL_PATH.exists() and MODEL_PATH.stat().st_size > 0
    attach = getattr(args, "attach", False)

    # This subcommand only ever manages a LOCAL Ollama process (there's
    # nothing to "start" for a remote/cloud endpoint) -- derive the URL to
    # health-check/wait-on from LLM_BASE_URL itself (stripping the /v1
    # OpenAI-compat suffix, since Ollama's own native /api/tags health
    # endpoint is used below) rather than a second, independently
    # configurable host/port that could silently drift out of sync with it.
    OLLAMA_URL = LLM_OPENAI_BASE_URL.rstrip("/")
    if OLLAMA_URL.endswith("/v1"):
        OLLAMA_URL = OLLAMA_URL[: -len("/v1")]

    if local_model_ready and backend != "openai_compatible":
        print("[KRATOS-LLM] Starting the local GGUF model server...", flush=True)
        print(f"[KRATOS-LLM] Host : {LLAMA_SERVER_HOST}:{LLAMA_SERVER_PORT}", flush=True)
        print(f"[KRATOS-LLM] Model: {MODEL_PATH}", flush=True)
        print(f"[KRATOS-LLM] Keep this terminal open. Run 'kratos chat' in another terminal.", flush=True)
        print(f"[KRATOS-LLM] Press Ctrl+C to stop the server.", flush=True)
        print(flush=True)

        cmd = [
            sys.executable, "-m", "llama_cpp.server",
            "--model",     str(MODEL_PATH),
            "--host",      LLAMA_SERVER_HOST,
            "--port",      str(LLAMA_SERVER_PORT),
            "--n_ctx",     str(LLAMA_N_CTX),
            "--n_threads", str(LLAMA_N_THREADS),
            "--seed",      str(LLAMA_SEED),
            "--verbose",   "false",
        ]

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\n[KRATOS-LLM] Server stopped.", flush=True)
        return 0

    if backend == "openai_compatible" or (backend == "auto" and not local_model_ready):
        ollama_bin = shutil.which("ollama") or (OLLAMA_BIN if Path(OLLAMA_BIN).exists() else None)
        if ollama_bin is None:
            print("[KRATOS-LLM] Ollama is not installed or not on PATH.", flush=True)
            return 1

        try:
            import requests

            resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=1)
            if resp.status_code == 200:
                print(f"[KRATOS-LLM] Ollama already running at {OLLAMA_URL}", flush=True)
                # If user requested to attach, try to tail known log file(s)
                if attach:
                    logs_dir = Path.home() / ".local" / "ollama" / "logs"
                    possible = [
                        logs_dir / "kratos-ollama.out.log",
                        logs_dir / "kratos-ollama.err.log",
                    ]
                    existing = [p for p in possible if p.exists()]
                    if existing:
                        # Use tail -f if available, else fallback to blocking read
                        tail_bin = shutil.which("tail")
                        if tail_bin:
                            try:
                                subprocess.run([tail_bin, "-f"] + [str(p) for p in existing])
                                return 0
                            except KeyboardInterrupt:
                                return 0
                        else:
                            # Simple Python follow: stream file growth
                            try:
                                for p in existing:
                                    print(f"[KRATOS-LLM] Tailing log: {p}", flush=True)
                                files = [open(p, "r", errors="replace") for p in existing]
                                for f in files:
                                    f.seek(0, 2)
                                import time
                                while True:
                                    for f in files:
                                        line = f.readline()
                                        if line:
                                            print(line, end="", flush=True)
                                    time.sleep(0.25)
                            except KeyboardInterrupt:
                                return 0
                    else:
                        print("[KRATOS-LLM] No Ollama log files found to attach to.", flush=True)
                        print("Start Ollama in foreground with: KRATOS_OLLAMA_DETACH=0 kratos llm-serve", flush=True)
                        return 0
                return 0
        except Exception:
            pass

        print("[KRATOS-LLM] Starting LLM server (Ollama fallback)...", flush=True)
        print(f"[KRATOS-LLM] Ollama URL: {OLLAMA_URL}", flush=True)
        print(f"[KRATOS-LLM] Context length: {_ollama_env_ctx} (OLLAMA_CONTEXT_LENGTH)", flush=True)
        print("[KRATOS-LLM] Keep this terminal open. Run 'kratos chat' in another terminal.", flush=True)

        # By default we run Ollama in the foreground so the terminal remains
        # attached and users can Ctrl+C to stop it. If OLLAMA_DETACH is True
        # we start it as a detached background process and redirect logs.
        try:
            if OLLAMA_DETACH:
                log_out = None
                log_err = None
                if OLLAMA_QUIET:
                    logs_dir = Path.home() / ".local" / "ollama" / "logs"
                    try:
                        logs_dir.mkdir(parents=True, exist_ok=True)
                    except Exception:
                        pass
                    log_out = open(logs_dir / "kratos-ollama.out.log", "ab")
                    log_err = open(logs_dir / "kratos-ollama.err.log", "ab")

                detached_env = dict(**_os.environ)
                detached_env["OLLAMA_CONTEXT_LENGTH"] = _ollama_env_ctx
                proc = subprocess.Popen(
                    [ollama_bin, "serve"],
                    stdout=log_out if log_out is not None else None,
                    stderr=log_err if log_err is not None else None,
                    start_new_session=True,
                    env=detached_env,
                )

                # Wait for Ollama to report readiness via the /api/tags endpoint
                import time
                import requests

                deadline = time.time() + STARTUP_TIMEOUT_SECONDS
                started = False
                while time.time() < deadline:
                    try:
                        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=1)
                        if resp.status_code == 200:
                            print(f"[KRATOS-LLM] Ollama started at {OLLAMA_URL}", flush=True)
                            started = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.5)

                if not started:
                    print("[KRATOS-LLM] Timeout waiting for Ollama to start.", flush=True)

                return 0
            else:
                # Foreground mode: run Ollama directly so its logs appear here.
                # When OLLAMA_QUIET is enabled, reduce Ollama's own verbosity
                # by setting its debug env vars to a higher threshold.
                try:
                    env = dict(**_os.environ)
                    if OLLAMA_QUIET:
                        env["OLLAMA_DEBUG"] = env.get("OLLAMA_DEBUG", "ERROR")
                        env["OLLAMA_DEBUG_LOG_REQUESTS"] = env.get("OLLAMA_DEBUG_LOG_REQUESTS", "false")
                    env["OLLAMA_CONTEXT_LENGTH"] = _ollama_env_ctx

                    subprocess.run([ollama_bin, "serve"], env=env)
                except KeyboardInterrupt:
                    print("\n[KRATOS-LLM] Server stopped.", flush=True)
                return 0
        except KeyboardInterrupt:
            print("\n[KRATOS-LLM] Server stopped.", flush=True)
            return 0

    if not local_model_ready:
        print(f"[KRATOS-LLM] Model not found: {MODEL_PATH}", flush=True)
        print(f"[KRATOS-LLM] Set KRATOS_LLM_MODEL_PATH or download the model first.", flush=True)
        return 1


def cmd_chat(args: argparse.Namespace) -> int:
    """
    Explain the latest findings in plain language with the configured model.
    Loads (or prepares) the latest findings bundle; it needs findings from an
    earlier check, and says so plainly when there are none yet.
    """
    data_dir: Path = args.data_dir
    mode = getattr(args, "mode", "summary").lower()
    question = getattr(args, "question", None)
    since = getattr(args, "since", None)
    until = getattr(args, "until", None)

    # Locate latest bundle; auto-generate if missing or stale
    reports_dir = data_dir / "reports"
    bundle_path = latest_file(reports_dir, "bundle_*.txt")

    class _BundleArgs:
        def __init__(self, d, since_date=None, until_date=None):
            self.data_dir = d
            self.max_words = 1000
            self.since = since_date
            self.until = until_date

    def _regen_bundle() -> bool:
        ret = cmd_prepare_bundle(_BundleArgs(data_dir, since_date=since, until_date=until))
        return ret == 0

    # Check if findings are newer than the bundle (stale bundle guard)
    findings_path = latest_file(reports_dir, "findings_*.json")
    
    # Force regenerate if date-range filtering is requested (to ensure correct date range)
    force_regen = since or until
    
    if bundle_path and findings_path and not force_regen:
        bundle_mtime = bundle_path.stat().st_mtime
        findings_mtime = findings_path.stat().st_mtime
        if findings_mtime > bundle_mtime:
            print("[KRATOS] Findings are newer than bundle — regenerating bundle...", flush=True)
            if _regen_bundle():
                bundle_path = latest_file(reports_dir, "bundle_*.txt")
            else:
                print("[KRATOS] WARNING: Bundle regeneration failed — using stale bundle.", flush=True)
    elif force_regen and bundle_path:
        print("[KRATOS] Date-range filter requested — regenerating bundle for specified interval...", flush=True)
        if _regen_bundle():
            bundle_path = latest_file(reports_dir, "bundle_*.txt")
        else:
            print("[KRATOS] WARNING: Date-filtered bundle regeneration failed — using most recent bundle.", flush=True)

    if not bundle_path and not findings_path:
        print("[KRATOS] Nothing to explain yet: `kratos chat` talks about the findings from an earlier check, "
              "and there aren't any.\n"
              "         Run a check first -- `kratos run` (a fixed audit) or `kratos investigate \"<what to look "
              "for>\"` -- or start `kratos` and ask in plain words.", file=sys.stderr, flush=True)
        return 1
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
                                    max_tokens=MAX_TOKENS_QUESTION, is_custom_question=True)
    else:
        response = analyze_findings(bundle_text=bundle_text, mode=mode)

    if response is None:
        print("[KRATOS-LLM] LLM unavailable — showing raw findings instead.", flush=True)
        print("\n" + "=" * 70, flush=True)
        print("  KRATOS RAW FINDINGS  (model unavailable — no AI interpretation)", flush=True)
        print("=" * 70, flush=True)
        print(bundle_text, flush=True)
        print("=" * 70, flush=True)
        print("[KRATOS] Tip: ensure model file exists and disk has 1 GB+ free.", flush=True)
        shutdown_llm()
        return 2  # 2 = partial success: findings shown, LLM unavailable

    print("\n" + "=" * 70, flush=True)
    print("KRATOS SECURITY ANALYSIS", flush=True)
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
            since=getattr(args, "since", None),
            until=getattr(args, "until", None),
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
    """Standard audit — a fixed, deterministic security sweep of the target.

    Runs on the deterministic engine (``agent/pipeline.py``, see
    docs/DESIGN.md's "Presets and pipelines" section), not a standalone
    hardcoded pipeline — an earlier version bypassed the tool registry
    entirely (no approval-gating, no target resolution) and could mix
    Kratos-host-local auth-log/context analysis into what was reported as
    the target's findings. The engine is target-correct by construction and
    runs over ``TOOL_REGISTRY`` via ``execute_tool_call``, inheriting every
    guard. Same recipe shape (scan → config → auth → correlate).
    """
    from kratos.agent.pipeline import run_pipeline, standard_audit_steps
    from kratos.kratos_config import get_active_target, set_active_target

    prior_active = None
    if args.target:
        prior_active = get_active_target()
        set_active_target(args.target)

    target = get_active_target()
    if not target:
        from kratos.kratos_config import NO_TARGET_MESSAGE

        print(f"[KRATOS] {NO_TARGET_MESSAGE} For this command you can also pass --target <host>.")
        return 1
    print(f"[KRATOS] Standard audit — deterministic security sweep of {target} (no LLM).")
    try:
        outcome = run_pipeline(standard_audit_steps(), args.data_dir)
    finally:
        if prior_active is not None:
            set_active_target(prior_active)

    for s in outcome.steps:
        if s.status == "ok":
            print(f"[KRATOS]   ✓ {s.tool} — {s.label}")
        elif s.status == "skipped":
            print(f"[KRATOS]   – {s.tool} — skipped ({s.detail or 'condition not met'})")
        elif s.status == "not_approved":
            print(f"[KRATOS]   – {s.tool} — not approved; skipped")
        else:
            print(f"[KRATOS]   ✗ {s.tool} FAILED — {s.detail or 'no detail'}")

    tally = outcome.severity_tally
    if outcome.findings:
        summary = "  ".join(f"{tally[k]} {k}" for k in
                            ("critical", "high", "medium", "low", "info") if tally.get(k))
        print(f"[KRATOS] Findings: {summary}")
        # Surface the report files the correlation step wrote, for traceability.
        for s in outcome.steps:
            if s.tool == "correlate_findings" and s.result:
                if s.result.get("findings_json_file"):
                    print(f"[KRATOS] Findings JSON -> {s.result['findings_json_file']}")
                if s.result.get("findings_md_file"):
                    print(f"[KRATOS] Findings MD   -> {s.result['findings_md_file']}")
    else:
        print("[KRATOS] No findings raised by the correlation engine.")
    if outcome.lifecycle_line:
        print(f"[KRATOS] {outcome.lifecycle_line}  (kratos findings list)")

    if outcome.status != "completed":
        print(f"[KRATOS] ERROR: audit aborted — required step '{outcome.aborted_on}' did not succeed.")
        return 1
    return 0


def cmd_scheduled_run(args: argparse.Namespace) -> int:
    """A6.3 -- run ONE schedule headlessly (what a systemd user timer invokes).

    UI-free: runs the schedule's unit of work with approval-gated tools excluded
    by construction, persists a findings report, and delivers a notification.
    Never hangs on an approval prompt (there's no human here)."""
    from kratos.agent import schedules as _sched
    from kratos.agent.scheduled_run import run_scheduled

    try:
        schedule = _sched.load_schedule(args.data_dir, args.name)
    except _sched.ScheduleError as e:
        print(f"[KRATOS] {e}")
        return 1
    if schedule is None:
        print(f"[KRATOS] No schedule named '{args.name}'. See: kratos → /schedule list")
        return 1

    print(f"[KRATOS] Scheduled run '{schedule.name}' ({schedule.kind}) → target "
          f"{schedule.target or 'active'} …")
    record = run_scheduled(schedule, args.data_dir, deliver=not args.no_deliver)

    print(f"[KRATOS]   status: {record['status']}")
    for j in (record.get("jobs") or []):  # A6.5: per-job breakdown for a group
        print(f"[KRATOS]     job {j.get('label')}: {j.get('status')}"
              + (f" — {j['error']}" if j.get("error") else ""))
    if record.get("omitted_gated_tools"):
        print(f"[KRATOS]   omitted (approval-gated, unattended): "
              f"{', '.join(record['omitted_gated_tools'])}")
    tally = record.get("severity_tally") or {}
    if tally:
        order = ("critical", "high", "medium", "low", "info")
        print("[KRATOS]   findings: " + "  ".join(f"{tally[k]} {k}" for k in order if tally.get(k)))
    if record.get("report_md"):
        print(f"[KRATOS]   report: {record['report_md']}")
    if record.get("notified"):
        d = record.get("delivered") or {}
        print(f"[KRATOS]   notify: {d.get('status', 'sent')}")
        if d.get("status") != "sent" and d.get("observation"):
            print(f"[KRATOS]     {d['observation']}")
    if record.get("error"):
        print(f"[KRATOS]   note: {record['error']}")
    # Exit 0 for a run that completed (clean or with findings); 1 for a failure
    # so a systemd unit / cron wrapper can detect a genuinely failed run.
    return 0 if record["status"] in ("completed", "final_answer", "max_iters_reached") else 1


# ============================================================================
# PHASE 2 - Network Anomaly Detection (Tier 2 Aggregator)
# ============================================================================

def cmd_network_capture(args: argparse.Namespace) -> int:
    """Capture network traffic passively."""
    try:
        duration = getattr(args, "duration", 60)
        interface = getattr(args, "interface", "any")
        
        out_file = capture_traffic(
            duration_seconds=duration,
            interface=interface,
        )
        
        if out_file:
            print(f"[KRATOS] Network capture saved -> {out_file}")
            return 0
        else:
            print("[KRATOS] ERROR: Network capture failed (tcpdump not available?)")
            return 1
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1


def cmd_network_anomalies(args: argparse.Namespace) -> int:
    """Correlate Nmap + tcpdump to find anomalies."""
    try:
        out_file, report = build_anomaly_report(
            data_dir=args.data_dir,
        )
        
        if out_file:
            print(f"[KRATOS] Anomaly report saved -> {out_file}")
            return 0
        else:
            print("[KRATOS] ERROR: Anomaly report failed")
            return 1
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1


# ============================================================================
# PHASE 3 - Reporting & Persistence
# ============================================================================

def cmd_daily_report(args: argparse.Namespace) -> int:
    """Generate a daily security briefing."""
    try:
        db_path = args.data_dir / "kratos.db"
        store = AnomalyStore(db_path)
        
        report_path = generate_daily_report(args.data_dir, store)
        print(f"[KRATOS] Daily report generated -> {report_path}")
        return 0
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1


def cmd_weekly_report(args: argparse.Namespace) -> int:
    """Generate a comprehensive weekly report."""
    try:
        db_path = args.data_dir / "kratos.db"
        store = AnomalyStore(db_path)
        
        report_path = generate_weekly_report(args.data_dir, store)
        print(f"[KRATOS] Weekly report generated -> {report_path}")
        return 0
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1


def cmd_store_anomalies(args: argparse.Namespace) -> int:
    """Store anomalies in time-series database."""
    try:
        from kratos.utils.latest_file import latest_file
        
        db_path = args.data_dir / "kratos.db"
        store = AnomalyStore(db_path)
        
        # Find latest anomaly report
        anomaly_file = latest_file(args.data_dir / "reports", "network_anomalies_*.json")
        if not anomaly_file:
            print("[KRATOS] No anomaly report found. Run: kratos network-anomalies first")
            return 1
        
        report = json.loads(anomaly_file.read_text(encoding="utf-8", errors="replace"))
        anomalies = report.get("anomalies", [])
        
        count = store.store_anomalies(anomalies)
        store.update_daily_summary()
        
        print(f"[KRATOS] Stored {count} anomalies in database -> {db_path}")
        return 0
    except Exception as e:
        print(f"[KRATOS] ERROR: {e}")
        return 1


# ============================================================================
# PHASE 4 - ReAct Agent (experimental, additive -- does not replace `kratos run`)
# ============================================================================

def cmd_investigate(args: argparse.Namespace) -> int:
    """
    ReAct-style investigation: the LLM picks which Kratos tool to call next
    (see agent/loop.py, agent/tools.py) instead of running the fixed
    scan -> logs -> context -> findings pipeline that `kratos run` uses.
    Reuses the exact same adapters as the other subcommands, unmodified.

    Output rendering only, via agent/console.py -- run_agent()'s own
    decisions, transcript shape, and on_step() callback timing are
    unchanged (see console.py's module docstring for why no live per-tool
    spinner is possible without touching agent/loop.py's dispatch timing).
    """
    goal = args.goal
    max_iters = args.max_iters if args.max_iters is not None else DEFAULT_MAX_ITERS

    console = _console.get_console()
    if not get_active_target():
        # Stop before any (possibly billed) model call: every tool would fail.
        from kratos.kratos_config import NO_TARGET_MESSAGE

        _console.render_error(console, NO_TARGET_MESSAGE)
        return 1
    backend_label = LLM_OPENAI_MODEL
    _console.render_session_header(console, goal=goal, max_iters=max_iters,
                                   ssh_target=get_active_target(), backend=backend_label)

    session_events: list[str] = []
    findings_count = 0
    live = _console.thinking_spinner(console)

    def _print_step(step: dict) -> None:
        nonlocal findings_count
        live.stop()
        iteration = step.get("iteration")

        if step.get("status") == "llm_unavailable":
            _console.render_error(console, f"Step {iteration}: could not reach the language model backend -- stopping.")
            session_events.append(f"Step {iteration}: LLM unavailable, investigation aborted")
            return

        if step.get("status") == "parse_error":
            _console.render_note(console, f"Step {iteration}: the model's response wasn't understood -- asking it to try again.")
            return

        if step.get("status") == "stopped_by_budget":
            session_events.append(f"Step {iteration}: stopped by a spending limit")
            return  # the result panel below says which limit and what was collected

        if step.get("status") == "final_iteration_tool_call_ignored":
            _console.render_note(
                console,
                f"Step {iteration}: ran out of steps while the model was still trying to use "
                f"'{step.get('attempted_tool')}' -- wrapping up with a best-effort answer instead.",
            )
            return

        if step.get("status") == "final_answer_rejected":
            # One or more structural guards violated at once (correlate_findings
            # missing / file-integrity contradiction / dismissive-verdict
            # contradiction) -- agent/loop.py now combines all co-firing guards
            # into a single rejection + retry rather than one per guard.
            violation_labels = {
                "missing_correlation": "did not run the correlation engine before concluding",
                "file_integrity_contradiction": "contradicted the file-integrity check's actual result",
                "dismissive_verdict_contradiction": "dismissive verdict contradicted a real high-severity finding",
            }
            violations = step.get("violations", [])
            reasons = [violation_labels.get(v, v) for v in violations]
            body = (
                "Kratos's own draft answer needed a second look before it could be trusted:\n"
                + "\n".join(f"  - {r}" for r in reasons)
                + f"\n\nReasoning given: {step.get('reasoning', '')}"
                + f"\nAttempted answer: {step.get('attempted_final_answer', '')}"
            )
            _console.render_result_panel(console, f"Step {iteration}: answer sent back for reconsideration", body, "yellow")
            session_events.append(f"Step {iteration}: draft answer rejected ({'; '.join(reasons)})")
            return

        if "final_answer" in step:
            console.print(f"[green]✓[/green] Step {iteration}: concluding -- {step.get('reasoning', '')}")
            return

        tool_name = step.get("tool")
        observation = step.get("observation")
        tool_result, effective_status = _console.unwrap_tool_result(observation)

        if effective_status == "error":
            error_text = tool_result.get("observation") if isinstance(tool_result, dict) else None
            _console.render_error(console, f"{tool_name} failed -- {error_text or 'no error detail available'}")
            session_events.append(f"Step {iteration}: {tool_name} failed")
        elif tool_name == "correlate_findings" and isinstance(tool_result, dict):
            findings = tool_result.get("findings") or []
            if findings:
                console.print(f"[green]✓[/green] [bold]{tool_name}[/bold] -- {_console.plain_label(tool_name)} ({len(findings)} found)")
                for finding in findings:
                    _console.render_finding(console, finding)
                    findings_count += 1
                    session_events.append(f"Finding {finding.get('id', '?')} ({finding.get('severity', '?')}): {finding.get('title', '')}")
            else:
                _console.render_tool_call(console, tool_name, effective_status)
                session_events.append(f"Step {iteration}: used {tool_name}")
            _console.render_tool_metadata_notes(console, tool_result)
        else:
            _console.render_tool_call(console, tool_name, effective_status)
            session_events.append(f"Step {iteration}: used {tool_name}")
        _console.render_window_note(console, tool_result)
        _console.render_transport_note(console, tool_result)

    started_at = time.monotonic()
    try:
        result = run_agent(goal, args.data_dir, max_iters=max_iters, on_step=_print_step)
    finally:
        live.stop()
    duration = time.monotonic() - started_at

    console.print()
    lifecycle = _console.lifecycle_line(result.get("transcript"))
    if result["status"] == "final_answer":
        _console.render_result_panel(console, "Investigation complete", result["final_answer"], "green")
        if lifecycle:
            console.print(f"{lifecycle}  (kratos findings list)")
        console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
        session_events.append("Investigation concluded with a final answer")
        _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
        return 0

    if result["status"] == "llm_unavailable":
        _console.render_error(console, "Language model backend unavailable. Check `kratos llm-serve` / your model config.")
        return 2

    if result["status"] == "max_iters_reached" and result.get("final_answer"):
        _console.render_result_panel(
            console,
            "Investigation incomplete (step limit reached)",
            "The agent did not reach its own conclusion in time. Best-effort summary:\n\n" + result["final_answer"],
            "yellow",
        )
        if lifecycle:
            console.print(f"{lifecycle}  (kratos findings list)")
        console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
        session_events.append("Investigation stopped: step limit reached (best-effort answer shown)")
        _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
        return 1

    if result["status"] == "stopped_by_budget":
        _console.render_result_panel(console, "Stopped by budget", result["final_answer"], "yellow")
        if lifecycle:
            console.print(f"{lifecycle}  (kratos findings list)")
        console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
        _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
        return 3

    _console.render_error(console, f"Investigation stopped: {result['status']} (no final answer reached).")
    console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
    _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROJECT_NAME,
        description="Kratos — a self-hostable, self-growing security assistant",
    )
    p.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory for storing sessions/scans/logs/reports (default: {DEFAULT_DATA_DIR})",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored/styled output (also honors the NO_COLOR env var). Affects "
        "`kratos investigate` and its approval prompts only -- other subcommands' output is "
        "unstyled plain text already.",
    )

    sub = p.add_subparsers(dest="command", required=True)

    runp = sub.add_parser(
        "run",
        help="Standard audit — a fixed, deterministic security sweep of the target",
    )
    runp.add_argument(
        "--target",
        default=None,
        help="Target to audit (default: the configured active target, same as `investigate`)",
    )
    runp.set_defaults(func=cmd_run)

    schedrun = sub.add_parser(
        "scheduled-run",
        help="Run ONE saved schedule headlessly (invoked by a systemd user timer)",
    )
    schedrun.add_argument("name", help="Name of the saved schedule to run")
    schedrun.add_argument(
        "--no-deliver", action="store_true",
        help="Run + write the report but skip the notification (for testing)",
    )
    schedrun.set_defaults(func=cmd_scheduled_run)

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
    trends.add_argument("--since", type=str, default=None, help="Start date in YYYYMMDD format (e.g., 20260201)")
    trends.add_argument("--until", type=str, default=None, help="End date in YYYYMMDD format (e.g., 20260228)")
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

    bundle = sub.add_parser("prepare-bundle", help="Create a clean, short text bundle for LLM input")
    bundle.add_argument("--max-words", type=int, default=500, help="Max words in the bundle (default: 500)")
    bundle.add_argument("--since", type=str, default=None, help="Start date in YYYYMMDD format (e.g., 20260201)")
    bundle.add_argument("--until", type=str, default=None, help="End date in YYYYMMDD format (e.g., 20260228)")
    bundle.set_defaults(func=cmd_prepare_bundle)

    analyze = sub.add_parser("analyze", help="Same as findings-generate (older name)")
    analyze.set_defaults(func=cmd_analyze)


    chat = sub.add_parser("chat", help="Explain the latest findings (from an earlier check) in plain words")
    chat.add_argument(
        "--mode",
        choices=["summary", "deep"],
        default="summary",
        help="summary = executive overview, deep = attack chains + blind spots (default: summary)",
    )
    chat.add_argument("--question", "-q", default=None, help="Ask a specific question about the findings")
    chat.add_argument("--since", type=str, default=None, help="Start date in YYYYMMDD format (e.g., 20260201)")
    chat.add_argument("--until", type=str, default=None, help="End date in YYYYMMDD format (e.g., 20260228)")
    chat.set_defaults(func=cmd_chat)

    # ====== PHASE 2: Network Anomaly Detection ======
    net_capture = sub.add_parser("network-capture", help="Passively capture network traffic (requires tcpdump)")
    net_capture.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60)")
    net_capture.add_argument("--interface", default="any", help="Network interface to capture on (default: any)")
    net_capture.set_defaults(func=cmd_network_capture)

    net_anomalies = sub.add_parser("network-anomalies", help="Correlate Nmap + tcpdump → detect anomalies")
    net_anomalies.set_defaults(func=cmd_network_anomalies)

    # ====== PHASE 3: Reporting & Persistence ======
    store_anom = sub.add_parser("store-anomalies", help="Save anomalies to time-series database")
    store_anom.set_defaults(func=cmd_store_anomalies)

    daily_rep = sub.add_parser("daily-report", help="Generate daily security briefing (HTML)")
    daily_rep.set_defaults(func=cmd_daily_report)

    weekly_rep = sub.add_parser("weekly-report", help="Generate weekly security report (HTML)")
    weekly_rep.set_defaults(func=cmd_weekly_report)

    llm_serve = sub.add_parser(
        "llm-serve",
        help="Start the LLM server (loads model once — run in a separate terminal for fast kratos chat)"
    )
    llm_serve.add_argument(
        "--attach",
        action="store_true",
        help="If Ollama is already running, attach and tail its logs instead of returning immediately",
    )
    llm_serve.set_defaults(func=cmd_llm_serve)

    mcp_serve = sub.add_parser(
        "mcp-serve",
        help="Start the Kratos MCP server (stdio) -- exposes investigate/get_findings/list_sessions to an MCP client",
    )
    mcp_serve.set_defaults(func=cmd_mcp_serve)

    init_p = sub.add_parser(
        "init",
        help="Create your settings file if missing; show where Kratos keeps its data",
    )
    init_p.set_defaults(func=cmd_init)

    vulscan_p = sub.add_parser(
        "vulscan-install",
        help="Install or refresh the CVE list the vulnerability scan matches services against (built from NVD)",
    )
    vulscan_p.add_argument("--force", action="store_true", help="Rebuild everything even if it's current")
    vulscan_p.set_defaults(func=cmd_vulscan_install)

    # ====== Sub-agent telemetry (capability 1 only -- docs/subagent_architecture.md) ======
    subagent_pair = sub.add_parser(
        "subagent-pair",
        help="Generate a one-time pairing code for a new sub-agent (read-only telemetry)",
    )
    subagent_pair.add_argument("--name", default=None, help="Optional human-readable label for this target")
    subagent_pair.add_argument("--core-host", required=True, help="This core's address, as the target will reach it")
    subagent_pair.add_argument("--core-port", type=int, default=8765)
    subagent_pair.set_defaults(func=cmd_subagent_pair)

    subagent_serve = sub.add_parser(
        "subagent-serve",
        help="Run the core-side sub-agent telemetry listener (accepts paired agents' read-only telemetry)",
    )
    subagent_serve.add_argument("--host", default="0.0.0.0",
                                help="Address(es) to listen on, comma-separated (default: all interfaces)")
    subagent_serve.add_argument("--port", type=int, default=8765)
    subagent_serve.set_defaults(func=cmd_subagent_serve)

    subagent_install = sub.add_parser(
        "subagent-install",
        help="Emit a one-command installer script to onboard a target (capability 1)",
    )
    subagent_install.add_argument("--core-host", required=True, help="This core's address, as the target will reach it")
    subagent_install.add_argument("--core-port", type=int, default=8765)
    subagent_install.add_argument("--name", default=None, help="Optional human-readable label for this target")
    subagent_install.add_argument("--code", default=None, help="Reuse an existing pairing code instead of creating one")
    subagent_install.add_argument("-o", "--output", default=None, help="Write the script to a file instead of stdout")
    subagent_install.add_argument(
        "--trusted-interface", dest="trusted_interfaces", action="append", default=[], metavar="NAME",
        help="An interface on the target that encrypts by itself (e.g. your WireGuard wg0); Tailscale needs none",
    )
    subagent_install.set_defaults(func=cmd_subagent_install)

    subagent_status = sub.add_parser(
        "subagent-status",
        help="List paired sub-agent targets, their liveness status, and latest telemetry",
    )
    subagent_status.set_defaults(func=cmd_subagent_status)

    snapshots_p = sub.add_parser(
        "snapshots",
        help="Saved scans/snapshots by capture time: index, list the history horizon, or prune (preview unless --apply)",
    )
    snapshots_p.add_argument("action", choices=("index", "list", "prune"))
    snapshots_p.add_argument("--apply", action="store_true", help="prune: actually delete (default is a preview)")
    snapshots_p.set_defaults(func=cmd_snapshots)

    events_p = sub.add_parser(
        "events",
        help="Show the log lines Kratos has read from a machine (stored on this computer); read-only",
    )
    events_p.add_argument("--target", default=None, help="Machine (default: the active target)")
    events_p.add_argument("--since", default=None, help="e.g. '1 hour ago', 'today', '2026-10-09 13:00'")
    events_p.add_argument("--until", default=None, help="End of the period (default: now)")
    events_p.add_argument("--ip", default=None, help="Only events from this source IP")
    events_p.add_argument("--user", default=None, help="Only events by this user")
    events_p.add_argument("--process", default=None, help="Only events from this program, e.g. sshd")
    events_p.add_argument("--action", default=None, help="e.g. ssh_failed_login, sudo_command")
    events_p.add_argument("--dataset", default=None,
                          choices=("kratos.auth", "kratos.journal", "kratos.privileged_accounts", "kratos.auditd",
                                   "kratos.cron", "kratos.systemd", "kratos.firewall", "kratos.package", "kratos.web"))
    events_p.add_argument("--limit", type=int, default=50, help="How many (newest first; max 10000)")
    events_p.add_argument("--oldest-first", action="store_true", help="Oldest first instead")
    events_p.add_argument("--json", action="store_true", help="One ECS JSON document per line")
    events_p.set_defaults(func=cmd_events)

    fnd = sub.add_parser(
        "findings",
        help="Findings Kratos remembers across runs: list, show history, verify, accept a risk, "
             "mark false positive / out of scope, reopen",
    )
    fsub = fnd.add_subparsers(dest="findings_action", required=True)
    f_list = fsub.add_parser("list", help="List findings (default: open and verified, active machine)")
    f_list.add_argument("--target", default=None, help="Machine (default: the active target; 'all' for every machine)")
    f_list.add_argument("--state", default="open_verified",
                        choices=("open_verified", "open", "verified", "mitigated", "inactive", "decided",
                                 "risk_accepted", "false_positive", "out_of_scope", "all"))
    f_list.add_argument("--json", action="store_true")
    f_show = fsub.add_parser("show", help="One finding: details and its history")
    f_show.add_argument("key", help="Finding key (the 12 characters shown are enough)")
    f_show.add_argument("--json", action="store_true")
    scopes = ("key", "rule-target", "rule")
    scope_help = "key: this finding (default); rule-target: this rule on this machine; rule: this rule everywhere"
    for name, help_text in (("verify", "Confirm a finding is real (it stays shown)"),
                            ("reopen", "Undo a decision: show the finding again")):
        f_act = fsub.add_parser(name, help=help_text)
        f_act.add_argument("key")
        f_act.add_argument("--reason", required=True)
    f_acc = fsub.add_parser("accept", help="Accept the risk until a date (it comes back after)")
    f_acc.add_argument("key")
    f_acc.add_argument("--reason", required=True)
    f_acc.add_argument("--days", type=float, default=None, help="How many days (at most findings.accept_max_days)")
    f_acc.add_argument("--until", default=None, help="Until a date: 2026-12-31 or '2026-12-31 18:00'")
    f_acc.add_argument("--owner", default=None, help="Who owns this risk (default: you)")
    f_acc.add_argument("--scope", default="key", choices=scopes, help=scope_help)
    for name, help_text in (("fp", "Not a real problem (false positive)"),
                            ("out-of-scope", "Not relevant for this machine (out of scope)")):
        f_dec = fsub.add_parser(name, help=help_text)
        f_dec.add_argument("key")
        f_dec.add_argument("--reason", required=True)
        f_dec.add_argument("--scope", default="key", choices=scopes, help=scope_help)
        f_dec.add_argument("--days", type=float, default=None, help="Optional: for this many days")
        f_dec.add_argument("--until", default=None, help="Optional: until this date")
    fsub.add_parser("import-reports", help="Import findings from report files written before this version (safe to repeat)")
    fnd.set_defaults(func=cmd_findings)

    bud = sub.add_parser(
        "budget",
        help="Model spending limits: show today's spend against them, change one, or resume a paused source",
    )
    bsub = bud.add_subparsers(dest="budget_action")
    b_show = bsub.add_parser("show", help="Today's spend, every limit and any paused source (the default)")
    b_show.add_argument("--json", action="store_true")
    b_set = bsub.add_parser("set", help="Change one limit, e.g. `kratos budget set daily_cost_usd 5`")
    b_set.add_argument("key", help="The limit's name, with or without 'budget.'")
    b_set.add_argument("value", help="The new value (0 = none allowed; on/off for yes/no settings)")
    b_res = bsub.add_parser("resume", help="End a pause after repeated failures (e.g. schedule:nightly)")
    b_res.add_argument("source", help="The paused source, as `kratos budget` lists it")
    bud.set_defaults(func=cmd_budget)

    seal_p = sub.add_parser(
        "seal",
        help="Journal sealing (forward secure sealing): keep a machine's verification key here and check its "
             "journal hasn't been edited",
    )
    ssub = seal_p.add_subparsers(dest="seal_action", required=True)
    s_set = ssub.add_parser("set-key", help="Save a machine's verification key (read from stdin, never the command line)")
    s_set.add_argument("target", help="The machine (as in /target)")
    ssub.add_parser("status", help="Machines with a key on file and their last check")
    s_ver = ssub.add_parser("verify", help="Copy the machine's sealed journal files here and verify them now")
    s_ver.add_argument("target")
    s_ver.add_argument("--json", action="store_true")
    s_rm = ssub.add_parser("remove-key", help="Forget a machine's verification key")
    s_rm.add_argument("target")
    seal_p.set_defaults(func=cmd_seal)

    # ====== PHASE 4: ReAct Agent (experimental, additive) ======
    investigate = sub.add_parser(
        "investigate",
        help="Investigate a question in plain words: the model picks Kratos's read-only checks one at a time "
             "and explains what it found (for a fixed, repeatable sweep use `kratos run`)",
    )
    investigate.add_argument("goal", help="Natural-language investigation goal, e.g. 'check for suspicious activity on this system'")
    investigate.add_argument(
        "--max-iters",
        type=int,
        default=None,
        help=f"Max agent iterations before stopping (default: {DEFAULT_MAX_ITERS})",
    )
    investigate.set_defaults(func=cmd_investigate)

    return p


def _subcommand_help_text(parser: argparse.ArgumentParser) -> dict[str, str]:
    """Best-effort: name -> its `help=...` string, as passed to add_parser().
    Reaches into argparse's own (undocumented but long-stable) internals
    rather than re-typing every subcommand's help text a second time here,
    which would drift. Falls back to an empty description per command if
    argparse's internals ever change shape -- never raises."""
    out: dict[str, str] = {}
    try:
        for action in parser._subparsers._group_actions:
            if isinstance(action, argparse._SubParsersAction):
                for pseudo in action._choices_actions:
                    out[pseudo.dest] = pseudo.help or ""
    except AttributeError:
        pass
    return out


# `kratos --help` needs to fit an 80x24 terminal without scrolling. Listing
# all ~23 real subcommands in one table can't fit that regardless of
# styling (the full-list render measures at 41 lines). Resolution -- shrink
# the DEFAULT view to the commands a new, non-technical user would actually
# reach for first (not a complete reference crammed onto one screen); the
# full list stays one flag away. Deliberately NOT the CLI-wide Rich
# migration for the other subcommands' own runtime output -- see
# docs/DESIGN.md's "Known limitations" section for why that's a separate,
# much larger, deliberately deferred item.
PRIMARY_COMMANDS = ["init", "investigate", "run", "chat", "findings-show", "scan"]
# Short, plain descriptions for that default view -- written to fit, never cut.
PRIMARY_HELP = {
    "init": "Create your settings file; show where data lives",
    "investigate": "Ask in plain words; Kratos picks its own checks",
    "run": "Run the fixed standard audit (no model involved)",
    "chat": "Explain the latest findings in plain words",
    "findings-show": "Show the latest findings",
    "scan": "Scan the target's open ports with nmap",
}


def _render_top_level_help(parser: argparse.ArgumentParser, show_all: bool = False) -> None:
    """Rich-formatted top-level --help only -- every other subcommand's own
    `--help` output is untouched argparse default formatting; the styled
    layer is scoped to `investigate` + the shared approval gate (see
    docs/DESIGN.md's "Known limitations" section)."""
    console = _console.get_console()
    console.print(
        Panel(
            "Kratos looks over a machine you point it at -- logs, ports, processes, changed files -- "
            "and explains what it finds in plain language, with the model you configure (hosted, or "
            "self-hosted to keep data on your hardware).\n\n"
            "Example:\n  kratos investigate \"check for suspicious SSH activity\"",
            title="kratos -- security assistant",
            border_style="cyan",
        )
    )
    all_help = _subcommand_help_text(parser)
    shown = all_help if show_all else {k: v for k, v in all_help.items() if k in PRIMARY_COMMANDS}
    table = Table(show_header=True, header_style="bold")
    table.add_column("Command", no_wrap=True)
    table.add_column("Description", overflow="fold")
    if not show_all:
        table.add_row("kratos", "Open the full-screen app -- start here")
        for name in PRIMARY_COMMANDS:
            if name in shown:
                table.add_row(f"kratos {name}", PRIMARY_HELP.get(name) or shown[name])
    else:
        for name, help_text in shown.items():
            table.add_row(name, help_text)  # full text, wrapped -- never cut off
    console.print(table)
    if not show_all:
        hidden_count = len(all_help) - len(shown)
        console.print(f"{hidden_count} more: `kratos --help --all`.  Options: `kratos <command> --help`.")
    else:
        console.print("One command's options: `kratos <command> --help`.")
    console.print("Global options: --data-dir PATH  --no-color  --resume SESSION  --continue/-c")


def _render_investigate_help(investigate_parser: argparse.ArgumentParser) -> None:
    console = _console.get_console()
    console.print(
        Panel(
            "Ask Kratos to investigate a goal in plain language -- it picks which of its "
            "own tools to run, step by step, and asks for your approval before anything "
            "that runs a command or escalates privilege.\n\n"
            'Example:\n  kratos investigate "check for suspicious SSH activity"',
            title="kratos investigate",
            border_style="cyan",
        )
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Argument")
    table.add_column("Description")
    table.add_row("goal", "Natural-language investigation goal (required)")
    table.add_row("--max-iters N", f"Max agent steps before stopping (default: {DEFAULT_MAX_ITERS})")
    table.add_row("--data-dir PATH", f"Directory for storing sessions/scans/logs/reports (default: {DEFAULT_DATA_DIR})")
    table.add_row("--no-color", "Disable colored/styled output")
    console.print(table)
    console.print()


_SELF_SCOPED_COMMANDS = frozenset({"scheduled-run", "mcp-serve", "subagent-serve", "llm-serve"})


def _unknown_command(word: str, commands: list[str]) -> int:
    import difflib

    close = difflib.get_close_matches(word, commands, n=1, cutoff=0.75)
    hint = f" Did you mean `kratos {close[0]}`?" if close else ""
    print(f"kratos: '{word}' isn't a command or option.{hint}\n"
          "`kratos --help` lists the commands; `kratos` on its own opens the app, where commands like "
          "/doctor and /findings are typed.", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    no_color = "--no-color" in argv or bool(os.environ.get("NO_COLOR"))
    _console.configure(no_color)

    parser = build_parser()

    # `kratos` with NO SUBCOMMAND (regardless of whether --data-dir/
    # --no-color are also given) launches the REPL instead of falling
    # through to argparse's own required=True error on the `command`
    # subparser. `kratos --data-dir /foo` (no subcommand, but WITH a global
    # flag) hits the exact same "the following arguments are required:
    # command" error as truly-bare `kratos` -- so the trigger has to be "no
    # known subcommand token present", not "argv is literally empty", or
    # `--data-dir`/`--no-color` alongside a bare invocation would still
    # incorrectly error instead of launching the session. Also note:
    # help_requested (any(a in ("-h","--help") for a in argv)) is always
    # False when argv is empty, so a "len(argv) == 0" check nested inside
    # the help_requested branch below would be dead code, never reachable
    # for a genuinely bare invocation.
    subcommand_names = set(_subcommand_help_text(parser).keys())
    has_subcommand = any(a in subcommand_names for a in argv)
    if not has_subcommand and not any(a in ("-h", "--help") for a in argv):
        global_only_parser = argparse.ArgumentParser(add_help=False)
        global_only_parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
        global_only_parser.add_argument("--no-color", action="store_true")
        # `kratos --resume <id>`: threaded into run_session() (cli/repl.py)
        # as a one-time "resolve this session by ID and skip straight to
        # its [l]/[f] resume-tier prompt" instruction, reusing the exact
        # same resolution path the chooser's own "type a session ID
        # directly" support uses. An unrecognized flag here would silently
        # fall through to parse_known_args's unrecognized-extras discard
        # and land on the normal bare chooser with no indication the flag
        # did nothing, so this needs to stay a genuinely registered
        # argument, not something callers can typo past silently.
        global_only_parser.add_argument("--resume", dest="resume_session_id", default=None)
        # --continue/-c: jump straight to the most recently active
        # session's [l]/[f] resume-tier prompt, no chooser table -- same
        # "skip the table, still ask the tier" behavior as --resume, for
        # the common case where you don't need to name a specific session
        # at all. See cli/repl.py::_resolve_continue_most_recent.
        global_only_parser.add_argument(
            "--continue", "-c", dest="continue_most_recent", action="store_true"
        )
        global_args, unknown = global_only_parser.parse_known_args(argv)
        if unknown:
            # A word or flag Kratos doesn't know used to be dropped here, opening the
            # app as if nothing was wrong (`kratos doctor`, a typo'd `kratos investgate`).
            return _unknown_command(unknown[0], sorted(subcommand_names))
        # Bare `kratos` launches the full-screen TUI -- the primary interface.
        # The classic prompt_toolkit REPL (cli/repl.py) is retired as the default
        # face (kept in the tree, just no longer the bare-command entry); every
        # subcommand (investigate / run / mcp-serve / llm-serve / ...) is
        # unaffected and still dispatches below. The TUI loads kept tools itself,
        # so there is no load_kept_tools() here. --resume/--continue are handled
        # by the TUI's own session picker rather than by these flags.
        from kratos.tui_mk2.app import main as tui_main
        tui_argv = ["--data-dir", str(global_args.data_dir)]
        if getattr(global_args, "no_color", False):
            tui_argv.append("--no-color")
        return tui_main(tui_argv)

    # Intercept the two --help forms the styled renderer covers (bare
    # top-level, and `investigate --help`) before argparse's own -h/--help
    # handling would print+exit -- every other subcommand's --help falls
    # through to parser.parse_args() below unchanged.
    help_requested = any(a in ("-h", "--help") for a in argv)
    if help_requested and (len(argv) == 0 or argv[0] in ("-h", "--help")):
        _render_top_level_help(parser, show_all="--all" in argv)
        return 0
    if help_requested and "investigate" in argv:
        investigate_parser = parser._subparsers._group_actions[0].choices["investigate"]
        _render_investigate_help(investigate_parser)
        return 0

    args = parser.parse_args(argv)

    _paths.ensure_private_dir(_paths.STATE_ROOT)  # kept tools, staging, vulscan live here too
    _paths.ensure_private_dir(args.data_dir)

    # No built-in default target: use KRATOS_SSH_HOST, else the target saved
    # at first run, for every subcommand (investigate, run, a systemd-scheduled
    # run...). The TUI's boot flow does the same for interactive use.
    from kratos import kratos_config as _kc

    _kc.seed_active_target_from_config(args.data_dir)
    _kc.set_active_data_dir(args.data_dir)
    from kratos.budget import guard as _budget_guard

    _budget_guard.migrate_at_startup(args.data_dir)  # 0.4 upgrade: keep existing investigate triggers working

    # Re-register any previously-APPROVED self-written tools (Part D,
    # agent/self_write_loop.py) into TOOL_REGISTRY for this process, on top
    # of the built-in tools' own @register_tool decorators -- those already
    # ran as an import-time side effect of the `from kratos.agent.loop
    # import run_agent, ...` above, before main() ever runs, so this always
    # layers kept tools on top of the built-ins, never before/instead of
    # them. One call site, shared by every subcommand (kratos investigate,
    # kratos run, everything else) -- they all go through this same main()
    # dispatch, so there's no second entry point to separately wire up.
    # Safe on a fresh install with no kept_tools/ directory at all: returns
    # an empty list, no error.
    load_kept_tools()

    # One run (kratos.run_context) per command, so model spending and stored
    # events are attributed. Commands that start their own runs open their own
    # scopes instead: a scheduled run is a "schedule" run, each MCP tool call is
    # an "mcp" run, and the long-lived servers are not runs at all.
    if args.command in _SELF_SCOPED_COMMANDS:
        return int(args.func(args))
    # Spending limits (kratos.budget): a person at this terminal is asked before
    # a run goes over one (default no); a refused call ends the command with the
    # limit's plain message instead of a traceback.
    from kratos.budget import guard as _budget

    _budget.set_prompt_provider(_budget.terminal_prompt, actor="cli")
    try:
        with run_scope("cli"):
            return int(args.func(args))
    except _budget.BudgetExceeded as e:
        print(f"[KRATOS] {e.user_message()}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    # `python -m kratos.cli.app ...` -- the fallback a systemd unit uses when the
    # `kratos` console script isn't available (core_listener._kratos_executable).
    raise SystemExit(main())
