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
from kratos.kratos_config import SSH_TARGET_HOST
from kratos.llm_config import LLM_OPENAI_MODEL

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
        script = _installer.generate_installer(args.core_host, code, core_port=args.core_port)
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
    Run the Kratos-core-side sub-agent telemetry listener (capability 1).
    Blocking -- accepts OUTBOUND connections from paired sub-agents and
    never dials out to one itself (see core_server.py's module docstring).
    Read-only: this process cannot send a command to any agent.
    """
    import asyncio

    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent.core_server import CoreServer, DEFAULT_PORT

    store = SubAgentStore(args.data_dir / "kratos.db")
    server = CoreServer(store, host=args.host, port=args.port)
    print(f"[KRATOS] Sub-agent telemetry server listening on {args.host}:{args.port} (Ctrl+C to stop)")
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
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


def cmd_subagent_status(args: argparse.Namespace) -> int:
    """List paired sub-agent targets and their derived liveness status, plus
    a one-line summary of the latest telemetry received from each (capability
    1). Status here is derived purely from persisted last_seen recency (see
    subagent/status.py) since this is a separate process from any running
    `subagent-serve` -- it has no live-socket visibility of its own."""
    from kratos.storage.subagent_store import SubAgentStore
    from kratos.subagent.status import derive_status

    store = SubAgentStore(args.data_dir / "kratos.db")
    targets = store.list_targets()
    if not targets:
        print("[KRATOS] No sub-agents paired yet. Run: kratos subagent-pair")
        return 0
    for t in targets:
        status = derive_status(t["last_seen"])
        revoked = " (REVOKED)" if t["revoked_at"] else ""
        print(f"[KRATOS] {t['target_id']}{revoked}  {t['hostname'] or '?'}  status={status}  last_seen={t['last_seen']}")
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
    Start the Qwen2.5-Coder LLM server (model loaded once, stays in memory).
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
        print(f"[KRATOS-LLM] Starting LLM server (Qwen2.5-Coder 7B)...", flush=True)
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
    AI-powered analysis of Kratos security findings using Qwen2.5-Coder 7B.
    Loads the latest prepared bundle and explains findings in plain language.
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
    backend_label = LLM_OPENAI_MODEL
    _console.render_session_header(console, goal=goal, max_iters=max_iters, ssh_target=SSH_TARGET_HOST, backend=backend_label)

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

    started_at = time.monotonic()
    try:
        result = run_agent(goal, args.data_dir, max_iters=max_iters, on_step=_print_step)
    finally:
        live.stop()
    duration = time.monotonic() - started_at

    console.print()
    if result["status"] == "final_answer":
        _console.render_result_panel(console, "Investigation complete", result["final_answer"], "green")
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
        console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
        session_events.append("Investigation stopped: step limit reached (best-effort answer shown)")
        _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
        return 1

    _console.render_error(console, f"Investigation stopped: {result['status']} (no final answer reached).")
    console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]")
    _console.render_session_summary(console, [f"Findings: {findings_count}"] + session_events)
    return 1


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

    bundle = sub.add_parser("prepare-bundle", help="Create a clean, short text bundle for offline LLM input")
    bundle.add_argument("--max-words", type=int, default=500, help="Max words in the bundle (default: 500)")
    bundle.add_argument("--since", type=str, default=None, help="Start date in YYYYMMDD format (e.g., 20260201)")
    bundle.add_argument("--until", type=str, default=None, help="End date in YYYYMMDD format (e.g., 20260228)")
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
    subagent_serve.add_argument("--host", default="0.0.0.0", help="Interface to listen on (default: all)")
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

    # ====== PHASE 4: ReAct Agent (experimental, additive) ======
    investigate = sub.add_parser(
        "investigate",
        help="ReAct-style agent investigation: the LLM picks which Kratos tool to call next (experimental; does not replace `kratos run`)",
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
PRIMARY_COMMANDS = ["investigate", "run", "chat", "findings-show", "scan"]


def _render_top_level_help(parser: argparse.ArgumentParser, show_all: bool = False) -> None:
    """Rich-formatted top-level --help only -- every other subcommand's own
    `--help` output is untouched argparse default formatting; the styled
    layer is scoped to `investigate` + the shared approval gate (see
    docs/DESIGN.md's "Known limitations" section)."""
    console = _console.get_console()
    console.print(
        Panel(
            "Kratos analyzes system, network, and log data for security issues -- offline, "
            "no cloud dependency by default.\n\n"
            "Example:\n  kratos investigate \"check for suspicious SSH activity\"",
            title="kratos -- Offline AI Security Assistant",
            border_style="cyan",
        )
    )
    all_help = _subcommand_help_text(parser)
    shown = all_help if show_all else {k: v for k, v in all_help.items() if k in PRIMARY_COMMANDS}
    table = Table(show_header=True, header_style="bold")
    table.add_column("Command")
    table.add_column("Description")
    for name, help_text in shown.items():
        # Curated view only: keep each row to one line (the full text is
        # always one flag/subcommand-help away) -- the parenthetical detail
        # on longer descriptions (e.g. investigate's "(experimental; does
        # not replace...)") is exactly what's safe to trim here, not the
        # core sentence.
        if not show_all and len(help_text) > 60:
            help_text = help_text.split(" (")[0].rstrip(".")
            if len(help_text) > 60:
                help_text = help_text[:57].rstrip() + "..."
        table.add_row(name, help_text)
    console.print(table)
    if not show_all:
        hidden_count = len(all_help) - len(shown)
        console.print(f"\n...and {hidden_count} more. Run `kratos --help --all` to see every command.")
    console.print(
        "\nGlobal options: --data-dir PATH   --no-color   --resume SESSION_ID_OR_NAME   --continue/-c"
    )
    console.print("Run `kratos <command> --help` for command-specific options.\n")


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
    table.add_row("--data-dir PATH", "Directory for storing scans/logs/context/reports (default: ./data)")
    table.add_row("--no-color", "Disable colored/styled output")
    console.print(table)
    console.print()


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
        global_args, _unused = global_only_parser.parse_known_args(argv)
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

    args.data_dir.mkdir(parents=True, exist_ok=True)

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

    return int(args.func(args))
