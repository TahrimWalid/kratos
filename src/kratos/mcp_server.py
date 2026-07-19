"""
MCP server exposing a small, high-level surface over Kratos's existing
investigation pipeline (run_agent) and session store.

Architecture: Model A, not Model B (standing decision, not re-decided here).
Kratos's own agent loop (agent/loop.py) and its own configured LLM remain
the sole orchestrator for all investigation logic, regardless of how the
request arrives -- this module exposes 4 top-level tools (kratos_investigate,
kratos_get_findings, kratos_list_sessions, kratos_notify_findings) that call
into run_agent()/SessionStore/agent/notify.py, never a raw pass-through of
individual TOOL_REGISTRY entries. An external MCP client's own LLM never
picks which internal Kratos tool (nmap, journalctl, correlate_findings, ...)
runs or in what order; that choice is made entirely inside run_agent(),
unchanged.

Hard boundary: read/investigate only, nothing approval-gated. The approval
gate (agent/tools.py::request_approval) is a blocking input() call whose
only fail-safe is catching EOFError/KeyboardInterrupt -- both raised when
stdin is CLOSED. Under MCP's stdio transport, Kratos's stdin is never
closed; it's the live, open JSON-RPC channel to the client for the whole
connection. A blocking input() reached via MCP would try to read a line
from that channel instead of raising EOFError -- at best consuming (and
discarding) one real protocol message before evaluating it as a garbage
non-'y' answer, at worst blocking forever waiting for a line-shaped read
that the transport was never going to produce, either way corrupting or
hanging the server, not failing safe the way it does at a real terminal.
This is a materially different (and worse) risk than "no human answers in
time" -- confirmed by reading request_approval's real implementation, not
assumed from its docstring.

Given that, kratos_investigate() runs every investigation with every tool
that can reach request_approval TEMPORARILY removed from TOOL_REGISTRY (see
_investigation_lock / _tool_reaches_approval below) -- the model literally
cannot select one, so nothing in this module ever calls, patches, or
otherwise touches agent/self_approve.py or request_approval itself. This is
prevention (the tool is never offered), not mitigation (letting it be
picked, then intercepting the call) -- deliberately, since the latter would
mean touching the approval call path in some way. Real call-graph trace
(2026-07-19), not assumed from the tool list: grep confirmed exactly 4
tools' handlers ever call request_approval() -- capture_traffic and
run_linux_command (both requires_approval=True at the registry level,
already excluded by that flag alone) plus run_vuln_scan and
check_ip_reputation (both requires_approval=False at the registry level,
calling request_approval() CONDITIONALLY from inside their own handler --
a stale local CVE database, or an opt-in live threat-intel escalation,
respectively). The registry flag alone would have silently missed the
latter two -- _tool_reaches_approval scans each handler's actual source
text instead of trusting that flag as a complete signal.

Evo-loop (agent/self_write_loop.py::run_self_write_loop) needs no special
exclusion here: it isn't in TOOL_REGISTRY at all and has exactly one caller
in the whole repo, cli/repl.py::_cmd_evolve -- nothing in agent/loop.py's
dispatch (execute_tool_call only ever calls a TOOL_REGISTRY handler) can
reach it. The model's tool_proposal auto-suggest response shape is
non-terminal and render-only by design (see CLAUDE.md) -- this module
doesn't pass an on_step callback at all, so a proposal surfaces in the
returned transcript exactly like any other step and is never acted on.

Concurrency: an MCP server is a single long-running process that can, in
principle, receive overlapping tool calls (FastMCP runs sync tool
functions in a thread pool). kratos_config.py's active-target override and
the TOOL_REGISTRY exclusion above are both plain mutable module globals --
safe for a single serial investigation (the same assumption
kratos_config.py's own docstring already states), not safe if two
investigate() calls interleave and stomp on each other's target/tool-list.
_investigation_lock serializes the whole "exclude tools -> set target ->
run_agent -> restore tools" critical section into one atomic unit per
call, rather than threading an explicit target/registry parameter through
run_agent()/execute_tool_call() (an 8-call-chain refactor kratos_config.py
already explicitly scoped out for the same reason /target doesn't do it).

kratos_notify_findings (2026-07-19, replaces an earlier free-form
kratos_notify(message, severity) that shipped, then was found to have a
real problem, then was removed here -- not kept alongside this one).
Closes out the original 3-tool MCP plan (analyze_logs/get_findings/notify
-- the first two shipped as kratos_investigate/kratos_get_findings). The
free-form version let a connecting MCP client send a notification with
ANY message/severity it liked, completely unrelated to anything Kratos
actually found -- i.e. a third-party caller could put words in Kratos's
mouth over a channel meant to report Kratos's own real findings. Fixed by
narrowing the surface, not by adding validation on top of free-form input:
kratos_notify_findings(session_id) is the only notify-shaped tool exposed
now, and its message/severity are ALWAYS derived from that session's real,
already-stored correlate_findings results (via the exact same
_load_session_turns lookup kratos_get_findings uses) -- there is no
parameter through which a caller can inject arbitrary text or assert a
severity that isn't backed by a real finding. Refuses to send anything
(raises, sends nothing) unless the session is real, at least one turn in
it reached a genuine completion (final_answer/max_iters_reached -- not
cancelled/in-progress/crashed), and it has at least one real finding.
Severity is the HIGHEST severity actually present among those findings,
mapped onto ntfy's 3-tier scale -- never caller-asserted.

This boundary is about the EXTERNAL MCP surface specifically, not internal
usage: agent/notify.py::send_notification itself is unchanged and remains
freely callable from Kratos's own internal code (the existing
send_notification TOOL_REGISTRY tool inside an investigation, or any
future internal/proactive checker) for whatever real reason it has --
only the external, free-form MCP entry point was the actual problem, and
only that was removed.

Deliberately NOT approval-gated (unchanged reasoning): confirmed
send_notification/tool_send_notification never appear in agent/tools.py's
request_approval( call sites (the same grep that found the 4 real
approval-reaching tools for the investigate path) -- sending a
notification isn't a security-relevant action the way target execution
is. No lock needed: this never touches TOOL_REGISTRY or the active-target
override -- session/transcript reads plus one stateless HTTP POST, no
shared mutable state to protect.
"""
from __future__ import annotations

import inspect
import json
import threading
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from kratos import kratos_config as _kconfig
from kratos.agent.loop import run_agent, DEFAULT_MAX_ITERS
from kratos.agent.notify import send_notification
from kratos.agent.tools import TOOL_REGISTRY, Tool
from kratos.llm_config import get_active_llm_model
from kratos.storage.session_store import SessionStore

# Must match cli/repl.py::TRANSCRIPTS_DIRNAME -- both write into the SAME
# data_dir/kratos.db + data_dir/sessions/ store, deliberately: an
# MCP-triggered investigation is a real session, indistinguishable in
# storage from one started via the REPL, so kratos_list_sessions/
# kratos_get_findings and the REPL's own chooser see the same data either
# way, not two silently separate stores.
_TRANSCRIPTS_DIRNAME = "sessions"

_investigation_lock = threading.Lock()

_data_dir: Path = Path("data")

mcp = FastMCP(name="kratos")


def _tool_reaches_approval(tool: Tool) -> bool:
    """True if this tool must be excluded from an MCP-invoked investigation
    because SOMETHING in its own handler can call request_approval --
    either the registry's own requires_approval=True (an always-gated
    tool), or (checked independently, since that flag is not a complete
    signal -- see module docstring) the handler's actual source text
    containing a request_approval( call, catching tools that only reach it
    CONDITIONALLY. inspect.getsource() failing (e.g. a kept tool whose
    source file went missing) fails SAFE -- treated as reaching approval,
    excluded, never assumed fine just because it couldn't be checked.
    Known, accepted limit: only scans the handler's own source text, not
    functions it calls indirectly -- true for all 4 real tools that
    actually reach request_approval today (confirmed by direct reading,
    2026-07-19), revisit if a future tool delegates its approval call to a
    private helper instead of calling it inline."""
    if tool.requires_approval:
        return True
    try:
        source = inspect.getsource(tool.handler)
    except (OSError, TypeError):
        return True
    return "request_approval(" in source


def _unwrap_tool_result(observation: Any) -> Any:
    """Same unwrapping agent/console.py::unwrap_tool_result does (execute_tool_call
    always wraps a tool's real return as {"status": "ok", "result": <real
    return>}) -- reimplemented here, not imported, so this module never
    pulls in the Rich-based rendering layer for a headless MCP server."""
    if not isinstance(observation, dict):
        return observation
    if str(observation.get("status", "")).lower() == "error":
        return observation
    inner = observation.get("result")
    return inner if isinstance(inner, dict) else observation


def _extract_findings(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for step in transcript:
        if step.get("tool") != "correlate_findings":
            continue
        result = _unwrap_tool_result(step.get("observation"))
        if isinstance(result, dict) and result.get("findings"):
            findings.extend(result["findings"])
    return findings


def _run_locked_investigation(goal: str, target: str, max_iters: int, data_dir: Path) -> dict[str, Any]:
    with _investigation_lock:
        _kconfig.set_active_target(target)

        excluded = {name: tool for name, tool in TOOL_REGISTRY.items() if _tool_reaches_approval(tool)}
        for name in excluded:
            del TOOL_REGISTRY[name]
        try:
            store = SessionStore(data_dir / "kratos.db")
            session_id = store.create_session([target], get_active_llm_model())
            turn_id = store.start_turn(session_id, goal)

            result = run_agent(goal, data_dir, max_iters=max_iters)

            status = result["status"]
            transcript = result.get("transcript", [])
            transcripts_dir = data_dir / _TRANSCRIPTS_DIRNAME
            transcripts_dir.mkdir(parents=True, exist_ok=True)
            transcript_path = transcripts_dir / f"{session_id}_turn{turn_id}.json"
            transcript_path.write_text(json.dumps(transcript, indent=2, default=str), encoding="utf-8")
            store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))

            return {
                "session_id": session_id,
                "status": status,
                "final_answer": result.get("final_answer"),
                "findings": _extract_findings(transcript),
            }
        finally:
            TOOL_REGISTRY.update(excluded)


@mcp.tool()
def kratos_investigate(goal: str, target: str, max_iters: int = DEFAULT_MAX_ITERS) -> dict[str, Any]:
    """Runs a real Kratos investigation against `target` for `goal`, using Kratos's own
    agent loop and its own configured local LLM to decide which internal tools to run and
    in what order -- this does not hand tool selection to the caller. Read/investigate only:
    approval-gated actions (running an arbitrary command, live traffic capture, live
    threat-intel escalation, evolving a new tool) are never reachable from this call.
    Returns the investigation's outcome, final answer, and any findings correlate_findings
    produced. `target` is required and explicit -- an MCP call has no prior session/`/target`
    state to fall back on."""
    if not target or not target.strip():
        raise ValueError("target is required (no implicit session state exists over MCP)")
    if not goal or not goal.strip():
        raise ValueError("goal is required")
    return _run_locked_investigation(goal.strip(), target.strip(), max_iters, _data_dir)


def _load_session_turns(store: SessionStore, session_id: str) -> list[dict[str, Any]]:
    """Loads every turn in `session_id` with its findings extracted from the saved
    transcript -- shared by kratos_get_findings and kratos_notify_findings so both resolve
    findings through the exact same path (kratos_notify_findings's own requirement: reuse
    this lookup rather than a second, parallel implementation)."""
    turns = []
    for turn in store.get_goal_history(session_id):
        findings: list[dict[str, Any]] = []
        ref = turn.get("transcript_ref")
        if ref:
            try:
                transcript = json.loads(Path(ref).read_text(encoding="utf-8"))
                findings = _extract_findings(transcript)
            except (OSError, json.JSONDecodeError):
                pass
        turns.append(
            {
                "goal": turn["goal"],
                "status": turn.get("status"),
                "started_at": turn.get("started_at"),
                "findings": findings,
            }
        )
    return turns


@mcp.tool()
def kratos_get_findings(session_id: str | None = None) -> dict[str, Any]:
    """Retrieves findings from a specific Kratos session (by session_id), or the most
    recently active session if session_id is omitted. Findings come from every turn in
    that session that called correlate_findings, grouped by the goal that produced them --
    a session with several investigations returns all of their findings, not just the
    latest one."""
    store = SessionStore(_data_dir / "kratos.db")
    if session_id:
        session = store.get_session(session_id)
        if session is None:
            raise ValueError(f"No session found with id {session_id!r}")
    else:
        recent = store.list_recent_sessions(limit=1)
        if not recent:
            return {"session_id": None, "target": [], "turns": []}
        session = recent[0]

    turns = _load_session_turns(store, session["session_id"])
    return {"session_id": session["session_id"], "target": session["targets"], "turns": turns}


@mcp.tool()
def kratos_list_sessions(limit: int = 10) -> list[dict[str, Any]]:
    """Lists recent Kratos sessions (most recently active first) -- id, target(s), the most
    recent goal, and when it was last active. Same data the interactive REPL's own session
    chooser shows."""
    store = SessionStore(_data_dir / "kratos.db")
    return [
        {
            "session_id": s["session_id"],
            "name": s.get("name"),
            "targets": s["targets"],
            "last_goal": s.get("latest_goal"),
            "last_active_at": s["last_active_at"],
        }
        for s in store.list_recent_sessions(limit=limit)
    ]


_TERMINAL_COMPLETION_STATUSES = {"final_answer", "max_iters_reached"}
_FINDING_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _derive_notify_severity(findings: list[dict[str, Any]]) -> str:
    """Maps the HIGHEST severity actually present among real findings onto ntfy's 3-tier
    scale (agent/notify.py::_SEVERITY_MAP) -- never caller-asserted, always derived from
    stored data. critical/high -> critical (ntfy urgent): CLAUDE.md's own CORR-SSH-001
    example is a HIGH finding for a live attack, which warrants an urgent push, not merely
    "warning". medium -> warning. low/info -> info."""
    rank = max((_FINDING_SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) for f in findings), default=0)
    if rank >= 3:
        return "critical"
    if rank == 2:
        return "warning"
    return "info"


def _build_findings_notification_message(session: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    target = ", ".join(session["targets"]) if session["targets"] else "unknown target"
    lines = [f"Kratos findings for session {session['session_id']} ({target}):"]
    for f in findings:
        severity = str(f.get("severity", "info")).upper()
        title = f.get("title") or f.get("id", "finding")
        lines.append(f"- [{severity}] {f.get('id', '?')}: {title}")
    return "\n".join(lines)


@mcp.tool()
def kratos_notify_findings(session_id: str) -> dict[str, Any]:
    """Sends a push notification summarizing a REAL, already-completed investigation's
    stored findings. The message and severity are always derived from that session's actual
    correlate_findings results -- there is no way to pass free-form text or an asserted
    severity through this tool. Fails clearly, sending nothing, if session_id doesn't resolve
    to a real session, no turn in it reached a genuine completion, or it has no findings."""
    if not session_id or not session_id.strip():
        raise ValueError("session_id is required")
    session_id = session_id.strip()

    store = SessionStore(_data_dir / "kratos.db")
    session = store.get_session(session_id)
    if session is None:
        raise ValueError(f"No session found with id {session_id!r}")

    turns = _load_session_turns(store, session_id)
    if not any(t.get("status") in _TERMINAL_COMPLETION_STATUSES for t in turns):
        raise ValueError(
            f"Session {session_id!r} has no turn that reached a real completion "
            "(final_answer/max_iters_reached) -- refusing to notify about an incomplete "
            "or cancelled investigation."
        )

    all_findings = [f for t in turns for f in t["findings"]]
    if not all_findings:
        raise ValueError(f"Session {session_id!r} has no findings to notify about.")

    message = _build_findings_notification_message(session, all_findings)
    severity = _derive_notify_severity(all_findings)
    result = send_notification(message, severity)
    return {"notified_message": message, "derived_severity": severity, **result}


def run_stdio_server(data_dir: Path = Path("data")) -> None:
    """Entry point for `kratos mcp-serve` (cli/app.py). Blocking -- runs until the client
    disconnects or the process is killed."""
    global _data_dir
    _data_dir = data_dir
    mcp.run(transport="stdio")
