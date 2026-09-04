"""
Minimal ReAct-style agent loop for Kratos.

The LLM picks one tool per turn from agent/tools.py::TOOL_REGISTRY and
responds in a fixed JSON schema (no free-form "Thought:/Action:" text — JSON
is far more reliable to parse from a small local model):

To call a tool:
    {"reasoning": "<why this tool, next>", "tool": "<tool_name>", "args": {...}}

To stop and answer the investigation goal:
    {"reasoning": "<why you're done>", "final_answer": "<answer text>"}

Only that one JSON object should be in the response — no markdown fences, no
extra prose. Tool results are fed back as an "Observation:" turn and the loop
continues until a final_answer is produced or max_iters is reached.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from kratos.agent.tools import (
    TOOL_REGISTRY,
    render_tools_for_prompt,
    approval_log_length,
    approval_was_recorded,
)
from kratos.kratos_config import get_active_target
from kratos.llm_interface import (
    agent_chat,
    get_context_window_tokens,
    get_last_token_usage,
    TokenUsage,
)
from kratos.llm_config import MAX_TOKENS_QUESTION

DEFAULT_MAX_ITERS = 10
# Keep each tool result bounded before it's fed back into the conversation —
# the local model's context window (LLAMA_N_CTX) is small, and some tools
# (e.g. collect_system_context) can return large raw text blobs.
OBSERVATION_CHAR_CAP = 1500

# When this many iterations (or fewer) remain, a short wrap-up reminder is
# appended to the prompt for that call. With the default max_iters=10, that's
# iterations 8, 9. Ephemeral: added only to the specific prompt sent for that
# call, not baked into the stored conversation history -- so it stays at
# maximum recency each time rather than scrolling further back (and getting
# effectively forgotten) as more turns accumulate after it.
#
# This soft nudge still lets the model call one more tool if it judges that
# necessary -- in practice it almost always does, since Prompt A's
# INVESTIGATION SCOPE guidance keeps pulling the other way. The FINAL
# iteration (max_iters) therefore gets a separate, escape-hatch-free hard
# stop instead (FINAL_ITERATION_NUDGE): no "if necessary" -- a tool call
# there would never get executed anyway (no iteration left to read its
# result), so there is nothing to gain by allowing it.
WRAP_UP_REMAINING_ITERS = 2
WRAP_UP_NUDGE = (
    "\n\nREMINDER: You have already gathered substantial evidence and only a few iterations "
    "remain before this investigation is cut off. On THIS response you MUST either call one "
    "more tool ONLY if it is truly necessary, or conclude now with a final_answer. Do not "
    "invent tool names that are not in the AVAILABLE TOOLS list above."
)
FINAL_ITERATION_NUDGE = (
    "\n\nTHIS IS YOUR FINAL RESPONSE. There is no next iteration -- a tool call now will not be "
    "executed and this investigation would end with no answer recorded. You MUST respond with "
    'a final_answer JSON object now: {"reasoning": "<brief>", "final_answer": "<your answer, '
    'grounded only in Observations you already received>"}. Do NOT call any tool, real or '
    "invented, in this response."
)

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)

# execute_tool_call's target-arg guard (2026-07-18, real incident): no real
# IP address or hostname contains an uppercase letter or an underscore --
# both are exactly what a hallucinated placeholder like "THE_TARGET_IP"
# looks like. Deliberately narrow (catches the confirmed pattern, not a
# full IP/hostname syntax validator), matching this file's other guards.
_IMPLAUSIBLE_TARGET_RE = re.compile(r"[A-Z_]")

# execute_tool_call's target-MISMATCH guard (2026-07-19, real incident): the
# guard above only catches an OBVIOUSLY fake placeholder -- it does nothing
# for a plausible-looking but WRONG real IP. Confirmed live via MCP: a
# kratos_investigate call with target=10.136.28.168 (the real, configured
# active target) resulted in the model calling run_nmap_scan with a
# hallucinated target=192.168.1.50 instead -- a real, valid-shaped IP that
# simply isn't the host the investigation was ever about. The tool ran
# without error and the final answer described the wrong host. Pre-existing
# in the CLI/REPL path too (nothing here is MCP-specific), fixed at this one
# shared dispatch point so every entry point benefits.
#
# The ONE legitimate exception, not invented here -- run_nmap_scan's own
# description already documents it ("pass target explicitly only to check a
# different host, e.g. '127.0.0.1' for Kratos's own local host specifically
# (self-monitoring, not the default)"): scanning Kratos's own loopback
# address on purpose. Allowing exactly this and nothing else closes the real
# hallucination gap (192.168.1.50 is neither the active target nor a
# self-reference) without breaking the one override this tool already
# promises is valid.
_LOOPBACK_SELF_TARGETS = {"127.0.0.1", "localhost", "::1"}

# State-changing command patterns rejected for run_linux_command DURING an
# investigation (see execute_tool_call). The investigation loop is observe-and-
# recommend only; run_linux_command may run READ-ONLY local self-diagnostics on
# Kratos's own host, never state changes. Deliberately scoped to the investigation
# dispatch, NOT the tool handler itself -- the handler stays capable for its
# intended out-of-investigation uses (design doc §8 human-approved installs, and
# the planned admin-approved remote-command channel). Reads like `cat /etc/passwd`,
# `dpkg -l`, `systemctl status/is-active`, `ps aux` are intentionally NOT matched.
_STATE_CHANGE_RE = re.compile(
    r"(?:^|[\s;&|`(])(?:"
    r"systemctl\s+(?:start|stop|enable|disable|restart|reload|mask|unmask)"
    r"|service\s+\S+\s+(?:start|stop|restart|reload)"
    r"|(?:apt|apt-get|aptitude|yum|dnf|snap)\s+(?:install|remove|purge|reinstall|autoremove)"
    r"|dpkg\s+(?:-i|--install|-r|--remove|--purge)"
    r"|pip3?\s+(?:install|uninstall)"
    r"|useradd|usermod|userdel|groupadd|groupdel|gpasswd|chpasswd"
    r"|reboot|shutdown|halt|poweroff"
    r"|iptables\s+-[AIDF]|nft\s+(?:add|delete|flush|insert)|ufw\s+(?:allow|deny|reject|enable|disable|delete)"
    r"|fail2ban-client\s+(?:set|start|stop|reload|restart|unban|ban)"
    r"|crontab\s+-[er]|pkill|killall|mkfs\S*"
    r")\b"
    r"|\brm\s+\S|\bchmod\s|\bchown\s"
    r"|>\s*/(?:etc|usr|boot|bin|sbin|lib|var|root)/"
    r"|\btee\s+(?:-a\s+)?/(?:etc|usr|boot|var)/",
    re.IGNORECASE,
)


def build_system_prompt() -> str:
    tools_desc = render_tools_for_prompt()
    return f"""You are Kratos, an offline security investigation agent that monitors a separate target device over SSH.

You investigate step by step by calling ONE tool at a time and reading its result before deciding the next step.

AVAILABLE TOOLS:
{tools_desc}

LOCAL HOST VS. MONITORED TARGET (read this before choosing tools):
Kratos runs on its own host, but the system you are investigating is a SEPARATE target device, reached over SSH. Tools that mention "target" or use SSH to a remote host inspect the protected system -- that is almost always what an investigation goal is actually asking about. FOUR tools are the exception and inspect Kratos's OWN local host instead, never the target: parse_auth_log, collect_system_context, capture_traffic, and run_linux_command. Every other tool in the registry inspects the monitored target. The four local-host tools are relevant only when a goal specifically concerns Kratos's own security (self-monitoring), never as the default way to check "the system" being protected. When a goal says "check for suspicious activity on this system", "is SSH exposed", "who has privileged access", or asks about logins/break-ins/running processes without saying otherwise, default to target-facing tools (e.g. read_journalctl for authentication activity, list_processes/list_open_files for running state, run_config_audit for hardening) -- not parse_auth_log, collect_system_context, capture_traffic, or run_linux_command.

RESPONSE FORMAT (mandatory):
Respond with EXACTLY one JSON object and nothing else — no markdown code fences, no commentary before or after it.

To call a tool:
{{"reasoning": "<one sentence: why this tool now>", "tool": "<tool_name>", "args": {{...}}}}

To finish, once you have enough evidence to answer the goal:
{{"reasoning": "<one sentence: why you're done>", "final_answer": "<your answer, grounded only in Observations you received>"}}

When your final_answer recommends concrete remediation, you MAY additionally attach a structured list of the exact commands for a HUMAN to run -- Kratos NEVER runs them itself, this only structures your recommendation so it can be shown clearly:
{{"reasoning": "...", "final_answer": "...", "recommended_commands": [{{"command": "<exact shell command>", "explanation": "<what it does and why>", "run_on": "target"}}]}}
Set "run_on" to "target" for a command the human runs on the monitored device, or "kratos_host" for one on Kratos's own host. Omit recommended_commands entirely unless the investigation genuinely warrants specific remediation -- it is never a claim that anything was executed.

To propose a NEW tool Kratos doesn't have yet -- use ONLY when you hit a genuine capability gap during THIS investigation that no existing tool covers, never speculatively and never instead of using an existing tool that already fits:
{{"reasoning": "<one sentence: what gap this fills and why you hit it just now>", "tool_proposal": {{"name": "<snake_case tool name>", "description": "<one or two sentences: what it does and what gap it fills>"}}}}
This does NOT end the investigation -- after proposing, continue with a tool call or a final_answer as normal. The proposal is surfaced to a human; you never build it yourself and never need to mention it again.

INVESTIGATION SCOPE:
Treat any investigation goal as a request for a reasonably thorough security check, not a literal keyword match. "Check for suspicious activity", "has anyone tried to break in", "run a full security check", and "is my server okay" are substantively the same underlying request phrased differently -- a human analyst would not skip network exposure just because the user said "break in" instead of "scan", or skip login activity just because the user said "okay" instead of "auth". Before concluding, briefly consider whether each of these categories is relevant to the goal, even if the wording doesn't mention it directly:
- Network exposure / attack surface (open ports, reachable services)
- Authentication activity (login attempts, sudo usage, failures)
- System state (running services, users, SSH config)
- Running processes (anything unexpected currently executing)
- File/config integrity (tampering with critical files)
- Hardening/config posture (firewall, root login, password auth, patching)
This does NOT mean call every tool regardless of relevance -- if a category is clearly irrelevant given the goal and the evidence gathered so far, say so in your reasoning and move on rather than calling its tool anyway. The goal is broader consideration before concluding, not blind exhaustiveness.

THREAT-INTEL ENRICHMENT (when a suspicious IP is in view): if the investigation surfaces a SPECIFIC source IP behind suspicious activity -- a failed-login or brute-force burst, a port scan, other attack traffic attributable to an IP -- consider check_ip_reputation on that IP before concluding. Correlating it against known threat intelligence strengthens the finding's confidence/severity when the IP is known-malicious, or tempers it when clean, and either way that result should be reflected in your final answer. This is a per-IP enrichment step to consider once a concrete suspicious IP is already identified -- not a routine check to run on every investigation, and not something to run speculatively on IPs with nothing suspicious tied to them.

RULES:
- Only use tool names exactly as listed above.
- Only include args the tool actually accepts; omit ones you don't have a value for.
- You do not need to supply data_dir — it is provided automatically.
- Never invent data. Only reference facts that appeared in an Observation.
- Do not call the same tool with the same args twice in a row.
- If a tool result shows an error, adapt (try different args, or move to a different tool, or give a final_answer noting the limitation) rather than repeating the same failing call.
"""


def _parse_agent_json(text: str) -> dict[str, Any] | None:
    """
    Extract the FIRST well-formed JSON object the model emitted, ignoring
    anything after it.

    Small local models frequently keep generating past their one intended
    JSON object — hallucinating fake "Observation:"/follow-up turns as if
    role-playing the rest of the conversation. A naive first-'{'-to-last-'}'
    span would swallow that hallucinated tail into the same string and fail
    to parse at all, discarding the model's real (valid) first decision. Using
    json.JSONDecoder.raw_decode from the first '{' parses only as much JSON as
    is actually there and discards everything after it.
    """
    candidate = text.strip()

    fence_match = _JSON_FENCE_RE.search(candidate)
    if fence_match:
        candidate = fence_match.group(1).strip()

    start = candidate.find("{")
    if start == -1:
        return None

    try:
        obj, _end_index = json.JSONDecoder().raw_decode(candidate, start)
        return obj
    except json.JSONDecodeError:
        return None


def execute_tool_call(tool_name: str, args: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    tool = TOOL_REGISTRY.get(tool_name)
    if tool is None:
        valid_names = ", ".join(sorted(TOOL_REGISTRY.keys()))
        return {
            "status": "error",
            "observation": (
                f"'{tool_name}' is not a real tool -- it does not exist in the registry. Do not "
                f"guess or invent tool names. The ONLY valid tool names are: {valid_names}. Pick "
                "one of these exactly, or if none are actually needed, respond with a "
                "final_answer instead of a tool call."
            ),
        }

    call_args = dict(args or {})
    if "data_dir" in tool.parameters:
        # ALWAYS the real value, even if the model already supplied its own
        # -- real incident, 2026-07-17: the system prompt already says "you
        # do not need to supply data_dir", but a prompt instruction alone
        # doesn't stop a hallucinated override from silently winning. The
        # model passed data_dir="/data" (a real filesystem-root path Kratos
        # has no permission to write to), producing a real PermissionError
        # that had nothing to do with the target at all -- confirmed via a
        # real transcript, not hypothetical. There is no legitimate reason
        # for the model to ever need to set this itself (unlike `target`
        # below, which has a real override use case), so this is a
        # structural override, not just a fill-in-if-missing default.
        call_args["data_dir"] = data_dir

    if "target" in tool.parameters and call_args.get("target") is not None:
        # Real incident, same turn as the data_dir bug above: the model
        # also invented a placeholder target ("THE_TARGET_IP") that isn't a
        # real IP/hostname -- the call raised no exception, silently
        # scanning nothing and returning a wrong, empty result (0 open
        # ports, vs. a real 1 open port minutes earlier in the same
        # session) that would have gone unnoticed had the data_dir error
        # above not also forced the model to explain itself. Unlike
        # data_dir, `target` has a real legitimate override (scanning a
        # specific different host on purpose), so it can't be force-
        # overridden the same way -- reject an OBVIOUSLY fake value before
        # it runs instead, same "not a real tool name" rejection shape used
        # above for an invented tool_name.
        target_value = str(call_args["target"])
        if _IMPLAUSIBLE_TARGET_RE.search(target_value):
            return {
                "status": "error",
                "observation": (
                    f"'{target_value}' does not look like a real IP address or hostname -- it "
                    "looks like a placeholder. Use the real target IP/hostname, or omit the "
                    "'target' argument entirely to use the configured default."
                ),
            }
        active_target = get_active_target()
        if target_value != active_target and target_value not in _LOOPBACK_SELF_TARGETS:
            # See _LOOPBACK_SELF_TARGETS above for why 127.0.0.1/localhost/::1
            # are the one allowed exception, not this codebase inventing a new
            # policy. Reject (not silently override) -- Kratos should never
            # scan/inspect a host the investigation wasn't asked about without
            # that being surfaced clearly, matching the same "not a real tool
            # name"/"looks like a placeholder" rejection shape already used
            # above rather than a silent correction the model (or a human
            # reading the transcript) would never see.
            return {
                "status": "error",
                "observation": (
                    f"target={target_value!r} does not match the configured active target "
                    f"({active_target!r}) and is not a recognized self-monitoring reference "
                    "(127.0.0.1/localhost/::1). Kratos does not scan or inspect a host the "
                    f"investigation wasn't asked about -- omit the 'target' argument to use "
                    f"{active_target!r}, or pass one of the loopback values above only if you "
                    "specifically intend to check Kratos's own host."
                ),
            }

    # run_linux_command runs on Kratos's OWN host and, during an investigation,
    # is for READ-ONLY local self-diagnostics only -- NOT a way to reach or
    # change the monitored target. This is enforced structurally, not left to
    # model judgment: the model has been observed (a) ssh-wrapping a command to
    # reach the target and (b) using it to remediate, then (c) misattributing
    # the Kratos-host result to the target and drawing a wrong conclusion.
    # Reject, BEFORE the approval prompt, anything that references the target or
    # changes state. Scoped here (the investigation dispatch), not the handler,
    # so the tool stays capable for its intended out-of-investigation uses.
    if tool_name == "run_linux_command":
        cmd = str(call_args.get("command", ""))
        active_target = get_active_target()
        if active_target and active_target in cmd:
            return {
                "status": "error",
                "observation": (
                    f"run_linux_command runs on KRATOS'S OWN HOST and cannot reach the monitored "
                    f"target ({active_target}) -- referencing the target in the command (e.g. "
                    "ssh'ing to it) is not allowed. Use the target-facing tools (read_journalctl, "
                    "run_config_audit, list_processes, check_file_integrity, ...) to learn about "
                    "the target. If the goal asks to CHANGE something on the target, Kratos does "
                    "not do that -- recommend the action in your final_answer instead of running it."
                ),
            }
        if _STATE_CHANGE_RE.search(cmd):
            return {
                "status": "error",
                "observation": (
                    "This investigation is observe-and-recommend only. run_linux_command may run "
                    "READ-ONLY local diagnostics on Kratos's own host, not state-changing commands "
                    "(service/package/user/file/firewall changes, reboots, etc.). Do NOT execute "
                    "remediation -- put the recommended command in your final_answer for a human "
                    "to run instead."
                ),
            }

    # Backstop for tools marked requires_approval=True: don't rely solely on
    # the tool's own in-handler request_approval() call being present and
    # correct. Mark the approval log's length before running the handler,
    # then after it returns, verify request_approval was actually invoked for
    # this tool during the call. If a future requires_approval tool forgets
    # to call it (a real regression, not a hypothetical), its result is
    # refused here rather than silently trusted just because the flag says
    # it should have been gated.
    approval_mark = approval_log_length() if tool.requires_approval else None

    try:
        result = tool.handler(**call_args)
    except TypeError as e:
        return {"status": "error", "observation": f"Bad arguments for tool '{tool_name}': {e}"}
    except Exception as e:
        return {"status": "error", "observation": f"Tool '{tool_name}' raised an error: {e}"}

    if approval_mark is not None and not approval_was_recorded(tool.name, approval_mark):
        return {
            "status": "error",
            "observation": (
                f"Tool '{tool_name}' is registered with requires_approval=True, but no approval "
                "prompt was recorded during this call -- refusing to trust its result. This "
                "indicates a bug in the tool's implementation (it must call request_approval and "
                "check its return value before taking any irreversible action)."
            ),
        }

    if tool_name == "run_linux_command" and isinstance(result, dict):
        # Stamp the result unmissably as the Kratos host so the model can't
        # attribute it to the target (the confirmed host-confusion hallucination:
        # it read Kratos-host `dpkg` output and declared the TARGET's fail2ban
        # "not installed", overriding a correct target audit). Put the note first
        # so it leads the observation the model reasons over.
        active_target = get_active_target()
        result = {
            "kratos_host_note": (
                f"[THIS RAN ON KRATOS'S OWN HOST, NOT the monitored target ({active_target}). "
                "Do NOT attribute this result to the target; for target facts use the "
                "target-facing tools.]"
            ),
            **result,
        }

    return {"status": "ok", "result": result}


# Structured recommended-remediation commands (feature 19b). The model MAY
# attach these to a final_answer so a UI can render a copyable command panel
# instead of a human digging them out of prose. They are RECOMMENDATIONS
# ONLY -- Kratos never executes them (the permanent observe-and-recommend
# boundary); nothing in this loop or any consumer wires them to an execution
# path. Bounded and sanitized so a malformed/oversized model response can't
# flood a caller.
_MAX_RECOMMENDED_COMMANDS = 12
_MAX_COMMAND_LEN = 500
_MAX_EXPLANATION_LEN = 500
_VALID_RUN_ON = {"target", "kratos_host"}


def _sanitize_recommended_commands(raw: Any) -> list[dict[str, str]]:
    """Normalize the optional recommended_commands into a clean, bounded list
    of {command, explanation, run_on} dicts. Drops any malformed entry rather
    than raising; returns [] for a missing/non-list value. `run_on` is
    normalized to 'target' (default) or 'kratos_host'."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command") or "").strip()
        if not command:
            continue
        explanation = str(item.get("explanation") or "").strip()[:_MAX_EXPLANATION_LEN]
        run_on = str(item.get("run_on") or "target").strip().lower()
        if run_on not in _VALID_RUN_ON:
            run_on = "target"
        out.append({"command": command[:_MAX_COMMAND_LEN], "explanation": explanation, "run_on": run_on})
        if len(out) >= _MAX_RECOMMENDED_COMMANDS:
            break
    return out


def _cap(text: str, limit: int = OBSERVATION_CHAR_CAP) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated, {len(text) - limit} more chars]"


def _synthesize_fallback_answer(transcript: list[dict[str, Any]]) -> str:
    """
    Best-effort answer built from the transcript when the model reaches the
    final iteration without ever emitting a final_answer itself. Explicit
    that this is a fallback, not a real conclusion -- lists what was actually
    gathered so there's still something usable instead of a bare failure.
    """
    lines = [
        "[Fallback summary -- the agent did not reach its own conclusion before the "
        "iteration limit. Findings gathered during the investigation:]"
    ]
    for entry in transcript:
        tool = entry.get("tool")
        if not tool:
            continue
        obs = json.dumps(entry.get("observation"), default=str)
        if len(obs) > 300:
            obs = obs[:300] + "...[truncated]"
        lines.append(f"- {tool}: {obs}")

    if len(lines) == 1:
        return (
            "Investigation reached the iteration limit before any tool produced usable "
            "evidence. No findings to report."
        )

    lines.append("Review the raw findings above manually; treat this as unfinished, not a clean result.")
    return "\n".join(lines)


def run_agent(
    goal: str,
    data_dir: Path,
    max_iters: int = DEFAULT_MAX_ITERS,
    on_step: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """
    Runs the ReAct loop for `goal`, returns a dict with the outcome and the
    full step-by-step transcript (each entry: iteration, reasoning, tool,
    args, observation) for callers to inspect or print.

    If `on_step` is given, it's called with each transcript entry the moment
    it's produced (useful for live progress in a CLI, since a single LLM call
    can take a minute or more) -- purely a notification hook, doesn't affect
    the loop's decisions or the returned transcript.
    """
    system_prompt = build_system_prompt()
    conversation = f"Investigation goal: {goal}\n"
    transcript: list[dict[str, Any]] = []

    # Real per-run token accounting (feature 7c). run_usage sums every LLM
    # call this run makes; last_context_tokens is the most recent call's
    # prompt_tokens -- the meaningful numerator for a context-fill meter
    # (how full the model's context was on the last turn). Both are added to
    # every return below as additive keys, so a UI has a real number instead
    # of a char-based estimate; existing consumers that read status/
    # final_answer/transcript are unaffected. A live per-iteration meter can
    # also read llm_interface.get_last_token_usage() from an on_step callback.
    run_usage = TokenUsage()
    last_context_tokens = 0

    def _with_usage(result: dict[str, Any]) -> dict[str, Any]:
        result["token_usage"] = run_usage.as_dict()
        result["context_tokens"] = last_context_tokens
        result["context_window"] = get_context_window_tokens()
        return result

    # Hard enforcement (not just a prompt instruction -- a prompt instruction
    # alone already failed to guarantee this in practice): correlate_findings
    # is the deterministic rule engine, the part of Kratos actually engineered
    # to reliably catch known attack patterns. A model concluding purely from
    # raw tool observations, never running it, has real-world precedent for
    # producing a false "nothing suspicious" answer despite genuine evidence
    # already having been collected.
    #
    # Guard 1's actual pass condition is SUCCESS (last_correlate_findings is
    # not None -- set below only when a call returns a real findings list),
    # not mere attempt. This was a real, live-confirmed gap (2026-07-15 Sprint
    # 2 closing regression): a call that failed on hallucinated file paths
    # was never retried, yet still satisfied the old attempt-only check,
    # letting the model conclude on raw observations a real correlation pass
    # never actually validated. correlate_findings_called still tracks
    # whether it's been invoked at least once -- kept as a separate flag
    # (not folded into the success check) because it's still needed to tell
    # "never even tried" apart from "tried and failed" below, which get
    # different feedback: the former can still be waived by an explicit
    # on-the-record explanation in the final_answer text (genuinely nothing
    # to correlate from); the latter cannot be waived that way -- a fixable
    # failure with real error detail available must be retried with a
    # corrected call, not talked past. last_correlate_findings_error holds
    # that real error text so the rejection message can feed it back
    # verbatim, matching the retry pattern already proven to work in this
    # exact investigation (the model self-corrected a YARA timeout from a
    # clear, specific error message with no extra prompting needed).
    # correlate_findings_reject_count bounds how many times a final_answer
    # submitted without a SUCCESSFUL call gets rejected: the first rejection
    # is unconditional (forces the model to actually consider calling it or
    # retrying it), the second is only waived (for the never-attempted case)
    # if the final_answer text itself visibly explains why it's concluding
    # without correlation -- capped at 2 so a stubborn/small model can't turn
    # this into a new max_iters_reached failure by refusing to comply
    # indefinitely.
    correlate_findings_called = False
    last_correlate_findings_error: str | None = None
    correlate_findings_reject_count = 0
    MAX_CORRELATE_REJECTIONS = 2
    _CORRELATION_EXPLAINED_RE = re.compile(r"correlat|rule engine", re.IGNORECASE)

    # Structural guard against a specific, confirmed hallucination pattern
    # (not a general fact-checker -- deliberately narrow, see comment at its
    # use site below): a live attack-and-detect exercise found the model
    # asserting "critical configuration files have not been tampered with"
    # in its final_answer while its OWN check_file_integrity observation,
    # two iterations earlier in the SAME investigation, showed a real
    # changed-file diff. Root-causing why the model loses track of its own
    # prior observation wasn't conclusive (see fixB_hallucination_diagnostic
    # notes) -- this catches the symptom structurally, the same way Fix #2
    # catches "concluded without running correlate_findings" structurally,
    # rather than continuing to chase the underlying cause.
    last_file_integrity_diff: dict[str, Any] | None = None
    file_integrity_reject_count = 0
    MAX_FILE_INTEGRITY_REJECTIONS = 2
    _FILE_INTEGRITY_NO_CHANGE_CLAIM_RE = re.compile(
        r"(?:files?|configs?|configuration)\b[^.]{0,40}\bnot\s+(?:been\s+)?(?:tampered|modified|altered|changed)\b"
        r"|\bnot\s+(?:been\s+)?tampered\s+with\b"
        r"|\bno\s+(?:unauthorized\s+)?tampering\b"
        r"|\bintegrity\s+(?:is\s+|remains\s+|appears\s+)?(?:intact|verified|confirmed)\b"
        r"|(?:files?|configs?|configuration)\b[^.]{0,40}\bunchanged\b",
        re.IGNORECASE,
    )

    # Structural guard against a second, distinct hallucination pattern found
    # during live testing: a final_answer's OWN opening framing contradicting
    # a real HIGH-severity finding correlate_findings itself just produced in
    # THIS investigation, e.g. "there is no suspicious activity detected, but
    # the system has been exposed via SSH with multiple failed login attempts
    # observed" -- a self-contradiction within one answer, not merely an
    # omission. Deliberately narrow like the file-integrity guard above: only
    # checks the dismissive-verdict phrase set against correlate_findings'
    # own severity-ranked output (the most authoritative synthesis available
    # in the investigation), not a general cross-sentence consistency
    # checker. Only fires on a HIGH/CRITICAL finding -- a nuanced answer that
    # mentions low/medium findings without an alarmist verdict is not a
    # contradiction and must not be flagged.
    last_correlate_findings: list[dict[str, Any]] | None = None
    dismissive_contradiction_reject_count = 0
    MAX_DISMISSIVE_CONTRADICTION_REJECTIONS = 2
    _NO_SUSPICIOUS_ACTIVITY_CLAIM_RE = re.compile(
        r"no\s+suspicious\s+activity"
        r"|nothing\s+suspicious"
        r"|no\s+(?:signs?\s+of\s+)?(?:compromise|intrusion|attack)\b"
        r"|system\s+(?:appears?\s+|looks?\s+)?(?:to\s+be\s+)?(?:clean|fine|normal|secure|safe)\b"
        r"|no\s+(?:issues?|problems?|concerns?)\s+(?:were\s+|was\s+)?(?:found|detected|identified)\b",
        re.IGNORECASE,
    )

    # Structural guard against a fourth, distinct hallucination pattern found
    # in real usage (2026-07-17): a final_answer confidently stating a
    # specific claimed timeframe ("last 24 hours") while correlate_findings'
    # own staleness_warning (adapters/findings_engine.py::_staleness_warning)
    # says the auto-discovered inputs it just correlated span FAR more than
    # that -- a real transcript showed the model see this exact warning and
    # answer "in the last 24 hours" anyway, no caveat. Same narrow,
    # phrase-matched philosophy as guards 2/3, not a general time-window
    # verifier: correlate_findings has no per-event time-window filtering at
    # all (find_latest_inputs just grabs whichever file is newest on disk),
    # so this guard can only catch "claims a specific recency window AND the
    # engine's own contemporaneity check already flagged a real problem" --
    # it cannot verify the claimed window is otherwise accurate. Tracks the
    # LATEST correlate_findings call's staleness_warning only (mirrors
    # last_file_integrity_diff's "latest wins" pattern below) -- a later,
    # fresher call genuinely clearing the warning must un-arm this guard.
    last_staleness_warning: str | None = None
    staleness_timeframe_reject_count = 0
    MAX_STALENESS_TIMEFRAME_REJECTIONS = 2
    _TIMEFRAME_CLAIM_RE = re.compile(
        r"\b(?:last|past|over\s+the\s+last|over\s+the\s+past|within\s+the\s+last|within\s+the\s+past)"
        r"\s+(?:\d+\s*)?(?:hours?|days?|weeks?|months?)\b",
        re.IGNORECASE,
    )

    def _record(entry: dict[str, Any]) -> None:
        transcript.append(entry)
        if on_step is not None:
            on_step(entry)

    for i in range(1, max_iters + 1):
        is_final_iteration = i == max_iters
        prompt_for_call = conversation
        if is_final_iteration:
            prompt_for_call += FINAL_ITERATION_NUDGE
        elif i >= max_iters - WRAP_UP_REMAINING_ITERS:
            prompt_for_call += WRAP_UP_NUDGE

        raw = agent_chat(system_prompt=system_prompt, user_prompt=prompt_for_call, max_tokens=MAX_TOKENS_QUESTION)

        # Fold this call's real usage into the run totals (get_last_token_usage
        # reflects the call just made -- serial by construction). A backend
        # that reports no usage leaves the totals unchanged rather than erroring.
        _call_usage = get_last_token_usage()
        if _call_usage is not None:
            run_usage.add(_call_usage)
            last_context_tokens = _call_usage.prompt_tokens

        if raw is None:
            _record({"iteration": i, "status": "llm_unavailable"})
            return _with_usage({"status": "llm_unavailable", "transcript": transcript})

        parsed = _parse_agent_json(raw)
        if parsed is None:
            if is_final_iteration:
                fallback = _synthesize_fallback_answer(transcript)
                _record({"iteration": i, "status": "parse_error", "raw_response": raw, "final_answer": fallback})
                return _with_usage({"status": "max_iters_reached", "final_answer": fallback, "transcript": transcript})

            correction = (
                "ERROR: your last response was not valid JSON per the required schema. "
                'Respond with exactly one JSON object: {"reasoning": "...", "tool": "...", "args": {...}} '
                'or {"reasoning": "...", "final_answer": "..."}.'
            )
            _record({"iteration": i, "status": "parse_error", "raw_response": raw})
            conversation += f"\nAssistant: {raw}\nObservation: {correction}\n"
            continue

        if "final_answer" in parsed:
            final_answer_text = parsed["final_answer"]
            # Optional structured remediation recommendations (feature 19b) --
            # sanitized here, carried through unchanged whether or not the
            # guards below NOTE-tag the prose answer. Recommendations only;
            # never executed.
            recommended_commands = _sanitize_recommended_commands(parsed.get("recommended_commands"))

            # Each guard's violated/can-reject condition is computed up front
            # (against the model's raw answer) before any rejection or
            # NOTE-tagging happens, so a final_answer tripping multiple
            # guards at once can be handled in ONE combined pass below rather
            # than each guard independently rejecting-and-retrying (which
            # previously cost one iteration PER violated guard on the same
            # bad answer).

            # --- Guard 1: correlate_findings must have SUCCEEDED ---
            # last_correlate_findings is not None <=> a real findings list was
            # returned -- see the tracking-var comment above for why success,
            # not attempt, is the actual condition now.
            correlate_never_attempted = not correlate_findings_called
            correlate_attempted_and_failed = correlate_findings_called and last_correlate_findings is None
            correlate_missing = correlate_never_attempted or correlate_attempted_and_failed
            # The "explain and skip" bypass only applies to the never-attempted
            # case (genuinely nothing to correlate from). A failed attempt has
            # a real, fixable error available -- that must be retried with a
            # corrected call, not talked past with an explanation sentence.
            explains_skip = correlate_never_attempted and bool(_CORRELATION_EXPLAINED_RE.search(final_answer_text))
            guard1_violated = correlate_missing and not explains_skip
            guard1_can_reject = (
                guard1_violated
                and not is_final_iteration
                and correlate_findings_reject_count < MAX_CORRELATE_REJECTIONS
            )

            # --- Guard 2: file-integrity contradiction (Fix F) ---
            # Deliberately narrow (file-integrity claims only, via a small
            # fixed phrase set) rather than a general fact-checker -- broader
            # scope risks false-triggering on unrelated phrasing. Only the
            # "false negative" direction (claims clean when it wasn't) is
            # checked, since that's the concrete failure pattern observed;
            # the reverse (claims tampering when it was clean) is a
            # different, rarer failure mode not covered here.
            has_real_file_changes = bool(
                last_file_integrity_diff
                and (
                    last_file_integrity_diff.get("changed")
                    or last_file_integrity_diff.get("added")
                    or last_file_integrity_diff.get("removed")
                )
            )
            guard2_violated = has_real_file_changes and bool(
                _FILE_INTEGRITY_NO_CHANGE_CLAIM_RE.search(final_answer_text)
            )
            guard2_can_reject = (
                guard2_violated
                and not is_final_iteration
                and file_integrity_reject_count < MAX_FILE_INTEGRITY_REJECTIONS
            )

            # --- Guard 3: dismissive-verdict contradiction ---
            # Severity-gated, fixed phrase set, not a general consistency
            # checker -- see the tracking-var comment above for why this is
            # scoped narrowly. Only fires on a real HIGH/CRITICAL finding.
            high_severity_findings = [
                f for f in (last_correlate_findings or [])
                if isinstance(f, dict) and str(f.get("severity", "")).lower() in ("high", "critical")
            ]
            guard3_violated = bool(high_severity_findings) and bool(
                _NO_SUSPICIOUS_ACTIVITY_CLAIM_RE.search(final_answer_text)
            )
            guard3_can_reject = (
                guard3_violated
                and not is_final_iteration
                and dismissive_contradiction_reject_count < MAX_DISMISSIVE_CONTRADICTION_REJECTIONS
            )

            # --- Guard 4: staleness-vs-claimed-timeframe contradiction ---
            # Deliberately narrow (fixed timeframe-phrase regex, only fires
            # when correlate_findings' OWN staleness_warning is non-null) --
            # see the tracking-var comment above for the real incident and
            # scope limits.
            guard4_violated = bool(last_staleness_warning) and bool(
                _TIMEFRAME_CLAIM_RE.search(final_answer_text)
            )
            guard4_can_reject = (
                guard4_violated
                and not is_final_iteration
                and staleness_timeframe_reject_count < MAX_STALENESS_TIMEFRAME_REJECTIONS
            )

            corrections: list[str] = []
            violations: list[str] = []

            if guard1_can_reject:
                correlate_findings_reject_count += 1
                violations.append("missing_correlation")
                if correlate_attempted_and_failed:
                    corrections.append(
                        "REJECTED (correlate_findings attempted but never succeeded): your "
                        "correlate_findings call did not return a real result -- concluding on raw "
                        "tool observations without a successful correlation pass risks missing "
                        f"evidence you already collected. The real error was: "
                        f"{last_correlate_findings_error!r}. If this was caused by a guessed file "
                        "path, retry correlate_findings using the EXACT path string from a prior "
                        "tool's own Observation in this conversation (e.g. run_nmap_scan's "
                        "parsed_json_file, collect_system_context's context_file, parse_auth_log's "
                        "stats_file) -- or omit the argument entirely to auto-discover the latest "
                        "file. Do not guess a new path."
                    )
                else:
                    corrections.append(
                        "REJECTED (correlate_findings not called): correlate_findings has not been "
                        "called yet in this investigation. It is the deterministic rule engine that "
                        "reliably classifies raw observations into real findings -- concluding without "
                        "ever running it risks missing evidence you already collected. Either call "
                        "correlate_findings now to synthesize what you've gathered, or if it genuinely "
                        "cannot run (e.g. no collection tool succeeded that it could use as input), your "
                        "final_answer text itself must explicitly say so (e.g. 'concluding without "
                        "correlate_findings because ...') -- a reasoning field alone is not enough, and "
                        "this cannot be omitted silently."
                    )

            if guard2_can_reject:
                file_integrity_reject_count += 1
                violations.append("file_integrity_contradiction")
                corrections.append(
                    "REJECTED (file-integrity contradiction): this final_answer's "
                    "characterization of file/config integrity conflicts with "
                    "check_file_integrity's actual result from THIS investigation. The real diff "
                    f"was: {json.dumps(last_file_integrity_diff)}. Revise your final_answer so it "
                    "accurately reflects this -- do not claim files are unchanged/not tampered "
                    "with when this diff shows real changes."
                )

            if guard3_can_reject:
                dismissive_contradiction_reject_count += 1
                violations.append("dismissive_verdict_contradiction")
                finding_summary = "; ".join(f"{f.get('id')}: {f.get('title')}" for f in high_severity_findings)
                corrections.append(
                    "REJECTED (dismissive-verdict contradiction): this final_answer's overall "
                    "verdict (e.g. 'no suspicious activity') contradicts real HIGH/CRITICAL "
                    f"finding(s) correlate_findings just produced in THIS investigation: "
                    f"{finding_summary}. Revise your final_answer so its overall characterization "
                    "is consistent with these findings -- do not describe the investigation as "
                    "clean/unsuspicious while also citing evidence that contradicts that."
                )

            if guard4_can_reject:
                staleness_timeframe_reject_count += 1
                violations.append("staleness_timeframe_contradiction")
                corrections.append(
                    "REJECTED (staleness-vs-timeframe contradiction): this final_answer states a "
                    "specific recency window (e.g. 'in the last 24 hours'), but correlate_findings' "
                    f"own staleness_warning from THIS investigation says: {last_staleness_warning!r} "
                    "-- the data you correlated is not actually known to be confined to that window. "
                    "Revise your final_answer to either drop the specific timeframe claim, or "
                    "explicitly caveat that the underlying data spans a wider/uncertain window than "
                    "what was asked."
                )

            if corrections:
                # Rejecting-and-retrying needs a next iteration to retry into,
                # so each guard above only contributes here when one exists
                # and its own retry budget isn't spent (guard*_can_reject).
                # Combining every violated-and-rejectable guard into a single
                # correction + single continue means one bad final_answer
                # tripping multiple guards costs one retried iteration, not
                # one per guard.
                correction = "\n\n".join(corrections)
                _record({
                    "iteration": i,
                    "reasoning": parsed.get("reasoning", ""),
                    "status": "final_answer_rejected",
                    "violations": violations,
                    "attempted_final_answer": final_answer_text,
                })
                conversation += f"\nAssistant: {json.dumps(parsed)}\nObservation: {correction}\n"
                continue

            # No guard rejected this attempt (either none were violated, or
            # the final iteration/rejection budget forecloses rejecting) --
            # the visibility requirement still applies regardless, so any
            # guard that's STILL violated gets tagged directly in the answer
            # text rather than silently accepted as a fully-corroborated
            # conclusion it isn't.
            if guard1_violated:
                if correlate_attempted_and_failed:
                    final_answer_text = (
                        "[NOTE: correlate_findings (the deterministic rule engine) was attempted "
                        "during this investigation but never returned a successful result (last "
                        f"error: {last_correlate_findings_error!r}), and this conclusion does not "
                        "explain why -- treat it as a lower-confidence, observation-only "
                        "conclusion, not one corroborated by the rule engine.]\n\n" + final_answer_text
                    )
                else:
                    final_answer_text = (
                        "[NOTE: correlate_findings (the deterministic rule engine) was never run "
                        "during this investigation, and this conclusion does not explain why -- "
                        "treat it as a lower-confidence, observation-only conclusion, not one "
                        "corroborated by the rule engine.]\n\n" + final_answer_text
                    )

            if guard2_violated:
                final_answer_text = (
                    "[NOTE: this answer's characterization of file/config integrity conflicts "
                    f"with check_file_integrity's actual result from this investigation: "
                    f"{json.dumps(last_file_integrity_diff)}. Treat the file-integrity portion of "
                    "this answer as unreliable -- trust the diff above instead.]\n\n" + final_answer_text
                )

            if guard3_violated:
                finding_summary = "; ".join(f"{f.get('id')}: {f.get('title')}" for f in high_severity_findings)
                final_answer_text = (
                    "[NOTE: this answer's overall verdict conflicts with real HIGH/CRITICAL "
                    f"finding(s) from this investigation: {finding_summary}. Treat the dismissive "
                    "framing above as unreliable.]\n\n" + final_answer_text
                )

            if guard4_violated:
                final_answer_text = (
                    "[NOTE: this answer states a specific recency window, but correlate_findings' "
                    f"own staleness_warning from this investigation says: {last_staleness_warning!r} "
                    "-- the underlying data is not actually confirmed to be confined to that window. "
                    "Treat the claimed timeframe as unreliable.]\n\n" + final_answer_text
                )

            _record({
                "iteration": i,
                "reasoning": parsed.get("reasoning", ""),
                "final_answer": final_answer_text,
                "recommended_commands": recommended_commands,
            })
            return _with_usage({
                "status": "final_answer",
                "final_answer": final_answer_text,
                "recommended_commands": recommended_commands,
                "transcript": transcript,
            })

        if "tool_proposal" in parsed:
            # Evo-loop auto-suggest (2026-07-18): a structured, reliably
            # parseable signal distinct from ordinary prose -- same
            # reliability principle as the [NOTE:...] guards above (a
            # known, code-recognized shape, not a fragile string match on
            # final_answer text), but implemented as its own top-level
            # JSON key rather than a text-embedded tag, since [NOTE:...]
            # itself is a one-way DISPLAY string (confirmed via a real
            # audit: nothing anywhere re-parses the literal "[NOTE:" text)
            # and a proposal needs to be a real, structured object a
            # caller (cli/repl.py) can act on, not just show. Never ends
            # the investigation and never invokes anything on its own --
            # auto-suggest only, per this project's standing no-auto-
            # escalation principle; /evolve (cli/repl.py) is the only
            # thing that can ever actually start evo-loop.
            proposal = parsed.get("tool_proposal") or {}
            proposal_name = str(proposal.get("name") or "").strip()
            proposal_description = str(proposal.get("description") or "").strip()

            if is_final_iteration:
                # Same treatment as a tool call attempted on the final
                # iteration (see the tool-call branch below) -- there's no
                # next iteration for the human-facing surfacing to matter
                # for THIS run, and the loop must still conclude with a
                # real final_answer now.
                fallback = _synthesize_fallback_answer(transcript)
                _record({
                    "iteration": i,
                    "reasoning": parsed.get("reasoning", ""),
                    "status": "final_iteration_tool_proposal_ignored",
                    "attempted_tool_proposal": proposal,
                    "final_answer": fallback,
                })
                return _with_usage({"status": "max_iters_reached", "final_answer": fallback, "transcript": transcript})

            if not proposal_name or not proposal_description:
                # Same "don't silently accept a broken structure" stance
                # as a parse_error -- tell the model precisely what's
                # missing and let it retry, rather than surfacing a
                # half-empty suggestion to the human.
                correction = (
                    "ERROR: a tool_proposal needs both a non-empty 'name' and 'description'. Respond "
                    'with {"reasoning": "...", "tool_proposal": {"name": "...", "description": "..."}} '
                    "or continue the investigation with a tool call / final_answer instead."
                )
                _record({"iteration": i, "status": "tool_proposal_malformed", "raw_response": raw})
                conversation += f"\nAssistant: {raw}\nObservation: {correction}\n"
                continue

            _record({
                "iteration": i,
                "reasoning": parsed.get("reasoning", ""),
                "tool_proposal": {"name": proposal_name, "description": proposal_description},
            })
            conversation += (
                f"\nAssistant: {json.dumps(parsed)}\n"
                f"Observation: Tool proposal noted ({proposal_name!r}) -- this has been surfaced to "
                "the human; you do not need to build it or mention it again. Continue the "
                "investigation and reach a final_answer when ready.\n"
            )
            continue

        tool_name = parsed.get("tool")
        args = parsed.get("args") or {}

        if is_final_iteration:
            # The FINAL_ITERATION_NUDGE told the model a tool call here would
            # not be executed -- honor that instead of quietly running it
            # anyway, and synthesize a fallback answer from whatever was
            # actually gathered in the iterations before this one.
            fallback = _synthesize_fallback_answer(transcript)
            _record({
                "iteration": i,
                "reasoning": parsed.get("reasoning", ""),
                "status": "final_iteration_tool_call_ignored",
                "attempted_tool": tool_name,
                "final_answer": fallback,
            })
            return _with_usage({"status": "max_iters_reached", "final_answer": fallback, "transcript": transcript})

        exec_result = execute_tool_call(tool_name, args, data_dir)

        if tool_name == "correlate_findings":
            # correlate_findings_called just tracks "was it attempted at
            # least once" (used only to distinguish never-attempted from
            # attempted-but-failed for guard 1's feedback/bypass logic, see
            # comment at its declaration) -- it is NOT guard 1's pass
            # condition anymore. That's last_correlate_findings being set
            # below, which requires a genuinely successful call with a real
            # findings list.
            correlate_findings_called = True

            inner_result = exec_result.get("result") if isinstance(exec_result, dict) else None
            if isinstance(inner_result, dict) and isinstance(inner_result.get("findings"), list):
                last_correlate_findings = inner_result["findings"]
                last_correlate_findings_error = None
                # "Latest wins" -- see guard 4's tracking-var comment above.
                # Not nested under the findings check specifically for any
                # other reason; a successful call always has this key (None
                # when there's nothing stale to warn about), so this is the
                # correct place to read it regardless of whether findings
                # happened to be empty.
                last_staleness_warning = inner_result.get("staleness_warning")
            else:
                # Real error text, from whichever layer it surfaced at:
                # execute_tool_call's own top-level error (bad tool name/
                # args, an exception from the handler) or the handler's own
                # domain-level error result (e.g. correlate_findings's real
                # "guessed file path" validation, which returns an error
                # dict rather than raising). Fed back verbatim in guard 1's
                # rejection message below -- not summarized/genericized.
                if isinstance(exec_result, dict) and exec_result.get("status") == "error":
                    last_correlate_findings_error = exec_result.get("observation") or "correlate_findings failed with no error detail."
                elif isinstance(inner_result, dict) and inner_result.get("status") == "error":
                    last_correlate_findings_error = inner_result.get("observation") or "correlate_findings failed with no error detail."
                else:
                    last_correlate_findings_error = "correlate_findings call did not return a real findings result."

        if tool_name == "check_file_integrity":
            # Only a real "ok" diff counts (not "baseline_established" --
            # nothing to contradict yet -- and not "error"). Tracks the
            # LATEST diff only, matching what a human reviewer would compare
            # a final answer against.
            inner_result = exec_result.get("result") if isinstance(exec_result, dict) else None
            if isinstance(inner_result, dict) and inner_result.get("status") == "ok" and isinstance(inner_result.get("diff"), dict):
                last_file_integrity_diff = inner_result["diff"]

        _record({
            "iteration": i,
            "reasoning": parsed.get("reasoning", ""),
            "tool": tool_name,
            "args": args,
            "observation": exec_result,
        })

        observation_json = _cap(json.dumps(exec_result, default=str))
        conversation += f"\nAssistant: {json.dumps(parsed)}\nObservation: {observation_json}\n"

    # Unreachable in practice (the is_final_iteration branches above always
    # return), but kept as a safety net in case max_iters is 0 or negative.
    _record({"status": "max_iters_reached"})
    return _with_usage({"status": "max_iters_reached", "transcript": transcript})
