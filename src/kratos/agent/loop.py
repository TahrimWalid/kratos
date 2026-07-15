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
from kratos.llm_interface import agent_chat
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

INVESTIGATION SCOPE:
Treat any investigation goal as a request for a reasonably thorough security check, not a literal keyword match. "Check for suspicious activity", "has anyone tried to break in", "run a full security check", and "is my server okay" are substantively the same underlying request phrased differently -- a human analyst would not skip network exposure just because the user said "break in" instead of "scan", or skip login activity just because the user said "okay" instead of "auth". Before concluding, briefly consider whether each of these categories is relevant to the goal, even if the wording doesn't mention it directly:
- Network exposure / attack surface (open ports, reachable services)
- Authentication activity (login attempts, sudo usage, failures)
- System state (running services, users, SSH config)
- Running processes (anything unexpected currently executing)
- File/config integrity (tampering with critical files)
- Hardening/config posture (firewall, root login, password auth, patching)
This does NOT mean call every tool regardless of relevance -- if a category is clearly irrelevant given the goal and the evidence gathered so far, say so in your reasoning and move on rather than calling its tool anyway. The goal is broader consideration before concluding, not blind exhaustiveness.

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
    if "data_dir" in tool.parameters and "data_dir" not in call_args:
        call_args["data_dir"] = data_dir

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

    return {"status": "ok", "result": result}


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

        if raw is None:
            _record({"iteration": i, "status": "llm_unavailable"})
            return {"status": "llm_unavailable", "transcript": transcript}

        parsed = _parse_agent_json(raw)
        if parsed is None:
            if is_final_iteration:
                fallback = _synthesize_fallback_answer(transcript)
                _record({"iteration": i, "status": "parse_error", "raw_response": raw, "final_answer": fallback})
                return {"status": "max_iters_reached", "final_answer": fallback, "transcript": transcript}

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

            _record({
                "iteration": i,
                "reasoning": parsed.get("reasoning", ""),
                "final_answer": final_answer_text,
            })
            return {"status": "final_answer", "final_answer": final_answer_text, "transcript": transcript}

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
            return {"status": "max_iters_reached", "final_answer": fallback, "transcript": transcript}

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
    return {"status": "max_iters_reached", "transcript": transcript}
