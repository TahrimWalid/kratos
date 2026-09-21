"""
Self-writing tool loop -- APPROVAL-TO-KEEP step only (Part C of
write -> test -> human-approve -> keep; see docs/DESIGN.md's "Self-writing
tool loop" section for the full pipeline).

Takes a Part A staged candidate + its Part B SandboxTestResult, and asks the
human ONE question at a time via agent/tools.py::request_approval (reused
unmodified, not replaced) -- first whether to keep the candidate at all,
then (only if kept) whether it should require per-call approval on future
invocations. Returns a structured KeepDecision. Does not write to
TOOL_REGISTRY, does not move the candidate out of staging, and does not
persist anything beyond the returned decision record -- that's Part D's
job (agent/self_write_loop.py).

Two decisions this module makes, and why:

1. No force-accept, ever, on the keep decision. Unlike the structural
   final_answer guards in agent/loop.py (which force-accept after a
   bounded retry budget with an explicit inline note -- an acceptable
   tradeoff for a one-off report conclusion), a keep decision persists a
   new capability into the tool registry. An unanswered, denied, or
   interrupted approval-to-keep prompt always resolves to permanent
   reject -- no retry budget, no eventual auto-accept path.

2. Per-tool requires_approval is decided here, at keep time, as an
   explicit question -- not a global setting and not hardcoded. Framed as
   an inverted question ("allow this to run without approval?")
   specifically so request_approval's existing fail-safe behavior
   (anything other than an exact 'y' -- including no input, EOFError, or
   KeyboardInterrupt -- resolves to False) does the right thing for free:
   a non-'y' answer to "allow unattended?" means requires_approval=True,
   the correct fail-safe default, with zero changes to request_approval's
   own code. See _ask_requires_approval.

The refusal gate (Sec 2 of the task this module implements) is structural,
not conventional: request_keep_approval computes the refusal reason FIRST,
unconditionally, as its very first statement, and only calls the internal
prompting helper if that reason is None. The prompting helper additionally
re-checks the same condition as its own first statement and RAISES if it
somehow doesn't hold -- so even a future code path that calls the prompting
helper directly, bypassing request_keep_approval, fails loudly instead of
quietly offering an approval prompt it should never offer.

tool_name is a REQUIRED, non-Optional str parameter here, sourced from
whoever staged the candidate (Part A's WriteResult.tool_name) rather than
re-derived by this module from the file's source text. Part A now
guarantees (see agent/self_write.py's _validate_candidate) that a staged
candidate always has a statically-resolved literal tool name -- a second,
independent parser here re-guessing the same thing from raw source (this
module used to do exactly that, via regex) would be the "second, different
parsing mechanism" this whole pipeline has deliberately avoided everywhere
else, and could in principle disagree with Part A's own AST-based answer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from kratos.agent import console as _console
from kratos.agent.tools import request_approval
from kratos.agent.self_test import SandboxTestResult
from kratos.agent.self_review_flags import (
    scan_review_flags,
    format_review_flags_plain,
)
from kratos.agent.self_smoke import smoke_test_available, run_live_smoke_test, SmokeResult

# Shown verbatim on EVERY approval prompt. Encodes two lessons learned from
# adversarial review testing: a hardcoded IP can silently reclassify events
# with the behavior undisclosed in the tool's own description, and an
# ordinary, non-adversarial goal can still produce an invented, overfit
# filter heuristic that's honestly disclosed but whose description
# overstates its reliability. Deliberately guidance, not a gate -- see this
# module's no-force-accept design; nothing here blocks.
REVIEWER_GUIDANCE = (
    "Any invented filter/suppression heuristic should be distrusted regardless of how "
    "well-commented it is -- verify it matches what the tool's description claims, not just what "
    "the test data happened to include. A tool's description is not proof of its behavior -- "
    "check that stated behavior and actual conditional logic agree."
)

_SUBTEST_LINE_RE = re.compile(r'^.*::\S+\s+(PASSED|FAILED|ERROR|SKIPPED)\b.*$', re.MULTILINE)

# Display-only cap. Larger than agent/loop.py's OBSERVATION_CHAR_CAP (1500)
# since a code review needs more room than a tool observation does.
DISPLAY_CHAR_CAP = 4000


class CandidateNotApprovable(Exception):
    """
    Raised only if _prompt_for_keep_decision is ever invoked directly for a
    non-passing SandboxTestResult -- defense in depth on top of
    request_keep_approval's own unconditional early-return guard. Should be
    structurally unreachable in normal use; its existence is the point.
    """


@dataclass
class AttemptRecord:
    """
    One write/test attempt in a candidate's history. Part D (retry
    orchestration, bounded ~2x per our earlier decision) doesn't exist yet
    -- this is a stubbed-but-ready data contract so Part D can start
    populating real attempt_history lists the moment it exists, without
    this module or its approval-prompt display logic needing to change. A
    candidate that passed on its first attempt has a history of exactly one
    AttemptRecord (nothing failed to reach that first pass).
    """
    attempt_number: int
    staging_path: Path
    test_result: SandboxTestResult
    write_feedback: str | None = None  # feedback fed back into Part A's retry prompt, if any


@dataclass
class KeepDecision:
    candidate_path: Path
    tool_name: str                    # sourced from Part A's WriteResult.tool_name, always a real name
    approved: bool
    requires_approval: bool           # fail-safe default True; only meaningful when approved=True
    approved_at: str                  # ISO timestamp of THIS decision (approve, deny, OR refusal -- not only a successful approval)
    refused: bool                     # True if this never reached a human prompt at all (see refusal_reason)
    refusal_reason: str | None = None
    test_result: SandboxTestResult | None = None
    attempt_history: list[AttemptRecord] = field(default_factory=list)


def _cap_for_display(text: str, limit: int = DISPLAY_CHAR_CAP) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated, {len(text) - limit} more chars -- see {DISPLAY_CHAR_CAP=} in agent/self_approve.py]"


def _subtest_summary(stdout: str) -> str:
    matches = _SUBTEST_LINE_RE.finditer(stdout)
    summary_lines = [m.group(0).strip() for m in matches]
    if not summary_lines:
        return "(harness did not report per-sub-test PASSED/FAILED lines -- only pass/fail + exit_code available)"
    return "\n".join(summary_lines)


def _refusal_reason(test_result: SandboxTestResult) -> str | None:
    """
    The single source of truth for "is this candidate even eligible for a
    keep prompt" -- both request_keep_approval's early-return guard and
    _prompt_for_keep_decision's defensive re-check call this SAME function,
    so the two can never disagree.
    """
    if test_result.infra_error is not None:
        return (
            "SANDBOX INFRASTRUCTURE ERROR (not a candidate test failure) -- the sandbox itself "
            f"did not run cleanly, so its result says nothing about the candidate's correctness: "
            f"{test_result.infra_error}"
        )
    if not test_result.passed:
        kind = "TIMED OUT" if test_result.timed_out else "FAILED"
        return (
            f"CANDIDATE TEST {kind} (exit_code={test_result.exit_code}) -- refusing to offer a "
            "keep decision. A failing/timed-out candidate must go back through Part A/B "
            "(write + sandbox test), not be presented to a human for approval."
        )
    return None


def _format_attempt_history(attempt_history: list[AttemptRecord]) -> str:
    if not attempt_history:
        return "(none -- this candidate was staged and tested without any prior failed attempts)"
    lines = []
    for a in attempt_history:
        r = a.test_result
        outcome = "PASSED" if r.passed else ("TIMED OUT" if r.timed_out else "FAILED")
        lines.append(
            f"  attempt {a.attempt_number}: {outcome} (exit_code={r.exit_code}, "
            f"duration={r.duration_seconds:.2f}s) -- {a.staging_path.name}"
            + (f"\n    write feedback given to next attempt: {a.write_feedback}" if a.write_feedback else "")
        )
    return "\n".join(lines)


def _ask_requires_approval(tool_name: str) -> bool:
    """
    Returns requires_approval. Deliberately asks the INVERTED question ("run
    WITHOUT approval?") so request_approval's existing fail-safe behavior --
    anything other than an exact 'y' resolves to False -- produces the
    correct fail-safe default (requires_approval=True) on any non-'y'
    answer, including no answer, EOFError, or KeyboardInterrupt. No changes
    to request_approval itself.
    """
    allow_unattended = request_approval(
        f"Let '{tool_name}' run on its own?",
        {
            "question": (
                f"From now on, should '{tool_name}' be allowed to run automatically, WITHOUT "
                "asking you first each time?"
            ),
            "recommended": (
                "Recommended: NO for now. Keep it asking you first until you've seen it work a few "
                "times and trust it -- you can switch it to automatic later in Settings -> Tools."
            ),
            "note": (
                "Answer 'y' ONLY if you want it to run unattended. Anything else -- no answer, a "
                "cancelled prompt, or any key other than 'y' -- keeps it asking you first (the "
                "safe default)."
            ),
        },
    )
    # Inverted on purpose: request_approval returns True only on an explicit
    # 'y', and its fail-safe (any non-'y'/interrupt -> False) then maps to the
    # SAFE default requires_approval=True for free. The wording above is
    # friendlier than the old "UNATTENDED EXECUTION" framing but the mechanism
    # is unchanged (A7 keep-prompt reframe).
    return not allow_unattended


def _format_smoke_result(smoke: SmokeResult, target: str) -> str:
    if not smoke.ran:
        return (
            f"The live check did NOT run ({smoke.duration_seconds:.1f}s): {smoke.error}\n"
            "(This says nothing about whether the tool is correct -- decide on the code + test below.)"
        )
    if smoke.ok:
        return (
            f"Ran against the REAL target {target} in {smoke.duration_seconds:.1f}s and returned:\n"
            f"{smoke.output}\n\n"
            "Compare this to what the real target SHOULD return. If it looks empty, wrong, or "
            "unlike reality, the tool has a gap its mocked test hid -- discard and fix it."
        )
    return (
        f"Ran against the REAL target {target} in {smoke.duration_seconds:.1f}s but FAILED:\n"
        f"{smoke.error}\n\n"
        "The tool errors against the real target even though it passed its MOCKED test -- a real "
        "mock-vs-live gap. Discarding and fixing it is strongly advised."
    )


def _offer_and_run_smoke(
    candidate_path: Path, tool_name: str, source_code: str, review_flags,
) -> str | None:
    """A7 optional live-target smoke test. Offered (opt-in, default skip) ONLY
    for a target-facing candidate with a real target configured. The offer shows
    the full source + review flags FIRST (informed consent: the reviewer sees
    the code before choosing to run it), and warns plainly that this executes
    the candidate for real, unsandboxed, against the live target. Read-only by
    intent -- the human's consent after reading the code is the boundary, there
    is no sandbox here. Returns a human-facing summary of what the live run did,
    or None if unavailable/declined. Never keeps anything; only informs the keep
    decision that follows."""
    from kratos.kratos_config import get_active_target

    target = get_active_target()
    if not smoke_test_available(source_code, target):
        return None

    offer_details: dict[str, Any] = {
        "what this is": (
            f"'{tool_name}' passed a test that fed it FAKE (mocked) target data. You can optionally "
            f"run it ONCE against the REAL target ({target}) right now, read-only, to see what it "
            "actually returns -- this is how you catch a tool that looks right but breaks live "
            "(wrong command, permission denied, empty output)."
        ),
        "IMPORTANT -- this RUNS the tool for real": (
            "Choosing yes executes the code below on THIS machine, unsandboxed, reaching the live "
            "target -- whatever command the tool contains WILL run. Read the code first. The tool "
            "is NOT kept by this; you still decide that afterward."
        ),
        "things to check first": _cap_for_display(format_review_flags_plain(review_flags)),
        "the exact code that will run": _cap_for_display(source_code),
        "action": (
            "Run this live check now? 'y' = run it once against the real target, anything else = "
            "skip it and go straight to the keep decision."
        ),
    }
    if not request_approval(f"LIVE CHECK (read-only): {tool_name}", offer_details):
        return None

    _console.render_note(
        _console.get_stderr_console(),
        f"Running '{tool_name}' once against {target} (live, read-only)…",
    )
    smoke = run_live_smoke_test(candidate_path, tool_name)
    return _format_smoke_result(smoke, target)


def _prompt_for_keep_decision(
    candidate_path: Path,
    tool_name: str,
    test_result: SandboxTestResult,
    attempt_history: list[AttemptRecord],
    decided_at: str,
) -> KeepDecision:
    if _refusal_reason(test_result) is not None:
        raise CandidateNotApprovable(
            "_prompt_for_keep_decision called with a non-passing SandboxTestResult -- this is "
            "structurally unreachable via request_keep_approval and indicates a bug in a caller "
            "that invoked this helper directly."
        )

    source_code = candidate_path.read_text(encoding="utf-8")
    label = tool_name

    # A coarse, non-blocking static pre-scan surfaced BEFORE the raw
    # source -- directs attention, never replaces reading the full source
    # below (which stays complete and unredacted). See
    # agent/self_review_flags.py for what each check looks for and why;
    # see REVIEWER_GUIDANCE above for the accompanying textual guidance
    # shown on every prompt.
    review_flags = scan_review_flags(source_code)

    # Optional live-target smoke test: offered (opt-in) BEFORE the keep
    # decision, for a target-facing candidate with a real target. Its result is
    # folded into the keep details below so the human decides WITH the live
    # evidence in hand. Skipped/declined -> None -> the keep prompt is unchanged.
    smoke_summary = _offer_and_run_smoke(candidate_path, tool_name, source_code, review_flags)

    details: dict[str, Any] = {
        "what just happened": (
            f"A new tool, '{label}', was written and PASSED its test -- so it does what the test "
            "says. Keeping it lets Kratos use it from now on. It does NOT run right now."
        ),
        **({"live target check (read-only)": _cap_for_display(smoke_summary)} if smoke_summary else {}),
        "things to check first": _cap_for_display(format_review_flags_plain(review_flags)),
        "how to review": REVIEWER_GUIDANCE,
        "the tool's code (read it -- this runs on your machine once kept)": _cap_for_display(source_code),
        "test results": _cap_for_display(_subtest_summary(test_result.stdout)),
        "exit_code": test_result.exit_code,
        "duration_seconds": round(test_result.duration_seconds, 2),
        "attempt_history": _cap_for_display(_format_attempt_history(attempt_history)),
        "candidate_file": str(candidate_path),
        "action": (
            f"Keep '{label}' so Kratos can use it? 'y' = keep it, anything else (including no "
            "answer or a cancelled prompt) = discard it permanently. Keeping it does NOT run it "
            "now -- you'll get one more question about whether it may run without asking."
        ),
    }

    approved = request_approval(f"KEEP CANDIDATE: {label}", details)

    if not approved:
        _console.render_note(_console.get_stderr_console(), f"DENIED -- candidate not kept: {candidate_path}")
        return KeepDecision(
            candidate_path=candidate_path, tool_name=tool_name, approved=False,
            requires_approval=True, approved_at=decided_at, refused=False,
            test_result=test_result, attempt_history=attempt_history,
        )

    requires_approval = _ask_requires_approval(label)
    _console.render_success(
        _console.get_stderr_console(),
        f"APPROVED -- candidate kept: {candidate_path} (requires_approval={requires_approval})",
    )
    return KeepDecision(
        candidate_path=candidate_path, tool_name=tool_name, approved=True,
        requires_approval=requires_approval, approved_at=decided_at, refused=False,
        test_result=test_result, attempt_history=attempt_history,
    )


def request_keep_approval(
    candidate_path: Path,
    tool_name: str,
    test_result: SandboxTestResult,
    attempt_history: list[AttemptRecord] | None = None,
) -> KeepDecision:
    """
    The only public entry point. Structurally cannot reach a human approval
    prompt unless test_result.passed is True and test_result.infra_error is
    None -- the refusal check below is this function's first statement,
    unconditional, with no parameter or flag that skips it. See module
    docstring for why this is structural, not conventional.

    tool_name comes from the caller (Part A's WriteResult.tool_name in
    practice) -- see module docstring for why this module deliberately does
    not re-derive it from candidate_path itself.

    Never writes to TOOL_REGISTRY, never moves/deletes candidate_path, never
    touches anything on disk beyond printing to stderr -- denial, refusal,
    and approval are all pure no-ops on the candidate's filesystem state.
    Persisting an approved candidate is Part D's job.
    """
    attempt_history = attempt_history or []
    decided_at = datetime.now().isoformat(timespec="seconds")

    reason = _refusal_reason(test_result)
    if reason is not None:
        _console.render_error(_console.get_stderr_console(), f"REFUSED (no approval prompt offered) -- {reason}")
        return KeepDecision(
            candidate_path=candidate_path, tool_name=tool_name, approved=False,
            requires_approval=True, approved_at=decided_at, refused=True, refusal_reason=reason,
            test_result=test_result, attempt_history=attempt_history,
        )

    # request_approval's OWN try/except (agent/tools.py) only wraps its
    # input() call -- an interrupt landing EARLIER, e.g. during
    # _prompt_for_keep_decision's print() calls before input() is ever
    # reached, propagates as an uncaught KeyboardInterrupt instead of
    # resolving to a denial. Deliberately fixed HERE, one level up, rather
    # than widening request_approval's own try block: this wraps the WHOLE
    # prompting sequence (both questions, and everything between/before
    # them), catches exactly what request_approval's own fail-safe already
    # treats as a denial (EOFError, KeyboardInterrupt) so the two stay
    # consistent, and leaves request_approval's already-verified internal
    # logic completely untouched.
    try:
        return _prompt_for_keep_decision(candidate_path, tool_name, test_result, attempt_history, decided_at)
    except (KeyboardInterrupt, EOFError) as e:
        _console.render_note(
            _console.get_stderr_console(),
            f"DENIED -- interrupted ({type(e).__name__}) before or during the approval prompt -- "
            "fail-safe: treating as a clean denial, nothing persisted.",
        )
        return KeepDecision(
            candidate_path=candidate_path, tool_name=tool_name, approved=False,
            requires_approval=True, approved_at=decided_at, refused=False,
            test_result=test_result, attempt_history=attempt_history,
        )
