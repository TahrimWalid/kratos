"""
Sprint 2 self-writing loop -- ORCHESTRATOR (Part D), the piece that ties
write (A) -> sandbox test (B) -> human-approve (C) together into the actual
write -> test -> human-approve -> keep cycle, plus the one new thing none of
A/B/C do: persisting an APPROVED candidate into the live, agent-loop-
reachable tool set.

Two independent, nested retry budgets exist in this pipeline -- do not
confuse them:
  - Part A's OWN internal retry (agent/self_write.py, MAX_WRITE_ATTEMPTS=3):
    fast, LLM-only, fixes SYNTAX/SHAPE problems (bad Python, missing/
    unresolvable @register_tool name) before anything is ever staged. A
    single call to write_candidate_tool() may itself involve up to 3 LLM
    calls internally.
  - THIS module's retry (MAX_ATTEMPTS=3: 1 initial + 2 retries): slower,
    a full write+sandbox-test round trip per attempt, fixes SEMANTIC/
    behavioral problems only a real test run can reveal. Each of these 3
    attempts is itself a full call into write_candidate_tool() (with its
    own up-to-3 internal sub-retries).

Control flow per attempt:
  - Part A reports "no_variation" -- a response byte-identical to the
    anchor it was retrying against, despite fresh real failing-test context
    (Phase 3f -- a real 5-attempt diagnostic run found attempts 2-5
    SHA-256-identical: the model can stop varying its output entirely,
    distinct from and not caught by the rewrite-vs-patch similarity guard)
    -> stop IMMEDIATELY, do NOT re-run the sandbox test (its result is
    already known -- see attempt_history's last real entry), status
    "stalled_no_variation". Deliberately not the same status as
    "exhausted_retries": that means budget ran out while the model kept
    trying different things; this means the model stopped trying anything
    different while budget remained.
  - Part A fails outright (its own retries exhausted) -> stop, status
    "write_failed". Nothing to test, nothing to retry at this level.
  - Part B reports infra_error -> stop IMMEDIATELY, no retry. A broken
    sandbox is a Kratos-infrastructure problem; re-running the same broken
    sandbox against a different candidate fixes nothing. Status "infra_error".
  - Part B reports passed=False (a real test failure, not infra) -> retry,
    feeding the failed attempt's FULL SOURCE (read back from its staging
    path) and the REAL SandboxTestResult (stdout/stderr, where the actual
    traceback lives) back into Part A's WriteRequest.previous_code /
    previous_error for the next attempt, framed as a targeted-fix request,
    not a fresh rewrite (Phase 3c -- see agent/self_write.py's
    MIN_RETRY_SIMILARITY_RATIO and module docstring for why: two
    independent real qwen2.5:7b runs, Phase 3a/3b, showed retries
    regenerating large parts of the file from scratch instead of making a
    minimal edit, letting already-correct code regress). Bounded at
    MAX_ATTEMPTS; the 3rd failure stops the loop entirely (status
    "exhausted_retries") without ever reaching Part C -- a candidate that
    has never passed has nothing to offer a human to approve.
  - Part B reports passed=True -> Part C. Denial/refusal there ends the
    loop (status "denied"); approval triggers persistence (status "approved").

Registry persistence (the one genuinely new thing here): TOOL_REGISTRY
(agent/tools.py) is PURELY in-memory, a dict populated by @register_tool's
decorator side effect at import time -- there is no existing persistence
mechanism for tool metadata to extend, so this module adds the minimal one
needed: kept_tools/<name>.py (the approved source, imported for real -- the
same @register_tool mechanism every hand-written tool uses, no second
registration path) plus kept_tools/metadata.json (a sidecar, keyed by tool
name, storing just requires_approval + when + which file -- enough for
Sprint 3's /settings to read and edit later, nothing more general than that).

This module's _persist_kept_tool is the FIRST point in the entire pipeline
where candidate code is ever imported/executed on the HOST (Parts A/B/C
never do -- Part B only ever executes inside the sandbox). That is
intentional, not an oversight: it happens strictly AFTER Part C returns
approved=True, i.e. only once a human has explicitly approved this exact
code. "Import" here means running the module's top-level statements
(definitions + the @register_tool(...) decorator call, which just stores
things in a dict) -- it does NOT invoke the tool's own handler function.
Actually CALLING the handler still goes through agent/loop.py's normal
execute_tool_call path, which honors requires_approval exactly as it does
for every hand-written tool.
"""
from __future__ import annotations

import contextlib
import fcntl
import importlib.util
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from kratos.agent import console as _console
from kratos.agent.self_write import write_candidate_tool, WriteRequest, WriteResult
from kratos.agent.self_test import run_sandbox_test, SandboxTestResult
from kratos.agent.self_approve import request_keep_approval, KeepDecision, AttemptRecord

MAX_ATTEMPTS = 3  # 1 initial + 2 retries, per our earlier bounded-retry decision

# Where an APPROVED tool's source actually lives, live and TOOL_REGISTRY-
# reachable -- distinct from sandbox_staging/ (never live, Part A/B only)
# and from src/kratos/agent/tools.py (hand-written tools only, never
# touched by this pipeline). agent/loop.py's build_system_prompt and
# execute_tool_call only ever read TOOL_REGISTRY itself; "live" means
# "imported into this process," not merely "written to disk somewhere."
KEPT_TOOLS_DIR = Path(__file__).resolve().parents[3] / "kept_tools"
KEPT_TOOLS_METADATA_FILENAME = "metadata.json"

# Phase 3b.6 fix: a real 20-trial concurrent-process test (Phase 3b.5, case 2)
# found metadata.json torn/corrupted -- and, separately, the persisted .py
# file and the metadata describing it disagreeing about which of two
# concurrent callers "won" -- because _persist_kept_tool's copy+read+modify+
# write was neither atomic nor serialized against a second concurrent
# invocation. LOCK_FILENAME is a dedicated, empty lockfile (never holds
# data itself) whose sole purpose is an flock() target scoping an exclusive
# lock around the ENTIRE persist operation (file copy + metadata read +
# modify + atomic write), so two concurrent callers are fully serialized --
# one completes entirely before the other's copy2() even starts -- not just
# individually atomic against each other.
KEPT_TOOLS_LOCK_FILENAME = ".kept_tools.lock"


@contextlib.contextmanager
def _kept_tools_lock(kept_tools_dir: Path):
    kept_tools_dir.mkdir(parents=True, exist_ok=True)
    lock_path = kept_tools_dir / KEPT_TOOLS_LOCK_FILENAME
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)  # blocks until held -- no LOCK_NB
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@dataclass
class LoopOutcome:
    # "stalled_no_variation": deliberately distinct from "exhausted_retries"
    # -- the latter means the model kept producing different candidates and
    # ran out of budget; this means the model stopped producing ANY new
    # candidate (byte-identical to the immediately preceding attempt) while
    # budget was still available. Different diagnosis, different fix if one
    # is ever needed -- collapsing them into one status would hide exactly
    # the distinction Phase 3f's real diagnostic run surfaced.
    status: Literal["approved", "denied", "exhausted_retries", "infra_error", "write_failed", "stalled_no_variation"]
    keep_decision: KeepDecision | None
    attempt_history: list[AttemptRecord]
    kept_path: Path | None = None


def _build_retry_error_text(attempt_number: int, test_result: SandboxTestResult) -> str:
    """
    The REASON attempt_number failed -- paired with that attempt's full
    source (read separately from its staging_path and threaded through as
    WriteRequest.previous_code, NOT embedded in this string) so
    agent/self_write.py can show both as distinct, structured pieces of the
    retry prompt. Previously (pre-Phase-3c) this function's return value
    WAS the entire retry payload, and it never included the previous
    attempt's source at all -- confirmed missing, not assumed present, by
    reading this function before making this change. That gap is exactly
    what let two independent real qwen2.5:7b runs (Phase 3a/3b) regenerate
    from scratch each retry instead of editing what they'd already written.
    """
    outcome = "TIMED OUT" if test_result.timed_out else "FAILED"
    return (
        f"Attempt {attempt_number} was staged successfully -- it parsed and matched the "
        f"@register_tool(...) convention -- but {outcome} when actually tested against the "
        f"human-authored test harness in the sandbox.\n"
        f"exit_code={test_result.exit_code}, duration={test_result.duration_seconds:.2f}s\n\n"
        f"Captured stdout (includes the real failure/traceback):\n{test_result.stdout}\n\n"
        f"Captured stderr:\n{test_result.stderr}"
    )


def _import_kept_tool(path: Path) -> None:
    """
    Executes the approved candidate's module-level code for the first time
    on the host -- see module docstring for why this is the correct, and
    only, point in the pipeline where that happens. Triggers
    @register_tool's decorator, which is what actually populates
    TOOL_REGISTRY -- no second registration mechanism.
    """
    spec = importlib.util.spec_from_file_location(f"kratos_kept_tool_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def _read_metadata(kept_tools_dir: Path) -> dict[str, Any]:
    metadata_file = kept_tools_dir / KEPT_TOOLS_METADATA_FILENAME
    if not metadata_file.exists():
        return {}
    return json.loads(metadata_file.read_text(encoding="utf-8"))


def _write_metadata(kept_tools_dir: Path, tool_name: str, source_file: Path, requires_approval: bool) -> None:
    """
    Phase 3b.6: writes via a temp file + os.replace(), never a direct
    write_text() to the live path. os.replace() is an atomic rename on
    POSIX -- a concurrent reader either sees the complete OLD file or the
    complete NEW file, never a torn mix of both (the real, confirmed
    failure mode in Phase 3b.5's case 2: metadata.json ending in "}}",
    unparseable). This alone only fixes TORN WRITES, not LOST UPDATES (two
    concurrent read-modify-write cycles can still race even if each
    individual write is atomic) -- that half is handled by
    _persist_kept_tool's caller holding _kept_tools_lock for this entire
    read+modify+write, not by this function alone.
    """
    metadata = _read_metadata(kept_tools_dir)
    metadata[tool_name] = {
        "requires_approval": requires_approval,
        "kept_at": datetime.now().isoformat(timespec="seconds"),
        "source_file": source_file.name,
    }
    metadata_file = kept_tools_dir / KEPT_TOOLS_METADATA_FILENAME
    # tempfile.mkstemp() defaults to mode 0600 (owner-only) -- os.replace()
    # keeps the TEMP file's mode, not the destination's, so without this
    # explicit chmod every write would silently narrow metadata.json's
    # permissions from whatever they were (matching the other, group-
    # readable kept_tools/*.py files) down to owner-only. Match the existing
    # file's mode if there is one; fall back to a standard 0644 for the
    # very first write.
    target_mode = metadata_file.stat().st_mode & 0o777 if metadata_file.exists() else 0o644
    fd, tmp_name = tempfile.mkstemp(dir=kept_tools_dir, prefix=".metadata.", suffix=".tmp")
    try:
        os.chmod(tmp_name, target_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(metadata, indent=2))
        os.replace(tmp_name, metadata_file)  # atomic on POSIX, same filesystem (same dir)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def _persist_kept_tool(keep_decision: KeepDecision, kept_tools_dir: Path = KEPT_TOOLS_DIR) -> Path:
    """
    THIS is the one moment a candidate becomes live: copied (not moved --
    the staged file in sandbox_staging/ is left in place as a historical
    record, matching Part A/B's own "nothing here is ever silently
    discarded" posture) into kept_tools/, imported (registering it into the
    real TOOL_REGISTRY), its requires_approval forced to the human-approved
    value, and that value persisted to the sidecar metadata file.

    Structurally guarded like every other gate in this pipeline: refuses
    (raises) rather than proceeding if called with a KeepDecision that
    isn't actually approved, or that somehow has no tool_name -- both
    should be unreachable by construction (the former because this is only
    ever called from run_self_write_loop's own approved-branch, the latter
    because agent/self_write.py's write-time validation now guarantees a
    resolved name on every staged candidate) but are checked anyway rather
    than trusted blindly, matching this codebase's established style.
    """
    if not keep_decision.approved:
        raise ValueError("_persist_kept_tool called with an unapproved KeepDecision -- structurally unreachable.")
    if not keep_decision.tool_name:
        raise ValueError("_persist_kept_tool called with no tool_name -- structurally unreachable given Part A's write-time guarantee.")
    # Phase 3b.6 (Case 1 fix): the two checks above only ever verified
    # approved/tool_name -- Phase 3b.5's adversarial test found a fabricated
    # KeepDecision with refused=True AND approved=True simultaneously, or
    # approved=True with a missing/failing test_result, sailed straight
    # through and got persisted. Both are supposed to be structurally
    # unreachable via the real request_keep_approval() path (refused and
    # approved are mutually exclusive branches there; _refusal_reason()
    # never lets a non-passing test reach an approval prompt at all) --
    # checked anyway, matching this module's existing "raise rather than
    # trust blindly" style for the two checks above.
    if keep_decision.refused and keep_decision.approved:
        raise ValueError(
            "_persist_kept_tool called with a KeepDecision that is both refused=True and "
            "approved=True -- structurally unreachable, a decision cannot be simultaneously a "
            "refusal and an approval."
        )
    if keep_decision.test_result is None or keep_decision.test_result.passed is not True:
        raise ValueError(
            "_persist_kept_tool called with a KeepDecision whose test_result is missing or did "
            "not pass -- structurally unreachable given request_keep_approval's own refusal gate "
            "(_refusal_reason), which never offers an approval prompt for a non-passing test."
        )

    # Phase 3b.6 (Case 2 fix): the ENTIRE operation below -- file copy,
    # metadata read, modify, atomic write -- runs under one exclusive lock,
    # so two concurrent callers are fully serialized rather than each half
    # only being individually atomic against the other. See _kept_tools_lock.
    with _kept_tools_lock(kept_tools_dir):
        dest = kept_tools_dir / f"{keep_decision.tool_name}.py"
        shutil.copy2(keep_decision.candidate_path, dest)

        _import_kept_tool(dest)

        from kratos.agent.tools import TOOL_REGISTRY
        if keep_decision.tool_name not in TOOL_REGISTRY:
            raise RuntimeError(
                f"Imported {dest} but '{keep_decision.tool_name}' did not appear in TOOL_REGISTRY -- "
                "the @register_tool(...) name and the approved tool_name have diverged somehow."
            )
        TOOL_REGISTRY[keep_decision.tool_name].requires_approval = keep_decision.requires_approval

        _write_metadata(kept_tools_dir, keep_decision.tool_name, dest, keep_decision.requires_approval)

    _console.render_success(
        _console.get_stderr_console(),
        f"PERSISTED -- '{keep_decision.tool_name}' is now live in TOOL_REGISTRY "
        f"(requires_approval={keep_decision.requires_approval}), source at {dest}",
    )
    return dest


def load_kept_tools(kept_tools_dir: Path = KEPT_TOOLS_DIR) -> list[str]:
    """
    Re-registers every previously-kept tool into TOOL_REGISTRY and restores
    each one's persisted requires_approval flag from metadata.json -- for a
    FRESH Kratos process to call at startup so approved tools survive a
    restart, not just the process that approved them. NOT wired into any
    CLI entry point yet (kratos investigate / kratos run) -- that wiring is
    a follow-up; this function only makes it possible. Returns the tool
    names successfully reloaded.
    """
    metadata = _read_metadata(kept_tools_dir)
    if not metadata:
        return []

    from kratos.agent.tools import TOOL_REGISTRY
    loaded: list[str] = []
    for tool_name, meta in metadata.items():
        source_file = kept_tools_dir / meta["source_file"]
        if not source_file.exists():
            _console.render_error(
                _console.get_stderr_console(),
                f"Evo-loop: metadata references a missing file for '{tool_name}': {source_file}",
            )
            continue
        _import_kept_tool(source_file)
        if tool_name in TOOL_REGISTRY:
            TOOL_REGISTRY[tool_name].requires_approval = meta["requires_approval"]
            loaded.append(tool_name)
    return loaded


def run_self_write_loop(request: WriteRequest, max_attempts: int = MAX_ATTEMPTS) -> LoopOutcome:
    """
    Runs the full write -> test -> [retry] -> human-approve -> keep cycle
    for one write request. See module docstring for the exact control flow
    and the two independent retry budgets involved.
    """
    attempt_history: list[AttemptRecord] = []
    extra_context = request.extra_context
    previous_code: str | None = None
    previous_error: str | None = None

    for attempt_number in range(1, max_attempts + 1):
        attempt_request = WriteRequest(
            goal=request.goal, test_file=request.test_file, extra_context=extra_context,
            previous_code=previous_code, previous_error=previous_error,
        )
        write_result = write_candidate_tool(attempt_request)

        if write_result.status == "no_variation":
            # Distinct from write_failed/exhausted_retries on purpose (see
            # LoopOutcome docstring) -- deliberately NOT calling
            # run_sandbox_test again: the repeated content is byte-identical
            # to the immediately preceding real attempt, so its result is
            # already known -- it's the last entry already in
            # attempt_history, not fabricated or re-fetched here.
            budget_remaining = max_attempts - attempt_number
            _console.render_error(
                _console.get_stderr_console(),
                f"Evo-loop: STALLED on attempt {attempt_number}/{max_attempts} -- the model produced "
                f"a candidate BYTE-IDENTICAL to the immediately preceding attempt, despite being shown "
                f"fresh, real failing-test context. This is NOT exhaustion ({budget_remaining} "
                "attempt(s) of budget remain unused) -- the model stopped varying its output, not the "
                "budget running out. Not re-running the sandbox test; its result is already known.",
            )
            if attempt_history:
                last = attempt_history[-1]
                _console.render_note(
                    _console.get_stderr_console(),
                    f"Evo-loop: the repeated candidate's known result (from attempt "
                    f"{last.attempt_number}): passed={last.test_result.passed} "
                    f"exit_code={last.test_result.exit_code}",
                )
            return LoopOutcome(status="stalled_no_variation", keep_decision=None, attempt_history=attempt_history)

        if write_result.status != "staged":
            _console.render_error(
                _console.get_stderr_console(),
                f"Evo-loop: WRITE STEP FAILED on attempt {attempt_number}/{max_attempts} -- {write_result.error}",
            )
            return LoopOutcome(status="write_failed", keep_decision=None, attempt_history=attempt_history)

        test_result = run_sandbox_test(write_result.staging_path, request.test_file)

        attempt_history.append(AttemptRecord(
            attempt_number=attempt_number,
            staging_path=write_result.staging_path,
            test_result=test_result,
            write_feedback=previous_error,
        ))

        if test_result.infra_error is not None:
            _console.render_error(
                _console.get_stderr_console(),
                f"Evo-loop: SANDBOX INFRASTRUCTURE ERROR on attempt {attempt_number} -- stopping "
                f"immediately, NOT retrying (a broken sandbox is a Kratos problem, not a candidate "
                f"problem): {test_result.infra_error}",
            )
            return LoopOutcome(status="infra_error", keep_decision=None, attempt_history=attempt_history)

        if test_result.passed:
            keep_decision = request_keep_approval(
                write_result.staging_path, write_result.tool_name, test_result, attempt_history,
            )
            if not keep_decision.approved:
                _console.render_note(
                    _console.get_stderr_console(),
                    f"NOT APPROVED (refused={keep_decision.refused}) -- "
                    "nothing persisted, candidate remains in sandbox_staging/ only.",
                )
                return LoopOutcome(status="denied", keep_decision=keep_decision, attempt_history=attempt_history)

            kept_path = _persist_kept_tool(keep_decision)
            return LoopOutcome(
                status="approved", keep_decision=keep_decision, attempt_history=attempt_history, kept_path=kept_path,
            )

        # Real test failure (not infra) -- prepare the next attempt's targeted-fix prompt: the
        # FULL current source (read back from disk, not reconstructed) plus the real error text,
        # both threaded through WriteRequest.previous_code/previous_error (Phase 3c) so the next
        # call to write_candidate_tool shows them as a distinct, structured retry section rather
        # than folding them into the generic extra_context channel.
        _console.render_note(
            _console.get_stderr_console(),
            f"Evo-loop: attempt {attempt_number}/{max_attempts} failed the sandbox test "
            f"(exit_code={test_result.exit_code}, timed_out={test_result.timed_out}) -- retrying with "
            "the real error fed back.",
        )
        previous_code = write_result.staging_path.read_text(encoding="utf-8")
        previous_error = _build_retry_error_text(attempt_number, test_result)

    stderr_console = _console.get_stderr_console()
    _console.render_error(
        stderr_console,
        f"Evo-loop: EXHAUSTED {max_attempts} attempts, none passed -- not proceeding to approval.",
    )
    for a in attempt_history:
        r = a.test_result
        stderr_console.print(
            f"  attempt {a.attempt_number}: exit_code={r.exit_code} timed_out={r.timed_out} passed={r.passed}",
            style=_console.TEXT_SECONDARY,
        )
    return LoopOutcome(status="exhausted_retries", keep_decision=None, attempt_history=attempt_history)
