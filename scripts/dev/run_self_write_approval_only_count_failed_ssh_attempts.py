#!/usr/bin/env python3
"""
Interactive-approval-only driver -- count_failed_ssh_attempts (2026-07-16).

NOT a full write-loop run. This deliberately skips Part A (the write step,
which needs a real LLM call) and reuses the ALREADY-PROVEN candidate from
tonight's real run: sandbox_staging/write_a_kratos_tool_that_counts_failed_s
_20260716_122258_b3d45054.py -- 6/6 harness tests passed, clean review flags
(see that run's full transcript). Re-running the write step would just
regenerate a new candidate via another LLM call for no reason; the point of
THIS script is purely to reach a real, live, interactive Part C approval
prompt, not to re-prove the tool works again.

What this does, in order, using only real, unmodified pipeline code:
  1. Re-runs Part B (run_sandbox_test) fresh against the existing staged
     file -- cheap (~2s, confirmed), deterministic, safe-by-construction
     (no network/filesystem/privilege access), so re-confirming it here
     costs nothing and guarantees an accurate, freshly-generated
     SandboxTestResult rather than a hand-transcribed one.
  2. Calls the real, public request_keep_approval() (agent/self_approve.py)
     directly -- the actual Part C entry point, completely unmodified. This
     blocks on a REAL input() call, exactly like the full loop does.
  3. (2026-07-16, added after a real approved=True run showed nothing was
     actually persisted) If the decision is approved, calls the real
     self_write_loop.py::_persist_kept_tool() -- the SAME function the full
     write-loop driver calls on a real approval, completely unmodified.
     This is the one point in the whole pipeline where candidate code is
     ever imported/executed on the host, and it only runs after a real,
     just-given approved=True.

No mocks, no stdin redirection, no auto-confirm. Must be run in a real,
interactive terminal by a human who will actually read the approval panel
and type an answer -- if stdin isn't a real interactive terminal, input()
will hit EOFError and the (real, documented) fail-safe will auto-deny it,
same as happened at the end of tonight's full run.

No LLM call happens anywhere in this script (Part A is skipped entirely),
so no LLM_MODEL / .env profile / backend selection matters here at all.

Usage (from the repo root, with the venv active):
    python3 scripts/dev/run_self_write_approval_only_count_failed_ssh_attempts.py
"""
from __future__ import annotations

from pathlib import Path

from kratos.agent.self_approve import AttemptRecord, request_keep_approval
from kratos.agent.self_test import run_sandbox_test
from kratos.agent.self_write_loop import _persist_kept_tool

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING_PATH = (
    REPO_ROOT / "sandbox_staging"
    / "write_a_kratos_tool_that_counts_failed_s_20260716_122258_b3d45054.py"
)
TEST_FILE = REPO_ROOT / "tests" / "self_write_harnesses" / "test_count_failed_ssh_attempts.py"
TOOL_NAME = "count_failed_ssh_attempts"


def main() -> int:
    if not STAGING_PATH.exists():
        print(f"FATAL: the proven candidate is no longer at {STAGING_PATH}")
        print("(it may have been cleaned up -- rerun the full write-loop driver instead:")
        print(" scripts/dev/run_self_write_count_failed_ssh_attempts.py)")
        return 2
    if not TEST_FILE.exists():
        print(f"FATAL: harness not found at {TEST_FILE}")
        return 2

    print(f"Re-running the real sandbox test against the existing candidate at:\n  {STAGING_PATH}\n")
    test_result = run_sandbox_test(STAGING_PATH, TEST_FILE)
    print(f"passed={test_result.passed} exit_code={test_result.exit_code} duration={test_result.duration_seconds:.2f}s\n")

    if not test_result.passed:
        print("The candidate did not pass just now (environment may have changed since tonight's")
        print("real run) -- request_keep_approval() will structurally refuse to offer a keep prompt")
        print("for a non-passing result. Printing what it reports instead of a prompt:")

    attempt_history = [
        AttemptRecord(attempt_number=1, staging_path=STAGING_PATH, test_result=test_result, write_feedback=None)
    ]

    decision = request_keep_approval(
        candidate_path=STAGING_PATH,
        tool_name=TOOL_NAME,
        test_result=test_result,
        attempt_history=attempt_history,
    )

    print("\n" + "=" * 70)
    print("KEEP DECISION")
    print("=" * 70)
    print(
        f"approved={decision.approved} requires_approval={decision.requires_approval} "
        f"refused={decision.refused} refusal_reason={decision.refusal_reason!r}"
    )
    if decision.approved:
        kept_path = _persist_kept_tool(decision)
        print(f"\nPERSISTED -- '{TOOL_NAME}' is now live in kept_tools/ and TOOL_REGISTRY.")
        print(f"kept_path: {kept_path}")
        print("Usable in a real `kratos investigate` run from now on (load_kept_tools() re-registers")
        print("it on every fresh process start, same as count_failed_sudo_attempts already is).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
