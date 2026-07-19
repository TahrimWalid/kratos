"""
Throwaway driver -- Sprint 2 self-writing loop real verification run,
count_failed_ssh_attempts (2026-07-16).

Not a CLI subcommand (confirmed via grep against src/kratos/cli/app.py's
build_parser() before writing this: no dedicated entry point for
run_self_write_loop() exists yet -- only load_kept_tools() is wired into
main(), for re-registering already-approved tools, not driving new writes).
Same pattern as every real Sprint 2/3 verification run: a one-off script
that imports run_self_write_loop() directly and calls it with a real
WriteRequest, run against the shipped local backend defaults, no mocks.

Motivation: count_failed_ssh_attempts is the exact tool the model proposed
during a real `kratos investigate` run (2026-07-16) that hit the
run_linux_command/target-remediation capability gap -- grounding this run in
a real scenario, not a synthetic one. Direct analog to the already-kept
count_failed_sudo_attempts (see kept_tools/count_failed_sudo_attempts.py and
tests/self_write_harnesses/test_count_failed_sudo_attempts.py, its harness's
direct precedent).

Usage:
    python3 scripts/dev/run_self_write_count_failed_ssh_attempts.py

Reads LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND from .env like
everything else -- whichever profile is uncommented there is what this runs
against. No overrides in this script.
"""
from __future__ import annotations

from pathlib import Path

from kratos.agent.self_write import WriteRequest
from kratos.agent.self_write_loop import run_self_write_loop

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_FILE = REPO_ROOT / "tests" / "self_write_harnesses" / "test_count_failed_ssh_attempts.py"

GOAL = (
    "Write a Kratos tool that counts failed SSH login attempts from a JSON file of parsed "
    "authentication events (the same auth_events_*.json file parse_auth_log produces). Each "
    "event in the file is an object with an 'event_type' field among other fields; a failed SSH "
    "login attempt is an event whose event_type is exactly 'ssh_failed_login'. The tool should "
    "accept a keyword argument 'auth_events_file' (the path to that JSON file) and return a dict "
    "containing at least a 'failed_ssh_count' key with the count as an integer. This is a "
    "focused, single-purpose counting tool -- it should not attempt to interpret bursts, IPs, or "
    "usernames, just count matching events. Handle malformed input defensively: an event missing "
    "the 'event_type' field, or a non-dict entry in the events list, must not crash the tool -- "
    "such entries simply should not be counted."
)


def main() -> int:
    if not TEST_FILE.exists():
        print(f"FATAL: harness not found at {TEST_FILE}")
        return 2

    request = WriteRequest(goal=GOAL, test_file=TEST_FILE)
    outcome = run_self_write_loop(request)

    print("\n" + "=" * 78)
    print(f"FINAL LOOP STATUS: {outcome.status}")
    print("=" * 78)

    for attempt in outcome.attempt_history:
        r = attempt.test_result
        print(f"\n--- Attempt {attempt.attempt_number} ---")
        print(f"staging_path: {attempt.staging_path}")
        print(
            f"passed={r.passed} timed_out={r.timed_out} exit_code={r.exit_code} "
            f"duration={r.duration_seconds:.2f}s infra_error={r.infra_error!r}"
        )
        if attempt.write_feedback:
            print(f"\nwrite_feedback shown to the NEXT attempt's retry prompt:\n{attempt.write_feedback}")
        print(f"\n--- candidate source at attempt {attempt.attempt_number} ---")
        try:
            print(attempt.staging_path.read_text(encoding="utf-8"))
        except OSError as e:
            print(f"(could not read staged source: {e})")
        print(f"\n--- sandbox stdout, attempt {attempt.attempt_number} ---")
        print(r.stdout)
        print(f"--- sandbox stderr, attempt {attempt.attempt_number} ---")
        print(r.stderr)

    if outcome.keep_decision is not None:
        kd = outcome.keep_decision
        print("\n" + "=" * 78)
        print("KEEP DECISION")
        print("=" * 78)
        print(
            f"approved={kd.approved} requires_approval={kd.requires_approval} "
            f"refused={kd.refused} refusal_reason={kd.refusal_reason!r} tool_name={kd.tool_name!r}"
        )

    if outcome.kept_path is not None:
        print(f"\nKEPT at: {outcome.kept_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
