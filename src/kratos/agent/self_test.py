"""
Sprint 2 self-writing loop -- SANDBOX TEST step only (Part B of
write -> test -> human-approve -> keep, per docs/sprint2_self_writing_loop_design.md).

Runs a Part A staged candidate tool against a human-authored test harness
inside an ephemeral, network-isolated Incus container, and reports a
structured pass/fail result. Does not retry on failure (that's Part D, and
it needs this step's result plus Part A's write step to build a feedback
loop -- neither exists yet), does not seek approval (Part C), does not touch
TOOL_REGISTRY or persist anything (Part D). This module only ever READS the
staged candidate path Part A produced; it never imports or executes it on
the host -- execution only ever happens inside the sandbox container.

Sandbox mechanism: reuses the exact Incus launch/exec/teardown idiom already
used for kratos-target/attacker-box (scripts/attacks/README.md:
`incus launch images:ubuntu/jammy <name>`, `incus exec <name> -- ...`),
extended with two one-time, idempotent preparation steps so PER-TEST-RUN
launches are fast and need no network of their own:

  1. `kratos-sandbox` Incus profile: a root disk device and CPU/memory
     limits, and DELIBERATELY NO NETWORK DEVICE AT ALL -- absence of the
     device, not a disabled/firewalled one, is the isolation mechanism (see
     docs/sprint2_self_writing_loop_design.md Sec 1/3). `--no-profiles`
     alone drops the disk device too (the default profile provides both),
     so this profile exists specifically to keep the disk while dropping
     only the network device.
  2. `kratos-sandbox-base` Incus image: built once (network required only
     for THIS one-time step, never for an actual candidate's test run) by
     launching the same images:ubuntu/jammy base kratos-target/attacker-box
     use, installing pytest + requests (the ONLY two dependencies actually
     needed -- see below), baking in a copy of this project's src/kratos/
     tree at /opt/kratos/src, then publishing the result as a new local
     image. Every actual test run afterward launches instantly from this
     cached image, exactly the same "prepare once, launch fast+isolated
     repeatedly from a cached image" pattern the design doc's own benchmark
     already relies on for images:ubuntu/jammy.

Why pytest + requests are enough: a candidate/harness pair needs to import
kratos.agent.tools (for @register_tool/TOOL_REGISTRY) and pytest (every
human-authored harness, including tests/self_write_harnesses/*, is written
against it). Tracing kratos.agent.tools's full import closure, the ONLY
third-party package it transitively needs is `requests` (used by
kratos.agent.notify for send_notification) -- fastapi/uvicorn/etc in
pyproject.toml's dependency list are for the project's (currently unused
here) API surface, not this path, so they're deliberately not installed
into the sandbox image to keep it minimal.

Measured on this project's own infra (see this module's verification run):
one-time base-image build ~3-4 min (apt/pip install + publish, dominated by
apt-get update/install); PER-TEST-RUN round trip after that is ~1-1.5s
infra overhead (launch ~0.3s, exec ~0.05s, delete ~0.75s) plus actual test
duration -- notably FASTER than the design doc's original ~3.5s no-op
estimate, because that benchmark measured a NETWORK-ATTACHED ephemeral
container; skipping network device setup at launch turns out to be most of
that original cost, not image unpacking.
"""
from __future__ import annotations

import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from kratos.agent import console as _console

INCUS_BASE_IMAGE = "images:ubuntu/jammy"    # same base image kratos-target/attacker-box use
SANDBOX_IMAGE_ALIAS = "kratos-sandbox-base"  # one-time-built, then locally cached
SANDBOX_PROFILE = "kratos-sandbox"           # no-network, resource-capped profile
SANDBOX_CPU_LIMIT = "1"
SANDBOX_MEMORY_LIMIT = "512MiB"
# Observed baseline (bash wrapper + `timeout` + python3 + pytest collection,
# no candidate subprocess activity yet) is pids.current=9. A legitimate
# candidate/harness calls subprocess.run() sequentially, at most 1-2
# processes alive at once (e.g. candidate_4_privilege.py: id/mount/modprobe/
# dmesg/capsh, one at a time, never concurrent) -- so 64 leaves ~7x headroom
# over any real observed usage, while still killing a fork bomb within a
# tiny fraction of a second (64 iterations, not 3000 spawned over ~7s).
SANDBOX_PIDS_LIMIT = "64"

# Hard wall-clock cap on the actual test run INSIDE the container (enforced
# by coreutils `timeout` there) -- a candidate with an infinite loop must
# not hang the sandbox indefinitely. Kept distinct from a normal test
# failure (see SandboxTestResult.timed_out).
TEST_TIMEOUT_SECONDS = 20
# Outer, host-side guard on top of the in-container timeout above -- catches
# the case where the container/incus link itself is unresponsive (not just
# the candidate process), so this module can never hang even if the inner
# `timeout` wrapper somehow didn't fire. Deliberately larger, as slack.
_HOST_SIDE_TIMEOUT_SECONDS = TEST_TIMEOUT_SECONDS + 15
CONTAINER_OP_TIMEOUT_SECONDS = 30  # cap on any individual incus launch/push/delete operation

# Output is truncated INSIDE the container (via `tail -n`) before it ever
# crosses back to the host process -- bounds what a runaway/verbose
# candidate can flood this module with, regardless of how much it actually
# wrote to its own log files on the container's disk.
OUTPUT_CAP_LINES = 200

KRATOS_SRC_IN_CONTAINER = "/opt/kratos/src"
CANDIDATE_PATH_IN_CONTAINER = "/root/candidate.py"
HARNESS_PATH_IN_CONTAINER = "/root/harness.py"

_KRATOS_REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class SandboxTestResult:
    passed: bool
    timed_out: bool
    exit_code: int | None    # None only when infra_error is set (test never actually ran)
    stdout: str               # capped to OUTPUT_CAP_LINES lines
    stderr: str                # capped to OUTPUT_CAP_LINES lines
    duration_seconds: float
    infra_error: str | None = None  # set only if the SANDBOX ITSELF failed -- distinct from a real test failure


def _run_incus(args: list[str], timeout: int = CONTAINER_OP_TIMEOUT_SECONDS, input: str | None = None) -> subprocess.CompletedProcess:
    # capture_output=True buffers this call's output in HOST memory for up to `timeout`
    # seconds (worst case _HOST_SIDE_TIMEOUT_SECONDS, on the actual test-run exec) -- sized
    # against one sandbox running at a time; revisit if Part D (or later work) ever runs
    # tests concurrently, since the worst case scales with however many run in parallel.
    return subprocess.run(["incus", *args], capture_output=True, text=True, timeout=timeout, input=input)


def _ensure_sandbox_profile() -> None:
    """
    Idempotent: creates the no-network, resource-capped profile if missing.
    The resource-limit `profile set` calls run on EVERY call, not just at
    creation -- `profile set` is a cheap, idempotent overwrite, and applying
    limits only at creation-time would silently skip already-provisioned
    infra on a host where this profile predates a limits change (confirmed
    this would otherwise be a real gap: kratos-sandbox already existed on
    this host from prior test runs when limits.processes was added below).
    """
    existing = _run_incus(["profile", "list", "-f", "csv", "-c", "n"])
    names = {line.strip() for line in existing.stdout.splitlines() if line.strip()}
    if SANDBOX_PROFILE not in names:
        _run_incus(["profile", "create", SANDBOX_PROFILE], timeout=10)
        _run_incus(["profile", "device", "add", SANDBOX_PROFILE, "root", "disk", "path=/", "pool=default"], timeout=10)
        # No network device is ever added -- see module docstring.

    _run_incus(["profile", "set", SANDBOX_PROFILE, "limits.cpu", SANDBOX_CPU_LIMIT], timeout=10)
    _run_incus(["profile", "set", SANDBOX_PROFILE, "limits.memory", SANDBOX_MEMORY_LIMIT], timeout=10)
    _run_incus(["profile", "set", SANDBOX_PROFILE, "limits.processes", SANDBOX_PIDS_LIMIT], timeout=10)


def _ensure_sandbox_base_image() -> None:
    """
    Idempotent: build+publish kratos-sandbox-base once if it doesn't already
    exist locally. This is the ONLY point in the entire test-execution path
    that touches the network, and it never runs as part of an individual
    candidate's test -- see module docstring for the full rationale.
    """
    existing = _run_incus(["image", "list", SANDBOX_IMAGE_ALIAS, "-f", "csv", "-c", "l"])
    if SANDBOX_IMAGE_ALIAS in existing.stdout:
        return

    builder = f"kratos-sandbox-builder-{uuid.uuid4().hex[:8]}"
    try:
        _run_incus(["launch", INCUS_BASE_IMAGE, builder], timeout=60)
        _run_incus(
            ["exec", builder, "--", "bash", "-c",
             "for i in $(seq 1 30); do getent hosts archive.ubuntu.com >/dev/null 2>&1 && break; sleep 1; done"],
            timeout=40,
        )
        _run_incus(
            ["exec", builder, "--", "bash", "-c", "apt-get update -qq && apt-get install -y -qq python3-pip >/dev/null"],
            timeout=180,
        )
        _run_incus(["exec", builder, "--", "pip3", "install", "--quiet", "pytest", "requests"], timeout=90)
        _run_incus(
            ["file", "push", "-r", "-p", str(_KRATOS_REPO_ROOT / "src" / "kratos"), f"{builder}/opt/kratos/src/"],
            timeout=60,
        )
        _run_incus(["stop", builder], timeout=30)
        _run_incus(["publish", builder, "--alias", SANDBOX_IMAGE_ALIAS], timeout=120)
    finally:
        _run_incus(["delete", builder, "--force"], timeout=30)


def _tail_capped(container: str, remote_path: str) -> str:
    result = _run_incus(["exec", container, "--", "tail", "-n", str(OUTPUT_CAP_LINES), remote_path])
    return result.stdout


def run_sandbox_test(
    candidate_path: Path,
    harness_path: Path,
    timeout_seconds: int = TEST_TIMEOUT_SECONDS,
) -> SandboxTestResult:
    """
    Runs `harness_path` (human-authored, pytest-based) against
    `candidate_path` (a Part A staged candidate) inside a fresh, ephemeral,
    network-isolated Incus container, and returns a structured result.

    Ensures the sandbox profile/base image exist first (idempotent --
    instant no-ops after the first call on a given host). Tears the
    container down unconditionally in a `finally` block: on a passing test,
    a failing test, a timeout, or an infrastructure error mid-setup.
    """
    _ensure_sandbox_profile()
    _ensure_sandbox_base_image()

    container = f"kratos-sandboxtest-{uuid.uuid4().hex[:8]}"
    t0 = time.monotonic()
    launched = False

    try:
        launch = _run_incus(["launch", SANDBOX_IMAGE_ALIAS, container, "-p", SANDBOX_PROFILE, "--ephemeral"], timeout=60)
        if launch.returncode != 0:
            return SandboxTestResult(
                passed=False, timed_out=False, exit_code=None, stdout="", stderr="",
                duration_seconds=time.monotonic() - t0,
                infra_error=f"Container launch failed: {launch.stderr.strip() or launch.stdout.strip()}",
            )
        launched = True

        push_candidate = _run_incus(["file", "push", str(candidate_path), f"{container}{CANDIDATE_PATH_IN_CONTAINER}"], timeout=30)
        push_harness = _run_incus(["file", "push", str(harness_path), f"{container}{HARNESS_PATH_IN_CONTAINER}"], timeout=30)
        if push_candidate.returncode != 0 or push_harness.returncode != 0:
            return SandboxTestResult(
                passed=False, timed_out=False, exit_code=None, stdout="", stderr="",
                duration_seconds=time.monotonic() - t0,
                infra_error=f"Failed to push candidate/harness into sandbox: "
                            f"{push_candidate.stderr.strip()} {push_harness.stderr.strip()}".strip(),
            )

        # In-container wrapper: redirects stdout/stderr to files (so only a
        # CAPPED tail ever crosses back to the host, regardless of how much
        # a runaway candidate actually writes) and wraps the real command in
        # coreutils `timeout` so a hanging candidate cannot block forever --
        # `timeout` exits 124 specifically on its own kill, distinguishing
        # "timed out" from every one of pytest's own exit codes (0-5).
        script = (
            f"cd /root && "
            f"PYTHONPATH={KRATOS_SRC_IN_CONTAINER} CANDIDATE_MODULE_PATH={CANDIDATE_PATH_IN_CONTAINER} "
            f"timeout {timeout_seconds}s python3 -m pytest {HARNESS_PATH_IN_CONTAINER} -v "
            f"> /root/stdout.log 2> /root/stderr.log; "
            f"exit $?"
        )
        try:
            run = _run_incus(["exec", container, "--", "bash", "-c", script], timeout=_HOST_SIDE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            # The outer host-side guard had to intervene -- treat the same
            # as an in-container timeout from this result's perspective.
            return SandboxTestResult(
                passed=False, timed_out=True, exit_code=None,
                stdout=_tail_capped(container, "/root/stdout.log") if launched else "",
                stderr=_tail_capped(container, "/root/stderr.log") if launched else "",
                duration_seconds=time.monotonic() - t0,
            )

        exit_code = run.returncode
        stdout = _tail_capped(container, "/root/stdout.log")
        stderr = _tail_capped(container, "/root/stderr.log")
        timed_out = exit_code == 124  # coreutils `timeout`'s own kill signal exit code

        return SandboxTestResult(
            passed=(exit_code == 0),
            timed_out=timed_out,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - t0,
        )
    except subprocess.TimeoutExpired as e:
        return SandboxTestResult(
            passed=False, timed_out=False, exit_code=None, stdout="", stderr="",
            duration_seconds=time.monotonic() - t0,
            infra_error=f"Sandbox infrastructure operation timed out: {e}",
        )
    finally:
        # Unconditional teardown -- runs on pass, fail, timeout, or any
        # infra error above. --ephemeral already auto-deletes on stop, but
        # --force (stop+delete) is used directly as a stronger guarantee
        # that doesn't depend on that flag having taken effect correctly.
        if launched:
            # De-emphasized (TEXT_SECONDARY, not the default ATTENTION amber) --
            # routine cleanup bookkeeping, not something decision-relevant for
            # a human watching evo-loop run.
            _console.render_note(
                _console.get_stderr_console(),
                f"Evo-loop: tearing down sandbox container {container}",
                style=_console.TEXT_SECONDARY,
            )
            _run_incus(["delete", container, "--force"], timeout=30)
