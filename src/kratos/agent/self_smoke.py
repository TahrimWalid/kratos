"""
Sprint 2 self-writing loop -- OPTIONAL LIVE-TARGET SMOKE TEST (A7).

The sandbox (Part B) mocks the SSH layer -- by design, since the sandbox has no
network -- so a candidate can PASS its sandbox test and still FAIL live (read a
root-only file without sudo, run the wrong command, get empty output). Two real
tools shipped broken exactly this way (docs/evoloop_polish_brief.md, 2026-09-07).
The write-step prompt hardening (self_write.py) reduces the FREQUENCY; this is
the actual FIX for the trust gap: run the sandbox-passed candidate ONCE against
the REAL target, read-only, at keep time, so a mock-vs-live gap surfaces BEFORE
the tool is persisted and used on every future investigation.

This deliberately breaks the sandbox's no-network isolation for one controlled
run -- so it is:
  - OPT-IN PER RUN, default OFF (offered at keep time; a non-'y' answer skips
    it -- never a persisted auto-flag, which would be a standing
    pre-approval-execution path someone forgets is on).
  - Offered ONLY for a TARGET-FACING candidate (one that reaches the monitored
    device over ssh_remote) with a real target configured -- a local-data tool
    has no mock-vs-live SSH gap to surface.
  - Preceded by the candidate's full source + review flags (informed consent:
    the reviewer has SEEN the code before choosing to run it), shown by the
    caller (self_approve.py) in the offer prompt itself.
  - READ-ONLY BY INTENT, NOT by enforcement. There is no sandbox here; the
    candidate runs unsandboxed on the host with real network. The control is the
    human's informed consent after reading the code, exactly like every other
    approval gate in this project. Whatever fixed command the candidate contains
    is what runs -- so the reviewer, not this module, is the boundary.
  - NEVER auto-keep. The smoke result only INFORMS the human keep decision that
    still follows; nothing here approves, persists, or registers anything.

Registration hygiene: importing the candidate triggers @register_tool (its only
way to expose a handler), which mutates TOOL_REGISTRY. This module snapshots
whether the name was already present and REMOVES a registration it introduced,
so a smoke test never leaves a tool live without a real keep decision -- the
only thing that legitimately persists a tool is Part D's _persist_kept_tool,
strictly after approval.
"""
from __future__ import annotations

import importlib.util
import inspect
import time
from dataclasses import dataclass
from pathlib import Path

# Loopback / self targets are NOT the monitored device -- a smoke test against
# Kratos's own host has no target mock-vs-live gap to reveal, so it's not offered
# there. Mirrors agent/loop.py's own set.
_LOOPBACK_SELF_TARGETS = {"127.0.0.1", "localhost", "::1"}

_SSH_MARKERS = ("ssh_remote", "run_remote_command", "run_remote_script")

# Cap on the live output shown to the reviewer (a runaway/verbose live result
# shouldn't flood the keep prompt).
_OUTPUT_CAP_CHARS = 2000


@dataclass
class SmokeResult:
    ran: bool                 # did the handler actually get called?
    ok: bool                  # did it return without raising?
    output: str               # repr of the return value (capped), or ""
    error: str | None         # why it didn't run, or the exception if it raised
    duration_seconds: float


def is_target_facing(source_code: str) -> bool:
    """A candidate that reaches the monitored device over SSH -- the only kind
    with a mock-vs-live gap a smoke test can surface."""
    return any(m in source_code for m in _SSH_MARKERS)


def smoke_test_available(source_code: str, active_target: str | None) -> bool:
    """Whether a live smoke test is meaningful for this candidate: it's
    target-facing AND a real (non-loopback) target is configured."""
    if not is_target_facing(source_code):
        return False
    if not active_target or active_target.strip() in _LOOPBACK_SELF_TARGETS:
        return False
    return True


def run_live_smoke_test(candidate_path: Path, tool_name: str, data_dir: Path | None = None) -> SmokeResult:
    """Import the sandbox-passed candidate, call its handler ONCE (read-only by
    intent) against whatever the real target returns, and report the result.
    Restores TOOL_REGISTRY afterward so the smoke run never leaves the tool
    registered without a real keep decision.

    Only ever called after an explicit per-run opt-in in the keep flow (see
    self_approve.py). Never raises -- every failure is captured into the
    SmokeResult so the caller can surface it and continue to the keep decision."""
    from kratos.agent.tools import TOOL_REGISTRY

    t0 = time.monotonic()
    # Snapshot the ENTIRE registry, not just tool_name: importing the candidate
    # runs EVERY @register_tool in it, so a candidate with a hidden second
    # registration would otherwise leak a tool into TOOL_REGISTRY after a smoke
    # run -- live, with no keep decision. The finally below removes anything the
    # import added and restores anything it overwrote, so a smoke test leaves
    # the registry exactly as it found it. (Part A validates one literal name,
    # but this contains a candidate that ignores that anyway.)
    pre_entries = dict(TOOL_REGISTRY)

    try:
        spec = importlib.util.spec_from_file_location(f"kratos_smoke_{candidate_path.stem}", candidate_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # triggers @register_tool
    except Exception as e:  # noqa: BLE001
        return SmokeResult(ran=False, ok=False, output="", error=f"could not import candidate: {e}",
                           duration_seconds=time.monotonic() - t0)

    try:
        if tool_name not in TOOL_REGISTRY:
            return SmokeResult(ran=False, ok=False, output="",
                               error=f"candidate did not register a tool named '{tool_name}'",
                               duration_seconds=time.monotonic() - t0)
        handler = TOOL_REGISTRY[tool_name].handler

        try:
            sig = inspect.signature(handler)
        except (TypeError, ValueError):
            sig = None

        kwargs: dict = {}
        missing: list[str] = []
        if sig is not None:
            for pname, p in sig.parameters.items():
                if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                    continue
                if pname == "data_dir":
                    if data_dir is not None:
                        kwargs["data_dir"] = data_dir
                    # data_dir is auto-injected at real dispatch; if we have none
                    # and it's required, that's a real gap -> report below.
                    elif p.default is p.empty:
                        missing.append(pname)
                elif p.default is p.empty:
                    missing.append(pname)
        if missing:
            return SmokeResult(
                ran=False, ok=False, output="",
                error=(f"this quick check can't supply required argument(s): {', '.join(missing)} "
                       "-- a live check only runs a tool that needs no arguments (or just data_dir)"),
                duration_seconds=time.monotonic() - t0,
            )

        result = handler(**kwargs)
        out = repr(result)
        if len(out) > _OUTPUT_CAP_CHARS:
            out = out[:_OUTPUT_CAP_CHARS] + f"\n…[truncated, {len(out) - _OUTPUT_CAP_CHARS} more chars]"
        return SmokeResult(ran=True, ok=True, output=out, error=None, duration_seconds=time.monotonic() - t0)
    except Exception as e:  # noqa: BLE001 -- a candidate blowing up live is exactly what we want to surface
        return SmokeResult(ran=True, ok=False, output="", error=f"{type(e).__name__}: {e}",
                           duration_seconds=time.monotonic() - t0)
    finally:
        # Registration hygiene: restore the registry to EXACTLY its pre-smoke
        # state -- drop every key the import added (incl. any hidden extra
        # registration), and put back any pre-existing entry the import
        # overwrote. A smoke test never leaves a tool live without a real keep.
        for k in list(TOOL_REGISTRY.keys()):
            if k not in pre_entries:
                del TOOL_REGISTRY[k]
        for k, v in pre_entries.items():
            if TOOL_REGISTRY.get(k) is not v:
                TOOL_REGISTRY[k] = v
