"""
Trivial verification-only test harness -- used to exercise /evolve's REPL
wiring end-to-end for real (2026-07-18), not a real product tool. Kept
alongside the real harnesses (same directory/convention, not a throwaway
scratch location) so the write step sees a real, correctly-shaped harness
file, matching every other candidate this pipeline has ever produced.
Deliberately the simplest possible spec (no args, one fixed key in the
return dict) to keep real LLM write-step iterations fast while verifying
the REPL wiring itself, not the write step's own reliability (already
covered by Phase 3a/3d).
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "evolve_verification_ping"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip(
            "CANDIDATE_MODULE_PATH not set -- this harness is meant to be pointed at a staged "
            "candidate (by Part B) or a reference implementation (manual sanity check)."
        )
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY, (
        f"Candidate did not register a tool named '{TOOL_NAME}' via @register_tool -- "
        f"found instead: {sorted(TOOL_REGISTRY.keys())}"
    )
    return TOOL_REGISTRY[TOOL_NAME].handler


def test_returns_pong_true(registered_handler):
    result = registered_handler()
    assert isinstance(result, dict)
    assert result.get("pong") is True
