"""Live-mode lab setup/teardown, kept OUT of the repo.

The attack orchestration a live scenario needs -- a failed login from the attacker
box, a planted EICAR string, a stopped fail2ban -- lives in the durable external
harness (`~/kratos_eval_artifacts/harness.py`, overridable with KRATOS_EVAL_HARNESS),
never in the repository (Phase A's "never vendor offensive tooling into the repo").

This bridge loads that harness lazily and exposes, per scenario id, the `setup(ctx)`
and `teardown(ctx)` it already defines. It is imported only for `--mode live`;
replay mode never touches it, so the gate and its smoke test run with no lab and no
external file present.
"""
from __future__ import annotations

import importlib.util
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

DEFAULT_HARNESS = Path.home() / "kratos_eval_artifacts" / "harness.py"


class HarnessMissing(RuntimeError):
    """The external live harness isn't where it should be (live mode only)."""


def harness_path() -> Path:
    return Path(os.environ.get("KRATOS_EVAL_HARNESS") or DEFAULT_HARNESS)


@lru_cache(maxsize=1)
def _harness() -> Any:
    path = harness_path()
    if not path.is_file():
        raise HarnessMissing(
            f"live mode needs the external scenario harness at {path} (it sets up the lab for each "
            "scenario and is kept out of the repo). Set KRATOS_EVAL_HARNESS, or use --mode replay.")
    import sys

    sys.argv = [str(path)]  # the harness parses argv only as __main__; keep it quiet on import
    spec = importlib.util.spec_from_file_location("kratos_eval_live_harness", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@lru_cache(maxsize=1)
def _scenarios() -> dict[str, dict[str, Any]]:
    return {s["id"]: s for s in _harness().SCENARIOS}


def available() -> bool:
    return harness_path().is_file()


def setup_teardown(scenario_id: str) -> tuple[Callable[[dict], Any], Callable[[dict], Any], dict[str, Any]]:
    """(setup, teardown, extras) for a scenario from the external harness, where
    extras carries its max_iters / needs_baseline / spacing. Unknown id -> no-ops."""
    sc = _scenarios().get(scenario_id)
    if sc is None:
        noop = lambda ctx=None: None  # noqa: E731
        return noop, noop, {}
    extras = {k: sc.get(k) for k in ("max_iters", "needs_baseline", "space") if sc.get(k)}
    return sc["setup"], sc["teardown"], extras


def seed_baseline(data_dir: Path) -> None:
    _harness().seed_baseline(data_dir)
