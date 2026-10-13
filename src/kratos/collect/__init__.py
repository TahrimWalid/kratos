"""Kratos collects by itself.

Before the model reasons about a machine, code makes sure the basics are fresh --
open ports, the last day of sign-in activity, signs of altered logs, privileged
accounts, configuration -- each re-run only when its last result is older than its
freshness limit, in parallel, on a time budget. The model then starts from a short
digest of what was checked and found (and what could not be checked) and drills down
with a small, fixed tool list. Nothing here calls a model, and nothing is written on
a monitored machine: freshness and sync positions live in `kratos.db` on this host.

    registry.py   what a check is; the built-in checks register themselves (checks.py)
    state.py      `collect_state`: last result per machine and check, claims
    runner.py     prepare(): fresh -> reuse, stale -> claim and run in parallel, budget
    digest.py     the model's digest and the one-line summary for the screen
"""
from __future__ import annotations

import os

# "off" turns collection off for this process (an escape hatch for the eval harness,
# tests and anyone who wants the old model-driven behaviour). People change the
# setting `collect.enabled`; this variable only forces it off.
ENV_DISABLE = "KRATOS_COLLECT"


def forced_off() -> bool:
    return os.environ.get(ENV_DISABLE, "").strip().lower() in ("off", "0", "false", "no")
