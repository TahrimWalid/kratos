"""The ``paths.*`` settings (E.1 §5.1; Settings -> General -> Attack paths).

A path build is pure code over stored evidence (no model call, no machine read), so
these are all bounds and one display cap -- nothing here spends money or reaches a
machine.
"""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.settings import _on_off, _whole
from kratos.settings_store import SettingError, SettingSpec

MAX_NODES = "paths.max_nodes"
MAX_EDGES = "paths.max_edges"
MAX_PATH_LEN = "paths.max_path_len"
MAX_PATHS = "paths.max_paths"
MAX_MACHINES = "paths.max_machines"
MAX_INPUT_AGE_HOURS = "paths.max_input_age_hours"
ASSUME_SAME_NETWORK = "paths.assume_same_network"
SEVERITY_CAP = "paths.severity_cap"

# PATH-* severity never exceeds this (gate decision, 2026-11-16: high, never critical --
# E.1 states a structural possibility, not an observed compromise; the underlying
# findings carry the critical verdicts). A test pins the cap.
SEVERITY_CHOICES = ("medium", "high")


def _severity_cap(value: Any) -> str:
    v = str(value or "").strip().lower()
    if v not in SEVERITY_CHOICES:
        raise SettingError(f"one of: {', '.join(SEVERITY_CHOICES)}")
    return v


for _spec in (
    SettingSpec(MAX_NODES, 5000, _whole(100, 100000, "nodes"),
                "The most nodes (machines, services, accounts, keys, containers, code folders) one attack-path "
                "build draws; beyond it the build stops adding nodes and says so in the coverage note."),
    SettingSpec(MAX_EDGES, 20000, _whole(100, 400000, "edges"),
                "The most edges (who-can-reach-what links) one attack-path build draws; beyond it the build stops "
                "adding edges and says so."),
    SettingSpec(MAX_PATH_LEN, 8, _whole(2, 20, "hops"),
                "The longest attack path (entry to a machine that matters) the build follows."),
    SettingSpec(MAX_PATHS, 2000, _whole(10, 50000, "paths"),
                "The most paths one build keeps; they are ranked and the strongest kept."),
    SettingSpec(MAX_MACHINES, 50, _whole(1, 500, "machines"),
                "The most machines one attack-path build covers (the fleet ceiling)."),
    SettingSpec(MAX_INPUT_AGE_HOURS, 72, _whole(1, 8760, "hours"),
                "A machine whose newest stored reading is older than this is counted as a coverage gap and is "
                "never ranked -- Kratos never reads a machine to fill the gap (run a fleet audit first)."),
    SettingSpec(ASSUME_SAME_NETWORK, True, _on_off,
                "Draw assumed 'same network' reach edges between machines in a group when no firewall rule is "
                "known to block them (clearly labelled 'assumed'). Off: only reach edges Kratos actually "
                "observed (an outbound connection a machine made)."),
    SettingSpec(SEVERITY_CAP, "high", _severity_cap,
                "The highest severity an attack-path finding may carry. A path is a possibility built from "
                "structure, not an observed compromise, so the default is 'high', never 'critical'."),
):
    settings_store.register(_spec)


def get(key: str, data_dir: Any) -> Any:
    return settings_store.get(key, data_dir=data_dir)
