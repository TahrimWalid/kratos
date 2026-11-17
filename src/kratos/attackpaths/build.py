"""Build a group's attack paths (E.1 decision 10): a fleet-style, code-only run.

Resolve the group within the caller's scope, load each machine's newest stored snapshots
(refusing any older than ``paths.max_input_age_hours`` -- counted in PATH-005, never read to
fill the gap), build the typed graph, rank entries and paths, find chokepoints, write the
``path_*`` rows and the per-run snapshot, and emit PATH-001..005 through the normal lifecycle
per machine. **No model call, so the budget cost is zero**; nothing reads a machine.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos import kratos_config
from kratos.attackpaths import settings as S
from kratos.lifecycle.decide import Actor

logger = logging.getLogger(__name__)

BUILD_INTERFACES = ("tui", "cli", "schedule")


class PathBuildError(ValueError):
    """The build can't run as asked (no such group, nothing visible, no person)."""


@dataclass
class BuildOutcome:
    status: str                         # done | incomplete | no_data
    run_id: str
    group_label: str
    machines: int
    outside_scope: int
    snapshot_file: str = ""
    entries: list[Any] = field(default_factory=list)
    paths: list[Any] = field(default_factory=list)
    chokepoints: list[Any] = field(default_factory=list)
    coverage: Any = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


def _check_actor(actor: Actor) -> None:
    if not isinstance(actor, Actor) or actor.interface not in BUILD_INTERFACES or not str(actor.user or "").strip():
        raise PathBuildError("an attack-path build needs an actor (who built it, through which interface)")


def run_path_build(*, data_dir: Path, group: str | list[str], actor: Actor, source: str = "interactive",
                   scope: Any = None, name: str = "") -> BuildOutcome:
    """Build the attack paths for a group. Raises PathBuildError only for a request that
    can't start; everything else is a BuildOutcome in plain words."""
    from kratos import authz, run_context
    from kratos.adapters.findings_engine import finding_dict
    from kratos.attackpaths import chokepoint as CH
    from kratos.attackpaths import construct, crown, entries as EN, findings as F, inputs as IN, judge as J
    from kratos.attackpaths import paths as PA
    from kratos.attackpaths import record
    from kratos.attackpaths import graph as G
    from kratos.fleet import groups as fleet_groups
    from kratos.lifecycle import apply as lc_apply, coverage as lc_coverage, migrate as lc_migrate
    from kratos.trace import recorder as _trace

    _check_actor(actor)
    data_dir = Path(data_dir)
    if kratos_config.get_active_data_dir() is None:
        kratos_config.set_active_data_dir(data_dir)

    # D.7: a build is a cross-machine synthesis -> the fleet door, scoped.
    try:
        who = authz.require(actor, authz.P.FLEET_ASK, data_dir=data_dir,
                            obj=f"attack-path build over {group if isinstance(group, str) else 'a list'}")
    except authz.Denied as e:
        raise PathBuildError(str(e)) from None
    if not who.scope.every:
        mine = list(who.scope.names)
        scope = mine if scope is None else [m for m in scope if authz.scope_allows(mine, m)]
    try:
        resolved = fleet_groups.resolve(data_dir, group, scope=scope)
    except fleet_groups.GroupError as e:
        raise PathBuildError(str(e)) from None
    label = resolved.label

    with run_context.run_scope(source, target=None):
        with _trace.run_trace("paths", data_dir, name=label, machines=len(resolved.machines),
                              outside_scope=resolved.outside_scope) as tr:
            run = run_context.current()
            run_id = (tr.trace_id if tr is not None else None) or (run.run_id if run else "adhoc")
            record.start(data_dir, run_id=run_id, group_ref=label, actor=actor, source=source,
                         machines=len(resolved.machines), outside_scope=resolved.outside_scope, trace_id=run_id)

            caps = G.Caps(max_nodes=int(S.get(S.MAX_NODES, data_dir)),
                          max_edges=int(S.get(S.MAX_EDGES, data_dir)),
                          max_path_len=int(S.get(S.MAX_PATH_LEN, data_dir)),
                          max_paths=int(S.get(S.MAX_PATHS, data_dir)),
                          max_machines=int(S.get(S.MAX_MACHINES, data_dir)))
            assume = bool(S.get(S.ASSUME_SAME_NETWORK, data_dir))

            with authz.acting_as(actor, action=authz.P.FLEET_ASK):
                machine_inputs = IN.load_group(data_dir, resolved.machines, now=time.time())
            graph = construct.build_graph(machine_inputs, caps=caps, assume_same_network=assume)
            ents = EN.entries(graph)
            crowns = crown.crown_jewels(graph, machine_inputs)
            paths_list, path_caps = PA.enumerate_paths(graph, crowns,
                                                       max_path_len=caps.max_path_len, max_paths=caps.max_paths)
            graph.caps_hit |= path_caps
            chokes = CH.chokepoints(graph, paths_list)
            cov = J.coverage_numbers(machine_inputs, paths_list, graph.caps_hit,
                                     outside_scope=resolved.outside_scope)
            single = len([m for m in machine_inputs.values() if m.has_data()]) <= 1
            specs = J.judge(graph, ents, crowns, paths_list, chokes, cov, data_dir=data_dir,
                            group_label=label, single_machine_scope=single)
            finding_rows = [{"target_key": s.target_key, **s.payload} for s in specs]

            built_at = time.time()
            snapshot_file = record.write_snapshot(data_dir, run_id=run_id, group_ref=label, graph=graph,
                                                  entries=ents, paths=paths_list, chokepoints=chokes,
                                                  coverage=cov, findings=finding_rows, built_at=built_at)
            record.finish(data_dir, run_id, graph=graph, entries=ents, paths=paths_list, chokepoints=chokes,
                          coverage=cov, snapshot_file=snapshot_file,
                          status=("incomplete" if graph.caps_hit else "done"))

            # Emit PATH-* through the lifecycle, per machine. Coverage marks ONLY attack_paths
            # fresh, so a machine's old PATH finding that is gone this build is mitigated, and
            # no other rule's finding is touched.
            lc_migrate.ensure_imported(data_dir)
            snap_doc = {"findings": finding_rows}
            cover = lc_coverage.Coverage(inputs={"attack_paths": None})
            for mk in resolved.machines:
                mk_findings = [finding_dict(f) for f in F.findings_for(snap_doc, mk)]
                with kratos_config.pinned_target(mk):
                    lc_apply.apply_run(mk_findings, target=mk, coverage=cover, run=run, data_dir=data_dir)

            status = "incomplete" if graph.caps_hit else ("no_data" if cov.machines_read == 0 else "done")
            summary = _summary(label, ents, paths_list, chokes, cov)
            _trace.set_result(status=status, machines=cov.machines_read, nodes=len(graph.nodes),
                              edges=len(graph.edges), paths=len(paths_list))
            return BuildOutcome(status=status, run_id=run_id, group_label=label, machines=len(resolved.machines),
                                outside_scope=resolved.outside_scope, snapshot_file=snapshot_file, entries=ents,
                                paths=paths_list, chokepoints=chokes, coverage=cov, findings=finding_rows,
                                summary=summary)


def _summary(label: str, entries: list[Any], paths_list: list[Any], chokes: list[Any], cov: Any) -> str:
    if cov.machines_read == 0:
        return (f"No attack paths for {label}: nothing collected for these machines yet -- run a fleet audit "
                "first. This is coverage, not a clean bill of health.")
    if not paths_list:
        parts = [f"No attack path drawn across {cov.machines_read} machine(s) in {label} from what Kratos has read"]
        gaps = []
        if cov.machines_unread:
            gaps.append(f"{cov.machines_unread} not read")
        if cov.machines_stale:
            gaps.append(f"{cov.machines_stale} too old")
        if cov.ssh_only:
            gaps.append(f"{cov.ssh_only} over SSH only")
        if gaps:
            parts.append("(" + ", ".join(gaps) + ")")
        parts.append("-- this is coverage, not a clean bill of health.")
        return " ".join(parts)
    top = paths_list[0]
    choke = chokes[0] if chokes else None
    s = (f"{len(entries)} entry point(s), {len(paths_list)} path(s) to the machines that matter. Top path "
         f"reaches {top.crown_jewel} in {top.length} hop(s)"
         + ("" if top.fully_observed else f" (assumes {top.assumed_hops} network hop(s))") + ".")
    if choke is not None:
        s += f" Fix first: {choke.fix_title} (cuts {choke.count} path(s))."
    return s


def read_latest(data_dir: Path, group_ref: str) -> dict[str, Any] | None:
    """The newest build's full snapshot doc for a group, or None. Tries the '@name' and the
    bare-name forms of the group ref."""
    from kratos.attackpaths import record

    for ref in (group_ref, f"@{group_ref.lstrip('@')}", group_ref.lstrip("@")):
        row = record.latest(data_dir, ref)
        if row is not None and row.get("snapshot_file"):
            return record.load_snapshot(row["snapshot_file"])
    return None


def read_scoped(data_dir: Path, actor: Actor, group: str) -> tuple[dict[str, Any] | None, set[str] | None]:
    """A reader's scoped view of the newest build for a group (PATHS_READ, viewer+). Returns
    (scoped doc or None, the reader's visible machines or None for all). Raises
    PathBuildError when the reader may not read it."""
    from kratos import authz
    from kratos.attackpaths import scope as SC
    from kratos.target_key import target_key

    try:
        who = authz.require(actor, authz.P.PATHS_READ, data_dir=data_dir,
                            obj=f"attack paths for {group}")
    except authz.Denied as e:
        raise PathBuildError(str(e)) from None
    visible = None if who.scope.every else {target_key(n) for n in who.scope.names}
    doc = read_latest(data_dir, group or "all")
    if doc is None:
        return None, visible
    return SC.scoped_view(doc, visible), visible
