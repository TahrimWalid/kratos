"""Turn a built graph into PATH-001..005 findings (E.1 decision 7).

A ``FindingSpec`` pairs a ``target_key`` (the machine the finding is about) with the
finding payload; ``build.py`` groups them by machine and writes them through the normal
lifecycle. Coverage is always numbers: a machine Kratos could not read is counted in
PATH-005, never assumed safe, and a group with no drawn path reads as coverage, not a clean
bill of health.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from kratos.attackpaths import graph as G
from kratos.attackpaths import settings as S
from kratos.attackpaths.chokepoint import Chokepoint
from kratos.attackpaths.crown import CrownJewel
from kratos.attackpaths.entries import Entry
from kratos.attackpaths.inputs import MachineInputs
from kratos.attackpaths.paths import Path

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class FindingSpec:
    target_key: str
    payload: dict[str, Any]


@dataclass
class CoverageNumbers:
    machines_total: int = 0
    machines_read: int = 0
    machines_stale: int = 0
    machines_unread: int = 0
    ssh_only: int = 0
    unconfirmed_roots: int = 0          # machines serving web with no confirmed code root
    outside_scope: int = 0
    caps_hit: list[str] = field(default_factory=list)
    assumed_hops_top: int = 0
    stale_names: list[str] = field(default_factory=list)
    unread_names: list[str] = field(default_factory=list)
    ssh_only_names: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    def lines(self) -> list[str]:
        out = [f"{self.machines_read} of {self.machines_total} machines read"]
        if self.machines_stale:
            out.append(f"{self.machines_stale} machine(s) too old to use (coverage gap, not assumed safe): "
                       + ", ".join(self.stale_names[:6]))
        if self.machines_unread:
            out.append(f"{self.machines_unread} machine(s) never read -- paths through them can't be drawn: "
                       + ", ".join(self.unread_names[:6]))
        if self.ssh_only:
            out.append(f"{self.ssh_only} machine(s) read over SSH only -- root-owned services, keys and processes "
                       "not seen (the sub-agent would): " + ", ".join(self.ssh_only_names[:6]))
        if self.unconfirmed_roots:
            out.append(f"{self.unconfirmed_roots} machine(s) serve code from a folder nobody confirmed -- drift and "
                       "web shells there are not checked")
        if self.outside_scope:
            out.append(f"{self.outside_scope} machine(s) in this group are outside your access")
        if self.caps_hit:
            out.append("the graph hit a size limit (" + ", ".join(sorted(self.caps_hit)) +
                       "); some of the group was not drawn")
        if self.assumed_hops_top:
            out.append(f"the top paths rely on {self.assumed_hops_top} assumed 'same network' hop(s) Kratos did "
                       "not observe")
        return out


def coverage_numbers(inputs: dict[str, MachineInputs], paths_list: list[Path], caps_hit: set[str],
                     outside_scope: int = 0) -> CoverageNumbers:
    cn = CoverageNumbers(machines_total=len(inputs), outside_scope=outside_scope,
                         caps_hit=sorted(caps_hit))
    for mk, mi in sorted(inputs.items()):
        if mi.unread:
            cn.machines_unread += 1
            cn.unread_names.append(mi.label or mk)
        elif mi.stale:
            cn.machines_stale += 1
            cn.stale_names.append(f"{mi.label or mk} (last read "
                                  f"{int(mi.data_age_hours or 0)}h ago)")
        else:
            cn.machines_read += 1
            if mi.ssh_only:
                cn.ssh_only += 1
                cn.ssh_only_names.append(mi.label or mk)
            # serves web but no confirmed root
            serves_web = any(isinstance(it, dict) and it.get("port") in (80, 443, 8080, 8443)
                             for it in (mi.live or {}).get("listeners") or [])
            if serves_web and not mi.code_roots:
                cn.unconfirmed_roots += 1
    cn.assumed_hops_top = sum(p.assumed_hops for p in paths_list[:10])
    return cn


def _entity_hash(path: Path) -> str:
    return hashlib.sha256(path.signature().encode("utf-8")).hexdigest()[:12]


def _cap(severity: str, data_dir: Any) -> str:
    cap = str(S.get(S.SEVERITY_CAP, data_dir))
    if _SEV_RANK.get(severity, 0) > _SEV_RANK.get(cap, 3):
        return cap
    return severity


def _path_severity(path: Path, data_dir: Any) -> str:
    crit = path.crown_criticality
    if crit in ("high", "critical"):
        sev = "high"
    elif crit == "medium":
        sev = "medium"
    else:
        sev = "low"
    if sev == "high" and not path.fully_observed:
        sev = "medium"       # an assumed hop is not a proven path
    return _cap(sev, data_dir)


def _hop_line(graph: G.Graph, edge: G.Edge) -> str:
    src = graph.node(edge.src)
    dst = graph.node(edge.dst)
    s = src.label if src else edge.src
    d = dst.label if dst else edge.dst
    tag = "" if edge.confidence == G.OBSERVED else " [assumed]"
    ev = (" [" + ", ".join(edge.evidence[:2]) + "]") if edge.evidence else ""
    return f"{s} → {d}: {edge.reason}{tag}{ev}"


def judge(graph: G.Graph, entries_list: list[Entry], crown: dict[str, CrownJewel],
          paths_list: list[Path], chokepoints_list: list[Chokepoint], coverage: CoverageNumbers,
          *, data_dir: Any, group_label: str, single_machine_scope: bool) -> list[FindingSpec]:
    """PATH-001..005 as FindingSpecs (target_key + payload). Deterministic."""
    specs: list[FindingSpec] = []

    # PATH-001: entry points
    for en in entries_list:
        node = graph.node(en.target_node_key)
        strongest = en.edge.attrs.get("finding") or ""
        ent = [en.target_node_key] + ([strongest] if strongest else [])
        reach = "from the internet" if en.tier == "internet" else "from inside your network"
        foot = "a foothold here" if en.grants_foothold else "no onward path Kratos can see (a weaker entry)"
        specs.append(FindingSpec(en.target_key, {
            "id": "PATH-001",
            "title": f"Attack entry point: {en.strength.label}",
            "severity": _cap(en.severity, data_dir),
            "subject": en.target_node_key,
            "entities": ent,
            "evidence": [f"{en.target_label} is reachable {reach}: {en.edge.reason}",
                         f"This gives {foot}."],
            "recommendation": ["Close or patch this entry; the chokepoint list (PATH-003) names the fix that "
                               "cuts the most paths."],
        }))

    # PATH-002: paths to crown jewels (the top path per crown jewel, others in evidence)
    by_cj: dict[str, list[Path]] = {}
    for p in paths_list:
        by_cj.setdefault(p.crown_jewel, []).append(p)
    for cj in sorted(by_cj):
        cj_paths = by_cj[cj]
        top = cj_paths[0]
        sev = _path_severity(top, data_dir)
        hops = [_hop_line(graph, e) for e in top.edges]
        assumed_note = ("" if top.fully_observed
                        else f" (assumes {top.assumed_hops} network hop(s) Kratos didn't observe)")
        crit = crown[cj].criticality + (" (assumed)" if crown[cj].assumed else "")
        label = graph.node(G.machine_key(cj))
        ev = [f"{len(cj_paths)} path(s) reach {label.label if label else cj} ({crit}){assumed_note}:",
              "Top path:"] + [f"  {i+1}. {h}" for i, h in enumerate(hops)]
        if len(cj_paths) > 1:
            ev.append(f"{len(cj_paths) - 1} other path(s) also reach it (see the graph / `/paths`).")
        specs.append(FindingSpec(cj, {
            "id": "PATH-002",
            "title": f"Attack path to {label.label if label else cj}",
            "severity": sev,
            "subject": G.machine_key(cj),
            "entities": [_entity_hash(top)],
            "evidence": ev,
            "recommendation": ["Cut the path at its chokepoint (PATH-003); the findings each hop rests on "
                               "carry their own fixes."],
        }))

    # PATH-003: the chokepoint that cuts the most paths (runner-ups in evidence)
    if chokepoints_list:
        top = chokepoints_list[0]
        target = top.machine or _first_machine_of(graph, top)
        runners = chokepoints_list[1:4]
        ev = [f"Fixing this cuts {top.count} path(s): {top.label}.", top.fix_text]
        if runners:
            ev.append("Next most effective:")
            ev += [f"  - {c.label} (cuts {c.count})" for c in runners]
        specs.append(FindingSpec(target, {
            "id": "PATH-003",
            "title": f"Fix this first: {top.fix_title} (cuts {top.count} path(s))",
            "severity": _cap("medium", data_dir),
            "subject": top.key,
            "entities": [top.key],
            "evidence": ev,
            "recommendation": [top.fix_title + " -- " + top.fix_text, "Kratos never runs this for you."],
            "fix": [{"title": top.fix_title, "text": top.fix_text}],
        }))

    # PATH-004: lateral-movement bridges (reused key, shared secret, account to root on >=2 machines)
    for spec in _bridges(graph, crown, data_dir, single_machine_scope):
        specs.append(spec)

    # PATH-005: coverage run note (group level; attached to a representative machine for display)
    rep = _representative(graph)
    specs.append(FindingSpec(rep, {
        "id": "PATH-005",
        "title": f"What Kratos could not see when drawing attack paths for {group_label}",
        "severity": "info",
        "subject": "",
        "entities": [],
        "evidence": (coverage.lines() or ["Kratos read every machine in this group."])
        + ["A machine Kratos didn't read is never 'not on a path'; a group with no drawn path is never 'safe'."],
        "recommendation": ["Run a fleet audit to refresh stale machines; read SSH-only machines through their "
                           "sub-agent to see root-owned services and keys."],
    }))
    return specs


def _first_machine_of(graph: G.Graph, c: Chokepoint) -> str:
    edge = graph.edges.get(c.key)
    if edge is not None:
        return sorted(m for m in (graph.machine_of(edge.src), graph.machine_of(edge.dst)) if m)[0] \
            if any((graph.machine_of(edge.src), graph.machine_of(edge.dst))) else ""
    node = graph.node(c.key)
    return node.target_key if node else ""


def _representative(graph: G.Graph) -> str:
    machines = sorted(n.target_key for n in graph.nodes_by_kind(G.MACHINE) if n.target_key)
    return machines[0] if machines else "unknown"


def _bridges(graph: G.Graph, crown: dict[str, CrownJewel], data_dir: Any,
             single_machine_scope: bool) -> list[FindingSpec]:
    out: list[FindingSpec] = []
    sev = _cap("low" if single_machine_scope else "medium", data_dir)
    seen: set[str] = set()
    # reused keys
    for e in sorted(graph.all_edges(), key=lambda x: x.edge_key):
        if e.kind != G.KEY_REUSE:
            continue
        fp = str(e.attrs.get("fingerprint") or "")
        if fp in seen:
            continue
        seen.add(fp)
        a, b = sorted({graph.machine_of(e.src), graph.machine_of(e.dst)} - {""})
        rep = a
        out.append(FindingSpec(rep, {
            "id": "PATH-004",
            "title": "A reused SSH key bridges two machines",
            "severity": sev,
            "subject": f"key-reuse:{fp[7:23]}",
            "entities": [fp],
            "evidence": [f"The same SSH key authorises an account on {graph.node(G.machine_key(a)).label} and "
                         f"{graph.node(G.machine_key(b)).label}. One stolen private half reaches both; the "
                         "direction (which machine holds it) is not known from public keys alone."],
            "recommendation": ["Rotate this key: a fresh key pair per machine, then remove this public key "
                               "everywhere it is reused."],
        }))
    # accounts that reach root on >=2 machines (by user name)
    root_machines: dict[str, set[str]] = {}
    for n in graph.nodes_by_kind(G.ACCOUNT):
        if n.attrs.get("reaches_root"):
            root_machines.setdefault(n.label, set()).add(n.target_key)
    for user, machines in sorted(root_machines.items()):
        if len(machines) < 2:
            continue
        rep = sorted(machines)[0]
        out.append(FindingSpec(rep, {
            "id": "PATH-004",
            "title": f"The account '{user}' reaches root on several machines",
            "severity": sev,
            "subject": f"root-account:{user}",
            "entities": sorted(f"{user}@{m}" for m in machines),
            "evidence": [f"'{user}' can become root on {len(machines)} machines: "
                         + ", ".join(sorted(machines)) + ". Compromising it anywhere spreads."],
            "recommendation": ["Give each machine its own admin account, or remove the shared account's root "
                               "rights where it isn't needed."],
        }))
    return out
