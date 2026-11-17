"""Crown-jewel selection (E.1 decision 4).

The machines a path build aims at: the ones a person marked ``high`` or ``critical`` (D.3),
plus any machine that *holds a key or secret that reaches another machine* -- a key-reuse
hub, or a machine whose stored secret fingerprint (E.7a CODE-004) matches one used
elsewhere. Unset criticality is assumed ``medium`` and labelled; E.1 never invents
importance, and a machine of its own is never dropped just because no criticality was set.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from kratos.attackpaths import graph as G
from kratos.attackpaths.inputs import MachineInputs

CRITICAL_SET = ("high", "critical")


@dataclass
class CrownJewel:
    target_key: str
    criticality: str
    assumed: bool
    reasons: list[str] = field(default_factory=list)


def crown_jewels(graph: G.Graph, inputs: dict[str, MachineInputs]) -> dict[str, CrownJewel]:
    """target_key -> CrownJewel, deterministic. A machine qualifies by criticality or by
    holding a reused key / shared secret that reaches another machine."""
    out: dict[str, CrownJewel] = {}

    def crit_of(mk: str) -> tuple[str, bool]:
        node = graph.node(G.machine_key(mk))
        if node is not None:
            return str(node.attrs.get("criticality") or "medium"), bool(node.attrs.get("criticality_assumed"))
        return "medium", True

    for mk in sorted(inputs):
        crit, assumed = crit_of(mk)
        if crit in CRITICAL_SET:
            out.setdefault(mk, CrownJewel(mk, crit, assumed)).reasons.append(
                f"you marked this machine {crit}")

    # key-reuse hubs: a machine on any key-reuse edge (a stolen key from it reaches another)
    for e in graph.all_edges():
        if e.kind != G.KEY_REUSE:
            continue
        for mk in (graph.machine_of(e.src), graph.machine_of(e.dst)):
            if not mk:
                continue
            crit, assumed = crit_of(mk)
            cj = out.setdefault(mk, CrownJewel(mk, crit, assumed))
            reason = "a reused SSH key here also opens another machine"
            if reason not in cj.reasons:
                cj.reasons.append(reason)

    # shared secrets (E.7a CODE-004): a secret fingerprint on >=2 machines
    by_fp: dict[str, set[str]] = {}
    for mk in sorted(inputs):
        for f in inputs[mk].findings:
            if str(f.get("rule_id") or "") != "CODE-004":
                continue
            for ent in f.get("entities") or []:
                fp = str(ent)
                if "#" in fp or len(fp) >= 12:     # a fingerprint-shaped entity, never a value
                    by_fp.setdefault(fp, set()).add(mk)
    for fp, machines in by_fp.items():
        if len(machines) < 2:
            continue
        for mk in machines:
            crit, assumed = crit_of(mk)
            cj = out.setdefault(mk, CrownJewel(mk, crit, assumed))
            reason = "a secret stored here also appears on another machine"
            if reason not in cj.reasons:
                cj.reasons.append(reason)
    return out
