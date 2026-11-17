"""Entry-point detection (E.1 decision 3): the ``exposes`` edges, ranked.

An entry is a place an attacker starts -- an ``exposes`` edge from one of the two outside
start nodes into a service, container or code root. Entries are ranked by the pinned table
in :mod:`kratos.attackpaths.rank`.
"""
from __future__ import annotations

from dataclasses import dataclass

from kratos.attackpaths import graph as G
from kratos.attackpaths import rank as R


@dataclass(frozen=True)
class Entry:
    edge: G.Edge
    target_key: str              # the machine the entry is on
    target_node_key: str         # the service/container/code_root reached
    target_label: str
    tier: str                    # internet | network
    grants_foothold: bool        # the attacker can stand on the machine from here
    strength: R.Strength

    @property
    def rank_index(self) -> int:
        return self.strength.rank_index

    @property
    def severity(self) -> str:
        return self.strength.severity


def entries(graph: G.Graph) -> list[Entry]:
    """Every entry, strongest first (deterministic)."""
    out: list[Entry] = []
    for outside in (G.OUTSIDE_INTERNET, G.OUTSIDE_NETWORK):
        for e in graph.out_edges(outside):
            if e.kind != G.EXPOSES:
                continue
            dst = graph.node(e.dst)
            if dst is None:
                continue
            tier = "internet" if outside == G.OUTSIDE_INTERNET else "network"
            foothold = any(fe.kind == G.FOOTHOLD for fe in graph.out_edges(e.dst))
            out.append(Entry(edge=e, target_key=dst.target_key, target_node_key=e.dst,
                             target_label=dst.label, tier=tier, grants_foothold=foothold,
                             strength=R.entry_strength(e)))
    out.sort(key=lambda en: R.entry_sort_key(en.edge, en.target_label))
    return out
