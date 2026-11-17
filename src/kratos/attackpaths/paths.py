"""Bounded, cycle-safe, deterministic path enumeration (E.1 decision 5).

A path is a directed chain of edges from an outside start node to a crown-jewel machine.
Enumeration is a depth-first search from the two outside nodes, bounded by
``paths.max_path_len`` and ``paths.max_paths``; a cycle (A trusts B trusts A) is detected
and never traversed twice. Out-edges are followed in a deterministic order, so two builds of
the same graph enumerate byte-identical paths.

Ranking (decision 5): by the crown jewel's criticality; then confidence (a fully observed
path above one with any assumed hop, and the assumed-hop count); then entry strength; then
length (shorter is more reliable).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from kratos.attackpaths import graph as G
from kratos.attackpaths import rank as R
from kratos.attackpaths.crown import CrownJewel

_CRIT = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Path:
    edges: list[G.Edge]
    crown_jewel: str                       # target_key of the machine reached
    crown_criticality: str = "medium"
    nodes: list[str] = field(default_factory=list)   # node_key sequence (start .. crown)

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def assumed_hops(self) -> int:
        return sum(1 for e in self.edges if e.confidence == G.ASSUMED)

    @property
    def fully_observed(self) -> bool:
        return self.assumed_hops == 0

    @property
    def entry_rank(self) -> int:
        for e in self.edges:
            if e.kind == G.EXPOSES:
                return R.entry_strength(e).rank_index
        return R.NO_WEAKNESS

    def signature(self) -> str:
        """A stable hash input for the ordered edge keys (a path that changes shape is new)."""
        return "→".join(e.edge_key for e in self.edges)

    def rank_key(self) -> tuple:
        return (-_CRIT.get(self.crown_criticality, 1), self.assumed_hops, self.entry_rank,
                self.length, self.signature())


def enumerate_paths(graph: G.Graph, crown_jewels: dict[str, CrownJewel], *,
                    max_path_len: int = 8, max_paths: int = 2000) -> tuple[list[Path], set[str]]:
    """(paths ranked best-first, caps hit). Deterministic."""
    caps_hit: set[str] = set()
    crown_keys = {G.machine_key(mk): mk for mk in crown_jewels}
    found: list[Path] = []
    stop = False

    def record(edges: list[G.Edge], node_seq: list[str], machine_key: str) -> None:
        nonlocal stop
        mk = crown_keys[machine_key]
        cj = crown_jewels[mk]
        found.append(Path(edges=list(edges), crown_jewel=mk, crown_criticality=cj.criticality,
                          nodes=list(node_seq)))
        if len(found) >= max_paths:
            caps_hit.add("paths")
            stop = True

    def dfs(node_key: str, visited: set[str], edges: list[G.Edge], node_seq: list[str]) -> None:
        nonlocal stop
        if stop:
            return
        if len(edges) >= max_path_len:
            caps_hit.add("path_len")
            return
        for e in graph.out_edges(node_key):
            if e.kind not in G.TRAVERSABLE or e.dst in visited:
                continue
            node = graph.node(e.dst)
            if node is None:
                continue
            edges.append(e)
            node_seq.append(e.dst)
            visited.add(e.dst)
            if e.dst in crown_keys:
                record(edges, node_seq, e.dst)
            if not stop:
                dfs(e.dst, visited, edges, node_seq)
            visited.discard(e.dst)
            node_seq.pop()
            edges.pop()
            if stop:
                return

    for start in (G.OUTSIDE_INTERNET, G.OUTSIDE_NETWORK):
        if graph.node(start) is None or stop:
            continue
        dfs(start, {start}, [], [start])

    found.sort(key=lambda p: p.rank_key())
    return found, caps_hit
