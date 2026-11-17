"""Chokepoints (E.1 decision 6): the one fix that cuts the most paths.

For every node and edge on at least one kept path, count the paths through it; the highest
count is the chokepoint, listed first. The *fix* is the one the underlying finding already
recommends -- rotate the reused key, upgrade or limit the vulnerable package, unpublish the
container port, remove the group membership, restore the drifted file from git -- **shown,
never run** (the fix channel stays OFF). Pure counting; ties break deterministically.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from kratos.attackpaths import graph as G
from kratos.attackpaths.paths import Path


@dataclass
class Chokepoint:
    kind: str                    # "node" | "edge"
    key: str                     # node_key or edge_key
    count: int                   # paths cut if this is removed/fixed
    label: str
    machine: str                 # target_key (or "" for an outside/cross-machine edge)
    edge_kind: str = ""
    fix_title: str = ""
    fix_text: str = ""
    evidence: list[str] = field(default_factory=list)


# What to recommend for each edge kind -- the fix the underlying finding already advises.
_EDGE_FIX = {
    G.KEY_REUSE: ("Rotate the reused SSH key",
                  "Generate a fresh key pair, add the new public key where this one is used, then remove "
                  "this public key from every machine's authorized_keys. One stolen private half opens "
                  "every machine it is on."),
    G.ESCALATES: ("Remove the admin membership that reaches root",
                  "Take this account out of the group (sudo / docker / lxd / ...) that lets it become root, "
                  "or remove its sudoers grant, unless it genuinely needs it."),
    G.ESCAPES: ("Re-create the container without the escape setting",
                "Drop the privileged flag / socket mount / host namespace / writable host mount / added "
                "capability so the container can no longer reach the host."),
    G.EXPOSES: ("Close or patch the exposed entry",
                "Upgrade or limit the vulnerable package, unpublish the port, or remove the web shell / "
                "untracked script so this entry no longer gives a foothold."),
    G.FOOTHOLD: ("Remove the foothold",
                 "Patch the vulnerability, remove the web shell, or take the exposed service off the "
                 "network so it can no longer be a way in."),
    G.REACHES: ("Limit who can reach this service",
                "Restrict the service to the hosts that need it (firewall / bind address), so a foothold "
                "on one machine can't reach it."),
}

_NODE_FIX = {
    G.SERVICE: ("Close or patch this service", "Upgrade or firewall the service so it is no longer a way in."),
    G.CONTAINER: ("Harden or unpublish this container", "Unpublish its port or drop its escape setting."),
    G.CODE_ROOT: ("Clean up this code folder", "Remove the web shell / untracked script or restore the "
                  "drifted files from git."),
    G.ACCOUNT: ("Reduce this account's rights", "Remove the admin membership that lets it reach root."),
}


def _fix_for_edge(edge: G.Edge) -> tuple[str, str]:
    title, text = _EDGE_FIX.get(edge.kind, ("Break this link", "Remove what makes this hop possible."))
    return title, text


def _fix_for_node(node: G.Node) -> tuple[str, str]:
    return _NODE_FIX.get(node.kind, ("Fix this node", "Address the finding on this node."))


def chokepoints(graph: G.Graph, kept: list[Path]) -> list[Chokepoint]:
    """Every node/edge on >=1 kept path, by paths-through descending (deterministic).

    The outside start nodes and the crown-jewel machine endpoints are never chokepoints
    (you can't 'fix' the attacker or the asset); every hop in between is counted."""
    if not kept:
        return []
    crown = {G.machine_key(p.crown_jewel) for p in kept}
    node_count: dict[str, int] = {}
    edge_count: dict[str, int] = {}
    for p in kept:
        for nk in p.nodes:
            if nk.startswith(G.OUTSIDE + ":") or nk in crown:
                continue
            node_count[nk] = node_count.get(nk, 0) + 1
        for e in p.edges:
            edge_count[e.edge_key] = edge_count.get(e.edge_key, 0) + 1

    out: list[Chokepoint] = []
    for nk, n in node_count.items():
        node = graph.node(nk)
        if node is None:
            continue
        title, text = _fix_for_node(node)
        out.append(Chokepoint(kind="node", key=nk, count=n, label=node.label, machine=node.target_key,
                              fix_title=title, fix_text=text, evidence=list(node.evidence)))
    for ek, n in edge_count.items():
        edge = graph.edges.get(ek)
        if edge is None:
            continue
        title, text = _fix_for_edge(edge)
        machine = graph.machine_of(edge.src) or graph.machine_of(edge.dst)
        label = _edge_label(graph, edge)
        out.append(Chokepoint(kind="edge", key=ek, count=n, label=label, machine=machine,
                              edge_kind=edge.kind, fix_title=title, fix_text=text, evidence=list(edge.evidence)))
    # most paths cut first; ties by kind (edge before node -- a link is a cleaner single fix),
    # then by key for determinism.
    out.sort(key=lambda c: (-c.count, 0 if c.kind == "edge" else 1, c.key))
    return out


def _edge_label(graph: G.Graph, edge: G.Edge) -> str:
    src = graph.node(edge.src)
    dst = graph.node(edge.dst)
    s = src.label if src else edge.src
    d = dst.label if dst else edge.dst
    return f"{edge.kind}: {s} → {d}"
