"""Filter a built path view to a reader's scope (E.1 decision 9, D.2 §3.8 scope-before-dedup).

The graph is computed over the group's machines; a *view* for a reader is filtered to the
machines they may see. A node on a machine outside their access is never named: an edge that
crosses the boundary is shown as "a machine outside your access" and counted only, a
chokepoint outside scope is masked, a crown jewel outside scope is not listed. A viewer can
never learn a machine exists -- its services, accounts or keys -- through a path edge. The
number of out-of-scope hops is stated so a scoped view is honestly partial, not silently
wrong.
"""
from __future__ import annotations

from typing import Any

from kratos.attackpaths import graph as G

OUTSIDE_LABEL = "a machine outside your access"


def _node_machine(node: dict[str, Any]) -> str:
    return str(node.get("target_key") or "")


def _visible_node(node_key: str, nodes_by_key: dict[str, dict[str, Any]], visible: set[str] | None) -> bool:
    if visible is None:
        return True
    if node_key.startswith(G.OUTSIDE + ":"):
        return True
    node = nodes_by_key.get(node_key)
    if node is None:
        return False
    mk = _node_machine(node)
    return not mk or mk in visible


def scoped_view(doc: dict[str, Any], visible: set[str] | None) -> dict[str, Any]:
    """A presentation-ready copy of a path snapshot, filtered to ``visible`` (None = all).
    Out-of-scope machines are never named; crossing hops are masked and counted."""
    nodes_by_key = {n["node_key"]: n for n in doc.get("nodes") or []}

    entries = []
    for en in doc.get("entries") or []:
        if visible is None or str(en.get("target_key") or "") in visible:
            entries.append(en)

    out_of_scope_hops = 0
    paths = []
    for p in doc.get("paths") or []:
        if visible is not None and str(p.get("crown_jewel") or "") not in visible:
            continue                                   # a crown jewel outside scope is not listed
        hops = []
        masked = 0
        for hop in p.get("hops") or []:
            src_ok = _visible_node(hop.get("src", ""), nodes_by_key, visible)
            dst_ok = _visible_node(hop.get("dst", ""), nodes_by_key, visible)
            h = dict(hop)
            if not src_ok:
                h["src_label"] = OUTSIDE_LABEL
                h["masked_src"] = True
                masked += 1
            if not dst_ok:
                h["dst_label"] = OUTSIDE_LABEL
                h["masked_dst"] = True
                masked += 1
            hops.append(h)
        out_of_scope_hops += masked
        pp = dict(p)
        pp["hops"] = hops
        pp["masked_hops"] = masked
        paths.append(pp)

    chokepoints = []
    masked_chokepoints = 0
    for c in doc.get("chokepoints") or []:
        # A chokepoint touches a machine via its own `machine`, and -- for an edge -- via both
        # endpoints encoded in its key (``kind|src|dst``). Any out-of-scope machine it touches
        # masks the whole chokepoint: its label names the endpoints, so it would otherwise leak.
        touched = {str(c.get("machine") or "")}
        for part in str(c.get("key") or "").split("|")[1:]:
            node = nodes_by_key.get(part)
            if node is not None:
                touched.add(_node_machine(node))
        if visible is not None and any(mk and mk not in visible for mk in touched):
            masked_chokepoints += 1
            chokepoints.append({"kind": c.get("kind"), "count": c.get("count"),
                                "label": f"a fix on {OUTSIDE_LABEL}", "masked": True,
                                "machine": "", "key": "", "fix_title": "", "fix_text": "", "evidence": []})
            continue
        chokepoints.append(c)

    nodes = [n for n in doc.get("nodes") or [] if _visible_node(n["node_key"], nodes_by_key, visible)]
    edges = []
    for e in doc.get("edges") or []:
        src_ok = _visible_node(e.get("src", ""), nodes_by_key, visible)
        dst_ok = _visible_node(e.get("dst", ""), nodes_by_key, visible)
        if src_ok and dst_ok:
            edges.append(e)
        # a crossing edge is dropped from the graph view; it is still counted in paths above

    out = dict(doc)
    out["entries"] = entries
    out["paths"] = paths
    out["chokepoints"] = chokepoints
    out["nodes"] = nodes
    out["edges"] = edges
    out["out_of_scope_hops"] = out_of_scope_hops
    out["masked_chokepoints"] = masked_chokepoints
    return out
