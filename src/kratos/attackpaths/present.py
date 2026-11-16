"""Kratos-written summaries and detail lines for every surface (E.1 §5.3).

All machine-derived text is cleaned through :func:`kratos.untrusted.for_display`; the one
line that reaches the model (the digest / risk-question summary) is additionally framed by
the caller (A.4) and masked at ``_metered_call`` (B.2). Nothing here ranks or decides -- it
renders what the code already computed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kratos.untrusted import for_display


def _clean(text: Any) -> str:
    return for_display(str(text or ""))


# --- the one model-facing line (gate-measured) --------------------------------------


def model_line(data_dir: Path, group_ref: str) -> str | None:
    """A short, plain-English line for the digest / a risk question, from the newest build.
    Code-built numbers and the chosen chokepoint, never a model opinion. None when there is
    no current build to summarise."""
    from kratos.attackpaths import build as B

    doc = B.read_latest(data_dir, group_ref)
    if doc is None:
        return None
    paths = doc.get("paths") or []
    entries = doc.get("entries") or []
    chokes = doc.get("chokepoints") or []
    cov = doc.get("coverage") or {}
    read = int(cov.get("machines_read") or 0)
    if not paths:
        gaps = []
        if cov.get("machines_unread"):
            gaps.append(f"{cov['machines_unread']} not read")
        if cov.get("machines_stale"):
            gaps.append(f"{cov['machines_stale']} too old")
        tail = f" ({', '.join(gaps)})" if gaps else ""
        return (f"Attack paths for {_clean(group_ref)}: no path drawn across {read} machine(s){tail} -- this is "
                "coverage, not a clean bill of health.")
    top = paths[0]
    cj = _clean(top.get("crown_jewel"))
    assumed = "" if top.get("fully_observed") else f", assuming {top.get('assumed_hops')} network hop(s)"
    choke = f" The one fix that cuts the most paths: {_clean(chokes[0].get('fix_title'))} (cuts {chokes[0].get('count')})." if chokes else ""
    return (f"Attack paths for {_clean(group_ref)}: {len(entries)} entry point(s), {len(paths)} path(s) to the "
            f"machines that matter. The strongest reaches {cj} in {top.get('length')} hop(s){assumed}.{choke}")


# --- CLI / TUI rendering (plain data; the TUI wraps these in safe widgets) ------------


def entry_lines(doc: dict[str, Any]) -> list[str]:
    out = []
    for i, en in enumerate(doc.get("entries") or [], 1):
        foot = "foothold here" if en.get("grants_foothold") else "weaker (no onward path seen)"
        out.append(f"{i}. [{str(en.get('severity','')).upper()}] {_clean(en.get('label'))} on "
                   f"{_clean(en.get('target_key'))} -- {en.get('tier')}-facing, {foot}: {_clean(en.get('reason'))}")
    return out or ["No entry points found (reachable + weak) across the machines Kratos read."]


def path_lines(doc: dict[str, Any]) -> list[str]:
    nodes = {n["node_key"]: n for n in doc.get("nodes") or []}

    def lbl(nk: str) -> str:
        if nk.startswith("outside:"):
            return "an attacker on the internet" if nk.endswith("internet") else "an attacker inside your network"
        n = nodes.get(nk)
        return _clean(n["label"]) if n else _clean(nk)

    out = []
    # group by crown jewel, show the top path of each
    seen: set[str] = set()
    for p in doc.get("paths") or []:
        cj = str(p.get("crown_jewel") or "")
        if cj in seen:
            continue
        seen.add(cj)
        assumed = "" if p.get("fully_observed") else f"  (assumes {p.get('assumed_hops')} network hop(s))"
        out.append(f"→ {lbl('machine:' + cj) if ('machine:' + cj) in nodes else _clean(cj)} "
                   f"[{p.get('criticality')}]{assumed}")
        for j, hop in enumerate(p.get("hops") or [], 1):
            tag = "" if hop.get("confidence") == "observed" else " [assumed]"
            src = hop.get("src_label") or lbl(hop.get("src", ""))
            dst = hop.get("dst_label") or lbl(hop.get("dst", ""))
            out.append(f"   {j}. {src} → {dst}: {_clean(hop.get('reason'))}{tag}")
    return out or ["No path drawn to any machine that matters -- this is coverage, not a clean bill of health."]


def chokepoint_lines(doc: dict[str, Any]) -> list[str]:
    out = []
    for i, c in enumerate(doc.get("chokepoints") or [], 1):
        if c.get("masked"):
            out.append(f"{i}. {c.get('label')} (cuts {c.get('count')} path(s))")
            continue
        out.append(f"{i}. {_clean(c.get('fix_title'))} -- cuts {c.get('count')} path(s): {_clean(c.get('label'))}")
        if c.get("fix_text"):
            out.append(f"     {_clean(c.get('fix_text'))}  (Kratos never runs this for you.)")
    return out or ["No chokepoint: no path to cut."]


def coverage_lines(doc: dict[str, Any]) -> list[str]:
    cov = doc.get("coverage") or {}
    out = [f"{cov.get('machines_read', 0)} of {cov.get('machines_total', 0)} machines read."]
    for key, word in (("machines_stale", "too old to use (coverage gap, not assumed safe)"),
                      ("machines_unread", "never read -- paths through them can't be drawn"),
                      ("ssh_only", "read over SSH only -- root-owned services, keys and processes not seen"),
                      ("unconfirmed_roots", "serve code from a folder nobody confirmed"),
                      ("outside_scope", "outside your access")):
        n = int(cov.get(key) or 0)
        if n:
            out.append(f"- {n} machine(s) {word}.")
    if doc.get("caps_hit") or cov.get("caps_hit"):
        out.append("- the graph hit a size limit; some of the group was not drawn.")
    out.append("A machine Kratos didn't read is never 'not on a path'; a group with no drawn path is never 'safe'.")
    return out


def compact(doc: dict[str, Any], *, group_ref: str = "", max_items: int = 5) -> dict[str, Any]:
    """A small, scoped summary for MCP / chat (read-only). Never a path into a machine the
    reader can't see: the caller must pass a doc already run through ``scope.scoped_view``."""
    paths = doc.get("paths") or []
    entries = doc.get("entries") or []
    chokes = doc.get("chokepoints") or []
    cov = doc.get("coverage") or {}
    return {
        "group": doc.get("group") or group_ref,
        "built_at": doc.get("built_at"),
        "summary": model_line_from_doc(doc, group_ref or str(doc.get("group") or "")),
        "entries": [{"machine": _clean(e.get("target_key")), "where": _clean(e.get("label")),
                     "tier": e.get("tier"), "severity": e.get("severity"),
                     "grants_foothold": e.get("grants_foothold")} for e in entries[:max_items]],
        "paths": [{"to": _clean(p.get("crown_jewel")), "criticality": p.get("criticality"),
                   "hops": p.get("length"), "fully_observed": p.get("fully_observed"),
                   "assumed_hops": p.get("assumed_hops")} for p in paths[:max_items]],
        "chokepoints": [{"fix": _clean(c.get("fix_title")) or c.get("label"), "cuts_paths": c.get("count"),
                         "where": _clean(c.get("label"))} for c in chokes[:max_items]],
        "coverage": {k: cov.get(k) for k in ("machines_total", "machines_read", "machines_stale",
                                             "machines_unread", "ssh_only", "outside_scope")},
        "note": "Attack paths are recommendations built from stored evidence. Kratos never runs a fix, and a "
                "machine it didn't read is never 'not on a path'.",
    }


def model_line_from_doc(doc: dict[str, Any], group_ref: str) -> str:
    """The one-line summary from an already-loaded doc (no store read)."""
    paths = doc.get("paths") or []
    entries = doc.get("entries") or []
    chokes = doc.get("chokepoints") or []
    cov = doc.get("coverage") or {}
    read = int(cov.get("machines_read") or 0)
    if not paths:
        return (f"No attack path drawn across {read} machine(s) in {_clean(group_ref)} -- coverage, not a clean "
                "bill of health.")
    top = paths[0]
    choke = f" Fix first: {_clean(chokes[0].get('fix_title'))} (cuts {chokes[0].get('count')})." if chokes else ""
    assumed = "" if top.get("fully_observed") else f", assuming {top.get('assumed_hops')} network hop(s)"
    return (f"{len(entries)} entry point(s), {len(paths)} path(s). Strongest reaches {_clean(top.get('crown_jewel'))} "
            f"in {top.get('length')} hop(s){assumed}.{choke}")


def render_build(doc: dict[str, Any], group_ref: str) -> list[str]:
    """The full /paths text blocks (plain lines; the TUI/CLI style them)."""
    lines = [f"Attack paths for {_clean(group_ref)}", ""]
    lines += ["Entry points:"] + entry_lines(doc) + [""]
    lines += ["Paths to what matters:"] + path_lines(doc) + [""]
    lines += ["Fix this first:"] + chokepoint_lines(doc) + [""]
    lines += ["What Kratos couldn't see:"] + coverage_lines(doc)
    return lines
