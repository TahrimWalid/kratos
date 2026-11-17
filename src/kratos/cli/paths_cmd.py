"""`kratos paths ...` (E.1 §3.12): a read-free attack-path graph over a group of machines.

    kratos paths build [--group G]            build (synthesis over stored evidence; no model, no read)
    kratos paths show [--group G] [--machine M] [--json]   the latest build: entries, paths, chokepoints, coverage
    kratos paths entries [--group G] [--json]  the ranked entry points
    kratos paths chokepoints [--group G] [--json]  the fixes that cut the most paths

Nothing here reads a machine, calls a model, or changes anything: a build reads what D.2-E.7a
already stored and writes path_* rows and PATH-* findings. Paths are recommendations only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from kratos.untrusted import safe_print


def _actor():
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _group(args: argparse.Namespace) -> str:
    g = getattr(args, "group", None) or "all"
    return g.lstrip("@")


def cmd_paths(args: argparse.Namespace) -> int:
    from kratos.attackpaths import build as B
    from kratos.attackpaths import present, scope as SC

    data_dir = Path(args.data_dir)
    sub = args.paths_cmd
    group = _group(args)
    try:
        if sub == "build":
            out = B.run_path_build(data_dir=data_dir, group=group, actor=_actor(), source="interactive")
            safe_print(f"[KRATOS] {out.summary}")
            if out.outside_scope:
                safe_print(f"  ({out.outside_scope} machine(s) in this group are outside your access)")
            return 0
        # reads
        doc = B.read_latest(data_dir, f"@{group}" if group != "all" else "@all")
        if doc is None:
            doc = B.read_latest(data_dir, group)
        if doc is None:
            safe_print(f"[KRATOS] No attack-path build for {group} yet -- run `kratos paths build --group {group}`.")
            return 1
        doc = SC.scoped_view(doc, None)       # owner at the CLI sees every machine
        if getattr(args, "machine", None):
            doc = _filter_machine(doc, args.machine)
        if getattr(args, "json", False):
            print(json.dumps(_public(doc, sub), indent=2, default=str))
            return 0
        if sub == "entries":
            for line in present.entry_lines(doc):
                safe_print(line)
        elif sub == "chokepoints":
            for line in present.chokepoint_lines(doc):
                safe_print(line)
        else:   # show
            for line in present.render_build(doc, doc.get("group") or group):
                safe_print(line)
        return 0
    except B.PathBuildError as e:
        safe_print(f"[KRATOS] {e}")
        return 2


def _filter_machine(doc: dict, machine: str) -> dict:
    from kratos.target_key import target_key

    mk = target_key(machine)
    out = dict(doc)
    out["entries"] = [e for e in doc.get("entries") or [] if e.get("target_key") == mk]
    out["paths"] = [p for p in doc.get("paths") or []
                    if p.get("crown_jewel") == mk or any(mk in str(h.get("src", "")) or mk in str(h.get("dst", ""))
                                                         for h in p.get("hops") or [])]
    out["chokepoints"] = [c for c in doc.get("chokepoints") or [] if c.get("machine") == mk]
    return out


def _public(doc: dict, sub: str) -> dict:
    if sub == "entries":
        return {"group": doc.get("group"), "entries": doc.get("entries")}
    if sub == "chokepoints":
        return {"group": doc.get("group"), "chokepoints": doc.get("chokepoints")}
    return {k: doc.get(k) for k in ("group", "built_at", "coverage", "entries", "paths", "chokepoints", "caps_hit")}


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("paths", help="Attack paths: where an attacker gets in and reaches what matters (read-free)")
    ps = p.add_subparsers(dest="paths_cmd", required=True)
    b = ps.add_parser("build", help="build the attack paths for a group (no model, no machine read)")
    b.add_argument("--group", default="all")
    for name, text in (("show", "the latest build: entries, paths, chokepoints, coverage"),
                       ("entries", "the ranked entry points"),
                       ("chokepoints", "the fixes that cut the most paths")):
        x = ps.add_parser(name, help=text)
        x.add_argument("--group", default="all")
        x.add_argument("--json", action="store_true")
        if name == "show":
            x.add_argument("--machine", default=None, help="only paths touching this machine")
    p.set_defaults(func=cmd_paths)
