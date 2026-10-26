"""`kratos detect`: the Sigma detection rules (phase C.1).

    kratos detect rules [--target T] [--skipped | --all] [--json]
    kratos detect rules disable|enable <RULE> [--target T] --reason "..."
    kratos detect run [--target T]
    kratos detect import <file|folder> [--name NAME]
    kratos detect watch [on|off <MACHINE>] [--json]     (C.2: continuous detection on agents)

Every rule shows its author (Detection Rule License 1.1). Turning a rule on or off is
a person's decision, recorded with who and why.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print  # rule text from an imported pack is cleaned like any other

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def add_parser(sub: Any) -> None:
    p = sub.add_parser("detect", help="Detection rules (SigmaHQ Linux rules): list them, turn one off for a "
                                      "machine, run them now, import your own Sigma rules")
    dsub = p.add_subparsers(dest="detect_action", required=True)
    r = dsub.add_parser("rules", help="The rules: id, level, what they read, title, author, on/off for a machine")
    r.add_argument("change", nargs="?", choices=("enable", "disable"), help="Turn a rule on or off")
    r.add_argument("rule", nargs="?", help="With enable/disable: the rule id, e.g. SIGMA-08F26069")
    r.add_argument("--target", default=None, help="Machine (default: the active target; with disable/enable: "
                                                   "'all' for every machine)")
    r.add_argument("--reason", default=None, help="With enable/disable: why (required)")
    r.add_argument("--skipped", action="store_true", help="The SigmaHQ rules not shipped, with why")
    r.add_argument("--all", action="store_true", help="Every candidate rule: shipped and not shipped")
    r.add_argument("--json", action="store_true")
    run = dsub.add_parser("run", help="Run the rules now over the logs Kratos holds for a machine")
    run.add_argument("--target", default=None, help="Machine (default: the active target)")
    run.add_argument("--json", action="store_true")
    imp = dsub.add_parser("import", help="Compile your own Sigma rules (a .yml file or a folder) into a rule pack "
                                         "(needs the sigma extra: pip install 'kratos-security-assistant[sigma]')")
    imp.add_argument("path")
    imp.add_argument("--name", default=None, help="Pack name (default: from the file or folder name)")
    w = dsub.add_parser("watch", help="Continuous detection: which machines' agents follow their logs and run the "
                                      "rules as lines are written; turn it on or off for one")
    w.add_argument("change", nargs="?", choices=("on", "off"), help="Turn it on or off")
    w.add_argument("machine", nargs="?", help="With on/off: the paired machine (its name, host or target id)")
    w.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_detect)


def _target(args: argparse.Namespace) -> str | None:
    from kratos.kratos_config import get_active_target

    return args.target or get_active_target()


def _ls_label(rule: dict[str, Any]) -> str:
    from kratos.events import sigma_fields as SF

    ls = rule.get("logsource") or {}
    found = SF.LOGSOURCES.get((ls.get("product") or "", ls.get("service"), ls.get("category")))
    return found.label if found else "/".join(v for v in ls.values() if v)


def cmd_detect(args: argparse.Namespace) -> int:
    action = args.detect_action
    if action == "rules":
        return _rules(args)
    if action == "run":
        return _run(args)
    if action == "watch":
        return _watch(args)
    return _import(args)


# ---------------------------------------------------------------------------- watch (C.2)
def _find_agent(data_dir: Path, name: str) -> dict[str, Any] | None:
    from kratos.storage.subagent_store import SubAgentStore

    store = SubAgentStore(data_dir / "kratos.db")
    key = (name or "").strip().lower()
    targets = [t for t in store.list_targets(include_revoked=False)]
    for t in targets:
        if key in {str(t.get(k) or "").lower() for k in ("target_id", "name", "hostname")}:
            return t
    for ln in store.list_links():
        if ln["host"] == key:
            return next((t for t in targets if t["target_id"] == ln["target_id"]), None)
    return None


def _watch(args: argparse.Namespace) -> int:
    from kratos.detect import live as L
    from kratos.lifecycle.decide import Actor
    from kratos.storage.subagent_store import SubAgentStore

    data_dir = Path(args.data_dir)
    if args.change:
        if not args.machine:
            print("Name the machine: kratos detect watch on <name>", file=sys.stderr)
            return 2
        t = _find_agent(data_dir, args.machine)
        if t is None:
            print(f"No paired machine called {args.machine!r} (see kratos subagent-status).", file=sys.stderr)
            return 2
        try:
            st = L.set_watching(data_dir, t["target_id"], args.change == "on", actor=Actor.current("cli"))
        except L.WatchSetupError as e:
            print(f"Not changed: {e}", file=sys.stderr)
            return 1
        print(f"Continuous detection {args.change} for {t.get('name') or t['target_id']} (findings filed under "
              f"{st.get('machine')}). The agent picks it up within seconds while connected"
              + ("; alerts while Kratos is closed need the always-on listener (/subagent, l)." if args.change == "on"
                 else "."))
        return 0
    store = SubAgentStore(data_dir / "kratos.db")
    out = []
    for t in store.list_targets(include_revoked=False):
        st = L.pack_state(data_dir, t["target_id"]) or {}
        h = L.health(data_dir, t["target_id"]) if st.get("enabled") else None
        out.append({"target_id": t["target_id"], "name": t.get("name"), "agent_version": t.get("agent_version"),
                    "machine": st.get("machine"), "enabled": bool(st.get("enabled")),
                    "can_watch": L.agent_can_watch(t.get("agent_version")),
                    "running": bool(h and h.healthy), "problems": [x for _c, x in h.reasons] if h else [],
                    "sources": [{k: r[k] for k in ("source", "state", "watching_since", "events_per_min", "lag_seconds",
                                                   "dropped", "error")} for r in L.watch_rows(data_dir, t["target_id"])],
                    "line": L.watch_line(data_dir, st["machine"]) if st.get("enabled") and st.get("machine") else None})
    if args.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    if not out:
        print("No paired machines. Continuous detection needs a sub-agent on the machine (/subagent).")
        return 0
    for o in out:
        label = o["name"] or o["target_id"]
        if not o["enabled"]:
            print(f"{label}: off" + ("" if o["can_watch"] else f" -- {L.UPDATE_HINT}"))
            continue
        print(f"{label} ({o['machine']}): {o['line']}")
        for p in o["problems"]:
            print(f"  ! {p}")
        for src in o["sources"]:
            print(f"  {src['source']}: {src['state']}" + (f" -- {src['error']}" if src.get("error") else ""))
    return 0


# ---------------------------------------------------------------------------- rules
def _rules(args: argparse.Namespace) -> int:
    from kratos.detect import pack as P
    from kratos.detect import store as ST

    data_dir = Path(args.data_dir)
    if args.change:
        return _change(args, data_dir)
    loaded = P.load(data_dir)
    target = _target(args)
    disabled = ST.disabled_rules(data_dir, target) if target else set()
    rows = []
    if not args.skipped:
        for lp, r in loaded.rules():
            m = r.meta
            rows.append({"id": m["id"], "shipped": True, "pack": lp.pack_id, "level": m["level"],
                         "reads": _ls_label(m), "title": m["title"], "author": m["author"],
                         "on": m["id"] not in disabled, "source": (m.get("source") or {}).get("url")})
    if args.skipped or args.all:
        for lp in loaded.loaded:
            for s in P.skipped(lp):
                rows.append({"id": s.get("id") or "", "shipped": False, "pack": lp.pack_id, "level": s.get("level"),
                             "reads": s.get("logsource"), "title": s.get("title"), "author": s.get("author"),
                             "path": s.get("path"), "reason": s.get("reason"), "kind": s.get("kind")})
    if args.json:
        print(json.dumps({"target": target, "rules": rows,
                          "refused_packs": [r.__dict__ for r in loaded.refused]}, indent=2, sort_keys=True))
        return 0
    shipped = [r for r in rows if r["shipped"]]
    if shipped:
        shipped.sort(key=lambda r: (LEVEL_ORDER.get(r["level"], 9), r["reads"], r["title"]))
        print(f"{'RULE':<15} {'LEVEL':<8} {'ON':<4} {'READS':<18} TITLE -- AUTHOR")
        for r in shipped:
            on = "on" if r["on"] else "OFF"
            print(f"{r['id']:<15} {r['level']:<8} {on:<4} {r['reads'][:18]:<18} {r['title']} -- {r['author']}")
        packs = ", ".join(f"{lp.pack_id} v{lp.version} ({len(lp.pack.rules)} rules)" for lp in loaded.loaded)
        print(f"[KRATOS] {len(shipped)} rules from {packs}"
              + (f"; on/off shown for {target}" if target else "")
              + ". Rules by their authors, Detection Rule License 1.1.")
    rest = [r for r in rows if not r["shipped"]]
    if rest:
        print(f"{'NOT SHIPPED':<12} {'LEVEL':<8} {'READS':<26} TITLE -- WHY")
        for r in sorted(rest, key=lambda r: (str(r.get("kind")), str(r.get("path")))):
            print(f"{str(r.get('kind'))[:12]:<12} {str(r.get('level') or '-'):<8} {str(r.get('reads') or '-')[:26]:<26} "
                  f"{r.get('title') or r.get('path')} -- {r.get('reason')}")
        print(f"[KRATOS] {len(rest)} candidate rules not shipped (import any of them yourself: kratos detect import).")
    for ref in loaded.refused:
        print(f"[KRATOS] refused rule pack {ref.path}: {ref.reason}", file=sys.stderr)
    return 0


def _change(args: argparse.Namespace, data_dir: Path) -> int:
    from kratos.detect import pack as P
    from kratos.detect import store as ST
    from kratos.lifecycle.decide import Actor

    rule_id = str(args.rule or "").strip().upper()
    if not rule_id or P.load(data_dir).rule(rule_id) is None:
        print(f"[KRATOS] No detection rule {args.rule!r} (see `kratos detect rules`).", file=sys.stderr)
        return 1
    if not args.reason:
        print("[KRATOS] Say why with --reason \"...\" (it is recorded with your name).", file=sys.stderr)
        return 1
    target = None if args.target == "all" else _target(args)
    if args.target != "all" and not target:
        print("[KRATOS] Which machine? Pass --target <host>, or --target all for every machine.", file=sys.stderr)
        return 1
    try:
        o = ST.set_rule_enabled(data_dir, rule_id, args.change == "enable", target=target, reason=args.reason,
                                actor=Actor.current("cli"))
    except ST.OverrideError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 1
    where = "every machine" if o.target == ST.EVERYWHERE else o.target
    print(f"[KRATOS] {rule_id} is now {'on' if o.enabled else 'off'} for {where} ({o.actor}: {o.reason}).")
    return 0


# ---------------------------------------------------------------------------- run now
def _run(args: argparse.Namespace) -> int:
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE
    from kratos.detect import run as R
    from kratos.run_context import run_scope

    target = _target(args)
    if not target:
        print("[KRATOS] Which machine? Pass --target <host>.", file=sys.stderr)
        return 1
    data_dir = Path(args.data_dir)
    with run_scope("cli", target=target), kratos_config.pinned_target(target):
        report = R.run_pass(target, data_dir)
        out_json, _md = FE.write_findings_report(data_dir=data_dir)
    findings = [f for f in json.loads(Path(out_json).read_text(encoding="utf-8")).get("findings", [])
                if str(f.get("id", "")).startswith(("SIGMA-", "KRATOS-", "DETECT-"))]
    if args.json:
        print(json.dumps({"target": target, "status": report.status, "events": report.events,
                          "matches": report.matches, "coverage": [c.__dict__ for c in report.coverage],
                          "findings": findings}, indent=2, sort_keys=True, default=str))
        return 0
    print(f"[KRATOS] {target}: {report.events:,} new stored log event(s) checked -- {len(report.matches)} new "
          "match(es). The rules run over the logs Kratos collected (on schedule, not continuously).")
    for p in report.packs:
        if p.status != "ok" or p.behind:
            print(f"  {p.pack_id}: {p.status} -- {p.reason}")
    for c in report.coverage:
        if c.state != "checked":
            print(f"  {c.label} ({c.rules} rules): {c.note}")
    for f in findings:
        if f["id"] == "DETECT-001":
            continue
        rule = f.get("detection_rule") or {}
        print(f"  {f['severity'].upper():<8} {f['id']} {f['title']} -- by {rule.get('author')} "
              f"[{f.get('state', 'open')}]" + (f" about {f['subject']}" if f.get("subject") else ""))
    return 0


# ---------------------------------------------------------------------------- import
def _import(args: argparse.Namespace) -> int:
    import re

    from kratos.detect import pack as P

    try:
        from kratos.detect.sigma_build.compile import Source, build_pack, compile_sources
        from kratos.detect.sigma_build.samples import add_samples
    except ImportError:
        print("[KRATOS] Importing Sigma rules needs pySigma: pip install 'kratos-security-assistant[sigma]' "
              "(Python 3.11 or newer).", file=sys.stderr)
        return 1
    src = Path(args.path)
    files = sorted(src.rglob("*.yml")) + sorted(src.rglob("*.yaml")) if src.is_dir() else [src]
    if not files or not all(f.is_file() for f in files):
        print(f"[KRATOS] No Sigma rule files at {src}.", file=sys.stderr)
        return 1
    name = re.sub(r"[^a-z0-9-]+", "-", (args.name or src.stem).lower()).strip("-")[:40] or "rules"
    data_dir = Path(args.data_dir)
    sources = [Source(path=f.name if not src.is_dir() else f.relative_to(src).as_posix(),
                      text=f.read_text(encoding="utf-8"), url=f.resolve().as_uri()) for f in files]
    compiled = compile_sources(sources, statuses=("stable", "test", "experimental"))
    shipped_ids = {r.id for lp in P.shipped_all() for r in lp.pack.rules}
    rules, skipped = [], list(compiled.skipped)
    for r in compiled.rules:
        if r["id"] in shipped_ids:
            skipped.append({"sigma_id": r["sigma_id"], "title": r["title"], "path": r["source"]["path"],
                            "kind": "duplicate", "reason": f"already shipped as {r['id']}", "author": r["author"]})
            continue
        why = add_samples(r)
        if why:
            skipped.append({"sigma_id": r["sigma_id"], "title": r["title"], "path": r["source"]["path"],
                            "kind": "samples", "reason": why, "author": r["author"]})
            continue
        rules.append(r)
    pack_id = f"local-{name}"
    previous = P.imported_dir(data_dir) / f"{pack_id}.json"
    version = 1
    if previous.exists():
        try:
            version = int(json.loads(previous.read_text(encoding="utf-8")).get("pack_version", 0)) + 1
        except (OSError, ValueError):
            version = 1
    for r in skipped:
        print(f"[KRATOS] not imported: {r.get('path')} ({r.get('title') or '?'}) -- {r.get('reason')}")
    if not rules:
        print("[KRATOS] No rule could be compiled faithfully; nothing imported.", file=sys.stderr)
        return 1
    pack = build_pack(rules, skipped, pack_id=pack_id, pack_version=version,
                      source={"imported_from": str(src.resolve()), "files": len(files)},
                      notice="Imported by a person from their own Sigma rules; each rule keeps its author.")
    dest = P.write_imported(data_dir, pack)
    print(f"[KRATOS] Imported {len(rules)} rule(s) as {pack_id} v{version} ({dest}). They run with the shipped "
          "rules from the next detection pass on.")
    return 0
