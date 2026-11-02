"""`kratos groups` and `kratos fleet`: groups of machines and questions about them (D.2).

    kratos groups list
    kratos groups show <GROUP>
    kratos groups create <GROUP> [MACHINE ...] [--note TEXT]
    kratos groups add <GROUP> MACHINE [MACHINE ...]
    kratos groups remove <GROUP> MACHINE [MACHINE ...]
    kratos groups delete <GROUP>

    kratos fleet ask <@GROUP | MACHINE,MACHINE,...> "<question>" [--slow] [--yes] [--json]
    kratos fleet audit <@GROUP> [--notify]
    kratos fleet status [@GROUP]
    kratos fleet runs [--limit N]

A fleet answer is one checked answer per machine: each machine's claims are held to that
machine's own evidence, a machine Kratos couldn't read is named with the reason, and the
summary line is built by Kratos. `@all` is every machine with an asset record.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    g = sub.add_parser("groups", help="Groups of machines to ask about at once (@web, @db ...; @all is built in)")
    gsub = g.add_subparsers(dest="groups_action", required=True)
    gsub.add_parser("list", help="Every group and its machines")
    s = gsub.add_parser("show", help="One group's machines and how each is reached")
    s.add_argument("group")
    c = gsub.add_parser("create", help="Make a group (recorded with your name)")
    c.add_argument("group")
    c.add_argument("machines", nargs="*")
    c.add_argument("--note", default="")
    a = gsub.add_parser("add", help="Add machines to a group")
    a.add_argument("group")
    a.add_argument("machines", nargs="+")
    r = gsub.add_parser("remove", help="Take machines out of a group")
    r.add_argument("group")
    r.add_argument("machines", nargs="+")
    d = gsub.add_parser("delete", help="Delete a group (its history is kept)")
    d.add_argument("group")
    g.set_defaults(func=cmd_groups)

    f = sub.add_parser("fleet", help="Ask one question about a group of machines; each answered and checked on its own")
    fsub = f.add_subparsers(dest="fleet_action", required=True)
    ask = fsub.add_parser("ask", help="Ask about a group: one checked answer per machine")
    ask.add_argument("group", help="@GROUP, or machines separated by commas")
    ask.add_argument("question")
    ask.add_argument("--slow", action="store_true", help="Also run the slow checks (vulnerability scan, YARA ...)")
    ask.add_argument("--yes", "-y", action="store_true", help="Don't ask before starting (the estimate is still shown)")
    ask.add_argument("--json", action="store_true")
    au = fsub.add_parser("audit", help="The standard audit on every machine of a group (code only, no model)")
    au.add_argument("group")
    au.add_argument("--notify", action="store_true", help="Send one grouped notification for the run")
    st = fsub.add_parser("status", help="Machines by group: last collection, open findings, agent version, link")
    st.add_argument("group", nargs="?", default="@all")
    st.add_argument("--json", action="store_true")
    rn = fsub.add_parser("runs", help="Recent fleet questions and audits")
    rn.add_argument("--limit", type=int, default=10)
    f.set_defaults(func=cmd_fleet)


def _actor() -> Any:
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def cmd_groups(args: argparse.Namespace) -> int:
    from kratos.fleet import groups as G
    from kratos.fleet.collect import machine_info

    data_dir = Path(args.data_dir)
    try:
        if args.groups_action == "list":
            for grp in G.list_groups(data_dir):
                kind = " (built in)" if grp.builtin else ""
                note = f" -- {grp.note}" if grp.note and not grp.builtin else ""
                print(f"@{grp.name}{kind}: {len(grp.members)} machine(s){note}")
                for m in grp.members[:20]:
                    print(f"    {m}")
            return 0
        if args.groups_action == "show":
            grp = G.get_group(data_dir, args.group)
            if grp is None:
                print(f"[KRATOS] No group named {args.group!r}.")
                return 1
            r = G.resolve(data_dir, f"@{grp.name}") if grp.members else None
            print(f"@{grp.name}: {len(grp.members)} machine(s)")
            for m in grp.members:
                info = machine_info(data_dir, m)
                dup = next((b for a, b in (r.duplicates if r else []) if a == m), None)
                extra = f" -- the same machine as {dup}, asked about once" if dup else ""
                name = f" ({info['label']})" if info["label"] else ""
                print(f"    {m}{name}: {info['transport']}{extra}")
            return 0
        actor = _actor()
        if args.groups_action == "create":
            grp = G.create_group(data_dir, args.group, actor, members=args.machines, note=args.note)
            print(f"[KRATOS] @{grp.name} made with {len(grp.members)} machine(s) -- recorded as {actor.user}.")
            return 0
        if args.groups_action == "add":
            added = G.add_members(data_dir, args.group, args.machines, actor)
            print(f"[KRATOS] Added to @{G.check_name(args.group)}: {', '.join(added) or 'nothing new'}.")
            return 0
        if args.groups_action == "remove":
            removed = G.remove_members(data_dir, args.group, args.machines, actor)
            print(f"[KRATOS] Removed from @{G.check_name(args.group)}: {', '.join(removed) or 'none of those'}.")
            return 0
        if args.groups_action == "delete":
            G.delete_group(data_dir, args.group, actor)
            print(f"[KRATOS] @{G.check_name(args.group)} deleted (its history is kept).")
            return 0
    except G.GroupError as e:
        print(f"[KRATOS] Not changed: {e}")
        return 1
    return 1


def _group_arg(value: str) -> str | list[str]:
    v = value.strip()
    if v.startswith("@"):
        return v
    parts = [p.strip() for p in v.split(",") if p.strip()]
    return parts if len(parts) > 1 else (parts[0] if parts and _is_group_name(parts[0]) else parts)


def _is_group_name(text: str) -> bool:
    from kratos.fleet import groups as G

    return bool(G.NAME_RE.match(text)) and "." not in text


def cmd_fleet(args: argparse.Namespace) -> int:
    from kratos.fleet import record
    from kratos.fleet import run as R

    data_dir = Path(args.data_dir)
    if args.fleet_action == "runs":
        for r in record.recent(data_dir, args.limit):
            from kratos.utils.timeutil import epoch_to_utc_iso

            print(f"{epoch_to_utc_iso(r['started_at'])}  {r['group_ref']}  {r['kind']}  {r['status']}  "
                  f"({r['actor']}, {r['interface']})  {r['summary'] or ''}")
        return 0
    if args.fleet_action == "status":
        return _status(data_dir, args.group, args.json)
    group = _group_arg(args.group)

    def progress(line: str) -> None:
        print(f"  {line}", file=sys.stderr)

    def confirm(est: Any) -> bool:
        print(f"[KRATOS] {est.text()}", file=sys.stderr)
        if args.fleet_action == "audit" or getattr(args, "yes", False) or not sys.stdin.isatty():
            return True
        try:
            return input("Start? [y/N] ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    kind = "audit" if args.fleet_action == "audit" else "question"
    req = R.FleetRequest(question=getattr(args, "question", "") or "", group=group, data_dir=data_dir,
                         actor=_actor(), source="cli", kind=kind, slow=getattr(args, "slow", False),
                         notify=getattr(args, "notify", False), on_progress=progress, confirm=confirm)
    try:
        out = R.run_fleet(req)
    except R.FleetError as e:
        print(f"[KRATOS] {e}")
        return 1
    if getattr(args, "json", False):
        print(json.dumps(_as_json(out), indent=2, default=str))
    else:
        print(out.text)
    return 0 if out.status in ("final_answer", "audit", "fallback") else 1


def _as_json(out: Any) -> dict[str, Any]:
    a = out.answer
    return {"status": out.status, "run_id": out.run_id, "group": out.group_label, "summary": a.summary if a else None,
            "model_summary": a.model_summary if a else None,
            "machines": [{"machine": m.machine, "name": m.label, "outcome": m.outcome, "reason": m.reason,
                          "passed": m.passed, "kratos_found": m.block, "notes": m.notes, "analysis": m.analysis,
                          "kratos_text": m.kratos_text} for m in (a.machines if a else [])],
            "extra_reads": a.extra_reads if a else [], "estimate": out.estimate.as_dict() if out.estimate else None,
            "refusal": out.refusal}


def _status(data_dir: Path, group: str, as_json: bool) -> int:
    from kratos.fleet.status import agent_update_note, rows as status_rows

    rows = status_rows(data_dir, group)
    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print(f"[KRATOS] No machines in {group}.")
        return 0
    from kratos.collect.digest import ago
    import time

    print(f"{'MACHINE':<24} {'LINK':<22} {'AGENT':<8} {'CERT':<10} {'COLLECTED':<12} OPEN FINDINGS")
    for r in rows:
        if r.get("duplicate_of"):
            print(f"{r['machine'][:24]:<24} the same machine as {r['duplicate_of']} (shown once)")
            continue
        when = ago(time.time() - r["last_collected"]) if r["last_collected"] else "never"
        found = ", ".join(f"{n} {s}" for s, n in sorted(r["open_findings"].items())) or "-"
        name = r["machine"] + (f" ({r['name']})" if r["name"] else "")
        print(f"{name[:24]:<24} {r['link'][:22]:<22} {(r['agent_version'] or '-')[:8]:<8} "
              f"{(r['certificate'] or '-')[:10]:<10} {when[:12]:<12} {found}")
    note = agent_update_note(rows)
    if note:
        print(f"\n[KRATOS] {note}")
    return 0
