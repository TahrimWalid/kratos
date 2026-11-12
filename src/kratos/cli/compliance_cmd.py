"""`kratos compliance ...` (E.2 §3.11): reports, control owners, "not applicable"
decisions and the CIS level per machine.

    kratos compliance report [--framework cis|iso27001|nis2] [--machine M | --group G]
                             [--format md|csv|json] [--out FILE] [--all] [--refresh]
    kratos compliance owner set FRAMEWORK CONTROL OWNER [--scope ...] [--due YYYY-MM-DD] [--note ...]
    kratos compliance owner clear FRAMEWORK CONTROL [--scope ...]
    kratos compliance na set FRAMEWORK CONTROL --reason "..." [--days N] [--scope ...]
    kratos compliance na clear FRAMEWORK CONTROL [--scope ...]
    kratos compliance level set MACHINE 1|2
    kratos compliance history [--limit N]

A report is evidence from Kratos's checks, never a certification. Decisions are a
person's (the owner at this computer) and are recorded with who made them.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kratos.untrusted import for_display, safe_print


def _actor():
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _scope(args: argparse.Namespace) -> str:
    if getattr(args, "scope", None):
        return args.scope
    if getattr(args, "machine", None):
        return f"machine:{args.machine}"
    return "all"


def cmd_compliance(args: argparse.Namespace) -> int:
    from kratos.compliance import owners as O
    from kratos.compliance import report as RP

    data_dir = Path(args.data_dir)
    sub = args.compliance_cmd
    try:
        if sub == "report":
            machines, outside, label = RP.resolve_machines(data_dir, _actor(), machine=args.machine, group=args.group)
            if args.refresh:
                _refresh(data_dir, machines)
            doc = RP.build(data_dir, args.framework, machines, outside_scope=outside, label=label)
            text = RP.render(doc, args.format, include_not_checked=args.all)
            if args.out and args.out != "-":
                from kratos.paths import write_private_text

                write_private_text(Path(args.out), text)
                print(f"[KRATOS] Wrote the {args.framework} report for {for_display(label)} to {args.out}")
                for s in doc["machines"]:
                    safe_print(f"  {s['machine']}: {s.get('summary') or s.get('reason')}")
            else:
                sys.stdout.write(text if args.format != "md" else for_display(text, max_len=None))
            return 0
        if sub == "owner":
            if args.owner_cmd == "set":
                row = O.set_owner(data_dir, _actor(), args.framework, args.control, _scope(args), args.owner,
                                  due=args.due, note=args.note or "")
                safe_print(f"[KRATOS] {row['framework']} {row['control']} ({row['scope']}): owner {row['owner_name']}"
                           + (f", due {row['due']}" if row["due"] else ""))
            else:
                ok = O.clear_owner(data_dir, _actor(), args.framework, args.control, _scope(args))
                print("[KRATOS] Owner cleared." if ok else "[KRATOS] No owner was set there.")
            return 0
        if sub == "na":
            if args.na_cmd == "set":
                row = O.set_na(data_dir, _actor(), args.framework, args.control, _scope(args), args.reason, args.days)
                safe_print(f"[KRATOS] {row['framework']} {row['control']} ({row['scope']}) is 'not applicable' for "
                           f"{args.days} days: {row['reason']}. Kratos asks again when it expires.")
            else:
                ok = O.clear_na(data_dir, _actor(), args.framework, args.control, _scope(args))
                print("[KRATOS] Decision cleared: the computed status is back." if ok
                      else "[KRATOS] No 'not applicable' decision was set there.")
            return 0
        if sub == "level":
            lv = O.set_level(data_dir, _actor(), args.machine, args.level)
            print(f"[KRATOS] CIS profile for {args.machine}: {lv.replace('_', ' ')}.")
            return 0
        if sub == "history":
            from kratos.compliance import store

            for e in reversed(store.events(data_dir, limit=args.limit)):
                from kratos.utils.timeutil import epoch_to_utc_iso

                safe_print(f"{epoch_to_utc_iso(e['at'])}  {e['kind']:<12} {e['framework']} {e['control_id']} "
                           f"{e['scope']}  by {e['actor']} ({e['interface']})  {e['detail']}")
            return 0
    except (RP.ReportError, O.ComplianceError) as e:
        print(f"[KRATOS] {for_display(e)}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        from kratos import authz

        if isinstance(e, authz.Denied):
            print(f"[KRATOS] {for_display(e)}", file=sys.stderr)
            return 2
        raise
    return 2


def _refresh(data_dir: Path, machines: list[str]) -> None:
    """Read the hardening facts again now (one fixed read per machine), before reporting."""
    from kratos.compliance import record
    from kratos.kratos_config import pinned_target
    from kratos.run_context import run_scope

    for m in machines:
        with run_scope("cli", target=m), pinned_target(m):
            doc = record.run(data_dir, m)
        safe_print(f"[KRATOS] {m}: {record.summary_line(doc)}")


def register(sub: argparse._SubParsersAction) -> None:
    from kratos.compliance import frameworks as F
    from kratos.compliance import report as RP

    p = sub.add_parser("compliance", help="Compliance reports (CIS, ISO 27001, NIS2) from Kratos's checks; control "
                                          "owners and 'not applicable' decisions")
    cs = p.add_subparsers(dest="compliance_cmd", required=True)
    r = cs.add_parser("report", help="a report for one machine or a group (evidence, not a certification)")
    r.add_argument("--framework", choices=F.FRAMEWORKS, default="cis")
    r.add_argument("--machine")
    r.add_argument("--group")
    r.add_argument("--format", choices=RP.FORMATS, default="md")
    r.add_argument("--out", help="write to this file (0600) instead of the screen")
    r.add_argument("--all", action="store_true", help="also list CIS sections Kratos has no check for")
    r.add_argument("--refresh", action="store_true", help="read the hardening facts again first")
    o = cs.add_parser("owner", help="set or clear who owns a control")
    os_ = o.add_subparsers(dest="owner_cmd", required=True)
    for name in ("set", "clear"):
        x = os_.add_parser(name)
        x.add_argument("framework", choices=F.FRAMEWORKS)
        x.add_argument("control")
        if name == "set":
            x.add_argument("owner", help="a Kratos user's name, or any name")
            x.add_argument("--due", help="YYYY-MM-DD")
            x.add_argument("--note")
        x.add_argument("--scope", help="machine:<name>, group:<name> or all (default all)")
        x.add_argument("--machine", help="shorthand for --scope machine:<name>")
    n = cs.add_parser("na", help="mark a control 'not applicable' (with a reason and an expiry) or clear it")
    ns = n.add_subparsers(dest="na_cmd", required=True)
    for name in ("set", "clear"):
        x = ns.add_parser(name)
        x.add_argument("framework", choices=F.FRAMEWORKS)
        x.add_argument("control")
        if name == "set":
            x.add_argument("--reason", required=True)
            x.add_argument("--days", type=int, default=365)
        x.add_argument("--scope")
        x.add_argument("--machine")
    lv = cs.add_parser("level", help="the CIS profile level for a machine")
    lvs = lv.add_subparsers(dest="level_cmd", required=True)
    ls = lvs.add_parser("set")
    ls.add_argument("machine")
    ls.add_argument("level", choices=("1", "2"))
    h = cs.add_parser("history", help="who changed owners, 'not applicable' decisions and levels")
    h.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_compliance)
