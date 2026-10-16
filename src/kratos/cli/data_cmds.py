"""`kratos data` (what Kratos keeps; prune) and `kratos trace` (run records).

Plain text through `untrusted.safe_print`; `--json` writes ASCII-escaped JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kratos.untrusted import safe_print as print  # noqa: A001 -- every line cleaned (A.4)


def cmd_data(args: argparse.Namespace) -> int:
    action = getattr(args, "data_action", None) or "list"
    if action == "prune":
        return _cmd_prune(args)
    if action == "history":
        return _cmd_prune_history(args)
    return _cmd_list(args)


def _cmd_list(args: argparse.Namespace) -> int:
    from kratos import datainv

    data_dir = Path(args.data_dir)
    measured = datainv.measure(data_dir)
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps({"data_dir": str(data_dir), "categories": [m.as_dict() for m in measured],
                                     "unlisted": [str(p) for p in datainv.unlisted(data_dir)]},
                                    indent=2, ensure_ascii=True) + "\n")
        return 0
    print(f"[KRATOS] What Kratos keeps in {data_dir}. {datainv.NOTHING_DELETED}")
    print(f"{'category':42s} {'size':>9s} {'items':>8s}  {'oldest':10s}  {'newest':10s}  personal")
    for m in measured:
        c = m.category
        print(f"{c.name[:42]:42s} {datainv.human_size(m.bytes):>9s} {m.items:>8,}  "
              f"{(datainv._iso(m.oldest) or '-')[:10]:10s}  {(datainv._iso(m.newest) or '-')[:10]:10s}  {c.personal}")
    total = sum(m.bytes for m in measured)
    print(f"{'total (data folder, kept tools, CVE list)':42s} {datainv.human_size(total):>9s}")
    if getattr(args, "verbose", False):
        for m in measured:
            c = m.category
            print("")
            print(f"{c.name} ({c.key}) -- {c.description}")
            print(f"  grows: {c.grows}" + (f"; {c.note}" if c.note else ""))
            for loc in m.locations or ["(nothing yet)"]:
                print(f"  {loc}")
            for e in m.errors:
                print(f"  could not read: {e}")
    others = datainv.unlisted(data_dir)
    if others:
        print("")
        print("Not made by Kratos (left alone): " + ", ".join(p.name for p in others))
    print("")
    print("Personal data: names of your machines, usernames, addresses, what you asked. Run records (traces) are "
          "the most detailed. `kratos data -v` shows where each lives; `kratos data prune --category "
          "traces|sessions|host_events --older-than 90d` removes old ones (preview first); `kratos snapshots prune` "
          "thins old snapshots.")
    return 0


def _days(text: str) -> int:
    t = str(text).strip().lower().rstrip("d")
    try:
        n = int(t)
    except ValueError:
        raise argparse.ArgumentTypeError("a number of days, e.g. 90d") from None
    if n < 1:
        raise argparse.ArgumentTypeError("at least 1 day")
    return n


def _cmd_prune(args: argparse.Namespace) -> int:
    from kratos import datainv, dataprune

    data_dir = Path(args.data_dir)
    try:
        plan = dataprune.plan_prune(data_dir, args.category, args.older_than)
    except dataprune.PruneError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 1
    name = datainv.category(args.category).name
    days = f"{args.older_than} day{'' if args.older_than == 1 else 's'}"
    print(f"[KRATOS] {name} older than {days} (before {datainv._iso(plan.cutoff)}):")
    for line in plan.describe():
        print(f"[KRATOS]   would remove {line}")
    if plan.bytes:
        print(f"[KRATOS]   about {datainv.human_size(plan.bytes)}")
    for b in plan.blockers:
        print(f"[KRATOS] Other data depends on this: {b}")
    if not args.apply:
        print("[KRATOS] Preview only -- nothing deleted. Re-run with --apply to remove these.")
        return 0
    if plan.empty:
        print("[KRATOS] Nothing to remove.")
        return 0
    try:
        done = dataprune.apply_prune(data_dir, plan, actor=dataprune.actor_name("cli"),
                                     force_orphans=args.force_orphans)
    except dataprune.PruneError as e:
        print(f"[KRATOS] Not removed: {e}", file=sys.stderr)
        return 1
    print("[KRATOS] Removed: " + (", ".join(f"{n} {k}" for k, n in done.items()) or "nothing")
          + ". Recorded in `kratos data history`.")
    return 0


def _cmd_prune_history(args: argparse.Namespace) -> int:
    from kratos import datainv, dataprune

    rows = dataprune.history(Path(args.data_dir))
    if not rows:
        print("[KRATOS] No prunes recorded. Kratos has never deleted stored data on its own.")
        return 0
    for r in rows:
        print(f"{datainv._iso(r['at'])}  {r['category']:12s} older than {r['older_than_days']}d  "
              f"{r['items']} item(s)  by {r['actor']}" + ("  (with --force-orphans)" if r["forced"] else ""))
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    from kratos.utils.timeutil import epoch_of as to_epoch
    from kratos.trace import store, view

    data_dir = Path(args.data_dir)
    if args.trace_action == "show":
        try:
            info = store.find(data_dir, args.run)
        except store.AmbiguousTrace as e:
            print(f"[KRATOS] {e}. Give more of the id.", file=sys.stderr)
            return 1
        if info is None:
            print(f"[KRATOS] No run record {args.run!r} in {data_dir / 'traces'}. `kratos trace list` shows them.",
                  file=sys.stderr)
            return 1
        if args.json:
            if info.data is None:
                print(f"[KRATOS] Could not read {info.path}: {info.error}", file=sys.stderr)
                return 1
            sys.stdout.write(json.dumps(info.data, indent=1, ensure_ascii=True) + "\n")
            return 0
        kids = store.children_of(data_dir, (info.data or {}).get("run_id") or "") if info.data else []
        for line in view.show_lines(info, children=kids):
            print(line)
        return 0
    since = None
    if args.since:
        from kratos.utils.time_window import TimeBoundError, resolve_time_bound

        try:
            since = to_epoch(resolve_time_bound(args.since))
        except TimeBoundError as e:
            print(f"[KRATOS] {e}", file=sys.stderr)
            return 1
    items = store.list_traces(data_dir, target=args.target, since=since, limit=args.limit)
    if not items:
        print("[KRATOS] No run records yet. Every investigation, /run audit, scheduled run and trigger writes one.")
        return 0
    for info in items:
        print(view.list_line(info))
    print("")
    print("[KRATOS] `kratos trace show <id>` for one run (the first characters of the id are enough).")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    data_p = sub.add_parser(
        "data",
        help="What Kratos keeps on this computer (where, how big, personal or not); prune old data yourself",
    )
    data_p.add_argument("--json", action="store_true", help="One JSON document")
    data_p.add_argument("-v", "--verbose", action="store_true", help="Where each kind lives")
    dsub = data_p.add_subparsers(dest="data_action")
    dsub.add_parser("list", help="The inventory (the default)")
    pr = dsub.add_parser("prune", help="Remove old run records, conversations or host events (preview unless --apply)")
    pr.add_argument("--category", required=True, choices=("traces", "sessions", "host_events"))
    pr.add_argument("--older-than", required=True, type=_days, metavar="DAYS", help="e.g. 90d")
    pr.add_argument("--apply", action="store_true", help="Actually delete (default: a preview)")
    pr.add_argument("--force-orphans", action="store_true",
                    help="Delete even when other data depends on it (the preview says what)")
    dsub.add_parser("history", help="Prunes you have run")
    data_p.set_defaults(func=cmd_data)

    tr = sub.add_parser("trace", help="Run records: what each investigation, audit or scheduled run did")
    tsub = tr.add_subparsers(dest="trace_action", required=True)
    tl = tsub.add_parser("list", help="Recent runs, newest first")
    tl.add_argument("--target", default=None, help="Only runs about this machine")
    tl.add_argument("--since", default=None, help="e.g. 'yesterday', '7 days ago'")
    tl.add_argument("--limit", type=int, default=30)
    ts = tsub.add_parser("show", help="One run: model calls, tool calls, checks, guards and the answer")
    ts.add_argument("run", help="The run id (or its first characters)")
    ts.add_argument("--json", action="store_true", help="The whole record as JSON")
    tr.set_defaults(func=cmd_trace)
