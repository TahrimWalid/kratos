"""`kratos trace` (run records).

Plain text through `untrusted.safe_print`; `--json` writes ASCII-escaped JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kratos.untrusted import safe_print as print  # noqa: A001 -- every line cleaned (A.4)


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
