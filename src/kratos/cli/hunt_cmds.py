"""`kratos hunt` and `kratos threat-intel-sync` (C.3)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kratos.untrusted import safe_print


def _actor() -> str:
    from kratos.dataprune import actor_name

    return actor_name("cli")


def cmd_hunt(args: argparse.Namespace) -> int:
    from kratos.hunt import front, report

    data_dir = Path(args.data_dir)
    if args.build_index:
        return _cmd_index(data_dir)
    if args.history:
        return _cmd_history(data_dir, args)
    if args.from_intel:
        return _cmd_auto(data_dir, args)
    req = front.Request(words=list(args.indicators or []), kind=args.type, since=args.since, until=args.until,
                        machines=list(args.machine or []))
    if not req.words:
        print("[KRATOS] " + front.USAGE.replace("/hunt", "kratos hunt"), file=sys.stderr)
        return 2
    try:
        prepared = front.prepare(req)
        if prepared.ambiguous:
            a = prepared.ambiguous[0]
            print(f"[KRATOS] {a.question()} Run again with --type {' or --type '.join(a.options)}.",
                  file=sys.stderr)
            return 2
        result = front.run(data_dir, prepared, source="cli", actor=_actor(),
                           progress=(lambda m: print(f"[KRATOS] {m}", file=sys.stderr)) if not args.json else None)
    except front.HuntUsageError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, default=str))
    else:
        safe_print(report.render(result))
    return 0


def _cmd_index(data_dir: Path) -> int:
    from kratos.events.store import EventStore
    from kratos.hunt import terms

    store = EventStore(data_dir / "kratos.db")
    conn = store._connect()
    try:
        st = terms.state(conn)
        if st["done"]:
            print("[KRATOS] The hunt's search index is complete.")
            return 0
        print(f"[KRATOS] Indexing {st['remaining']:,} stored events (resumable: Ctrl+C keeps what is done)…")
        while not st["done"]:
            st = terms.backfill(conn, seconds=10)
            print(f"[KRATOS]   {st['remaining']:,} left", file=sys.stderr)
        print("[KRATOS] The hunt's search index is complete.")
    finally:
        conn.close()
    return 0


def _cmd_history(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.hunt import store
    from kratos.hunt.coverage import fmt

    rows = store.recent(data_dir, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
        return 0
    if not rows:
        print("[KRATOS] No hunts yet.")
        return 0
    for r in rows:
        what = ", ".join(f"{i.get('kind')} {i.get('value')}" for i in r["indicators"][:3])
        more = f" (+{len(r['indicators']) - 3})" if len(r["indicators"]) > 3 else ""
        safe_print(f"#{r['id']}  {fmt(r['at'])}  {r['source']:<5} {r['actor'][:40]:<40}  {what}{more}  -> "
                   f"{r['hits']:,} hit(s) on {r['hit_machines']} machine(s)")
        safe_print(f"      searched: {r['coverage'] or '-'}")
    return 0


def _cmd_auto(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.adapters.threat_intel import after_cache_update

    print("[KRATOS] " + after_cache_update(data_dir))
    return 0


def cmd_threat_intel_sync(args: argparse.Namespace) -> int:
    from kratos.adapters.threat_intel import update_threat_intel_cache

    ok, msg = update_threat_intel_cache(data_dir=Path(args.data_dir), hunt=not args.no_hunt)
    print(f"[KRATOS] {msg}", file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def register(sub: argparse._SubParsersAction) -> None:
    h = sub.add_parser(
        "hunt",
        help="Has this address / hash / account / domain / program / path been seen on your machines? "
             "(searches what Kratos holds, states the coverage)",
        description="Search everything Kratos already holds -- stored log events, detections, saved snapshots, "
                    "findings -- for an indicator. No model call, nothing sent to any machine. Every answer says "
                    "what was searched: 'not found' only ever means 'not found in what Kratos holds'.")
    h.add_argument("indicators", nargs="*", metavar="INDICATOR",
                   help="an IPv4/IPv6 address or CIDR, a SHA-256, an account, a domain, a program or a path "
                        f"(up to 10)")
    h.add_argument("--type", default=None, help="force the kind: ip, sha256, account, domain, program, path")
    h.add_argument("--machine", action="append", default=None, help="only this machine (repeatable)")
    h.add_argument("--since", default=None, help="e.g. 30d, 24h, '7 days ago', 2026-10-01 (default: everything)")
    h.add_argument("--until", default=None, help="the end of the window (default: now)")
    h.add_argument("--json", action="store_true", help="one JSON document (lists up to hunt.max_hits hits)")
    h.add_argument("--history", action="store_true", help="the hunts run so far, newest first")
    h.add_argument("--limit", type=int, default=20, help="with --history: how many")
    h.add_argument("--build-index", action="store_true",
                   help="finish indexing log events stored before hunting existed (resumable)")
    h.add_argument("--from-intel", action="store_true",
                   help="hunt the addresses the threat-intel cache lists that no hunt searched yet (HUNT-001)")
    h.set_defaults(func=cmd_hunt)

    t = sub.add_parser("threat-intel-sync",
                       help="Update the offline OTX reputation cache (needs OTX_API_KEY), then hunt the new "
                            "malicious addresses over what Kratos holds")
    t.add_argument("--no-hunt", action="store_true", help="only update the cache")
    t.set_defaults(func=cmd_threat_intel_sync)
