"""`kratos review ...` (E.7b §3.14): prepare / start / status / show / runs / verdicts / about /
export. prepare and start are admin-local (person-started); the rest are read-only. The plan a
prepare builds is held in memory, so within one CLI process `start` can reuse it by id; if no
live plan is given, `start` re-prepares (the read + slice happen again) and then, only with an
explicit yes, sends. A run is refused above the cost ceiling unless the person raises it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from kratos.untrusted import for_display, safe_print


def _actor():
    from kratos.lifecycle.decide import Actor
    return Actor.current("cli")


def cmd_review(args: argparse.Namespace) -> int:
    from kratos.review import run as RUN
    from kratos.review.plan import PlanError
    from kratos.review.run import ReviewRefused

    data_dir = Path(args.data_dir)
    sub = args.review_cmd
    try:
        if sub == "about":
            return _about()
        if sub == "status":
            return _status(data_dir, args)
        if sub == "runs":
            return _runs(data_dir, args)
        if sub == "show":
            return _show(data_dir, args)
        if sub == "verdicts":
            return _verdicts(data_dir, args)
        if sub == "export":
            return _export(data_dir, args)
        if sub == "prepare":
            plan = RUN.prepare_review(data_dir, _actor(), args.machine, args.folder,
                                      profile_name=args.profile, fresh=args.fresh)
            _print_plan(plan)
            safe_print(f"\nplan id: {plan.plan_id} (valid {plan.ttl_seconds // 60} min)")
            safe_print("send it with:  kratos review start " + f"{args.machine} {args.folder} --yes "
                       f"--agreed <usd>   (or --plan {plan.plan_id})")
            return 0
        if sub == "start":
            return _start(data_dir, args)
    except ReviewRefused as e:
        print(f"[KRATOS] Refused: {for_display(str(e))}", file=sys.stderr)
        return 1
    except PlanError as e:
        print(f"[KRATOS] {for_display(str(e))}", file=sys.stderr)
        return 1
    return 2


def _print_plan(plan) -> None:
    s = plan.consent_summary()
    safe_print(for_display(s["line"]))
    safe_print(f"  reads/slices {s['slices_to_send']} slice(s), {s['bytes_to_send']} bytes from {s['root']} "
               f"on {s['machine']}")
    safe_print(f"  cached (free): {s['slices_cached']}; dropped by cap: {s['dropped_by_cap']}; "
               f"reproduction: {'on' if s['reproduction'] else 'OFF (no sandbox)'}")
    if s["incomplete_languages"]:
        safe_print("  not sliced (no `review` extra): "
                   + ", ".join(f"{n} {ext}" for ext, n in s["incomplete_languages"].items()))
    if s["priced"]:
        safe_print(f"  estimated cost: ${s['estimate_usd']:.4f} ({s['est_calls']} calls, {s['est_tokens']} tokens)")
    else:
        safe_print(f"  estimated cost: $0 (a model on your own network; {s['est_calls']} calls)")
    safe_print(f"  reduction: {s['reduction']}x (bytes in the folder / bytes sliced)")


def _start(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.review import cost as COST
    from kratos.review import run as RUN
    from kratos.review import settings as RS
    from kratos.review.plan import get_plan

    plan = get_plan(args.plan) if args.plan else None
    if plan is None:
        plan = RUN.prepare_review(data_dir, _actor(), args.machine, args.folder,
                                  profile_name=args.profile, fresh=args.fresh)
    _print_plan(plan)
    max_run = float(RS.get(RS.MAX_RUN_USD, data_dir))
    raised_to = float(args.raise_to) if args.raise_to is not None else None
    if not COST.fits_ceiling(plan.estimate.usd, max_run, raised_to):
        print(f"[KRATOS] Refused: the estimate ${plan.estimate.usd:.4f} is over the ceiling "
              f"${COST.ceiling_for(max_run, raised_to):.2f} (review.max_run_usd). Raise it for this run with "
              "--raise-to <usd>.", file=sys.stderr)
        return 1
    agreed = float(args.agreed) if args.agreed is not None else COST.ceiling_for(max_run, raised_to)
    if not args.yes:
        try:
            ans = input(f"Send these slices and spend up to ${agreed:.2f}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            safe_print("not sent; nothing left the machine.")
            return 0
    res = RUN.start_review(data_dir, _actor(), plan.plan_id, agreed_usd=agreed,
                           raised_by=("owner" if raised_to else ""), raised_to=raised_to)
    safe_print(f"\nreview {res.run_id}: {res.state}" + (f" ({res.stop_reason})" if res.stop_reason else ""))
    safe_print(f"  actual cost: ${res.actual_usd:.4f}; findings: {len(res.findings)}")
    for f in res.findings:
        safe_print(f"    {f['verdict']}" + (f"({f['strength']})" if f.get("strength") else "")
                   + f"  {f['cls']}  {f['rel']}:{f['function']}")
    return 0 if res.state in ("done", "stopped") else 1


def _status(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.code import present as P
    from kratos.review import store as ST
    tk, _scope = P.resolve_code_reader(data_dir, _actor(), args.machine)
    runs = ST.runs(data_dir, tk)
    confirmed = [r for r in P.view(data_dir, tk)["roots"] if r["status"] == "confirmed"]
    if args.json:
        sys.stdout.write(json.dumps({"roots": [r["path"] for r in confirmed], "runs": runs}, indent=2, default=str)
                         + "\n")
        return 0
    if not confirmed:
        safe_print("no confirmed code folders on this machine (`kratos code confirm ...`).")
    for r in confirmed:
        last = next((x for x in runs if x["root"] == r["path"]), None)
        if last:
            safe_print(f"{r['path']}: last review {last['state']} on "
                       f"{for_display(str(last.get('started_at')))}, cost ${last.get('actual_usd', 0):.4f}, "
                       f"profile {last.get('profile')}")
        else:
            safe_print(f"{r['path']}: never reviewed")
    return 0


def _runs(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.review import store as ST
    rows = ST.runs(data_dir, limit=int(args.limit))
    if args.json:
        sys.stdout.write(json.dumps(rows, indent=2, default=str) + "\n")
        return 0
    for r in rows:
        safe_print(f"{r['id']:>4}  {r['state']:<10} {for_display(r['root'])}  {r['profile']}  "
                   f"${r.get('actual_usd', 0):.4f}  {for_display(str(r.get('stop_reason') or ''))}")
    return 0


def _show(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.review import store as ST
    run = ST.get_run(data_dir, int(args.run))
    if run is None:
        print("[KRATOS] no such review run", file=sys.stderr)
        return 1
    if args.json:
        sys.stdout.write(json.dumps({"run": run, "candidates": ST.candidates(data_dir, int(args.run)),
                                     "slices": ST.slices(data_dir, int(args.run))}, indent=2, default=str) + "\n")
        return 0
    safe_print(f"review {run['id']}: {run['state']} ({for_display(run['root'])})")
    safe_print(f"  profile {run['profile']}, cost estimate ${run.get('estimate_usd', 0):.4f}, agreed "
               f"${run.get('agreed_usd', 0):.4f}, actual ${run.get('actual_usd', 0):.4f}")
    for c in ST.candidates(data_dir, int(args.run)):
        safe_print(f"  lead {c['class']} {c['file']}:{c['line']}  {for_display(str(c.get('reason') or ''))[:80]}")
    return 0


def _verdicts(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.review import store as ST
    if not ST._exists(data_dir):
        safe_print("no reviews yet.")
        return 0
    conn = ST.connect(data_dir)
    try:
        rows = [dict(r) for r in conn.execute("SELECT verdict, strength, COUNT(*) n FROM review_verdicts "
                                              "GROUP BY verdict, strength ORDER BY verdict")]
    finally:
        conn.close()
    for r in rows:
        safe_print(f"  {r['verdict']}" + (f"({r['strength']})" if r['strength'] else "") + f": {r['n']} cached")
    return 0


def _export(data_dir: Path, args: argparse.Namespace) -> int:
    from kratos.review import sarif as S
    if not args.sarif:
        print("[KRATOS] use --sarif FILE", file=sys.stderr)
        return 1
    out = S.write_sarif(data_dir, args.sarif, machine=args.machine, include_code=args.code)
    safe_print(f"[KRATOS] wrote SARIF 2.1.0 to {out} (no code, no snippet).")
    return 0


def _about() -> int:
    from kratos.code.reads import review_extensions
    exts = review_extensions()
    safe_print("AI review of deployed code (opt-in, per folder):")
    safe_print("  - Kratos reads a confirmed folder's source locally, slices only what the network can reach,")
    safe_print("    and sends those slices to a saved model profile you pick -- shown on every run, with the")
    safe_print("    destination (a hosted service, or a model on your own network). Secrets are always removed.")
    safe_print("  - The verdict is decided by code (a sandbox reproduction or a direct rule, never the model's")
    safe_print("    words). A reproduction replaces the real dangerous call with a recorder: it is never run.")
    safe_print(f"  - Languages sliced now: {', '.join(exts)}"
               + ("" if ".php" in exts else "  (install the `review` extra for PHP/JS/TS)"))
    safe_print("  - Nothing runs on the monitored machine; fixes are proposed and sandbox-checked, never applied.")
    return 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("review", help="AI review of the code a machine serves (opt-in, per folder)")
    rs = p.add_subparsers(dest="review_cmd", required=True)

    pr = rs.add_parser("prepare", help="read and slice a confirmed folder locally; show the plan and cost")
    pr.add_argument("machine")
    pr.add_argument("folder")
    pr.add_argument("--profile", default=None, help="a saved model profile (see /model); the review never uses the "
                    "active model by default")
    pr.add_argument("--fresh", action="store_true", help="ignore the verdict cache for this run")

    st = rs.add_parser("start", help="send a prepared plan (or prepare + send) after you agree to the cost")
    st.add_argument("machine")
    st.add_argument("folder")
    st.add_argument("--plan", default=None, help="a plan id from `review prepare` (same process)")
    st.add_argument("--profile", default=None)
    st.add_argument("--fresh", action="store_true")
    st.add_argument("--agreed", default=None, help="the most to spend this run (USD)")
    st.add_argument("--raise-to", dest="raise_to", default=None, help="raise the per-run ceiling for this run (USD)")
    st.add_argument("--yes", action="store_true", help="don't ask; still prints the plan and refuses over the ceiling")

    for name, help_ in (("status", "confirmed folders and their last review"),
                        ("runs", "recent review runs")):
        x = rs.add_parser(name, help=help_)
        x.add_argument("machine", nargs="?")
        x.add_argument("--json", action="store_true")
        if name == "runs":
            x.add_argument("--limit", default=50)

    sh = rs.add_parser("show", help="one review run's leads and verdicts")
    sh.add_argument("run")
    sh.add_argument("--json", action="store_true")

    rs.add_parser("verdicts", help="how many verdicts are cached, by kind")
    rs.add_parser("about", help="what a review sends, where, and the languages it slices")

    ex = rs.add_parser("export", help="write REVIEW findings as SARIF 2.1.0 (no code)")
    ex.add_argument("--sarif", required=True, help="output file")
    ex.add_argument("--machine", default=None)
    ex.add_argument("--code", action="store_true", help="also include CODE-001..005 findings")

    p.set_defaults(func=cmd_review)
