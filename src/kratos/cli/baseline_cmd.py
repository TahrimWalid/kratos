"""`kratos baseline ...` (E.3 §3.12): what Kratos has learned is normal per machine, and
people's decisions about it.

    kratos baseline show [MACHINE] [--kind K] [--json]
    kratos baseline accept MACHINE KIND SUBJECT KEY [--reason "..."]
    kratos baseline forget MACHINE KIND SUBJECT KEY [--reason "..."]
    kratos baseline freeze MACHINE [--reason "..."]
    kratos baseline unfreeze MACHINE [--reason "..."]
    kratos baseline reset MACHINE [--kind K ...] --yes [--reason "..."]
    kratos baseline run [MACHINE]

KIND is one of login_source, login_time, login_method, sudo_use, listener, outbound,
program. SUBJECT and KEY are as `show` prints them. Decisions are the owner's, at this
computer, and are recorded with who made them.
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


def cmd_baseline(args: argparse.Namespace) -> int:
    from kratos.baseline import decide as BD
    from kratos.baseline import present as BP

    data_dir = Path(args.data_dir)
    sub = args.baseline_cmd
    try:
        if sub == "show":
            tk, scope = BP.resolve_reader(data_dir, _actor(), args.machine)
            v = BP.view(data_dir, tk, scope=scope, dim=args.kind)
            if args.json:
                sys.stdout.write(json.dumps(v, indent=2, default=str) + "\n")
            else:
                sys.stdout.write(for_display(BP.to_text(v), max_len=None) + "\n")
            return 0
        if sub == "run":
            from kratos import kratos_config
            from kratos.baseline import record

            tk, _scope = BP.resolve_reader(data_dir, _actor(), args.machine)
            with kratos_config.pinned_target(tk):
                doc = record.run(data_dir, tk)
            safe_print(f"[KRATOS] {tk}: {record.summary_line(doc)}")
            return 0
        actor = _actor()
        if sub == "accept":
            res = BD.accept(data_dir, args.machine, args.kind, args.subject, args.key, actor=actor, reason=args.reason)
            safe_print(f"[KRATOS] {res['subject']}: {res['key']} is normal on {res['machine']} from now on "
                       f"(finding: {res['finding']}).")
        elif sub == "forget":
            res = BD.forget(data_dir, args.machine, args.kind, args.subject, args.key, actor=actor, reason=args.reason)
            safe_print(f"[KRATOS] Forgot {args.subject}: {args.key} -- it counts as new again (finding: "
                       f"{res['finding']}).")
        elif sub == "freeze":
            BD.freeze(data_dir, args.machine, actor=actor, reason=args.reason)
            safe_print(f"[KRATOS] {args.machine}: baseline frozen -- deviations are still raised, nothing is learned "
                       "until you unfreeze it.")
        elif sub == "unfreeze":
            BD.unfreeze(data_dir, args.machine, actor=actor, reason=args.reason)
            safe_print(f"[KRATOS] {args.machine}: learning resumes.")
        elif sub == "reset":
            if not args.yes:
                print("[KRATOS] reset starts learning again from now (the old profile is kept as history); add --yes "
                      "to confirm", file=sys.stderr)
                return 2
            res = BD.reset(data_dir, args.machine, actor=actor, reason=args.reason, dims=args.kind or None)
            safe_print(f"[KRATOS] {res['machine']}: learning starts again for {', '.join(res['reset'])}; the old "
                       "profile is kept as history.")
        return 0
    except (BD.BaselineError, BP.ViewError) as e:
        print(f"[KRATOS] Refused: {for_display(str(e))}", file=sys.stderr)
        return 1


def register(sub: argparse._SubParsersAction) -> None:
    from kratos.baseline import dims as D

    kinds = tuple(D.BY_NAME)
    p = sub.add_parser("baseline", help="What Kratos has learned is normal per machine; accept, forget, freeze, reset")
    bs = p.add_subparsers(dest="baseline_cmd", required=True)
    s = bs.add_parser("show", help="each kind of normal, its learning status, the usual things, today's deviations")
    s.add_argument("machine", nargs="?")
    s.add_argument("--kind", choices=kinds)
    s.add_argument("--json", action="store_true")
    r = bs.add_parser("run", help="learn from what's stored now and judge it (no read of the machine)")
    r.add_argument("machine", nargs="?")
    for name, text in (("accept", "mark something normal: it is never raised again"),
                       ("forget", "forget something learned: it counts as new again")):
        x = bs.add_parser(name, help=text)
        x.add_argument("machine")
        x.add_argument("kind", choices=kinds)
        x.add_argument("subject", help="the account or program, as `show` prints it")
        x.add_argument("key", help="the place, hour, method, port... as `show` prints it")
        x.add_argument("--reason", default="")
    for name, text in (("freeze", "after an incident: keep raising deviations, learn nothing"),
                       ("unfreeze", "learning resumes")):
        x = bs.add_parser(name, help=text)
        x.add_argument("machine")
        x.add_argument("--reason", default="")
    x = bs.add_parser("reset", help="start learning again from now (the old profile is kept)")
    x.add_argument("machine")
    x.add_argument("--kind", action="append", choices=kinds, help="only these kinds (repeatable)")
    x.add_argument("--yes", action="store_true")
    x.add_argument("--reason", default="")
    p.set_defaults(func=cmd_baseline)
