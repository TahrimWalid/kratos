"""`kratos code ...` (E.7a §3.12): the code a machine serves, and people's decisions about it.

    kratos code roots [MACHINE] [--json]          candidates (with why) and confirmed folders
    kratos code status [MACHINE] [--json]         the same, with each folder's last check
    kratos code files MACHINE FOLDER [--json]     the files of one confirmed folder (changed first)
    kratos code confirm MACHINE FOLDER            a person confirms a candidate: it is read from now on
    kratos code ignore MACHINE FOLDER             not code to check (stays ignored until you change it)
    kratos code add MACHINE FOLDER [--no-check]   add a folder by path and confirm it
    kratos code accept-state MACHINE FOLDER       the folder's current files become the baseline (a deploy)

Decisions are the owner's, at this computer, and are recorded with who made them. Kratos
never runs anything in the folder: no git, no package manager, no build.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from kratos.untrusted import for_display, safe_print


def _actor():
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _exists(data_dir: Path, machine: str):
    """A quick look at the machine: is the folder there and a folder?"""
    from kratos import kratos_config
    from kratos.adapters import code_facts as CF
    from kratos.adapters import ssh_remote

    def check(path: str) -> str | None:
        with kratos_config.pinned_target(machine):
            inv = ssh_remote.fetch_code_inventory(os.fsencode(path), max_files=100, max_depth=2, seconds=30,
                                                  skip=CF.SKIP_DIRS, max_pack_mb=16)
        if not isinstance(inv, dict):
            return "Kratos couldn't look (" + " ".join(str(getattr(inv, "stderr", "")).split())[:200] + \
                "); add it with --no-check to have it checked at the next collection"
        st = (inv.get("root") or {}).get("status")
        return {"ok": None, "missing": "not found on the machine", "not_dir": "not a folder",
                "symlink": "it is a symbolic link (add the real folder)",
                "unreadable": "this login can't read it (the sub-agent can)"}.get(st, f"not readable ({st})")
    return check


def cmd_code(args: argparse.Namespace) -> int:
    from kratos.code import present as P
    from kratos.code import roots as RT

    data_dir = Path(args.data_dir)
    sub = args.code_cmd
    try:
        if sub in ("roots", "status"):
            tk, _scope = P.resolve_code_reader(data_dir, _actor(), args.machine)
            v = P.view(data_dir, tk)
            if sub == "roots":
                v["roots"] = [{**r, "read": None, "git": None, "findings": {}} if r["status"] != "confirmed" else r
                              for r in v["roots"]]
            if args.json:
                sys.stdout.write(json.dumps(v if sub == "status" else P.compact(v), indent=2, default=str) + "\n")
            else:
                sys.stdout.write(for_display(P.to_text(v), max_len=None) + "\n")
            return 0
        if sub == "files":
            tk, _scope = P.resolve_code_reader(data_dir, _actor(), args.machine)
            rows = P.files(data_dir, tk, args.folder)
            if args.json:
                sys.stdout.write(json.dumps(rows, indent=2) + "\n")
            else:
                for f in rows:
                    safe_print(f"{f['git_status'] or '-':12} {str(f['sha256'] or '')[:12]:12} {f['relpath']}")
            return 0
        actor = _actor()
        if sub == "confirm":
            RT.confirm(data_dir, args.machine, args.folder, actor=actor)
            safe_print(f"[KRATOS] {args.folder} on {args.machine} is confirmed: the next code check reads it "
                       "(`kratos collect --target ... --force`).")
        elif sub == "ignore":
            RT.ignore(data_dir, args.machine, args.folder, actor=actor)
            safe_print(f"[KRATOS] {args.folder} is ignored on {args.machine} (until you confirm it).")
        elif sub == "add":
            RT.add(data_dir, args.machine, args.folder, actor=actor,
                   exists=None if args.no_check else _exists(data_dir, args.machine))
            safe_print(f"[KRATOS] {args.folder} added and confirmed on {args.machine}.")
        elif sub == "accept-state":
            res = RT.accept_state(data_dir, args.machine, args.folder, actor=actor)
            safe_print(f"[KRATOS] {res['accepted_files']} file(s) of {args.folder} are the accepted state now; later "
                       "changes are measured against it.")
        return 0
    except (RT.CodeRootError, P.ViewError) as e:
        print(f"[KRATOS] Refused: {for_display(str(e))}", file=sys.stderr)
        return 1


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("code", help="The code a machine serves: folders, drift against git, dependencies, secrets")
    cs = p.add_subparsers(dest="code_cmd", required=True)
    for name, text in (("roots", "folders that look like served code (with why) and those you confirmed"),
                       ("status", "each confirmed folder's last check")):
        x = cs.add_parser(name, help=text)
        x.add_argument("machine", nargs="?")
        x.add_argument("--json", action="store_true")
    x = cs.add_parser("files", help="the files of one confirmed folder (changed and untracked first)")
    x.add_argument("machine")
    x.add_argument("folder")
    x.add_argument("--json", action="store_true")
    for name, text in (("confirm", "confirm a folder holds deployed code: Kratos reads it from now on"),
                       ("ignore", "not code to check (stays ignored until you confirm it)"),
                       ("accept-state", "the folder's current files become the baseline (after a deploy)")):
        x = cs.add_parser(name, help=text)
        x.add_argument("machine")
        x.add_argument("folder")
    x = cs.add_parser("add", help="add a folder by path and confirm it")
    x.add_argument("machine")
    x.add_argument("folder")
    x.add_argument("--no-check", action="store_true", help="don't look at the machine first")
    p.set_defaults(func=cmd_code)
