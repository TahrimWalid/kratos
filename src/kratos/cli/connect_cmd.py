"""`kratos connect` (docs/phaseE/E.5b): connect a chat app to Kratos in one step.

    kratos connect                         asks which app
    kratos connect openwebui [--machines a,b] [--tools] [--url http://127.0.0.1:P | --new] [--keep-ollama]
    kratos connect ag-ui [--machines a,b]
    kratos connect other [--machines a,b]
    kratos connect status
    kratos connect <app> --renew [--machines a,b] | --undo

Notes go to stderr. The token is shown once, and only on a terminal (or with
--print-command, which prints just the command -- or for a paste app the key -- to stdout
for a script). `--yes` answers yes to every question (replace, turn AG-UI on, install the
chat-server service).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    c = sub.add_parser("connect", help="Connect a chat app (Open WebUI, an AG-UI app, any OpenAI-compatible app) "
                                       "to Kratos in one step")
    c.add_argument("app", nargs="?", default=None, help="openwebui | ag-ui | other | status")
    c.add_argument("--machines", default="", help="Machines the app may ask about, comma-separated (default: the "
                                                  "active machine)")
    c.add_argument("--tools", action="store_true", help="Open WebUI: also allow its tool servers (the MCP door)")
    c.add_argument("--url", default=None, help="Open WebUI already runs here (http://127.0.0.1:<port>)")
    c.add_argument("--keep-ollama", action="store_true", help="Open WebUI: keep its Ollama connection on")
    c.add_argument("--new", action="store_true",
                   help="Open WebUI: start a separate one for Kratos even if one already runs here")
    c.add_argument("--renew", action="store_true", help="A new token for the app (the old one stops working)")
    c.add_argument("--undo", action="store_true", help="Disconnect the app: revoke its token, remove its file")
    c.add_argument("--print-command", action="store_true",
                   help="Print only the command (or, for an app you paste into, the key) to stdout")
    c.add_argument("--yes", action="store_true", help="Answer yes to every question")
    c.set_defaults(func=cmd_connect)


def _note(text: str = "") -> None:
    print(text, file=sys.stderr)


def _ask(question: str, args: argparse.Namespace) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        _note(f"{question} -- not asked (no terminal); re-run with --yes to agree.")
        return False
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _pick_app(args: argparse.Namespace) -> str | None:
    from kratos.serve import connect as CN

    if not sys.stdin.isatty():
        _note(f"kratos connect: name the app -- {', '.join(CN.APPS)} (or status)")
        return None
    for i, a in enumerate(CN.APPS, 1):
        _note(f"  {i}. {CN.APP_WORDS[a]} ({a})")
    try:
        choice = input("Which app? ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None
    if choice.isdigit() and 1 <= int(choice) <= len(CN.APPS):
        return CN.APPS[int(choice) - 1]
    return choice if choice in CN.APPS else None


def _print_status(data_dir: Path) -> int:
    from kratos.serve import connect as CN
    from kratos.serve import status as ST

    _note(f"chat server: {ST.summary(data_dir)}")
    rows = CN.status(data_dir)
    if not rows:
        _note("No chat app is connected. kratos connect openwebui | ag-ui | other")
        return 0
    for s in rows:
        _note(f"  [{s.state}] {s.words()}")
    return 0


def _show(result: Any, args: argparse.Namespace) -> None:
    from kratos.serve import connect as CN

    p = result.plan
    tty = sys.stdout.isatty()
    if result.replaced_token:
        _note(f"Replaced: the old token {result.replaced_token} no longer works.")
    if args.print_command:
        if result.command:
            sys.stdout.write(result.command + "\n")
        elif result.paste:
            sys.stdout.write(dict(result.paste).get("API key", dict(result.paste).get("Header", "")) + "\n")
        return
    _note(f"Connected {CN.APP_WORDS[p.app]} (token {result.token_id}, machines {', '.join(p.machines)}).")
    if result.command:
        _note("\nRun this one command (Kratos doesn't run it for you):\n")
        _note(result.command)
        _note(f"\nThe token is in {result.secret_path} (only you can read it); the command reads it from there.")
    if result.address:
        _note(f"\nThen open {result.address}")
    if result.paste:
        if tty:
            _note("\nPaste these into the app (the key is shown once -- Kratos keeps it only in "
                  f"{result.secret_path}):")
            for label, value in result.paste:
                _note(f"  {label}: {value}")
        else:
            _note(f"\nThe values to paste are not printed (output isn't a terminal). The key is in {result.secret_path}; "
                  "use --print-command to print it.")
            for label, value in result.paste:
                if label not in ("API key", "Header"):
                    _note(f"  {label}: {value}")
    if result.check:
        _note("\nCheck it works:\n  " + result.check)
    for n in result.notes:
        if result.plan.facts.serve_running or not n.startswith(CN.SERVER_DOWN_NOTE):
            _note("\n" + n)


def cmd_connect(args: argparse.Namespace) -> int:
    from kratos.serve import connect as CN

    data_dir = Path(args.data_dir)
    app = (args.app or "").strip().lower() or _pick_app(args)
    if not app:
        return 2
    if app == "status":
        return _print_status(data_dir)
    machines = [m for m in str(args.machines or "").replace(" ", ",").split(",") if m.strip()]
    try:
        if args.undo:
            u = CN.undo(data_dir, app)
            _note(f"Disconnected {CN.APP_WORDS[u.app]}: token {u.token_id} revoked"
                  + (", its file removed." if u.removed_file else "."))
            for line in u.cleanup:
                _note("  " + line)
            return 0
        facts = CN.gather(data_dir, url=args.url)
        if args.renew:
            result = CN.renew(data_dir, app, machines=machines or None, facts=facts)
            _show(result, args)
            _maybe_service(data_dir, facts, args)
            return 0
        plan = CN.plan(data_dir, app, machines=machines or None, tools=args.tools, url=args.url,
                       keep_ollama=args.keep_ollama, new=args.new, facts=facts)
        for line in plan.summary():
            _note(line)
        replace = False
        if plan.replaces:
            replace = _ask(f"{CN.APP_WORDS[app]} is already connected (token {plan.replaces['token_id']}). Replace "
                           "it? The old token stops working at once.", args)
            if not replace:
                _note("Nothing changed.")
                return 1
        enable = False
        if plan.enable_agui:
            enable = _ask("AG-UI is off. Turn it on (agui.enabled = yes)?", args)
            if not enable:
                _note("AG-UI stays off -- nothing was made.")
                return 1
        result = CN.apply(data_dir, plan, replace=replace, enable_agui=enable, created_by="cli")
        _show(result, args)
        _maybe_service(data_dir, facts, args)
        return 0
    except CN.ConnectError as e:
        _note(f"kratos connect: {e}")
        return 2


def _maybe_service(data_dir: Path, facts: Any, args: argparse.Namespace) -> None:
    """The chat server isn't running: offer the user service (G2), or say how to run it."""
    from kratos.serve import connect as CN

    if facts.serve_running:
        return
    _note("\n" + CN.SERVER_DOWN_NOTE + ".")
    if not facts.systemd_user:
        _note("\nThe chat server isn't running and there's no systemd user manager here: run `kratos serve` in a "
              "terminal and keep it open -- the app works only while it runs.")
        return
    if not _ask("\nThe chat server isn't running. Install it as the user service kratos-serve (starts by itself, keeps "
                "running after you close Kratos)?", args):
        _note("Not installed. Start it yourself with `kratos serve`; the commands to install it later:")
        for cmd in CN.serve_service_commands(data_dir):
            _note("  " + cmd.replace("\n", "\n  "))
        return
    ok, words = CN.install_serve_service(data_dir)
    _note(("\n✓ " if ok else "\n✗ ") + words)
