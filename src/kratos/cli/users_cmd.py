"""`kratos users`, `kratos tokens`, `kratos audit` -- sharing Kratos with other people (D.7).

    kratos users list
    kratos users add NAME --role viewer|investigator|admin [--scope web-01,@lab]
    kratos users role NAME ROLE
    kratos users scope NAME [--set A,@g | --add A | --remove A]
    kratos users disable NAME / kratos users enable NAME
    kratos users map openwebui OPENWEBUI_USER_ID NAME [--email E]
    kratos users unmap openwebui OPENWEBUI_USER_ID
    kratos users run-as (--schedule S | --trigger T) NAME

    kratos tokens list
    kratos tokens create --name N [--user NAME] [--machines A,B] [--mcp] [--days 90|never] [--gateway]
    kratos tokens revoke ID|NAME
    kratos tokens rotate ID|NAME [--days N|never]

    kratos audit [--user U] [--action A] [--refused] [--machine M] [--since 7d] [--limit N] [--json]
    kratos audit prune --older-than 365d [--apply]

Every change here is the owner's, at this computer -- never over the network -- and is
recorded in the audit trail.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    p = sub.add_parser("users", help="People who may use Kratos through the chat server: roles, machines, "
                                     "Open WebUI mappings")
    u = p.add_subparsers(dest="users_action", required=True)
    u.add_parser("list", help="Every user with role, machines and tokens")
    a = u.add_parser("add", help="Add a user")
    a.add_argument("name")
    a.add_argument("--role", required=True, choices=("viewer", "investigator", "admin"))
    a.add_argument("--scope", default="", help="Machines and @groups they may see, comma-separated")
    a.add_argument("--note", default="")
    r = u.add_parser("role", help="Change a user's role")
    r.add_argument("name")
    r.add_argument("role", choices=("viewer", "investigator", "admin"))
    s = u.add_parser("scope", help="Show or change which machines and @groups a user may see")
    s.add_argument("name")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--set", dest="set_scope", default=None)
    g.add_argument("--add", dest="add_scope", default=None)
    g.add_argument("--remove", dest="remove_scope", default=None)
    for word in ("disable", "enable", "show"):
        x = u.add_parser(word, help=f"{word.capitalize()} a user")
        x.add_argument("name")
    m = u.add_parser("map", help="Map a shared Open WebUI's user id to a Kratos user")
    m.add_argument("provider", choices=("openwebui",))
    m.add_argument("external_id")
    m.add_argument("name")
    m.add_argument("--email", default="")
    um = u.add_parser("unmap", help="Remove an Open WebUI mapping")
    um.add_argument("provider", choices=("openwebui",))
    um.add_argument("external_id")
    ra = u.add_parser("run-as", help="Make a schedule or trigger run with a user's machines and budget")
    w = ra.add_mutually_exclusive_group(required=True)
    w.add_argument("--schedule", default=None)
    w.add_argument("--trigger", default=None)
    ra.add_argument("name")
    p.set_defaults(func=cmd_users)

    t = sub.add_parser("tokens", help="Chat/MCP tokens: each belongs to a user, expires, can be rotated")
    ts = t.add_subparsers(dest="tokens_action", required=True)
    ts.add_parser("list", help="Every token with its user, machines, doors and expiry")
    c = ts.add_parser("create", help="Make a token (printed once)")
    c.add_argument("--name", required=True)
    c.add_argument("--user", default=None, help="The Kratos user it belongs to (default: the owner)")
    c.add_argument("--machines", default="", help="Narrow it to these machines (default: the user's whole scope; "
                                                  "the owner's: the default machine)")
    c.add_argument("--mcp", action="store_true", help="Also allow the MCP door")
    c.add_argument("--days", default=None, help="Days until it expires (default users.token_days); 'never' for "
                                                "the owner's own tokens only")
    c.add_argument("--gateway", action="store_true",
                   help="A shared Open WebUI's token: each request carries Open WebUI's signed user identity")
    rv = ts.add_parser("revoke", help="Stop a token working at once")
    rv.add_argument("ref")
    ro = ts.add_parser("rotate", help="A replacement with the same user, machines and doors; the old one stops")
    ro.add_argument("ref")
    ro.add_argument("--days", default=None)
    t.set_defaults(func=cmd_tokens)

    au = sub.add_parser("audit", help="Who did what, through which door -- every allowed and refused action")
    au.add_argument("audit_action", nargs="?", choices=("show", "prune"), default="show")
    au.add_argument("--user", default=None)
    au.add_argument("--action", dest="action_name", default=None)
    au.add_argument("--refused", action="store_true")
    au.add_argument("--machine", default=None)
    au.add_argument("--interface", default=None, choices=("tui", "cli", "mcp", "serve", "schedule"))
    au.add_argument("--since", default=None, help="e.g. 24h, 7d, 2026-11-01")
    au.add_argument("--limit", type=int, default=50)
    au.add_argument("--json", action="store_true")
    au.add_argument("--older-than", dest="older_than", default=None, help="prune: e.g. 365d")
    au.add_argument("--apply", action="store_true", help="prune: actually remove (default: preview)")
    au.set_defaults(func=cmd_audit)


def _actor() -> Any:
    from kratos import authz

    return authz.current_actor()


def _list(text: str) -> list[str]:
    return [x.strip() for x in str(text or "").replace(" ", ",").split(",") if x.strip()]


def _when(epoch: float | None) -> str:
    if epoch is None:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(epoch)))


def _tokens_of(dd: Path, user_id: str) -> list[dict[str, Any]]:
    from kratos.serve import store as S

    return [t for t in S.list_tokens(dd) if (t.get("user_id") or "owner") == user_id and not t.get("revoked_at")]


def _print_user(dd: Path, u: Any) -> None:
    state = "disabled" if u.disabled else "active"
    print(f"{u.name:<20} {u.user_id:<14} {u.role:<13} {state:<9} machines: {u.scope_text}")
    for t in _tokens_of(dd, u.user_id):
        print(f"    token {t['token_id']} {t['name']!r} ({t['kind']}) expires {_when(t.get('expires_at'))}")


def cmd_users(args: argparse.Namespace) -> int:
    from kratos.authz import Denied
    from kratos.authz import users as U

    dd = Path(args.data_dir)
    act = args.users_action
    try:
        if act == "list":
            for u in U.list_users(dd):
                _print_user(dd, u)
            for m in U.list_mappings(dd):
                print(f"  Open WebUI {m.external_id} ({m.email or 'no email'}) -> {m.user_name}")
            return 0
        if act == "show":
            u = U.find(dd, args.name)
            if u is None:
                print(f"[KRATOS] no user {args.name!r}", file=sys.stderr)
                return 2
            _print_user(dd, u)
            return 0
        if act == "add":
            u = U.add_user(dd, args.name, args.role, _actor(), scopes=_list(args.scope), note=args.note)
            print(f"[KRATOS] added {u.name} ({u.user_id}) as {u.role}; machines: {u.scope_text}")
            print(f"[KRATOS] give them a token: kratos tokens create --name {u.name}-chat --user {u.name}")
            return 0
        if act == "role":
            u = U.set_role(dd, args.name, args.role, _actor())
            print(f"[KRATOS] {u.name} is now {u.role} (applies at their next request, and stops a running "
                  "investigation they may no longer start at its next read)")
            return 0
        if act == "scope":
            u = U.find(dd, args.name)
            if u is None:
                print(f"[KRATOS] no user {args.name!r}", file=sys.stderr)
                return 2
            if args.set_scope is not None:
                u = U.set_scopes(dd, u.user_id, _list(args.set_scope), _actor())
            elif args.add_scope is not None:
                u = U.add_scopes(dd, u.user_id, _list(args.add_scope), _actor())
            elif args.remove_scope is not None:
                u = U.remove_scopes(dd, u.user_id, _list(args.remove_scope), _actor())
            print(f"[KRATOS] {u.name} may see: {u.scope_text}")
            return 0
        if act in ("disable", "enable"):
            u = U.set_disabled(dd, args.name, act == "disable", _actor())
            print(f"[KRATOS] {u.name} is {'disabled -- refused everywhere from their next request' if u.disabled else 'enabled'}")
            return 0
        if act == "map":
            m = U.map_gateway(dd, args.provider, args.external_id, args.name, _actor(), email=args.email)
            print(f"[KRATOS] Open WebUI user {m.external_id} is now {m.user_name}")
            return 0
        if act == "unmap":
            U.unmap_gateway(dd, args.provider, args.external_id, _actor())
            print(f"[KRATOS] removed the mapping for {args.external_id}")
            return 0
        if act == "run-as":
            return _run_as(dd, args)
    except (U.UserError, Denied) as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2
    return 2


def _run_as(dd: Path, args: argparse.Namespace) -> int:
    from kratos import authz
    from kratos.agent import schedules, triggers
    from kratos.authz import users as U

    u = U.find(dd, args.name)
    if u is None:
        print(f"[KRATOS] no user {args.name!r}", file=sys.stderr)
        return 2
    authz.require(_actor(), authz.P.SCHEDULES_MANAGE, data_dir=dd,
                  obj=f"run {args.schedule or args.trigger} as {u.name}")
    try:
        if args.schedule:
            schedules.set_run_as(dd, args.schedule, u.user_id)
        else:
            triggers.set_run_as(dd, args.trigger, u.user_id)
    except (schedules.ScheduleError, triggers.TriggerError) as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2
    print(f"[KRATOS] {args.schedule or args.trigger} now runs as {u.name}: their machines and their budget; "
          "it refuses (and says so) if they are disabled or lose access")
    return 0


def cmd_tokens(args: argparse.Namespace) -> int:
    from kratos.serve import auth as A
    from kratos.serve import store as S

    dd = Path(args.data_dir)
    act = args.tokens_action
    try:
        if act == "create":
            token, row = A.create_token(dd, name=args.name, targets=_list(args.machines), mcp=bool(args.mcp),
                                        created_by="cli", user=args.user, expires=args.days, gateway=args.gateway)
            print(token)
            _after_create(dd, row)
            return 0
        if act == "revoke":
            row = A.revoke(dd, args.ref)
            print(f"[KRATOS] revoked {row['token_id']} ({row['name']})")
            return 0
        if act == "rotate":
            token, row, old = A.rotate(dd, args.ref, expires=args.days)
            print(token)
            print(f"\n[KRATOS] {row['name']} ({row['token_id']}) replaces {old['name']} ({old['token_id']}), which "
                  f"stopped working now. Same user, machines and doors; expires {_when(row.get('expires_at'))}.",
                  file=sys.stderr)
            return 0
    except A.TokenError as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2
    from kratos.authz import users as U

    names = {u.user_id: u.name for u in U.list_users(dd)}
    for t in S.list_tokens(dd):
        state = f"revoked {_when(t['revoked_at'])}" if t.get("revoked_at") else "active"
        print(f"{t['token_id']}  {t['name']:<20} {names.get(t.get('user_id') or 'owner', t.get('user_id')):<14} "
              f"{t.get('kind', 'person'):<8} {state:<24} expires {_when(t.get('expires_at')):<16} "
              f"machines: {', '.join(t['targets']) or 'default/user scope'}  doors: {', '.join(t['doors'])}")
    return 0


def _after_create(dd: Path, row: dict[str, Any]) -> None:
    from kratos.authz import users as U

    owner = U.get(dd, row["user_id"])
    who = owner.name if owner else row["user_id"]
    if row["targets"]:
        machines = ", ".join(row["targets"])
    elif row.get("kind") == "gateway":
        machines = "each mapped user's own scope"
    elif row["user_id"] == "owner":
        machines = "the default machine only"
    else:
        machines = f"{who}'s whole scope"
    print(f"\nThat is the token for {row['name']!r} ({who}) -- copy it now, Kratos keeps only a hash of it.\n"
          f"Machines: {machines}.  Doors: {', '.join(row['doors'])}.  Expires: {_when(row.get('expires_at'))}.",
          file=sys.stderr)
    if row.get("kind") == "gateway":
        import secrets

        from kratos.authz import openwebui

        secret = secrets.token_urlsafe(32)
        path = openwebui.write_secret(dd, row["token_id"], secret)
        print("\nShared Open WebUI (gateway) -- set these in Open WebUI's environment and restart it:\n"
              "  ENABLE_FORWARD_USER_INFO_HEADERS=true\n"
              f"  FORWARD_USER_INFO_HEADER_JWT_SECRET={secret}\n"
              "Then add the connection (Admin Settings -> Connections -> OpenAI) with the token above as the API key,\n"
              "and map each Open WebUI user: kratos users map openwebui <their Open WebUI user id> <kratos user>.\n"
              f"The secret is kept in {path} (owner-only). The token and this secret together can act as every\n"
              "mapped user -- keep both private.", file=sys.stderr)


def _since(text: str | None) -> float | None:
    if not text:
        return None
    t = text.strip().lower()
    try:
        if t.endswith("h"):
            return time.time() - float(t[:-1]) * 3600
        if t.endswith("d"):
            return time.time() - float(t[:-1]) * 86400
        from datetime import datetime

        return datetime.strptime(t, "%Y-%m-%d").timestamp()
    except ValueError:
        raise SystemExit(f"[KRATOS] not a time: {text!r} (use 24h, 7d or 2026-11-01)") from None


def cmd_audit(args: argparse.Namespace) -> int:
    from kratos.authz import audit

    dd = Path(args.data_dir)
    if args.audit_action == "prune":
        before = _since(args.older_than)
        if before is None:
            print("[KRATOS] give --older-than, e.g. 365d", file=sys.stderr)
            return 2
        n = audit.prune_preview(dd, before)
        if not args.apply:
            print(f"[KRATOS] would remove {n} audit rows older than {args.older_than}. Add --apply to remove them "
                  "(the prune itself is recorded).")
            return 0
        removed = audit.prune(dd, before, _actor())
        print(f"[KRATOS] removed {removed} audit rows")
        return 0
    rows = audit.query(dd, user=args.user, action=args.action_name, result="refused" if args.refused else None,
                       machine=args.machine, interface=args.interface, since=_since(args.since), limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("[KRATOS] no audit rows match")
        return 0
    for r in reversed(rows):
        who = r["user_name"] or r["user_id"] or "(nobody)"
        cred = f" [{r['credential']}]" if r["credential"] else ""
        what = r["action"] + (f" on {r['machine']}" if r["machine"] else "") + (f" -- {r['object']}" if r["object"] else "")
        reason = f"  ({r['reason']})" if r["reason"] else ""
        print(f"{_when(r['at'])}  {r['result']:<8} {who} via {r['interface']}{cred}: {what}{reason}")
    return 0
