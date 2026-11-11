"""`kratos hashdb-update`, `kratos hashdb-key` and `kratos hash lookup` (E.4 §5.2)."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from kratos.untrusted import for_display, safe_print

UNIT = "kratos-hashdb-update"


def _status(data_dir: Path) -> int:
    from kratos.hashdb import circl, datasets as D, malwarebazaar
    from kratos.hashdb import settings as S

    for ds in (circl.DATASET, malwarebazaar.DATASET):
        row = D.get(data_dir, ds.name)
        path = D.installed_path(data_dir, ds)
        if path is None:
            extra = ""
            if ds.name == "malwarebazaar" and not D.read_key(data_dir, ds.name):
                extra = " -- needs your free abuse.ch Auth-Key first (`kratos hashdb-key set malwarebazaar`)"
            safe_print(f"[KRATOS] {ds.label}: not downloaded{extra}. Run `{ds.update_hint}`.")
        else:
            age = row.age_days() if row else 0.0
            warn = S.CIRCL_WARN_DAYS if ds.name == "circl" else S.MB_WARN_DAYS
            stale = f" -- older than {warn} days, refresh it" if age > warn else ""
            what = (f"{row.detail.get('elements', 0):,} hashes" if ds.name == "circl"
                    else f"{row.detail.get('rows', 0):,} hashes") if row else ""
            safe_print(f"[KRATOS] {ds.label}: {what}, {row.size / 1e6:.1f} MB, version {row.version}, "
                       f"fetched {age:.1f} days ago{stale}.")
            safe_print(f"         sha256 {row.sha256}; licence: {row.licence}")
        if row and row.last_error:
            safe_print(f"         last attempt failed: {for_display(row.last_error)}")
    return 0


def cmd_hashdb_update(args: argparse.Namespace) -> int:
    """Download the file-reputation datasets: the CIRCL known-good filter (opt-in, about
    1 GB) and the MalwareBazaar known-bad set (needs your abuse.ch key). Only the
    datasets' own servers are contacted; no hash from your machines is sent."""
    from kratos.hashdb import circl, malwarebazaar

    data_dir = Path(args.data_dir)
    if args.about:
        print(circl.ABOUT)
        print(malwarebazaar.ABOUT)
        return 0
    if args.status:
        return _status(data_dir)
    if args.timer:
        from kratos.agent.schedule_units import kratos_bin
        from kratos.pkgvuln import timer as T

        if args.timer == "off":
            print("[KRATOS] To stop the scheduled file-reputation update, run:")
            cmds = T.uninstall_commands(UNIT)
        else:
            service = ("[Unit]\nDescription=Kratos: refresh the file-reputation datasets\n"
                       "After=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\n"
                       f"ExecStart={kratos_bin()} hashdb-update --auto --data-dir {data_dir.resolve()}\nNice=10\n")
            timer = T.timer_text(args.timer, data_dir).replace("package-vulnerability data update",
                                                               "file-reputation datasets update")
            s, t = T.write_timer_units(data_dir / "hashdb" / "systemd", UNIT, service, timer)
            print(f"[KRATOS] Wrote {s} and {t}: a {args.timer} refresh of the MalwareBazaar set (and of the CIRCL "
                  "filter once it is a month old, only if you installed it). Kratos doesn't install it; run:")
            cmds = T.install_commands(s, t, UNIT)
        for c in cmds:
            print(f"  {c}")
        return 0
    want_circl, want_mb = bool(args.circl), bool(args.malwarebazaar)
    if args.auto:                       # the timer: MalwareBazaar when set up; CIRCL only when installed and old
        from kratos.hashdb import datasets as D

        want_mb = bool(D.read_key(data_dir, "malwarebazaar"))
        row = D.get(data_dir, "circl")
        want_circl = bool(D.installed_path(data_dir, circl.DATASET)) and row is not None and row.age_days() > 28
    if not (want_circl or want_mb):
        print("[KRATOS] Say which set to download: --malwarebazaar (the known-bad set; needs your free abuse.ch key) "
              "and/or --circl (the known-good filter, about 1 GB). `--about` explains both; `--status` shows what "
              "is installed.")
        return 0 if args.auto else 2
    ok = True
    log = (lambda m: print(f"         {m}", flush=True))
    if want_mb:
        print("[KRATOS] Updating the MalwareBazaar known-bad set (from abuse.ch; nothing of yours is sent) ...",
              flush=True)
        good, msg = malwarebazaar.update(data_dir, log=log, force_interval=not args.auto)
        print(f"[KRATOS] {msg}")
        ok = ok and (good or "Nothing was requested" in msg)
    if want_circl:
        print("[KRATOS] Downloading the CIRCL hashlookup known-good filter (about 1 GB; nothing of yours is sent) ...",
              flush=True)
        good, msg = circl.update(data_dir, log=log)
        print(f"[KRATOS] {msg}")
        ok = ok and good
    if ok:
        from kratos.collect import state as _cstate

        _cstate.expire(data_dir, "hash_reputation")
    return 0 if ok else 1


def cmd_hashdb_key(args: argparse.Namespace) -> int:
    """Store or remove a dataset's key (the abuse.ch Auth-Key for MalwareBazaar). The key
    is read from standard input, never from the command line (it would land in the shell
    history), and kept owner-only."""
    from kratos.authz import check
    from kratos.authz import permissions as P
    from kratos.hashdb import datasets as D

    data_dir = Path(args.data_dir)
    check.require(check.current_actor(), P.HASHDB_UPDATE, data_dir=data_dir, obj=f"{args.action} dataset key")
    if args.action == "remove":
        print("[KRATOS] Key removed." if D.remove_key(data_dir, args.dataset) else "[KRATOS] No key was stored.")
        return 0
    if sys.stdin.isatty():
        print("Paste your abuse.ch Auth-Key, then press Enter (it isn't shown):", file=sys.stderr)
        import getpass

        key = getpass.getpass("")
    else:
        key = sys.stdin.readline()
    try:
        D.write_key(data_dir, args.dataset, key)
    except ValueError as e:
        print(f"[KRATOS] Not stored: {e}")
        return 2
    print("[KRATOS] Key stored (owner-only, sent only to abuse.ch). Now run `kratos hashdb-update --malwarebazaar`.")
    return 0


def _print_offline(info: dict) -> None:
    from kratos.hashdb import reputation as R

    safe_print(f"[KRATOS] {info['kind'].upper()} {info['hash']}")
    if info["kind"] == "sha256":
        if not info["malwarebazaar_installed"]:
            safe_print("  MalwareBazaar (offline): not set up -- `kratos hashdb-update --malwarebazaar`")
        elif info["malwarebazaar"]:
            mb = info["malwarebazaar"]
            safe_print(f"  MalwareBazaar (offline): LISTED as malware (first seen {for_display(mb.get('first_seen'))}"
                       + (f", family name {for_display(mb.get('signature'))!r}" if mb.get("signature") else "") + ")")
        else:
            safe_print("  MalwareBazaar (offline): not listed (that is not the same as clean)")
    if not info["circl_installed"]:
        safe_print("  CIRCL known-good filter (offline): not installed -- `kratos hashdb-update --circl`")
    elif info["circl"] is None:
        safe_print("  CIRCL known-good filter (offline): needs the file's SHA-1 (no machine read gave one)")
    else:
        safe_print("  CIRCL known-good filter (offline): " + ("probably known-good (a Bloom filter match)"
                                                             if info["circl"] else "not in the set"))
    if info["machines"]:
        safe_print("  Seen on your machines:")
        for r in info["machines"]:
            when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(r["checked_at"])))
            safe_print(f"    {for_display(r['target_key'])}: {for_display(r.get('path') or '?')} -- "
                       f"{R.LABELS.get(r['verdict'], r['verdict'])} (checked {when})")
    elif info["kind"] == "sha256":
        safe_print("  Not seen by Kratos's reputation checks on any machine (`kratos hunt <sha256>` searches "
                   "everything Kratos holds).")
    for r in info["online_cached"]:
        when = time.strftime("%Y-%m-%d", time.gmtime(float(r["checked_at"])))
        safe_print(f"  Looked up online on {when}: {R.LABELS.get(r['verdict'], r['verdict'])} -- "
                   + "; ".join(for_display(s.get("detail")) for s in r.get("sources") or []))


def cmd_hash(args: argparse.Namespace) -> int:
    """`kratos hash lookup <hash> [--online]`."""
    from kratos.hashdb import lookup as L

    data_dir = Path(args.data_dir)
    try:
        info = L.offline(data_dir, args.hash)
    except ValueError as e:
        print(f"[KRATOS] {e}")
        return 2
    _print_offline(info)
    if not args.online:
        return 0

    def confirm(question: str) -> bool:
        if not sys.stdin.isatty():
            print(f"[KRATOS] {question} -- needs a person at the terminal to answer; not sent.")
            return False
        return input(f"{question} [y/N] ").strip().lower() == "y"

    try:
        out = L.online(data_dir, args.hash, confirm=confirm)
    except L.LookupRefused as e:
        print(f"[KRATOS] {e}")
        return 1
    c, m = out.get("circl") or {}, out.get("malwarebazaar")
    safe_print("  circl.lu: " + (f"found (trust {c.get('trust')}; sources: {for_display(', '.join(c.get('sources') or []))})"
                                 if c.get("found") else "not found" if c else "no answer"))
    if m is not None:
        safe_print("  abuse.ch: " + (f"LISTED (first seen {for_display(m.get('first_seen'))}, family name "
                                     f"{for_display(m.get('signature'))!r})" if m.get("found") else "not listed"))
    for e in out.get("errors") or []:
        safe_print(f"  {for_display(e)}")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    u = sub.add_parser("hashdb-update", help="Download the file-reputation datasets (MalwareBazaar known-bad set, "
                                             "CIRCL known-good filter); nothing of yours is sent")
    u.add_argument("--malwarebazaar", action="store_true", help="the known-bad set (needs your free abuse.ch key)")
    u.add_argument("--circl", action="store_true", help="the known-good filter (about 1 GB, opt-in)")
    u.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    u.add_argument("--timer", choices=("daily", "weekly", "off"), help="write a systemd user timer that refreshes them")
    u.add_argument("--about", action="store_true", help="what each set is, its licence and terms")
    u.add_argument("--status", action="store_true", help="what is installed, how old, its checksum")
    u.set_defaults(func=cmd_hashdb_update)
    k = sub.add_parser("hashdb-key", help="Store (from standard input) or remove the abuse.ch key for MalwareBazaar")
    k.add_argument("action", choices=("set", "remove"))
    k.add_argument("dataset", choices=("malwarebazaar",))
    k.set_defaults(func=cmd_hashdb_key)
    h = sub.add_parser("hash", help="What Kratos knows about one file hash (offline; --online asks first)")
    hs = h.add_subparsers(dest="hash_cmd", required=True)
    lk = hs.add_parser("lookup", help="look one SHA-256 or SHA-1 up")
    lk.add_argument("hash")
    lk.add_argument("--online", action="store_true",
                    help="also send this one hash to circl.lu (and abuse.ch with a key), after asking you")
    h.set_defaults(func=cmd_hash)
