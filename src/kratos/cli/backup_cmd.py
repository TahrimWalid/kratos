"""`kratos backup` (docs/phaseD/D.8).

    kratos backup key new [--write-to FILE]   make the key backups are encrypted to (secret shown once)
    kratos backup key list | add age1… | remove <age1…|age:fingerprint>
    kratos backup create [--dry-run] [--dest DIR] [--copy-to DIR|sftp://user@host/path ...]
                         [--passphrase | --generate-passphrase] [--without-secrets]
                         [--exclude CATEGORY ...] [--include-rebuildable] [--scheduled] [--json]
    kratos backup verify FILE [--full]        no secret needed; --full reads the key from stdin
    kratos backup drill FILE                  --full plus a real restore into a scratch home
    kratos backup restore FILE [--replace] [--dry-run] [--ca-mode tpm|file|agent] [--hub-address A]
    kratos backup extract FILE --to EMPTY_FOLDER
    kratos backup prune --keep N [--apply]
    kratos backup schedule daily|weekly|off [--copy-to ...]
    kratos backup status

The key or passphrase that opens a backup is read from stdin when stdin is not a terminal
(`kratos backup verify f.age --full < key.txt`), otherwise asked for without echo.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    bk = sub.add_parser("backup", help="Encrypted backups of everything Kratos keeps, restore drills, restore onto "
                                       "a new computer")
    bs = bk.add_subparsers(dest="backup_action", required=True)

    k = bs.add_parser("key", help="The keys backups are encrypted to")
    ks = k.add_subparsers(dest="key_action", required=True)
    kn = ks.add_parser("new", help="Make a backup key: the secret half is shown ONCE, Kratos keeps only the public "
                                   "half")
    kn.add_argument("--write-to", type=Path, default=None,
                    help="Also write the secret key to this file (a USB stick, not this computer's disk)")
    ks.add_parser("list", help="The keys backups are encrypted to")
    ka = ks.add_parser("add", help="Add your own age1… public key (e.g. a second admin's), up to 5")
    ka.add_argument("recipient")
    kr = ks.add_parser("remove", help="Stop encrypting new backups to a key")
    kr.add_argument("which", help="the age1… key or its age:… fingerprint")

    c = bs.add_parser("create", help="Make an encrypted backup now")
    c.add_argument("--dry-run", action="store_true", help="Show what would go in, write nothing")
    c.add_argument("--dest", type=Path, default=None, help="Backup folder (default ~/kratos-backups)")
    c.add_argument("--copy-to", action="append", default=None,
                   help="Also copy it here (a folder on another disk, or sftp://user@host/path); repeatable")
    c.add_argument("--passphrase", action="store_true", help="Lock it with a passphrase instead (asked twice)")
    c.add_argument("--generate-passphrase", action="store_true", help="Lock it with six random words, shown once")
    c.add_argument("--without-secrets", action="store_true",
                   help="Leave out keys, pairing tokens and .env (restoring it means re-pairing and re-enrolling)")
    c.add_argument("--exclude", action="append", default=[], help="Leave out a data category (see --dry-run)")
    c.add_argument("--include-rebuildable", action="store_true",
                   help="Include the public data Kratos can download again (vulnerability data, CVE list)")
    c.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    c.add_argument("--json", action="store_true", help="Print the result as JSON")

    v = bs.add_parser("verify", help="Check a backup file (no secret needed; --full decrypts it all)")
    v.add_argument("file", type=Path)
    v.add_argument("--full", action="store_true", help="Decrypt and check every file (key from stdin or asked)")

    d = bs.add_parser("drill", help="Prove a backup restores: full check + a real restore into a scratch home + "
                                    "doctor, then the scratch home is removed")
    d.add_argument("file", type=Path)
    _trust_args(d)

    r = bs.add_parser("restore", help="Restore a backup onto this computer (CLI only)")
    r.add_argument("file", type=Path)
    r.add_argument("--replace", action="store_true",
                   help="Over an existing install: back it up first, move it aside (nothing is deleted)")
    r.add_argument("--dry-run", action="store_true", help="Check everything and show what would happen")
    r.add_argument("--ca-mode", choices=("tpm", "file", "agent"), default=None,
                   help="How to keep an SSH CA key that was TPM-sealed (default: tpm if this computer has one)")
    r.add_argument("--hub-address", default=None, help="The address agents should dial to reach this computer")
    r.add_argument("--no-wait", action="store_true", help="Don't wait for the agents to reconnect")
    r.add_argument("--yes", action="store_true", help="Don't ask for confirmation")
    _trust_args(r)

    x = bs.add_parser("extract", help="Unpack a backup into an empty folder, to look inside (installs nothing)")
    x.add_argument("file", type=Path)
    x.add_argument("--to", type=Path, required=True)

    p = bs.add_parser("prune", help="Remove old backups, keeping the newest N (shown first; nothing automatic)")
    p.add_argument("--keep", type=int, required=True)
    p.add_argument("--dest", type=Path, default=None)
    p.add_argument("--apply", action="store_true")

    s = bs.add_parser("schedule", help="Back up on a timer (needs a backup key)")
    s.add_argument("cadence", choices=("daily", "weekly", "off"))
    s.add_argument("--copy-to", action="append", default=None)

    bs.add_parser("status", help="Backup lock, last backup, last drill, schedule, what isn't covered")
    bk.set_defaults(func=cmd_backup)


def _cli_actor(args: argparse.Namespace) -> Any:
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _read_secret(prompt: str) -> list[object]:
    return _read_secret_and_signer(prompt)[0]


def _read_secret_and_signer(prompt: str) -> tuple[list[object], str | None]:
    """The identities, and the signer fingerprint when a whole key file was piped in."""
    from kratos.backup import keys as K
    from kratos.backup import origin

    if not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        text = getpass.getpass(prompt)
    return K.read_identities(text), origin.fingerprint_in(text)


def _trust_args(p: Any) -> None:
    p.add_argument("--signer", default=None, metavar="SHA256:…",
                   help="Accept a backup signed by this signing-key fingerprint (the one you wrote down with your "
                        "backup key); needed on a new computer")
    p.add_argument("--unsigned-ok", action="store_true",
                   help="Accept a backup with no signature (its .sha256 sidecar lost) -- only if you know where it "
                        "came from")


def _signer_choice(args: argparse.Namespace, from_key_file: str | None) -> str | None:
    from kratos.backup import origin

    given = getattr(args, "signer", None)
    if given and not origin.valid_fingerprint(given):
        raise SystemExit("[KRATOS] --signer takes a fingerprint like SHA256:abc… (43 characters after the colon)")
    return given or from_key_file


def cmd_backup(args: argparse.Namespace) -> int:
    from kratos.backup import keys as _keys   # noqa: F401 -- registers the backup.* settings
    from kratos.backup import settings as _bs  # noqa: F401
    from kratos.backup.create import BackupError
    from kratos.backup.keys import KeyError_
    from kratos.backup.prune import PruneError
    from kratos.backup.restore import RestoreError
    from kratos.backup.schedule import ScheduleError

    from kratos.backup import agefmt as _A
    from kratos.backup.archive import ArchiveError

    try:
        return int(_HANDLERS[args.backup_action](args))
    except (BackupError, RestoreError, PruneError, ScheduleError, KeyError_) as e:
        print(f"[KRATOS] {e}", file=sys.stderr)
        return 2
    except ArchiveError as e:
        print(f"[KRATOS] This backup can't be trusted, so nothing was written: {e}", file=sys.stderr)
        return 2
    except _A.NoMatchError:
        print("[KRATOS] The key or passphrase given doesn't open this backup.", file=sys.stderr)
        return 2
    except _A.PayloadError as e:
        print(f"[KRATOS] The backup is damaged at chunk {e.chunk} (nothing was written): {e}", file=sys.stderr)
        return 2
    except _A.AgeError as e:
        print(f"[KRATOS] The backup can't be decrypted (nothing was written): {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[KRATOS] stopped.", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------- key
def _key(args: argparse.Namespace) -> int:
    from kratos.backup import keys as K
    from kratos.backup.create import _authorize

    dd = Path(args.data_dir)
    actor = _cli_actor(args)
    if args.key_action == "list":
        recs = K.recipients(dd)
        if not recs:
            print("No backup key yet. Make one: kratos backup key new")
        for r in recs:
            print(f"{K.fingerprint(r)}  {r}")
        return 0
    if args.key_action == "add":
        _authorize(actor, dd, "backup key add")
        r = K.add_recipient(dd, args.recipient, actor="cli:backup key add")
        print(f"[KRATOS] New backups are also encrypted to {K.fingerprint(r)} ({r}).")
        return 0
    if args.key_action == "remove":
        _authorize(actor, dd, "backup key remove")
        K.remove_recipient(dd, args.which, actor="cli:backup key remove")
        print("[KRATOS] Removed. Backups made before still open with that key.")
        return 0
    _authorize(actor, dd, "backup key new")
    have = K.recipients(dd)
    if len(have) >= 5:
        print("[KRATOS] a backup can be opened by at most 5 keys; remove one first", file=sys.stderr)
        return 2
    ident = K.new_identity()
    pub = str(ident.recipient())
    if args.write_to is not None:
        _write_identity(args.write_to, ident, dd)
    if sys.stdin.isatty() and sys.stdout.isatty():
        print("\nYOUR BACKUP KEY -- shown this one time. Kratos does not keep it.\n")
        print(f"    {ident.secret}\n")
        print("Keep it OFF this computer: print it, put it in a password manager, or save it to a USB stick.")
        print("Anyone holding it can open every backup -- and a backup can act as this Kratos to your agents")
        print("and sign SSH certificates for your machines. Without it, no backup can be restored.\n")
        typed = input("To confirm you saved it, type its last 6 characters: ").strip().upper()
        if typed != ident.secret[-6:]:
            print("[KRATOS] That doesn't match -- nothing was set up. Run `kratos backup key new` again.", file=sys.stderr)
            return 2
    elif args.write_to is None:
        print("[KRATOS] not at a terminal: give --write-to FILE so the secret key isn't lost", file=sys.stderr)
        return 2
    K.add_recipient(dd, pub, actor="cli:backup key new")
    from kratos.backup import origin

    print(f"[KRATOS] Backups are now encrypted to {K.fingerprint(pub)} ({pub}).")
    print(f"         They are signed by this Kratos's key {origin.signer_fingerprint(dd, create=True)} -- write it "
          "down with your backup key: restoring onto a new computer asks for it.")
    print("         Next: kratos backup create, then kratos backup drill <file>.")
    return 0


def _write_identity(path: Path, ident: Any, data_dir: Path) -> None:
    import os

    from kratos import paths
    from kratos.backup.create import BackupError, same_disk

    path = Path(path).expanduser()
    real = Path(os.path.realpath(path.parent))
    for root in (Path(data_dir), paths.STATE_ROOT, paths.CONFIG_DIR):
        try:
            real.relative_to(os.path.realpath(root))
            raise BackupError(f"{path} is inside Kratos's folders -- the secret key must not be kept with the data")
        except ValueError:
            continue
    from kratos.backup.create import utc_iso

    from kratos.backup import origin

    signer = origin.signer_fingerprint(Path(data_dir), create=True)
    text = (f"# created: {utc_iso()}\n# public key: {ident.recipient()}\n# {origin.SIGNER_LINE}: {signer}\n"
            f"# Kratos backup key. Keep it off the Kratos computer.\n{ident.secret}\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(text)
    print(f"[KRATOS] Secret key written to {path} (0600).")
    if path.parent.exists() and same_disk(path.parent, Path(data_dir)):
        print("[KRATOS] Warning: that file is on this computer's own disk -- move it off this computer.")


# --------------------------------------------------------------------------- create
def _passphrase(args: argparse.Namespace) -> str | None:
    from kratos.backup import keys as K

    if args.generate_passphrase:
        phrase = K.generate_passphrase()
        print("\nPASSPHRASE for this backup -- shown once, not stored anywhere:\n")
        print(f"    {phrase}\n")
        return phrase
    if not args.passphrase:
        return None
    if not sys.stdin.isatty():
        phrase = sys.stdin.read().rstrip("\r\n")
        K.check_passphrase(phrase)
        return phrase
    a = getpass.getpass("Passphrase for this backup (16+ characters): ")
    K.check_passphrase(a)
    if getpass.getpass("Again: ") != a:
        raise K.KeyError_("the two passphrases differ")
    return a


def _create(args: argparse.Namespace) -> int:
    from kratos.backup import create as CR
    from kratos.backup import schedule as SC

    dd = Path(args.data_dir)
    if args.dry_run:
        d = CR.dry_run(dd, dest=args.dest, exclude=tuple(args.exclude), include_rebuildable=args.include_rebuildable,
                       without_secrets=args.without_secrets)
        if args.json:
            print(json.dumps(d, indent=1, default=str))
            return 0
        _print_dry_run(d)
        return 0
    phrase = _passphrase(args)
    try:
        res = CR.create(dd, actor=_cli_actor(args), dest=args.dest, passphrase=phrase, exclude=tuple(args.exclude),
                        include_rebuildable=args.include_rebuildable, without_secrets=args.without_secrets,
                        copy_to=args.copy_to, scheduled=args.scheduled,
                        progress=(lambda st, t: None) if args.json or args.scheduled else
                        (lambda st, t: print(f"[KRATOS] {t} ...", flush=True)))
    except BaseException as e:
        if args.scheduled and not isinstance(e, KeyboardInterrupt):
            SC.notify(dd, f"Kratos's scheduled backup FAILED: {SC.reason_word(e)}. Next: run `kratos backup "
                          "create` on the Kratos computer.", severity="critical")
        raise
    if args.scheduled:
        bad = [c for c in res.copies if not c.get("ok")]
        if bad:
            SC.notify(dd, f"Kratos's scheduled backup was made, but {len(bad)} copy of it failed. Next: `kratos "
                          "backup status` on the Kratos computer.")
        if SC.drill_overdue(dd):
            SC.notify(dd, "No Kratos restore drill has passed recently: a backup counts as verified only after one. "
                          "Next: `kratos backup drill <file>` on the Kratos computer.")
    if args.json:
        print(json.dumps({"file": str(res.file), "sha256": res.sha256, "size": res.size, "same_disk": res.same_disk,
                          "copies": res.copies, "warnings": res.warnings, "seconds": round(res.seconds, 2),
                          "stages": res.stages}, indent=1))
        return 0 if all(c.get("ok") for c in res.copies) else 1
    from kratos.datainv import human_size

    m = res.manifest
    print(f"[KRATOS] Backup written: {res.file}")
    print(f"         {m['totals']['files']} files, {human_size(m['totals']['bytes'])} before compression; "
          f"{human_size(res.size)} encrypted, in {res.seconds:.1f} s")
    print(f"         SHA-256 {res.sha256}  (also in {res.sidecar.name})")
    lock = m["lock"]
    print("         Locked to " + (f"{len(lock['recipients'])} recipient key(s): " + ", ".join(lock["recipients"])
                                   if lock["mode"] == "recipients" else "the passphrase"))
    from kratos.backup import origin

    print(f"         Signed by this Kratos: {origin.signer_fingerprint(Path(args.data_dir))} (keep this fingerprint "
          "with your backup key: a restore on a new computer asks for it)")
    for c in res.copies:
        print(f"         copy -> {c['target']}: " + ("verified (" + str(c.get("verified")) + ")" if c.get("ok")
                                                     else f"FAILED: {c.get('error')}"))
    for w in res.warnings:
        print(f"[KRATOS] Warning: {w}")
    for item in m.get("not_included") or []:
        print(f"[KRATOS] Not in this backup: {item['what']} -- {item['fix']}")
    print(f"[KRATOS] Next: prove it restores -- kratos backup drill {res.file}")
    return 0 if all(c.get("ok") for c in res.copies) else 1


def _print_dry_run(d: dict[str, Any]) -> None:
    from kratos.datainv import human_size

    print(f"Backup dry run -- data folder {d['data_dir']} ({d['layout']} layout), Kratos {d['kratos_version']}")
    print(f"Would write to {d['destination']}" + ("  -- REFUSED: inside the data folder" if d["inside_data"] else ""))
    if d["same_disk"]:
        print("  that is the same disk as the data: also copy each backup somewhere else (--copy-to)")
    print("Locked to: " + (", ".join(d["recipients"]) if d["recipients"] else
                           "no backup key set up -- `kratos backup key new` (or --passphrase)"))
    for t in d["copy_targets"]:
        print(f"Copied to: {t}")
    print(f"\n{d['files']} files, {human_size(d['bytes'])} ({d['secret_files']} of them secrets); databases "
          "(each copied once, consistently, while Kratos keeps writing): " + ", ".join(d["databases"]))
    print("\n  category              class        in?   files       size  why   (+db: its tables are in the "
          "kratos.db copy)")
    for c in d["categories"]:
        files = f"{c['files']}{'+db' if c.get('in_database') else ''}"
        print(f"  {c['key']:<21} {c['cls']:<12} {'yes' if c['included'] else 'no ':<5} {files:>6} "
              f"{human_size(c['bytes']):>10}  {c['reason']}")
    if d["emptied_tables"]:
        print("\nTables emptied in the database copy (their category is left out): " + ", ".join(d["emptied_tables"]))
    if d["scrubbed"]:
        print("Withheld from the database copy (--without-secrets): " + "; ".join(d["scrubbed"]))
    for item in d["not_included"]:
        print(f"Not included: {item['what']} -- {item['why']}; {item['fix']}")
    for s in d["skipped"][:20]:
        print(f"Skipped: {s}")
    print("\nNothing was read or written. A real backup: kratos backup create")


# --------------------------------------------------------------------------- verify / drill
def _verify(args: argparse.Namespace) -> int:
    from kratos.backup import verify as V
    from kratos.backup.create import _authorize

    dd = Path(args.data_dir)
    actor = _cli_actor(args)
    _authorize(actor, dd, "backup verify")
    if args.full:
        ids = _read_secret("Backup key (AGE-SECRET-KEY-1…) or passphrase: ")
        c = V.full(args.file, ids, data_dir=dd, progress=lambda t: print(f"[KRATOS] {t} ...", flush=True))
    else:
        c = V.quick(args.file)
    V.record_verify(dd, Path(args.file), actor, c, depth="full" if args.full else "quick")
    for n in c.notes:
        print(f"         {n}")
    if c.ok:
        print(f"[KRATOS] OK: {args.file}" + (" -- every file, database and key checked" if args.full else
                                             " -- header, size and sidecar (no secret used)"))
        return 0
    for p in c.problems:
        print(f"[KRATOS] PROBLEM: {p}")
    return 1


def _drill(args: argparse.Namespace) -> int:
    from kratos.backup import verify as V

    ids, hint = _read_secret_and_signer("Backup key (AGE-SECRET-KEY-1…) or passphrase: ")
    t0 = time.monotonic()
    r = V.drill(args.file, ids, data_dir=Path(args.data_dir), actor=_cli_actor(args),
                progress=lambda t: print(f"[KRATOS] {t} ...", flush=True),
                accept_signer=_signer_choice(args, hint), accept_unsigned=args.unsigned_ok)
    if r.ok:
        print(f"[KRATOS] Drill PASSED in {time.monotonic() - t0:.1f} s: {r.restored_files} files restored into a "
              "scratch home, the health check passed, the scratch home removed. This backup is verified.")
        return 0
    for p in r.problems:
        print(f"[KRATOS] Drill FAILED: {p}")
    return 1


# --------------------------------------------------------------------------- restore / extract
def _restore(args: argparse.Namespace) -> int:
    from kratos import paths
    from kratos.backup import restore as RS
    from kratos.backup.plan import Roots

    roots = Roots(Path(args.data_dir), paths.STATE_ROOT, paths.CONFIG_DIR)
    actor = _cli_actor(args)
    ids, hint = _read_secret_and_signer("Backup key (AGE-SECRET-KEY-1…) or passphrase: ")
    trust = {"accept_signer": _signer_choice(args, hint), "accept_unsigned": args.unsigned_ok}
    print("[KRATOS] Checking the whole backup first (nothing is written yet) ...", flush=True)
    dry = RS.restore(args.file, ids, roots=roots, actor=actor, replace=args.replace, dry_run=True, **trust)
    m = dry.manifest
    print(f"         made {m.get('created')} on {m.get('host')} by Kratos {m.get('kratos_version')}; "
          f"{m['totals']['files']} files; {len(m.get('agents') or [])} paired agent(s)")
    keys = m.get("keys") or {}
    if keys.get("agent_link"):
        print(f"         agent-link pins: {', '.join(p[:16] + '…' for p in keys['agent_link'].get('pins', []))}")
    for ca in keys.get("ssh_ca") or []:
        print(f"         SSH {ca.get('kind')} CA ({ca.get('role')}): {ca.get('fingerprint')} [{ca.get('mode')}]")
    for n in dry.notes:
        print(f"[KRATOS] {n}")
    if args.dry_run:
        print("[KRATOS] Dry run: the backup checks out. Nothing was written.")
        return 0
    pre_phrase = None
    if args.replace:
        from kratos.backup import keys as K

        if not K.recipients(roots.data):
            if not sys.stdin.isatty():
                print("[KRATOS] --replace backs up the current state first; set up `kratos backup key new` here or "
                      "run this at a terminal to give a passphrase", file=sys.stderr)
                return 2
            pre_phrase = getpass.getpass("Passphrase for the backup of the CURRENT state (16+ characters): ")
            K.check_passphrase(pre_phrase)
    if not args.yes:
        if not sys.stdin.isatty():
            print("[KRATOS] not at a terminal: add --yes to restore", file=sys.stderr)
            return 2
        if input("Type 'restore' to restore it here: ").strip() != "restore":
            print("[KRATOS] Not restored.")
            return 1
    since = time.time()
    res = RS.restore(args.file, ids, roots=roots, actor=actor, replace=args.replace, ca_mode=args.ca_mode,
                     hub_address=args.hub_address, pre_backup_passphrase=pre_phrase,
                     progress=lambda t: print(f"[KRATOS] {t} ...", flush=True), **trust)
    print(f"[KRATOS] Restored {res.files} files into {roots.data}.")
    if res.pre_backup:
        print(f"         The state before the restore was backed up first: {res.pre_backup}")
    for a, b in res.moved_aside:
        print(f"         moved aside (not deleted): {a} -> {b}")
    for n in res.notes:
        if n not in dry.notes:          # the dry run above already said the rest
            print(f"[KRATOS] {n}")
    _, start = RS.stop_start_lines()
    if res.agents:
        same = [a for a in res.agents if a.get("same")]
        moved = [a for a in res.agents if not a.get("same")]
        for a in moved:
            if a.get("installer"):
                print(f"[KRATOS] {a['name']} dials {a.get('dials')}, which isn't this computer. Run this upgrade "
                      f"installer ON that machine (same pairing, same keys, the new address {a['new_address']}):")
                print(f"           {a['installer']}")
                print(f"           e.g. scp {a['installer']} <user>@<machine>: && ssh <user>@<machine> "
                      f"'sudo sh {Path(a['installer']).name}'")
            else:
                print(f"[KRATOS] {a['name']}: {a.get('note')}")
        if moved:
            print("[KRATOS] Next time, give agents a name that moves with you (e.g. your tailnet's MagicDNS name).")
        if same and not args.no_wait:
            print("[KRATOS] Start the agent listener now, then the agents reconnect on their own:")
            for line in start:
                print(f"           {line}")
            print("[KRATOS] Waiting up to 2 minutes for them (Ctrl-C to stop waiting) ...", flush=True)
            try:
                missing = RS.wait_for_agents(roots.data, same, since=since, timeout=120,
                                             on_seen=lambda a: print(f"         {a['name']}: connected again",
                                                                     flush=True))
            except KeyboardInterrupt:
                missing = []
            if missing:
                print(f"[KRATOS] Not back yet: {', '.join(missing)} -- `kratos subagent-status` shows them later.")
    else:
        print("[KRATOS] Start Kratos again:")
        for line in start:
            print(f"           {line}")
    return 0


def _extract(args: argparse.Namespace) -> int:
    import os

    from kratos.backup import restore as RS
    from kratos.backup.create import _authorize

    dd = Path(args.data_dir)
    _authorize(_cli_actor(args), dd, "backup extract")
    to = Path(args.to).expanduser()
    if to.exists() and any(to.iterdir()):
        print(f"[KRATOS] {to} is not empty; extract into an empty folder", file=sys.stderr)
        return 2
    real = Path(os.path.realpath(to))
    try:
        real.relative_to(os.path.realpath(dd))
        print("[KRATOS] not inside Kratos's data folder", file=sys.stderr)
        return 2
    except ValueError:
        pass
    ids = _read_secret("Backup key (AGE-SECRET-KEY-1…) or passphrase: ")
    if to.exists():
        to.rmdir()   # deletion-scan: an EMPTY folder, recreated owner-only below
    st = RS.stage(args.file, ids, to)
    print(f"[KRATOS] Unpacked {st.files} files into {to} (data/, state/, config/ -- owner-only). It holds secrets: "
          "delete it when you have looked.")
    if st.memory:
        print("[KRATOS] The TPM-sealed SSH CA key was not written out (it is restored only by `kratos backup "
              "restore`).")
    return 0


# --------------------------------------------------------------------------- prune / schedule / status
def _prune(args: argparse.Namespace) -> int:
    from kratos.backup import prune as PR
    from kratos.backup import status as ST
    from kratos.datainv import human_size

    dd = Path(args.data_dir)
    folder = Path(args.dest).expanduser() if args.dest else ST.destination(dd)
    pp = PR.plan(folder, args.keep)
    print(f"In {folder}: keeping the newest {len(pp.keep)}, removing {len(pp.remove)} ({human_size(pp.bytes)}):")
    for p in pp.remove:
        print(f"  remove  {p.name}")
    for p in pp.keep:
        print(f"  keep    {p.name}")
    if not args.apply:
        print("Nothing removed. Add --apply to remove them (copies elsewhere are never touched).")
        return 0
    if not pp.remove:
        return 0
    done = PR.apply(dd, pp, actor=_cli_actor(args))
    print(f"[KRATOS] Removed {len(done['removed'])} backup(s), {human_size(done['bytes'])}; recorded.")
    return 0


def _schedule(args: argparse.Namespace) -> int:
    from kratos.backup import schedule as SC

    out = SC.set_schedule(Path(args.data_dir), args.cadence, actor=_cli_actor(args), copy_to=args.copy_to)
    if out["cadence"] == "off":
        print("[KRATOS] Backups are no longer scheduled. To remove the timer:")
    else:
        print(f"[KRATOS] Timer written ({out['oncalendar']}): {out['timer']}")
        if out["copy_targets"]:
            print("         each backup is copied to: " + ", ".join(out["copy_targets"]))
        else:
            print("         Warning: no copy target -- the backups stay on this computer's disk. Add --copy-to.")
        print("Install it (Kratos doesn't run systemctl itself):")
    for c in out["commands"]:
        print(f"  {c}")
    return 0


def _status(args: argparse.Namespace) -> int:
    from kratos.backup import status as ST

    for r in ST.doctor_rows(Path(args.data_dir)):
        print(f"{r['status'].upper():<5} {r['check']:<20} {r['detail']}")
        if r.get("fix") and r["status"] in ("warn", "fail"):
            print(f"{'':<26} -> {r['fix']}")
    return 0


_HANDLERS = {"key": _key, "create": _create, "verify": _verify, "drill": _drill, "restore": _restore,
             "extract": _extract, "prune": _prune, "schedule": _schedule, "status": _status}
