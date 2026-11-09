"""`kratos export` and `kratos evidence` (D.6).

    kratos export create --machine M [--machine M2] | --group G  [--since 3d] [--until now]
                         [--redacted] [--narrative] [--findings window|open|all|none]
                         [--no-events] [--no-snapshots] [--no-runs] [--no-archive] [--yes]
    kratos export verify <bundle folder>
    kratos export list
    kratos evidence verify      the evidence ledger's hash chain, and every recorded file against it
    kratos evidence checkpoint  sign the ledger's head now (Kratos also does it once a day)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

from kratos.untrusted import safe_print as print


def add_parser(sub: Any) -> None:
    ex = sub.add_parser("export", help="An incident bundle someone else can check with OpenSSH: evidence with "
                                       "collection-time hashes, a signed manifest, an HTML report, CASE/UCO")
    es = ex.add_subparsers(dest="export_action", required=True)
    c = es.add_parser("create", help="Make a bundle for machines (or a group) and a period")
    c.add_argument("--machine", "-m", action="append", default=[], help="A machine (repeat for several)")
    c.add_argument("--group", "-g", default=None, help="Every machine of a group (@name or name)")
    c.add_argument("--since", default="7d", help="Start of the period: 3d, 24h, '7 days ago', 2026-11-01, or 'all' "
                                                 "(default 7d)")
    c.add_argument("--until", default=None, help="End of the period (default now)")
    c.add_argument("--redacted", action="store_true", help="Replace names, addresses and accounts with placeholders "
                                                         "and remove secrets (for sending outside your team)")
    c.add_argument("--narrative", action="store_true", help="Add a written summary by the model (it holds no "
                                                          "tools; its cost estimate is shown first)")
    c.add_argument("--findings", choices=("window", "open", "all", "none"), default="window",
                   help="Which findings: with evidence in the period (default), open, all, none")
    c.add_argument("--no-events", action="store_true", help="Leave out the stored log events")
    c.add_argument("--no-snapshots", action="store_true", help="Leave out saved reads (persistence, packages, ...)")
    c.add_argument("--no-runs", action="store_true", help="Leave out run records")
    c.add_argument("--no-archive", action="store_true", help="Only the folder, no .tar.gz")
    c.add_argument("--yes", "-y", action="store_true", help="Don't ask before making it")
    v = es.add_parser("verify", help="Check a bundle: signature, hashes, manifest, ledger (and, on the Kratos "
                                     "that made it, against its own records)")
    v.add_argument("bundle")
    es.add_parser("list", help="Every export made here: who, when, scope, hashes")
    ex.set_defaults(func=cmd_export)

    ev = sub.add_parser("evidence", help="The evidence ledger: hashes Kratos took when it wrote each evidence file")
    vs = ev.add_subparsers(dest="evidence_action", required=True)
    vs.add_parser("verify", help="Check the hash chain and every recorded file against it")
    vs.add_parser("checkpoint", help="Sign the ledger's head now with Kratos's signing key")
    ev.set_defaults(func=cmd_evidence)


def _actor() -> Any:
    from kratos.lifecycle.decide import Actor

    return Actor.current("cli")


def _window(args: argparse.Namespace) -> tuple[float | None, float]:
    from kratos.hunt.front import time_bound

    start = None if str(args.since).lower() in ("all", "everything") else time_bound(args.since)
    end = time_bound(args.until) if args.until else time.time()
    return start, end


def _machines(args: argparse.Namespace, data_dir: Path) -> tuple[list[str], str | None]:
    from kratos.fleet import groups as G
    from kratos.target_key import target_key

    if args.group:
        res = G.resolve(data_dir, args.group)
        return res.machines, res.name
    ms = [target_key(m) for m in args.machine if target_key(m)]
    if not ms:
        from kratos import kratos_config

        active = kratos_config.get_active_target()
        ms = [target_key(active)] if active else []
    return ms, None


def cmd_export(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir)
    if args.export_action == "verify":
        return _verify(Path(args.bundle), data_dir)
    if args.export_action == "list":
        return _list(data_dir)
    from kratos.export import create as C
    from kratos.export import narrative as N
    from kratos.export import settings as ES
    from kratos.export.scope import ExportError, ExportRequest, plan

    try:
        start, end = _window(args)
        machines, group = _machines(args, data_dir)
        req = ExportRequest(machines=machines, start=start, end=end, group=group,
                            variant="redacted" if args.redacted else "full",
                            include_snapshots=not args.no_snapshots, include_runs=not args.no_runs,
                            include_events=not args.no_events, findings=args.findings, narrative=args.narrative,
                            archive=not args.no_archive)
        p = plan(data_dir, req)
    except Exception as e:  # noqa: BLE001 -- bad input in plain words
        print(f"[KRATOS] Can't export: {e}", file=sys.stderr)
        return 2
    print("[KRATOS] This export will hold:")
    for line in p.summary_lines():
        print(f"  {line}")
    if req.narrative:
        cap = float(ES.get(ES.NARRATIVE_MAX_USD, data_dir))
        print(f"  written summary: by the model ({_narrative_cost(p, data_dir, N)}; at most ${cap:.2f} -- "
              "export.narrative_max_usd)")
    sys.stdout.flush()          # the summary before the progress lines (stderr), also when piped
    if not args.yes:
        try:
            ans = input("Make it? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            print("[KRATOS] Not exported.")
            return 1
    try:
        r = C.create(data_dir, req, _actor(), plan=p,
                     progress=lambda m: print(f"[KRATOS] {m}...", file=sys.stderr))
    except ExportError as e:
        print(f"[KRATOS] Can't export: {e}", file=sys.stderr)
        return 2
    _print_result(r)
    return 0


def _narrative_cost(p: Any, data_dir: Path, N: Any) -> str:
    approx_findings = sum(len(v) for v in p.findings.values())
    est_prompt = "x" * (2000 + approx_findings * 400 + len(p.request.machines) * 1500)
    _t, cost, model = N.estimate(est_prompt, data_dir)
    return f"{model}, about ${cost:.3f}" if cost is not None else f"{model}, cost unknown (no rate set)"


def _print_result(r: Any) -> None:
    print(f"[KRATOS] Bundle: {r.bundle}")
    if r.archive:
        print(f"[KRATOS] Archive: {r.archive}")
        print(f"[KRATOS] Archive SHA-256: {r.archive_sha256}  (note it down or send it separately from the file)")
    print(f"[KRATOS] {r.files} files, {r.events:,} events, {r.bytes / 1e6:.1f} MB, in {r.seconds:.1f}s")
    print(f"[KRATOS] Signed by: {r.fingerprint}  (the same fingerprint /doctor shows as 'signing key')")
    for w in r.warnings:
        print(f"[KRATOS] WARNING: {w}")
    if r.narrative and r.narrative.get("skipped"):
        print(f"[KRATOS] {r.narrative['skipped']}")
    print("[KRATOS] Anyone can check it with OpenSSH, in the bundle folder:")
    from kratos.export.manifest import VERIFY_COMMANDS

    for c in VERIFY_COMMANDS:
        print(f"  {c}")


def _verify(bundle: Path, data_dir: Path) -> int:
    from kratos.export import verify as V

    rep = V.verify(bundle, data_dir=data_dir)
    mark = {True: "ok", False: "FAILED", None: "not checked"}
    print(f"[KRATOS] Signature on SHA256SUMS: {mark[rep.sums_signature_ok]}" + (f" ({rep.signer})" if rep.signer else ""))
    print(f"[KRATOS] Signature on manifest.json: {mark[rep.signature_ok]}")
    if rep.signer_is_this_kratos is not None:
        print(f"[KRATOS] Signed by this Kratos's key: {'yes' if rep.signer_is_this_kratos else 'NO'}")
    print(f"[KRATOS] SHA256SUMS: {mark[rep.sums_ok]}")
    print(f"[KRATOS] Manifest ({rep.files_checked} files): {mark[rep.manifest_ok]}")
    print(f"[KRATOS] Evidence ledger excerpt: {mark[rep.ledger_ok]}")
    print(f"[KRATOS] Against this Kratos's records: {mark[rep.local_ok]}")
    for p in rep.problems:
        print(f"[KRATOS]   {p}")
    for n in rep.notes:
        print(f"[KRATOS]   note: {n}")
    print(f"[KRATOS] {'Bundle verified.' if rep.ok else 'Bundle does NOT verify.'}")
    return 0 if rep.ok else 1


def _list(data_dir: Path) -> int:
    from kratos.export import create as C

    rows = C.list_exports(data_dir)
    if not rows:
        print("[KRATOS] No export made here yet (`kratos export create`).")
        return 0
    for r in rows:
        sc = r.get("scope") or {}
        win = sc.get("window") or {}
        print(f"{r['at']}  {r['export_id']}  {r.get('variant')}  by {r.get('by')} ({r.get('interface')})  "
              f"{', '.join(sc.get('machines') or [])}  {win.get('start') or 'beginning'} .. {win.get('end')}  "
              f"{r.get('files')} files  {'' if r.get('bundle_present') else '(bundle folder gone) '}"
              f"manifest {str(r.get('manifest_sha256'))[:16]}  archive {str(r.get('archive_sha256') or '-')[:16]}  "
              f"key {r.get('fingerprint')}")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    from kratos.evidence import ledger as L

    data_dir = Path(args.data_dir)
    if args.evidence_action == "checkpoint":
        cp = L.checkpoint_now(data_dir)
        print("[KRATOS] " + (f"Signed the ledger's head (row {cp.detail['signs_seq']}) as row {cp.seq}."
                             if cp else "The ledger's head is already signed (or the ledger is empty)."))
        return 0
    rep = L.verify_chain(data_dir)
    print(f"[KRATOS] Evidence ledger: {rep.rows} row(s), head row {rep.head_seq} {rep.head_hash[:16]}..., "
          f"{rep.checkpoints} signed checkpoint(s)")
    if rep.problems:
        print("[KRATOS] The hash chain is BROKEN:")
        for p in rep.problems:
            print(f"[KRATOS]   {p}")
    else:
        print("[KRATOS] Hash chain: ok (no row edited, deleted, inserted or moved)")
    for rel in rep.changed:
        print(f"[KRATOS] CHANGED since Kratos recorded it: {rel}")
    if rep.missing:
        print(f"[KRATOS] {len(rep.missing)} recorded file(s) no longer on disk (pruned or deleted), e.g. "
              f"{', '.join(rep.missing[:3])}")
    if rep.unrecorded:
        print(f"[KRATOS] {len(rep.unrecorded)} evidence file(s) written after the ledger began have no row "
              f"(written by something that doesn't record), e.g. {', '.join(rep.unrecorded[:3])}")
    ok = rep.chain_ok and not rep.changed
    print(f"[KRATOS] {'Evidence ledger verified.' if ok else 'Evidence ledger does NOT verify.'}")
    return 0 if ok else 1
