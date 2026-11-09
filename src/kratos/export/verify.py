"""``kratos export verify <bundle>``: everything a responder's two OpenSSH/coreutils commands
check, plus what only a program can.

1. the manifest's SSHSIG signature (namespace ``kratos-export``), and -- run on the Kratos
   that made it -- that the key is this Kratos's signing key (current or retired);
2. ``SHA256SUMS``: every listed file's hash, and that it lists exactly the bundle's files;
3. the manifest: every file it lists exists with that hash and size, no evidence file is
   missing from it, each events file matches its per-line index;
4. the ledger excerpt: its rows link into one chain ending at the head the (signed)
   manifest names; each file hashed at collection has its row there with the same hash;
5. on the Kratos that made it: each of those ledger rows is the same row in this Kratos's
   ledger, and (full variant) each event line is the store's canonical document for that
   event id.

Every problem names the file it is about.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.export import manifest as M
from kratos.export import sshsig


@dataclass
class VerifyReport:
    bundle: Path
    signature_ok: bool = False
    signer: str | None = None              # fingerprint of the key that signed
    signer_is_this_kratos: bool | None = None
    sums_ok: bool = False
    manifest_ok: bool = False
    ledger_ok: bool | None = None          # None: no ledger excerpt (nothing hashed at collection)
    local_ok: bool | None = None           # None: not checked (not the Kratos that made it)
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    files_checked: int = 0

    @property
    def ok(self) -> bool:
        return (self.signature_ok and self.sums_ok and self.manifest_ok and self.ledger_ok is not False
                and self.local_ok is not False and self.signer_is_this_kratos is not False)


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fp(public_openssh: str) -> str:
    import base64

    blob = base64.b64decode(public_openssh.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def verify(bundle: Path | str, *, data_dir: Path | str | None = None) -> VerifyReport:
    bundle = Path(bundle)
    rep = VerifyReport(bundle)
    man_p = bundle / M.MANIFEST
    if not man_p.is_file():
        rep.problems.append(f"{M.MANIFEST} is missing -- not a Kratos bundle folder")
        return rep
    man_bytes = man_p.read_bytes()

    # 1. signature
    try:
        sig = (bundle / M.SIGNATURE).read_text(encoding="ascii")
        parsed = sshsig.verify(man_bytes, sig)
        rep.signature_ok = True
        rep.signer = _fp(parsed.public_openssh)
    except (OSError, UnicodeDecodeError) as e:
        rep.problems.append(f"{M.SIGNATURE}: can't be read ({type(e).__name__})")
    except sshsig.SignatureError as e:
        rep.problems.append(f"{M.SIGNATURE}: {e} -- {M.MANIFEST} was changed after it was signed, or the "
                            "signature isn't Kratos's")
    try:
        man = json.loads(man_bytes)
    except ValueError:
        rep.problems.append(f"{M.MANIFEST} isn't valid JSON")
        return rep
    if rep.signer and man.get("signing_key", {}).get("fingerprint") != rep.signer:
        rep.problems.append(f"{M.MANIFEST}: names a different signing key than the one that signed it")
        rep.signature_ok = False
    if data_dir is not None and rep.signer:
        from kratos import signing

        keys = []
        try:
            if signing.load_key(data_dir, create=False) is not None:
                keys.append(signing.public_key_openssh(data_dir))
            keys += signing.retired_public_keys(data_dir)
        except Exception:  # noqa: BLE001
            keys = []
        if keys:
            rep.signer_is_this_kratos = any(_fp(k) == rep.signer for k in keys)
            if not rep.signer_is_this_kratos:
                rep.notes.append(f"signed by {rep.signer}, which is not this Kratos's signing key (current or "
                                 "retired): this bundle was made by another Kratos, or by someone else")

    # 2. SHA256SUMS
    try:
        sums = M.parse_sums((bundle / M.SUMS).read_text(encoding="utf-8"))
    except OSError:
        sums = {}
        rep.problems.append(f"{M.SUMS} is missing")
    on_disk = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}
    expected = on_disk - M.NOT_IN_SUMS
    bad_sum = False
    for rel in sorted(set(sums) | expected):
        if rel not in sums:
            rep.problems.append(f"{rel}: in the bundle but not in {M.SUMS} (a file was added)")
            bad_sum = True
        elif rel not in on_disk:
            rep.problems.append(f"{rel}: listed in {M.SUMS} but missing from the bundle")
            bad_sum = True
        elif _sha256(bundle / rel) != sums[rel]:
            rep.problems.append(f"{rel}: its SHA-256 doesn't match {M.SUMS} -- the file was changed")
            bad_sum = True
    rep.sums_ok = bool(sums) and not bad_sum

    # 3. the manifest's own list
    listed = {f["path"]: f for f in man.get("files") or []}
    bad_man = False
    for rel, f in sorted(listed.items()):
        p = bundle / rel
        rep.files_checked += 1
        if not p.is_file():
            rep.problems.append(f"{rel}: listed in the manifest but missing")
            bad_man = True
            continue
        if p.stat().st_size != f.get("size") or _sha256(p) != f.get("sha256"):
            rep.problems.append(f"{rel}: doesn't match the manifest's SHA-256 -- the file was changed"
                                + (" (this is the hash Kratos recorded when it collected it)"
                                   if f.get("hashed_at") == "collection" and not f.get("original_sha256") else ""))
            bad_man = True
    for rel in sorted(on_disk - set(listed) - M.NOT_IN_MANIFEST):
        rep.problems.append(f"{rel}: in the bundle but not in the manifest (a file was added)")
        bad_man = True
    for rel, f in listed.items():
        if f.get("kind") == "events" and f.get("index") and (bundle / rel).is_file() and (bundle / f["index"]).is_file():
            bad_man |= not _check_events(bundle, rel, f["index"], rep)
    rep.manifest_ok = not bad_man

    # 4. the ledger excerpt
    lg = man.get("ledger") or {}
    collection_files = [f for f in listed.values() if f.get("hashed_at") == "collection"]
    if lg.get("excerpt"):
        rows = []
        try:
            for line in (bundle / lg["excerpt"]).read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rows.append(json.loads(line))
        except (OSError, ValueError) as e:
            rep.problems.append(f"{lg['excerpt']}: can't be read ({type(e).__name__})")
            rep.ledger_ok = False
        else:
            probs = M.check_excerpt(rows, int(lg.get("head_seq") or 0), str(lg.get("head_hash") or ""))
            by_seq = {r["seq"]: r for r in rows}
            for f in collection_files:
                r = by_seq.get(f.get("ledger_seq"))
                want = f.get("original_sha256") or f.get("sha256")
                if r is None:
                    probs.append(f"{f['path']}: its ledger row {f.get('ledger_seq')} isn't in the excerpt")
                elif r.get("entry_hash") != f.get("ledger_entry_hash") or (r.get("sha256") and r["sha256"] != want):
                    probs.append(f"{f['path']}: doesn't match its ledger row {r['seq']} (the hash recorded when "
                                 "Kratos collected it)")
            rep.problems += probs
            rep.ledger_ok = not probs
    elif collection_files:
        rep.problems.append("the manifest lists files hashed at collection but has no ledger excerpt")
        rep.ledger_ok = False

    # 5. against this Kratos
    if data_dir is not None:
        rep.local_ok = _check_local(Path(data_dir), man, listed, rep)
    return rep


def _check_events(bundle: Path, rel: str, idx_rel: str, rep: VerifyReport) -> bool:
    ok = True
    with open(bundle / rel, "rb") as fd, open(bundle / idx_rel, "rb") as fx:
        header = fx.readline()
        if not header.startswith(b"#"):
            rep.problems.append(f"{idx_rel}: not an event index")
            return False
        n = 0
        for line in fd:
            n += 1
            rec = fx.readline().decode("ascii", "replace").rstrip("\n").split("\t")
            if len(rec) != 3 or rec[0] != str(n):
                rep.problems.append(f"{idx_rel}: line {n} missing or out of order")
                return False
            if hashlib.sha256(line.rstrip(b"\n")).hexdigest() != rec[2]:
                rep.problems.append(f"{rel}: line {n} doesn't match its index (event {rec[1]})")
                ok = False
        if fx.readline():
            rep.problems.append(f"{idx_rel}: lists more lines than {rel} holds")
            ok = False
    return ok


def _check_local(data_dir: Path, man: dict[str, Any], listed: dict[str, Any], rep: VerifyReport) -> bool | None:
    from kratos.evidence import ledger as L

    if not (data_dir / "kratos.db").exists():
        return None
    seqs = {f["ledger_seq"]: f for f in listed.values() if f.get("ledger_seq")}
    if not seqs and man.get("variant") != "full":
        return None
    ok = True
    mine = {e.seq: e for e in L.entries(data_dir, kind=None, upto_seq=int((man.get("ledger") or {}).get("head_seq") or 0))}
    head = (man.get("ledger") or {}).get("head_seq")
    if head and (head not in mine or mine[head].entry_hash != man["ledger"].get("head_hash")):
        if rep.signer_is_this_kratos:
            rep.problems.append(f"this Kratos signed the bundle, but its evidence ledger no longer holds the bundle's "
                                f"head (row {head}): the ledger was changed since the export")
            return False
        rep.notes.append("this Kratos's evidence ledger doesn't hold the bundle's head: the bundle was made by "
                         "another Kratos, so its records can't be compared here")
        return None
    for seq, f in seqs.items():
        e = mine.get(seq)
        if e is None or e.entry_hash != f.get("ledger_entry_hash"):
            rep.problems.append(f"{f['path']}: this Kratos's ledger row {seq} is not the row the bundle names")
            ok = False
    if man.get("variant") == "full":
        ok &= _check_events_local(data_dir, man, listed, rep)
    return ok


def _check_events_local(data_dir: Path, man: dict[str, Any], listed: dict[str, Any], rep: VerifyReport) -> bool:
    """Each event line is the store's canonical document for its event id (re-derived)."""
    from kratos.storage.sqlite_files import connect_store

    names = {m["shown"] for m in man.get("machines") or []}
    ok = True
    conn = connect_store(data_dir / "kratos.db")
    try:
        for rel, f in listed.items():
            if f.get("kind") != "events" or not f.get("index") or f.get("machine") not in names:
                continue
            with open(rep.bundle / f["index"], "r", encoding="ascii") as fx:
                fx.readline()
                for line in fx:
                    n, event_id, digest = line.rstrip("\n").split("\t")
                    row = conn.execute("SELECT doc FROM host_events WHERE target = ? AND event_id = ?",
                                       (f["machine"], event_id)).fetchone()
                    if row is None:
                        rep.problems.append(f"{rel}: line {n}: event {event_id} isn't in this Kratos's store")
                        ok = False
                        break
                    if hashlib.sha256(row[0].encode("utf-8")).hexdigest() != digest:
                        rep.problems.append(f"{rel}: line {n}: event {event_id} differs from this Kratos's store")
                        ok = False
                        break
    finally:
        conn.close()
    return ok
