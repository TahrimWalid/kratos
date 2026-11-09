"""``manifest.json``, ``SHA256SUMS``, ``allowed_signers`` and ``VERIFY.txt``.

The manifest is written once, with sorted keys and a fixed layout, then signed (SSHSIG,
``manifest.json.sig``). It lists every file in the bundle except itself, the two signatures,
``SHA256SUMS``, ``allowed_signers`` and ``VERIFY.txt``. ``SHA256SUMS`` (coreutils' format)
lists every file except itself and its own signature -- the manifest and its signature
included -- and is signed too (``SHA256SUMS.sig``). The two stock commands check that
signature and then every hash: a file changed, added or removed, with ``SHA256SUMS``
regenerated or not, fails one of them. (Signing only the manifest would let someone change
a file and regenerate ``SHA256SUMS``: both commands would still pass.)

The ledger excerpt (``ledger.ndjson``) carries the chain from the first exported file's
row to the head: full rows for this bundle's files (full variant) and the daily
checkpoints, and for every other row only its number and hashes, so the chain links can be
checked without showing other machines' files. The head is in the manifest, which is
signed: a file moved, removed or reordered in the ledger no longer links to it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from kratos.evidence import ledger as L

FORMAT = "kratos-incident-bundle/1"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.json.sig"
SUMS = "SHA256SUMS"
SUMS_SIG = "SHA256SUMS.sig"
SIGNERS = "allowed_signers"
VERIFY = "VERIFY.txt"
LEDGER = "ledger.ndjson"
NOT_IN_MANIFEST = frozenset({MANIFEST, SIGNATURE, SUMS, SUMS_SIG, SIGNERS, VERIFY})
NOT_IN_SUMS = frozenset({SUMS, SUMS_SIG})
VERIFY_COMMANDS = (
    "ssh-keygen -Y verify -f allowed_signers -I kratos -n kratos-export -s SHA256SUMS.sig < SHA256SUMS",
    "sha256sum -c SHA256SUMS",
)


def dumps(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def ledger_excerpt(data_dir: Path, *, first_seq: int, head_seq: int, full_seqs: set[int],
                   redacted: bool) -> list[dict[str, Any]]:
    """Rows ``first_seq`` .. ``head_seq``. Full rows only for ``full_seqs`` and checkpoints
    (and never in a redacted bundle, where paths and machine names would show)."""
    out = []
    for e in L.entries(data_dir, kind=None, upto_seq=head_seq):
        if e.seq < first_seq:
            continue
        if not redacted and (e.seq in full_seqs or e.kind == "checkpoint"):
            out.append({"full": True, **e.as_dict()})
        else:
            out.append({"full": False, "seq": e.seq, "kind": e.kind, "prev_hash": e.prev_hash,
                        "entry_hash": e.entry_hash, **({"sha256": e.sha256} if e.seq in full_seqs else {})})
    return out


def check_excerpt(rows: list[dict[str, Any]], head_seq: int, head_hash: str) -> list[str]:
    """Chain links of an excerpt; a full row's hash is recomputed from its content."""
    problems: list[str] = []
    prev = None
    expected = rows[0]["seq"] if rows else None
    for r in rows:
        if r["seq"] != expected:
            problems.append(f"ledger excerpt: row {expected} missing (next is {r['seq']})")
            expected = r["seq"]
        if prev is not None and r["prev_hash"] != prev:
            problems.append(f"ledger excerpt: row {r['seq']} doesn't follow the row before it")
        if r.get("full"):
            if L.chain_hash(r["prev_hash"], r) != r["entry_hash"]:
                problems.append(f"ledger excerpt: row {r['seq']}'s content doesn't match its hash")
        prev = r["entry_hash"]
        expected += 1
    if rows and (rows[-1]["seq"] != head_seq or rows[-1]["entry_hash"] != head_hash):
        problems.append("ledger excerpt: doesn't end at the head the manifest names")
    return problems


def sums_text(bundle: Path) -> str:
    lines = []
    for p in sorted(bundle.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(bundle).as_posix()
        if rel in NOT_IN_SUMS:
            continue
        lines.append(f"{_sha256_file(p)}  {rel}\n")
    return "".join(lines)


def parse_sums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep:
            digest, sep, rel = line.partition(" *")
        out[rel] = digest.lower()
    return out


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_text(fingerprint: str, export_id: str) -> str:
    return f"""Kratos incident bundle {export_id}

You can check this bundle on any computer that has OpenSSH (Linux, macOS, Windows 10+).
No Kratos install is needed. In a terminal, in this folder:

1. Check the signature on the list of hashes:

   ssh-keygen -Y verify -f allowed_signers -I kratos -n kratos-export -s SHA256SUMS.sig < SHA256SUMS

   It must print: Good "kratos-export" signature for kratos with ED25519 key {fingerprint}
   Compare that fingerprint with the one the person who sent you the bundle reads from
   Kratos's /doctor ("signing key") -- told to you some other way than with the bundle.

2. Check every file against the hashes:

   sha256sum -c SHA256SUMS

   Every line must end in OK. (On macOS: shasum -a 256 -c SHA256SUMS. On Windows, in
   PowerShell, compare Get-FileHash output with SHA256SUMS.)

Together, steps 1 and 2 prove that no file in this folder changed since Kratos signed it.
manifest.json (also signed on its own: manifest.json.sig) lists every evidence file with the
SHA-256 Kratos recorded when it collected the file, so a file whose hash matches was not
changed since Kratos wrote it. A file marked "hash taken when exporting" predates Kratos's evidence ledger: its hash
proves only that it didn't change after the export.

Open report.html in a browser to read it (it uses no network).
"""
