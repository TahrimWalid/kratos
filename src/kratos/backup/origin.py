"""Who made a backup.

age encrypts to a PUBLIC key, so anyone who knows one of the recipient keys can make a file
that opens with the matching secret key -- age doesn't say who wrote a file. A forged
"backup" dropped on a copy target or a USB stick would otherwise restore an attacker's
database, settings and kept tools as if they were yours.

So every backup is signed with this Kratos's signing key (kratos.signing, Ed25519). The
signature covers the encrypted file's SHA-256, its size and when it was made; it lives in the
public sidecar, so `kratos backup verify` checks it without the secret key. A drill or a
restore goes ahead only when the backup was signed by this Kratos (its active or a rotated
key), or by a key whose fingerprint the person confirms -- on a new computer, the one they
wrote down with their backup key (`kratos backup key new` prints it and puts it in the key
file). An unsigned backup (its sidecar lost) needs an explicit "I know where this came from".
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

STATEMENT = "kratos-backup-origin-v1"
SIGNER_LINE = "kratos-backup-signer"            # in the key file: `# kratos-backup-signer: SHA256:...`
_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def statement(sha256: str, size: int, created: str) -> bytes:
    """What the signature covers: the encrypted file itself (by hash and size) and when."""
    return f"{STATEMENT}\nsha256 {sha256}\nsize {int(size)}\ncreated {created}\n".encode("ascii")


def sidecar_lines(data_dir: Path, sha256: str, size: int, created: str) -> str:
    """The sidecar lines that say who made this backup (the signing key is made on first use)."""
    from kratos import signing

    sig = signing.sign(statement(sha256, size, created), data_dir)
    info = signing.info(data_dir)
    assert info is not None
    key = " ".join(info.public_openssh.split()[:2])
    return (f"# signer: {info.fingerprint}\n# signing-key: {key}\n"
            f"# signature: {base64.b64encode(sig).decode('ascii')}\n")


def signer_fingerprint(data_dir: Path, *, create: bool = False) -> str | None:
    from kratos import signing

    try:
        info = signing.info(data_dir, create=create)
    except Exception:  # noqa: BLE001 -- an unreadable key is "no key" here
        return None
    return info.fingerprint if info else None


def local_fingerprints(data_dir: Path) -> set[str]:
    """This Kratos's signing keys: the active one and every rotated-out one."""
    from cryptography.hazmat.primitives import serialization

    from kratos import signing

    out: set[str] = set()
    fp = signer_fingerprint(data_dir)
    if fp:
        out.add(fp)
    for line in signing.retired_public_keys(data_dir):
        try:
            pub = serialization.load_ssh_public_key(" ".join(line.split()[:2]).encode("ascii"))
            out.add(signing.fingerprint_of(pub))  # type: ignore[arg-type]
        except (ValueError, TypeError, IndexError):
            continue
    return out


def fingerprint_in(text: str) -> str | None:
    """`# kratos-backup-signer: SHA256:...` from a key file pasted or piped in."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("#") and SIGNER_LINE in line:
            fp = line.split(":", 1)[1].strip() if ":" in line else ""
            if _FP_RE.match(fp):
                return fp
    return None


def valid_fingerprint(fp: str) -> bool:
    return bool(_FP_RE.match(fp or ""))


@dataclass(frozen=True)
class Origin:
    status: str                # this | other | unsigned | bad
    signer: str | None = None
    detail: str = ""

    def describe(self) -> str:
        if self.status == "this":
            return f"signed by this Kratos ({self.signer})"
        if self.status == "other":
            return f"signed by another Kratos signing key ({self.signer})"
        if self.status == "unsigned":
            return "not signed: " + (self.detail or "no sidecar says who made it")
        return "its signature is INVALID: " + self.detail


def origin_of(meta: dict | None, sha256: str | None, size: int | None, data_dir: Path | None) -> Origin:
    """Check a sidecar's signature against the file's real hash and size, then say whose key
    it is. `meta` is `create.read_sidecar`'s dict (None when there is no sidecar)."""
    if not meta:
        return Origin("unsigned", detail="there is no sidecar (.sha256) next to it")
    sig_b64, key, claimed = meta.get("signature"), meta.get("signing-key"), meta.get("signer")
    if not sig_b64 and not key:
        return Origin("unsigned", detail="its sidecar has no signature")
    if not (sig_b64 and key and claimed and meta.get("created")) or sha256 is None or size is None:
        return Origin("bad", detail="its sidecar's signature lines are incomplete")
    from cryptography.hazmat.primitives import serialization

    from kratos import signing

    try:
        sig = base64.b64decode(str(sig_b64), validate=True)
        pub = serialization.load_ssh_public_key(str(key).encode("ascii"))
        fp = signing.fingerprint_of(pub)  # type: ignore[arg-type]
    except (ValueError, TypeError, UnicodeEncodeError):
        return Origin("bad", detail="its sidecar's signing key or signature can't be read")
    if fp != claimed:
        return Origin("bad", detail=f"the sidecar names signer {str(claimed)[:60]} but carries key {fp}")
    if sha256 != meta.get("sha256") or size != meta.get("size"):
        return Origin("bad", fp, "the file doesn't match its sidecar")
    if not signing.verify(sig, statement(sha256, size, str(meta["created"])), str(key)):
        return Origin("bad", fp, "the signature doesn't match the file (it was changed, or the sidecar is forged)")
    if data_dir is not None and fp in local_fingerprints(Path(data_dir)):
        return Origin("this", fp)
    return Origin("other", fp)


class UntrustedBackup(RuntimeError):
    """A drill or restore refused because Kratos can't tell the backup is yours."""


def require_trusted(o: Origin, *, accept_signer: str | None, accept_unsigned: bool, action: str,
                    has_local_key: bool) -> None:
    """Raise UntrustedBackup unless `o` may be drilled / restored."""
    if o.status == "this":
        return
    if o.status == "bad":
        raise UntrustedBackup(f"refused to {action}: {o.describe()}. Don't use this file.")
    if o.status == "other":
        if accept_signer and accept_signer == o.signer:
            return
        if accept_signer:
            raise UntrustedBackup(f"refused to {action}: the backup is signed by {o.signer}, not by "
                                  f"{accept_signer} (the fingerprint you gave)")
        why = ("This computer has no Kratos signing key yet, so Kratos can't tell on its own that this backup "
               "is yours." if not has_local_key else
               "That is not this Kratos's signing key, so this backup was made by another Kratos -- or forged "
               "by someone who knows your backup key's PUBLIC half.")
        raise UntrustedBackup(
            f"refused to {action}: the backup is signed by {o.signer}. {why} Compare that fingerprint with the "
            "one you wrote down with your backup key (`kratos backup key new` printed it; the key file has a "
            f"'# {SIGNER_LINE}:' line -- pipe the whole file in and it is read from there), then run again with "
            f"--signer {o.signer}")
    if accept_unsigned:
        return
    raise UntrustedBackup(
        f"refused to {action}: this backup is {o.describe()} -- Kratos can't tell who made it, and anyone who "
        "knows your backup key's PUBLIC half can make a file that opens with your key. Put its .sha256 file next "
        "to it, or, only if you know where this file came from, run again with --unsigned-ok. "
        "(`kratos backup extract` lets you look inside without installing anything.)")
