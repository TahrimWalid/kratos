"""Who can open a backup (docs/phaseD/D.8 §3.2).

Recipient keys (recommended, the only option for scheduled backups): `new_identity()`
makes an X25519 identity, the secret half is shown to the person ONCE and never stored;
Kratos keeps only the public half in `backup.recipients`. Nothing on the Kratos host can
then decrypt a backup. Up to 5 recipients (the person may add their own `age1…` keys).

Passphrase (manual backups only): asked twice, never stored or logged, at least 16
characters; `generate_passphrase()` offers six random words from the BIP-0039 English list
(2,048 words, 66 bits).
"""
from __future__ import annotations

import hashlib
import secrets as _secrets
from importlib import resources
from pathlib import Path

from kratos.backup import agefmt as A
from kratos.backup import settings as BS

MIN_PASSPHRASE = 16
WORDS_IN_PASSPHRASE = 6


class KeyError_(ValueError):
    """A key or passphrase problem, in plain words."""


def fingerprint(recipient: str) -> str:
    """A short, stable label for an age1… key (safe to log)."""
    raw = A.X25519Recipient.parse(recipient).raw
    return "age:" + hashlib.sha256(raw).hexdigest()[:16]


def recipients(data_dir: Path) -> list[str]:
    return list(BS.get(BS.RECIPIENTS, data_dir))


def recipient_objects(data_dir: Path) -> list[A.X25519Recipient]:
    return [A.X25519Recipient.parse(r) for r in recipients(data_dir)]


def new_identity() -> A.X25519Identity:
    return A.X25519Identity.generate()


def _save(data_dir: Path, values: list[str], actor: str) -> None:
    from kratos import settings_store

    try:
        settings_store.set(BS.RECIPIENTS, values, data_dir=Path(data_dir), actor=actor)
    except settings_store.SettingError as e:
        raise KeyError_(str(e)) from None


def add_recipient(data_dir: Path, recipient: str, *, actor: str) -> str:
    try:
        r = str(A.X25519Recipient.parse(recipient))
    except ValueError as e:
        raise KeyError_(f"that is not an age public key (age1…): {e}") from None
    have = recipients(data_dir)
    if r in have:
        return r
    if len(have) >= BS.MAX_RECIPIENTS:
        raise KeyError_(f"a backup can be opened by at most {BS.MAX_RECIPIENTS} keys; remove one first")
    _save(data_dir, have + [r], actor)
    return r


def remove_recipient(data_dir: Path, which: str, *, actor: str) -> str:
    have = recipients(data_dir)
    keep = [r for r in have if r != which and fingerprint(r) != which]
    if len(keep) == len(have):
        raise KeyError_("no such backup key (give the age1… key or its age:… fingerprint from `kratos backup key list`)")
    _save(data_dir, keep, actor)
    return which


def check_passphrase(text: str) -> None:
    if len(text) < MIN_PASSPHRASE:
        raise KeyError_(f"the passphrase must be at least {MIN_PASSPHRASE} characters "
                        "(or use --generate-passphrase for six random words)")


def word_list() -> list[str]:
    text = resources.files("kratos.backup").joinpath("data/bip39_english.txt").read_text(encoding="utf-8")
    words = [w.strip() for w in text.splitlines() if w.strip()]
    if len(words) != 2048:
        raise RuntimeError("the bundled word list is damaged")
    return words


def generate_passphrase() -> str:
    words = word_list()
    return " ".join(_secrets.choice(words) for _ in range(WORDS_IN_PASSPHRASE))


def read_identities(text: str) -> list[object]:
    """Identities from what the person pasted or piped in: an age identity file
    (`# comments`, AGE-SECRET-KEY-1… lines) or, failing that, a passphrase."""
    lines = [ln.strip() for ln in text.splitlines()]
    keys = [ln for ln in lines if ln and not ln.startswith("#")]
    if keys and all(k.upper().startswith("AGE-SECRET-KEY-") for k in keys):
        out: list[object] = []
        for k in keys:
            if k.upper().startswith("AGE-SECRET-KEY-PQ-"):
                raise KeyError_("post-quantum keys (AGE-SECRET-KEY-PQ-1…) aren't supported by Kratos's backups")
            try:
                out.append(A.X25519Identity.parse(k))
            except ValueError as e:
                raise KeyError_(f"not a valid backup key: {e}") from None
        return out
    phrase = text.rstrip("\r\n")
    if not phrase:
        raise KeyError_("no key or passphrase was given")
    return [A.ScryptIdentity(phrase.encode("utf-8"))]
