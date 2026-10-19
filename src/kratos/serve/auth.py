"""Client tokens for `kratos serve` (docs/phaseB/B.3 §3.5).

A token is `krt_<id>_<secret>`: `<id>` (12 hex) finds the row, `<secret>` (43 url-safe
characters, 256 bits) is checked against an scrypt hash with its own salt, compared in
constant time. The token itself is printed once at creation and stored nowhere.

Tokens are made on the command line (`kratos serve token create`) or in the app -- never
over the network: no endpoint creates, lists or revokes one. A token says which machines
it may investigate (`targets`; none = the default machine only) and which doors it may use
(`openai` always; `mcp` only when asked for).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.serve import store as _store

PREFIX = "krt_"
DOORS = ("openai", "mcp")
# scrypt cost: n=2**14, r=8, p=1 (16 MB, ~50 ms here) -- the secret is 256 random bits,
# so the cost only has to make an offline check of a leaked database slow, not resist a
# guessable password. Recorded per row, so it can be raised later without breaking tokens.
SCRYPT = {"name": "scrypt", "n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
_TOKEN_RE = re.compile(r"^krt_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")


class TokenError(ValueError):
    pass


@dataclass(frozen=True)
class Client:
    """A verified token: who is calling and what they may reach."""
    token_id: str
    name: str
    targets: tuple[str, ...]          # () = the default machine only
    doors: tuple[str, ...]

    def may_use(self, door: str) -> bool:
        return door in self.doors


def _hash(secret: str, salt: bytes, kdf: dict[str, Any]) -> str:
    if kdf.get("name") != "scrypt":
        raise TokenError("unknown key-derivation function")
    n, r, p, dklen = int(kdf["n"]), int(kdf["r"]), int(kdf["p"]), int(kdf["dklen"])
    return hashlib.scrypt(secret.encode("ascii"), salt=salt, n=n, r=r, p=p, dklen=dklen,
                          maxmem=128 * r * n * 2 + 1024 * 1024).hex()


def _clean_targets(targets: Any) -> list[str]:
    from kratos.utils.hostnames import is_ip_or_hostname

    out: list[str] = []
    for t in targets or ():
        value = str(t).strip().lower()
        if not value:
            continue
        if not is_ip_or_hostname(value):
            raise TokenError(f"{value!r} is not a machine address or host name")
        if value not in out:
            out.append(value)
    return out


def create_token(data_dir: Path, *, name: str, targets: Any = (), mcp: bool = False,
                 created_by: str = "cli", now: float | None = None) -> tuple[str, dict[str, Any]]:
    """Make a token. Returns (the token -- show it once, it isn't kept -- , its row)."""
    from kratos import run_context

    if run_context.current() is not None and getattr(run_context.current(), "source", "") in ("web", "mcp"):
        raise TokenError("a token can only be made by a person, on the command line or in the app")
    name = str(name or "").strip()
    if not _NAME_RE.match(name):
        raise TokenError("a token name is 1-40 letters, digits, spaces, dots, dashes or underscores")
    if _store.name_in_use(data_dir, name):
        raise TokenError(f"a token named {name!r} already exists (revoke it first, or pick another name)")
    token_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    row = {"token_id": token_id, "name": name, "secret_hash": _hash(secret, salt, SCRYPT), "salt": salt.hex(),
           "kdf": dict(SCRYPT), "targets": _clean_targets(targets),
           "doors": ["openai"] + (["mcp"] if mcp else []),
           "created_at": time.time() if now is None else now, "created_by": created_by}
    _store.insert_token(data_dir, row)
    token = f"{PREFIX}{token_id}_{secret}"
    assert _TOKEN_RE.match(token)
    return token, row


# A dummy row so a wrong token id costs the same scrypt work as a wrong secret: how long a
# check takes says nothing about whether the id exists.
_DUMMY_SALT = bytes(16)


def verify(data_dir: Path, presented: str | None) -> Client | None:
    """The client a bearer token belongs to, or None (malformed, unknown, wrong, revoked).
    Same cost whichever way it fails."""
    m = _TOKEN_RE.match(str(presented or "").strip())
    token_id, secret = (m.group(1), m.group(2)) if m else ("0" * 12, "x" * 43)
    row = _store.get_token(data_dir, token_id) if m else None
    salt = bytes.fromhex(row["salt"]) if row else _DUMMY_SALT
    kdf = row["kdf"] if row else SCRYPT
    try:
        computed = _hash(secret, salt, kdf)
    except (TokenError, ValueError, KeyError):
        return None
    expected = row["secret_hash"] if row else "0" * 64
    ok = hmac.compare_digest(computed, expected)
    if not (m and row and ok) or row.get("revoked_at"):
        return None
    try:
        _store.touch_token(data_dir, token_id)
    except Exception:  # noqa: BLE001 -- a last-used stamp never fails a request
        pass
    return Client(token_id=token_id, name=row["name"], targets=tuple(row["targets"]),
                  doors=tuple(d for d in row["doors"] if d in DOORS))


def bearer_from(header: str | None) -> str | None:
    value = str(header or "").strip()
    if value[:7].lower() != "bearer ":
        return None
    return value[7:].strip() or None


def revoke(data_dir: Path, token_ref: str) -> dict[str, Any]:
    """Revoke by token id, name, or the full token. Returns the row."""
    from kratos import run_context

    if run_context.current() is not None and getattr(run_context.current(), "source", "") in ("web", "mcp"):
        raise TokenError("a token can only be revoked by a person, on the command line or in the app")
    ref = str(token_ref or "").strip()
    m = _TOKEN_RE.match(ref)
    rows = _store.list_tokens(data_dir)
    match = [r for r in rows if r["token_id"] == (m.group(1) if m else ref) or (not m and r["name"] == ref)]
    live = [r for r in match if not r["revoked_at"]]
    if not match:
        raise TokenError(f"no token {ref!r}")
    if not live:
        raise TokenError(f"token {ref!r} is already revoked")
    if len(live) > 1:
        raise TokenError(f"{ref!r} matches more than one token; use its id")
    _store.revoke_token(data_dir, live[0]["token_id"])
    return live[0]
