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
    targets: tuple[str, ...]          # () = the default machine only (owner) / the user's whole scope (others)
    doors: tuple[str, ...]
    user_id: str = "owner"            # D.7: the Kratos user the token belongs to
    kind: str = "person"              # person | gateway (a shared Open WebUI: the user comes from its signed JWT)
    expires_at: float | None = None
    expired: bool = False             # the secret matched but the token is past expires_at -- refuse with the date

    def may_use(self, door: str) -> bool:
        return door in self.doors

    @property
    def expired_text(self) -> str:
        if self.expires_at is None:
            return ""
        return "this token expired on " + time.strftime("%Y-%m-%d", time.localtime(self.expires_at))


def client_from_row(row: dict[str, Any], now: float | None = None) -> Client:
    now = time.time() if now is None else now
    exp = row.get("expires_at")
    return Client(token_id=row["token_id"], name=row["name"], targets=tuple(row["targets"]),
                  doors=tuple(d for d in row["doors"] if d in DOORS), user_id=row.get("user_id") or "owner",
                  kind=row.get("kind") or "person", expires_at=float(exp) if exp is not None else None,
                  expired=exp is not None and float(exp) <= now)


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


def _expiry(data_dir: Path, expires: Any, user_id: str, now: float) -> float | None:
    """None -> the default (users.token_days); "never" -> no expiry (the owner's own tokens
    only); a whole number of days."""
    from kratos import settings_store
    from kratos.authz import settings as _as

    if isinstance(expires, str) and expires.strip().lower() == "never":
        if user_id != "owner":
            raise TokenError("only the owner's own tokens may never expire")
        return None
    if expires is None or (isinstance(expires, str) and not expires.strip()):
        days = int(settings_store.get(_as.TOKEN_DAYS, data_dir=data_dir))
    else:
        try:
            days = int(expires)
        except (TypeError, ValueError):
            raise TokenError("expiry is a number of days (or 'never' for the owner's own tokens)") from None
        if not 1 <= days <= 3650:
            raise TokenError("expiry is 1-3650 days")
    return now + days * 86400.0


def _people_only(data_dir: Path, what: str) -> Any:
    """Tokens are made, revoked and rotated by the owner at the TUI/CLI only (D.7 §3.2)."""
    from kratos import authz, run_context

    if run_context.current() is not None and getattr(run_context.current(), "source", "") in ("web", "mcp"):
        raise TokenError("a token can only be managed by a person, on the command line or in the app")
    actor = authz.current_actor()
    try:
        authz.require(actor, authz.P.TOKENS_MANAGE, data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise TokenError(str(e)) from None
    return actor


def create_token(data_dir: Path, *, name: str, targets: Any = (), mcp: bool = False,
                 created_by: str = "cli", now: float | None = None, user: str | None = None,
                 expires: Any = None, gateway: bool = False,
                 rotated_from: str | None = None) -> tuple[str, dict[str, Any]]:
    """Make a token. Returns (the token -- show it once, it isn't kept -- , its row).

    `user`: the Kratos user it belongs to (id or name; default the owner). `expires`: days,
    "never" (owner only) or None for the default. `gateway`: a shared Open WebUI's token --
    the person comes from its signed JWT on each request (a JWT secret is made with it)."""
    from kratos.authz import users as U

    name = str(name or "").strip()
    if not _NAME_RE.match(name):
        raise TokenError("a token name is 1-40 letters, digits, spaces, dots, dashes or underscores")
    owner_row = U.find(data_dir, user) if user else U.owner(data_dir)
    if owner_row is None:
        raise TokenError(f"no Kratos user {user!r} (kratos users list)")
    if owner_row.disabled:
        raise TokenError(f"{owner_row.name} is disabled")
    if gateway and not owner_row.is_owner:
        raise TokenError("a gateway token belongs to the owner (it acts for the mapped Open WebUI users)")
    if gateway and not rotated_from and any(t.get("kind") == "gateway" and not t.get("revoked_at")
                                            for t in _store.list_tokens(data_dir)):
        # Open WebUI user mappings are not tied to one gateway: a second shared Open WebUI
        # could sign as a user mapped from the first. One shared Open WebUI per Kratos.
        raise TokenError("a gateway token already exists -- one shared Open WebUI per Kratos; rotate or revoke it "
                         "(kratos tokens rotate / revoke)")
    now = time.time() if now is None else now
    expires_at = _expiry(data_dir, expires, owner_row.user_id, now)
    cleaned = _clean_targets(targets)
    _people_only(data_dir, f"create token {name} for {owner_row.name}" + (" (gateway)" if gateway else ""))
    if _store.name_in_use(data_dir, name):
        raise TokenError(f"a token named {name!r} already exists (revoke it first, or pick another name)")
    token_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    salt = secrets.token_bytes(16)
    row = {"token_id": token_id, "name": name, "secret_hash": _hash(secret, salt, SCRYPT), "salt": salt.hex(),
           "kdf": dict(SCRYPT), "targets": cleaned,
           "doors": ["openai"] + (["mcp"] if mcp else []),
           "created_at": now, "created_by": created_by,
           "user_id": owner_row.user_id, "kind": "gateway" if gateway else "person", "expires_at": expires_at,
           "rotated_from": rotated_from}
    _store.insert_token(data_dir, row)
    token = f"{PREFIX}{token_id}_{secret}"
    assert _TOKEN_RE.match(token)
    return token, row


def rotate(data_dir: Path, token_ref: str, *, expires: Any = None, created_by: str = "cli"
           ) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """A replacement with the same user, machines, doors and kind (a gateway keeps its
    JWT secret); the old one stops working at once. Returns (new token, new row, old row)."""
    old = _find_live(data_dir, token_ref)
    base = re.sub(r"(-r\d+)?$", "", old["name"])[:34]
    n = 2
    while _store.name_in_use(data_dir, f"{base}-r{n}"):
        n += 1
    if expires is None and old.get("expires_at") is None and old.get("user_id") == "owner":
        expires = "never"
    token, row = create_token(data_dir, name=f"{base}-r{n}", targets=old["targets"], mcp="mcp" in old["doors"],
                              created_by=created_by, user=old.get("user_id") or "owner", expires=expires,
                              gateway=old.get("kind") == "gateway", rotated_from=old["token_id"])
    if old.get("kind") == "gateway":
        from kratos.authz import openwebui

        secret = openwebui.read_secret(data_dir, old["token_id"])
        if secret:
            openwebui.write_secret(data_dir, row["token_id"], secret)
    _store.revoke_token(data_dir, old["token_id"], rotated_to=row["token_id"])
    return token, row, old


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
    client = client_from_row(row)
    if not client.expired:
        try:
            _store.touch_token(data_dir, token_id)
        except Exception:  # noqa: BLE001 -- a last-used stamp never fails a request
            pass
    return client


def bearer_from(header: str | None) -> str | None:
    value = str(header or "").strip()
    if value[:7].lower() != "bearer ":
        return None
    return value[7:].strip() or None


def _find_live(data_dir: Path, token_ref: str) -> dict[str, Any]:
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
    return live[0]


def revoke(data_dir: Path, token_ref: str) -> dict[str, Any]:
    """Revoke by token id, name, or the full token. Returns the row."""
    row = _find_live(data_dir, token_ref)
    _people_only(data_dir, f"revoke token {row['name']} ({row['token_id']})")
    _store.revoke_token(data_dir, row["token_id"])
    return row
