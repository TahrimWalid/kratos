"""Open WebUI's signed forwarded identity (docs/phaseD/D.7 §3.6).

With `ENABLE_FORWARD_USER_INFO_HEADERS=true` and `FORWARD_USER_INFO_HEADER_JWT_SECRET`
set, Open WebUI sends one header, `X-OpenWebUI-User-Jwt`, instead of its plain
`X-OpenWebUI-User-*` headers: an HS256 JWT with claims sub (its user id), email, name,
role, iss = "open-webui", iat and exp (iat + 300 s by default). Checked against Open
WebUI v0.12.3's source (`backend/open_webui/utils/headers.py::_mint_forward_user_jwt`,
`env.py`). If minting fails Open WebUI falls back to the plain headers -- Kratos never
trusts those, so that fails closed here.

Verified with the standard library (HMAC-SHA256, constant-time compare). Only HS256 is
accepted (never `none`, never an algorithm the token itself picks); the issuer must be
open-webui; the token must be current (a little clock skew allowed), and its whole
validity may not exceed MAX_LIFETIME -- so a captured JWT is useless after its `exp`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HEADER = "x-openwebui-user-jwt"
ISSUER = "open-webui"
CLOCK_SKEW = 60              # seconds of clock difference tolerated
MAX_LIFETIME = 3600          # exp - iat may not exceed this (Open WebUI's default is 300)
MAX_LENGTH = 4096
SECRET_DIRNAME = "gateway-secrets"


class JWTError(ValueError):
    """Why a forwarded identity was refused (plain words, no secret in it)."""


@dataclass(frozen=True)
class Forwarded:
    sub: str
    email: str
    name: str
    role: str
    exp: float


def _b64(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    try:
        return base64.urlsafe_b64decode(part + pad)
    except (ValueError, TypeError) as e:
        raise JWTError("the forwarded identity is not a valid token") from e


def verify(token: str | None, secret: str | bytes, *, now: float | None = None) -> Forwarded:
    if not token:
        raise JWTError("no signed identity was forwarded (Open WebUI needs FORWARD_USER_INFO_HEADER_JWT_SECRET)")
    token = str(token).strip()
    if len(token) > MAX_LENGTH or token.count(".") != 2:
        raise JWTError("the forwarded identity is not a valid token")
    if not secret:
        raise JWTError("no secret is set for this gateway token")
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    head_b64, body_b64, sig_b64 = token.split(".")
    try:
        header = json.loads(_b64(head_b64))
        claims = json.loads(_b64(body_b64))
    except ValueError as e:
        raise JWTError("the forwarded identity is not a valid token") from e
    if not isinstance(header, dict) or header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        raise JWTError("the forwarded identity is not signed with HS256")
    expected = hmac.new(key, f"{head_b64}.{body_b64}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64(sig_b64)):
        raise JWTError("the forwarded identity's signature does not match (wrong secret?)")
    if not isinstance(claims, dict):
        raise JWTError("the forwarded identity has no claims")
    if claims.get("iss") != ISSUER:
        raise JWTError("the forwarded identity was not issued by Open WebUI")
    t = time.time() if now is None else float(now)
    try:
        exp, iat = float(claims["exp"]), float(claims["iat"])
    except (KeyError, TypeError, ValueError):
        raise JWTError("the forwarded identity has no valid time") from None
    if exp <= t - CLOCK_SKEW:
        raise JWTError("the forwarded identity has expired")
    if iat > t + CLOCK_SKEW:
        raise JWTError("the forwarded identity is dated in the future")
    if exp - iat > MAX_LIFETIME:
        raise JWTError("the forwarded identity is valid for too long")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip() or len(sub) > 128:
        raise JWTError("the forwarded identity names no user")
    return Forwarded(sub=sub.strip(), email=str(claims.get("email") or "")[:200],
                     name=str(claims.get("name") or "")[:120], role=str(claims.get("role") or "")[:40], exp=exp)


# --- the gateway token's secret ----------------------------------------------------
def secret_path(data_dir: Path | str, token_id: str) -> Path:
    import re

    if not re.fullmatch(r"[0-9a-f]{12}", str(token_id or "")):
        raise ValueError("bad token id")
    return Path(data_dir) / SECRET_DIRNAME / token_id


def write_secret(data_dir: Path | str, token_id: str, secret: str) -> Path:
    from kratos import paths

    p = secret_path(data_dir, token_id)
    paths.write_private_text(p, secret + "\n")
    return p


def read_secret(data_dir: Path | str, token_id: str) -> str | None:
    p = secret_path(data_dir, token_id)
    try:
        text = p.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return text or None


def mint_for_tests(claims: dict[str, Any], secret: str) -> str:
    """An HS256 JWT exactly as Open WebUI makes one -- tests and the lab only."""
    def enc(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

    head = enc({"alg": "HS256", "typ": "JWT"})
    body = enc(claims)
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
