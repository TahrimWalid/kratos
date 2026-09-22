"""
Command signing for the sub-agent execution channel (control 2;
docs/subagent_architecture.md). Defends against a rogue device on the same
network, a MITM, or a replayed message -- it does NOT defend against a
legitimate, correctly-signed request issued by a core that has itself been
manipulated (e.g. via prompt injection) into deciding to issue something
harmful. That distinction is load-bearing and must not be blurred: the
whitelist (kratos.subagent.whitelist) is the boundary against THAT threat,
not this module. State this explicitly anywhere signing is discussed,
per the architecture doc's corrected threat model.

The signing key is derived from the target's existing pairing token (the
same app-level secret `SubAgentStore`/`SubAgent` already establish and trust
for authentication) via HMAC-based key derivation -- never the raw token
bytes reused directly as a MAC key for a different purpose, and never a
second out-of-band exchange. Both core (which holds the token in
`SubAgentStore`) and the agent (which saved it after pairing) can derive the
identical key independently.

Stdlib-only (`hmac`/`hashlib`/`json`) -- deployed as a sibling of agent.py
onto the target, same constraint as protocol.py.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_KEY_DERIVATION_CONTEXT = b"kratos-subagent-exec-signing-v1"


def derive_signing_key(token: str) -> bytes:
    """HMAC-SHA256(token, fixed context) -- a key derived FROM the pairing
    token, not the token itself, so a signing key compromise and an auth
    token compromise are at least derivationally distinct even though they
    currently share a root secret (the token). Deterministic: the same token
    always derives the same key, so core and the agent never need to
    exchange this separately."""
    return hmac.new(token.encode("utf-8"), _KEY_DERIVATION_CONTEXT, hashlib.sha256).digest()


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_envelope(key: bytes, envelope: dict[str, Any]) -> str:
    """Hex HMAC-SHA256 over the canonical JSON of `envelope` (every key
    except `sig`, sorted, compact separators -- so signer and verifier can
    never disagree about byte-for-byte content due to key order or
    whitespace). `envelope` is never mutated."""
    payload = {k: v for k, v in envelope.items() if k != "sig"}
    return hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()


def verify_envelope(key: bytes, envelope: dict[str, Any]) -> bool:
    """True iff `envelope["sig"]` is a valid signature over the rest of
    `envelope` under `key`. Constant-time comparison (`hmac.compare_digest`)
    -- a timing side-channel on signature verification would undermine the
    whole point of signing. Missing/non-string `sig` is always False, never
    an exception (a caller can uniformly treat "not verified" as a reject)."""
    sig = envelope.get("sig")
    if not isinstance(sig, str):
        return False
    expected = sign_envelope(key, envelope)
    return hmac.compare_digest(expected, sig)
