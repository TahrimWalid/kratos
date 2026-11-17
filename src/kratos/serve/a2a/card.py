"""Kratos's A2A Agent Card (A2A 1.0 §4.4, §8), signed (§8.4).

Two forms:

* the PUBLIC card, at `/.well-known/agent-card.json` to anyone who can reach the server
  while `a2a.enabled` is on: who Kratos is, the closed list of skills, the bearer scheme,
  and the address of the task endpoint. It names no machine, group or person.
* the EXTENDED card, at `/a2a/v1/extendedAgentCard` to a caller with a valid person token:
  the same, plus the machines and groups THAT caller may use (D.7 scope applied first) in
  the skill-input extension.

Every card is signed with Kratos's Ed25519 signing key (the D.4/D.6 key,
`kratos.signing`): a JWS over the RFC 8785 canonical form of the card without
`signatures` and with empty values removed, protected header `{"alg": "EdDSA", "typ":
"JOSE", "kid": <the key's SHA256 fingerprint>}`. The public keys -- the active one and
every retired one -- are at `/a2a/v1/keys.json` (a JWK set) and in `kratos signing show`,
so a caller can pin which Kratos it talks to; after a rotation, cards signed with the old
key still verify against the retired key.

Field choices keep the served JSON identical to what the reference SDK's protobuf form
gives back (only fields A2A defines, no proto3 defaults), so a signature made here
verifies there.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from kratos.serve.a2a import jcs

PROTOCOL_VERSION = "1.0"
BINDING = "HTTP+JSON"
WELL_KNOWN_PATH = "/.well-known/agent-card.json"
API_PREFIX = "/a2a/v1"
KEYS_PATH = API_PREFIX + "/keys.json"
SCHEME_NAME = "kratosPersonToken"
INPUT_EXTENSION = "urn:kratos:a2a:skill-input:v1"
MAX_QUESTION = 4000
MAX_MACHINE = 255

# The closed skill list (E.5 §3.3). `action`: what the caller's role must allow (D.7);
# `runs`: the task runs something (a slot, the hourly limit, the person's daily budget).
SKILLS: tuple[dict[str, Any], ...] = (
    {"id": "investigate_machine", "name": "Investigate a machine",
     "description": ("Kratos investigates one machine you may reach and returns its checked answer (what it found, "
                     "its notes, then the analysis) plus the findings as data. Read-only: nothing on the machine "
                     "is changed. Investigators and up."),
     "tags": ["security", "investigation", "linux", "read-only"],
     "examples": ["Has anyone been trying to log in to web-01?", "Check db-01 for anything suspicious"],
     "input": {"type": "object", "additionalProperties": False, "required": ["skill", "machine", "question"],
               "properties": {"skill": {"const": "investigate_machine"},
                              "machine": {"type": "string", "maxLength": MAX_MACHINE},
                              "question": {"type": "string", "maxLength": MAX_QUESTION},
                              "window": {"type": "string", "maxLength": 80}}}},
    {"id": "ask_group", "name": "Ask about a group of machines",
     "description": ("One question over a group (\"@name\"): one checked answer per machine you may see; machines "
                     "outside your access are only counted. Investigators and up."),
     "tags": ["security", "fleet", "read-only"],
     "examples": ["Who gained sudo anywhere this week? (@lab)"],
     "input": {"type": "object", "additionalProperties": False, "required": ["skill", "group", "question"],
               "properties": {"skill": {"const": "ask_group"},
                              "group": {"type": "string", "maxLength": 80},
                              "question": {"type": "string", "maxLength": MAX_QUESTION},
                              "window": {"type": "string", "maxLength": 80}}}},
    {"id": "hunt_indicator", "name": "Hunt for an indicator",
     "description": ("Has this address, network, SHA-256, account, domain, program or path been seen on your "
                     "machines? Searches what Kratos already holds -- no model call, nothing sent to any machine -- "
                     "and says what that covered. Investigators and up."),
     "tags": ["security", "hunt", "read-only"],
     "examples": ["203.0.113.7", "an account name seen in an alert"],
     "input": {"type": "object", "additionalProperties": False, "required": ["skill", "indicators"],
               "properties": {"skill": {"const": "hunt_indicator"},
                              "indicators": {"type": "string", "maxLength": 1000},
                              "kind": {"enum": ["ip", "sha256", "account", "domain", "program", "path"]},
                              "machine": {"type": "string", "maxLength": MAX_MACHINE},
                              "since": {"type": "string", "maxLength": 40},
                              "until": {"type": "string", "maxLength": 40}}}},
    {"id": "finding_states", "name": "Finding states",
     "description": ("Read-only: the findings Kratos remembers for one of your machines (or all of them), each with "
                     "its state, latest verdict and SSVC decision. Changing a state is a person's decision in the "
                     "Kratos app. Viewers and up."),
     "tags": ["security", "findings", "read-only"],
     "examples": ["What is open on web-01?"],
     "input": {"type": "object", "additionalProperties": False, "required": ["skill"],
               "properties": {"skill": {"const": "finding_states"},
                              "machine": {"type": "string", "maxLength": MAX_MACHINE},
                              "state": {"enum": ["open_verified", "open", "verified", "fixed", "decided", "all"]}}}},
    {"id": "list_machines", "name": "List my machines",
     "description": "Read-only: the machines and groups you may use. Viewers and up.",
     "tags": ["inventory", "read-only"],
     "examples": ["Which machines can I ask about?"],
     "input": {"type": "object", "additionalProperties": False, "required": ["skill"],
               "properties": {"skill": {"const": "list_machines"}}}},
)
SKILL_IDS = tuple(s["id"] for s in SKILLS)


def _skill(s: dict[str, Any]) -> dict[str, Any]:
    return {"id": s["id"], "name": s["name"], "description": s["description"], "tags": list(s["tags"]),
            "examples": list(s["examples"]), "inputModes": ["application/json", "text/plain"],
            "outputModes": ["text/markdown", "application/json"]}


def base_url(data_dir: Path, request_host: str, *, scheme: str = "http") -> str:
    """Where other agents reach this server: `a2a.public_url`, else the Host the request
    came to (already checked against the server's allowed host names)."""
    from kratos import settings_store
    from kratos.serve.a2a import settings as AS

    configured = str(settings_store.get(AS.PUBLIC_URL, data_dir=data_dir) or "").strip()
    return configured or f"{scheme}://{request_host}"


def unsigned_card(base: str, *, version: str | None = None, machines: list[str] | None = None,
                  groups: list[str] | None = None) -> dict[str, Any]:
    """The card without signatures. `machines`/`groups` given: the caller's extended card."""
    from kratos import __version__

    params: dict[str, Any] = {"skills": {s["id"]: s["input"] for s in SKILLS},
                              "text_only": ("A message with only text is the question for investigate_machine "
                                            "when you may use exactly one machine.")}
    if machines is not None:
        params["machines"] = list(machines)
        params["groups"] = list(groups or [])
    description = ("Kratos, a self-hosted Linux security assistant: it investigates the machines you may reach, "
                   "read-only, and answers with what its own checks found, checked against that evidence. It "
                   "never asks another agent to approve anything, never fetches a URL you send and never calls "
                   "back (no push notifications). Tasks run as the person whose token you use, with their role, "
                   "machines and spending limits.")
    return {
        "name": "Kratos",
        "description": description,
        "supportedInterfaces": [{"url": base.rstrip("/") + API_PREFIX, "protocolBinding": BINDING,
                                 "protocolVersion": PROTOCOL_VERSION}],
        "version": version or __version__,
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "extendedAgentCard": True,
            "extensions": [{"uri": INPUT_EXTENSION,
                            "description": ("The input each skill takes, as a JSON Schema, sent as a data part "
                                            "(the extended card also lists your machines and groups)."),
                            "params": params}],
        },
        "securitySchemes": {SCHEME_NAME: {"httpAuthSecurityScheme": {
            "scheme": "Bearer",
            "description": ("A Kratos person token (krt_...) with the agent doors, made by the Kratos owner: "
                            "kratos tokens create --user <you> --agents")}}},
        "securityRequirements": [{"schemes": {SCHEME_NAME: {"list": []}}}],
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["text/markdown", "application/json"],
        "skills": [_skill(s) for s in SKILLS],
    }


# --------------------------------------------------------------------------- signing
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def canonical_bytes(card: dict[str, Any]) -> bytes:
    """What a signature covers: the card without `signatures`, empty values removed, JCS."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    return jcs.canonicalize(jcs.clean_empty(body) or {}).encode("utf-8")


def _kid(data_dir: Path) -> str:
    from kratos import signing

    key = signing.load_key(data_dir)
    assert key is not None
    return signing.fingerprint_of(key.public_key())


def sign(card: dict[str, Any], data_dir: Path) -> dict[str, Any]:
    """`card` with one signature by the active signing key (made on first use)."""
    from kratos import signing

    header = {"alg": "EdDSA", "kid": _kid(data_dir), "typ": "JOSE"}
    protected = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("ascii"))
    signing_input = (protected + "." + _b64url(canonical_bytes(card))).encode("ascii")
    sig = signing.sign(signing_input, data_dir)
    out = dict(card)
    out["signatures"] = [{"protected": protected, "signature": _b64url(sig)}]
    return out


def card_for(data_dir: Path, base: str, *, machines: list[str] | None = None,
             groups: list[str] | None = None) -> dict[str, Any]:
    return sign(unsigned_card(base, machines=machines, groups=groups), data_dir)


def _jwk(public_openssh: str, *, retired: bool = False) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from kratos import signing

    pub = serialization.load_ssh_public_key(" ".join(public_openssh.split()[:2]).encode("ascii"))
    assert isinstance(pub, Ed25519PublicKey)
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "kid": signing.fingerprint_of(pub), "alg": "EdDSA",
           "use": "sig"}
    if retired:
        jwk["kratos_retired"] = True
    return jwk


def key_set(data_dir: Path) -> dict[str, Any]:
    """The JWK set a caller verifies cards with: the active key, then every retired one."""
    from kratos import signing

    keys = [_jwk(signing.public_key_openssh(data_dir))]
    keys += [_jwk(line, retired=True) for line in signing.retired_public_keys(data_dir)]
    return {"keys": keys}


def verify(card: dict[str, Any], keys: list[dict[str, Any]]) -> str | None:
    """The kid of the first signature on `card` that a key in `keys` (JWKs) verifies, else
    None. Independent of the reference SDK -- used by tests and by `kratos` itself."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    by_kid = {k.get("kid"): k for k in keys if k.get("kty") == "OKP" and k.get("crv") == "Ed25519"}
    try:
        payload = _b64url(canonical_bytes(card))
    except jcs.CanonicalizationError:
        return None
    for s in card.get("signatures") or []:
        try:
            header = json.loads(_b64url_decode(str(s.get("protected") or "")))
            if not isinstance(header, dict) or header.get("alg") != "EdDSA":
                continue
            jwk = by_kid.get(header.get("kid"))
            if jwk is None:
                continue
            pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
            pub.verify(_b64url_decode(str(s.get("signature") or "")),
                       (str(s["protected"]) + "." + payload).encode("ascii"))
            return str(header["kid"])
        except (InvalidSignature, ValueError, KeyError, TypeError):
            continue
    return None
