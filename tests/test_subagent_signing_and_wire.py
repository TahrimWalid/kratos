"""
Tests for kratos.subagent.signing (HMAC envelope signing, control 2) and
whitelist.spec_to_wire/spec_from_wire (JSON round-trip for the whitelist-push
message).
"""
from __future__ import annotations

import pytest

from kratos.subagent import signing
from kratos.subagent import whitelist as W


def test_derive_signing_key_is_deterministic_and_token_specific():
    k1 = signing.derive_signing_key("token-a")
    k2 = signing.derive_signing_key("token-a")
    k3 = signing.derive_signing_key("token-b")
    assert k1 == k2
    assert k1 != k3
    assert isinstance(k1, bytes) and len(k1) == 32


def test_sign_and_verify_round_trip():
    key = signing.derive_signing_key("tok")
    envelope = {"type": "exec_dispatch", "dispatch_id": "abc", "action_id": "fail2ban.ban_ip"}
    sig = signing.sign_envelope(key, envelope)
    signed = {**envelope, "sig": sig}
    assert signing.verify_envelope(key, signed) is True


def test_verify_fails_on_tampered_content():
    key = signing.derive_signing_key("tok")
    envelope = {"type": "exec_dispatch", "action_id": "fail2ban.ban_ip", "slot_values": {"ip": "1.2.3.4"}}
    signed = {**envelope, "sig": signing.sign_envelope(key, envelope)}
    signed["slot_values"] = {"ip": "9.9.9.9"}  # tampered after signing
    assert signing.verify_envelope(key, signed) is False


def test_verify_fails_with_the_wrong_key():
    envelope = {"type": "exec_dispatch", "action_id": "x"}
    signed = {**envelope, "sig": signing.sign_envelope(signing.derive_signing_key("tok-a"), envelope)}
    assert signing.verify_envelope(signing.derive_signing_key("tok-b"), signed) is False


def test_verify_fails_cleanly_on_missing_or_malformed_sig():
    key = signing.derive_signing_key("tok")
    assert signing.verify_envelope(key, {"type": "x"}) is False
    assert signing.verify_envelope(key, {"type": "x", "sig": 12345}) is False
    assert signing.verify_envelope(key, {"type": "x", "sig": None}) is False


def test_sign_envelope_is_order_independent():
    key = signing.derive_signing_key("tok")
    e1 = {"a": 1, "b": 2}
    e2 = {"b": 2, "a": 1}
    assert signing.sign_envelope(key, e1) == signing.sign_envelope(key, e2)


def test_signing_key_derivation_never_leaks_the_raw_token():
    key = signing.derive_signing_key("super-secret-token-value")
    assert b"super-secret-token-value" not in key


# ---------------------------------------------------------------------------
# ActionSpec <-> wire round trip.
# ---------------------------------------------------------------------------
def test_all_builtin_specs_round_trip_through_the_wire_format():
    for spec in W.list_builtin_action_specs():
        wire = W.spec_to_wire(spec)
        rebuilt = W.spec_from_wire(wire)
        assert rebuilt == spec
        W.validate_spec(rebuilt)  # the receiver's own independent re-validation


def test_wire_round_trip_is_json_serializable():
    import json

    spec = W.list_builtin_action_specs()[0]
    wire = W.spec_to_wire(spec)
    reparsed = json.loads(json.dumps(wire))
    rebuilt = W.spec_from_wire(reparsed)
    assert rebuilt == spec


def test_spec_from_wire_rejects_malformed_payload():
    with pytest.raises(W.ActionSpecError):
        W.spec_from_wire({"id": "x"})  # missing required fields
    with pytest.raises(W.ActionSpecError):
        W.spec_from_wire({"id": "x", "layer": "maintainer", "argv_template": ["a"], "slots": {"bad": {}}})
