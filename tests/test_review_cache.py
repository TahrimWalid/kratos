"""E.7b cache (kratos.review.cache §3.10): per-Kratos reuse; code-made verdicts are
model-independent; verifier-derived verdicts key on the model; a repro-off needs_validation
is not cached; the context hash invalidates. Fails on old code."""
from __future__ import annotations

from kratos.review import cache as CA
from kratos.review import verdict as V

SLICE = "a" * 64
CTX = "c" * 64


def test_code_made_verdict_is_model_independent(tmp_path):
    v = V.Verdict(V.CONFIRMED, V.DIRECT, evidence="req -> os.system at L5")
    CA.store_verdict(tmp_path, v, slice_sha=SLICE, context_sha=CTX, cls="exec",
                     hunter_model="modelA", verifier_model="modelA")
    # found with the same model...
    hit = CA.lookup(tmp_path, SLICE, CTX, "exec", hunter_model="modelA", verifier_model="modelA")
    assert hit and hit["verdict"] == "confirmed" and hit["strength"] == "direct"
    # ...and with a completely different model (code decided it, not the model).
    hit2 = CA.lookup(tmp_path, SLICE, CTX, "exec", hunter_model="modelZ", verifier_model="modelZ")
    assert hit2 and hit2["verdict"] == "confirmed"


def test_verifier_derived_verdict_keys_on_the_model(tmp_path):
    v = V.Verdict(V.REJECTED, question="guarded by os.path.basename at line 9", from_verifier=True)
    CA.store_verdict(tmp_path, v, slice_sha=SLICE, context_sha=CTX, cls="path",
                     hunter_model="H1", verifier_model="V1")
    assert CA.lookup(tmp_path, SLICE, CTX, "path", hunter_model="H1", verifier_model="V1")["verdict"] == "rejected"
    # a different verifier model -> cache miss (its mistakes differ)
    assert CA.lookup(tmp_path, SLICE, CTX, "path", hunter_model="H1", verifier_model="V2") is None


def test_reproduction_off_is_not_cached(tmp_path):
    v = V.decide("exec", rule=V.RuleMatch(matched=False), repro=V.Repro(status=V.R_OFF), disproof=None)
    assert v.repro_off
    key = CA.store_verdict(tmp_path, v, slice_sha=SLICE, context_sha=CTX, cls="exec",
                           hunter_model="H1", verifier_model="V1")
    assert key is None
    assert CA.lookup(tmp_path, SLICE, CTX, "exec", hunter_model="H1", verifier_model="V1") is None


def test_context_change_misses(tmp_path):
    v = V.Verdict(V.CONFIRMED, V.DIRECT, evidence="x")
    CA.store_verdict(tmp_path, v, slice_sha=SLICE, context_sha=CTX, cls="exec", hunter_model="H", verifier_model="H")
    assert CA.lookup(tmp_path, SLICE, "d" * 64, "exec", hunter_model="H", verifier_model="H") is None


def test_logic_version_in_key():
    k1 = CA.code_key(SLICE, CTX, "exec")
    # Different class -> different key; same inputs -> same key (deterministic).
    assert CA.code_key(SLICE, CTX, "exec") == k1
    assert CA.code_key(SLICE, CTX, "sql") != k1
