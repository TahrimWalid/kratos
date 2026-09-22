"""
Property/fuzz tests over kratos.subagent.whitelist's slot validators and §5
hard exclusions (docs/subagent_whitelist_design.md §9 #7 / Appendix A #7):
"property-based/fuzz testing of every validator and exclusion (adversarial/
random inputs, assert nothing slips through) ... so 'can this validator be
bypassed?' is partly machine-answered and the human review focuses on action
*semantics*."

No third-party property-testing library is installed in this environment
(`hypothesis` is absent), so this uses stdlib `random` with FIXED seeds --
deterministic across runs/CI, but exercising a large, varied input space per
property rather than a handful of hand-picked examples. Each test either
checks the validator's decision against an independent ground truth (e.g.
Python's own `ipaddress`, or a plain regex re-implementation) or checks an
invariant that must hold for ANY input (e.g. "a string containing a shell
metacharacter is never accepted by the default token pattern").
"""
from __future__ import annotations

import ipaddress
import random
import re
import string

import pytest

from kratos.subagent import whitelist as W

_SAFE_TOKEN_CHARS = string.ascii_lowercase + string.digits + "_-"
_DANGEROUS_CHARS = list(" ;|&$`(){}<>*?[]!~'\"\\\t\n\r\0./,%^#@:+=") + list(string.ascii_uppercase)

_TRIALS = 1000


def _rand_str(rng: random.Random, alphabet: str, min_len: int = 0, max_len: int = 20) -> str:
    n = rng.randint(min_len, max_len)
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_case(rng: random.Random, s: str) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in s)


# ---------------------------------------------------------------------------
# token slot: default pattern must never accept a dangerous string, and must
# accept exactly what its own regex would (no implementation drift).
# ---------------------------------------------------------------------------
def test_fuzz_default_token_pattern_never_accepts_a_string_with_a_dangerous_char():
    rng = random.Random(12345)
    slot = W.Slot(kind="token")
    for _ in range(_TRIALS):
        base = _rand_str(rng, _SAFE_TOKEN_CHARS, 0, 15)
        bad_char = rng.choice(_DANGEROUS_CHARS)
        pos = rng.randint(0, len(base))
        value = base[:pos] + bad_char + base[pos:]
        with pytest.raises(W.SlotValueError):
            W._validate_slot_value("fuzz.token", "x", slot, value)


def test_fuzz_default_token_pattern_accepts_exactly_what_its_regex_matches():
    rng = random.Random(6789)
    slot = W.Slot(kind="token")
    compiled = re.compile(slot.pattern)
    alphabet = _SAFE_TOKEN_CHARS + string.ascii_uppercase + " ;|&$"  # mixed safe + unsafe
    for _ in range(_TRIALS):
        value = _rand_str(rng, alphabet, 0, 25)
        matches = bool(compiled.fullmatch(value)) and len(value) <= slot.max_length
        if matches:
            W._validate_slot_value("fuzz.token2", "x", slot, value)  # must not raise
        else:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.token2", "x", slot, value)


def test_fuzz_token_max_length_boundary():
    rng = random.Random(2468)
    for _ in range(500):
        max_len = rng.randint(1, 32)
        slot = W.Slot(kind="token", max_length=max_len)
        n = rng.randint(0, max_len + 10)
        value = _rand_str(rng, string.ascii_lowercase + string.digits, n, n) or "a"
        value = value[:n] if n > 0 else "a"
        should_pass = len(value) <= max_len and bool(re.fullmatch(slot.pattern, value))
        if should_pass:
            W._validate_slot_value("fuzz.len", "x", slot, value)
        else:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.len", "x", slot, value)


def test_fuzz_a_too_permissive_custom_pattern_is_always_caught_at_definition_time():
    """Any custom token pattern that matches even ONE of the adversarial
    probes must be rejected when the slot is DEFINED -- fuzz random patterns
    built to be permissive (wildcards, broad classes) and confirm every one
    that matches a probe is caught."""
    rng = random.Random(999)
    permissive_patterns = [r".*", r".+", r"[\s\S]*", r"^.*$", r"[ -~]*", r"\S*"]
    for pattern in permissive_patterns:
        slot = W.Slot(kind="token", pattern=pattern, max_length=256)
        with pytest.raises(W.ActionSpecError):
            W._validate_slot_definition("fuzzslot", slot)


# ---------------------------------------------------------------------------
# enum slot: exact membership, nothing more, nothing less.
# ---------------------------------------------------------------------------
def test_fuzz_enum_membership_matches_exactly():
    rng = random.Random(1111)
    alphabet = string.ascii_lowercase
    for _ in range(_TRIALS):
        values = tuple(sorted({_rand_str(rng, alphabet, 1, 6) or "a" for _ in range(rng.randint(1, 6))}))
        if not values:
            continue
        slot = W.Slot(kind="enum", values=values)
        candidate = rng.choice(values) if rng.random() < 0.5 else (_rand_str(rng, alphabet, 1, 6) or "z")
        if candidate in values:
            W._validate_slot_value("fuzz.enum", "x", slot, candidate)
        else:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.enum", "x", slot, candidate)


def test_fuzz_enum_rejects_non_string_types():
    rng = random.Random(3333)
    slot = W.Slot(kind="enum", values=("a", "b", "c"))
    for candidate in [1, 1.5, True, False, None, [], {}, ("a",)]:
        with pytest.raises(W.SlotValueError):
            W._validate_slot_value("fuzz.enum2", "x", slot, candidate)


# ---------------------------------------------------------------------------
# ip slot: must agree with stdlib ipaddress as ground truth, in both garbage
# rejection and the optional private/loopback/reserved denial.
# ---------------------------------------------------------------------------
def test_fuzz_ip_validator_matches_stdlib_ipaddress_ground_truth():
    rng = random.Random(2024)
    for _ in range(_TRIALS):
        octets = [rng.randint(0, 255) for _ in range(4)]
        value = ".".join(map(str, octets))
        slot = W.Slot(kind="ip", ip_deny_private=True)
        addr = ipaddress.ip_address(value)  # dotted-quad of 0-255 is always parseable
        denied = addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
        if denied:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.ip", "x", slot, value)
        else:
            W._validate_slot_value("fuzz.ip", "x", slot, value)


def test_fuzz_ip_validator_rejects_random_garbage_consistently_with_stdlib():
    rng = random.Random(4242)
    alphabet = string.printable
    for _ in range(_TRIALS):
        junk = _rand_str(rng, alphabet, 0, 24)
        slot = W.Slot(kind="ip")
        try:
            ipaddress.ip_address(junk)
            valid = True
        except ValueError:
            valid = False
        if valid:
            W._validate_slot_value("fuzz.ip2", "x", slot, junk)
        else:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.ip2", "x", slot, junk)


def test_fuzz_ip_validator_handles_random_ipv6_too():
    rng = random.Random(5150)
    for _ in range(500):
        groups = [format(rng.randint(0, 0xFFFF), "x") for _ in range(8)]
        value = ":".join(groups)
        slot = W.Slot(kind="ip", ip_deny_private=True)
        addr = ipaddress.ip_address(value)
        denied = addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
        if denied:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.ip6", "x", slot, value)
        else:
            W._validate_slot_value("fuzz.ip6", "x", slot, value)


# ---------------------------------------------------------------------------
# int_range slot: boundary fuzzing, plus the bool-is-not-an-int guard.
# ---------------------------------------------------------------------------
def test_fuzz_int_range_boundaries():
    rng = random.Random(998877)
    for _ in range(_TRIALS):
        lo = rng.randint(-10_000, 10_000)
        hi = lo + rng.randint(0, 1000)
        slot = W.Slot(kind="int_range", min_value=lo, max_value=hi)
        v = rng.randint(lo - 200, hi + 200)
        if lo <= v <= hi:
            W._validate_slot_value("fuzz.range", "x", slot, v)
        else:
            with pytest.raises(W.SlotValueError):
                W._validate_slot_value("fuzz.range", "x", slot, v)


def test_fuzz_int_range_rejects_non_int_types():
    slot = W.Slot(kind="int_range", min_value=0, max_value=100)
    for candidate in [True, False, "50", 50.0, None, [], {}]:
        with pytest.raises(W.SlotValueError):
            W._validate_slot_value("fuzz.range2", "x", slot, candidate)


# ---------------------------------------------------------------------------
# Hard exclusions: banned binaries caught regardless of case or path prefix;
# sensitive markers caught regardless of surrounding padding or case.
# ---------------------------------------------------------------------------
_ALL_BANNED_BINARIES = (
    W._BANNED_SHELL_INTERPRETERS | W._BANNED_PACKAGE_MANAGERS
    | W._BANNED_ACCOUNT_BINARIES | W._BANNED_REACHABILITY_BINARIES
)


def test_fuzz_banned_binaries_caught_regardless_of_case_or_path_prefix():
    rng = random.Random(13579)
    prefixes = ["", "/usr/bin/", "/bin/", "/usr/local/sbin/", "/opt/tools/"]
    for name in sorted(_ALL_BANNED_BINARIES):
        for _ in range(10):
            cased = _rand_case(rng, name)
            prefix = rng.choice(prefixes)
            token = prefix + cased
            spec = W.ActionSpec(
                id="fuzz.banned", layer="maintainer",
                argv_template=(token, "{x}"), slots={"x": W.Slot(kind="token")},
                effect="x", reversibility="x", blast_radius="x",
            )
            with pytest.raises(W.HardExclusionError):
                W.validate_spec(spec)


def test_fuzz_sensitive_marker_caught_regardless_of_padding_and_case():
    rng = random.Random(2468)
    pad_alphabet = string.ascii_letters + "-_"
    for marker in W._SENSITIVE_PATH_MARKERS:
        for _ in range(15):
            pad_before = _rand_str(rng, pad_alphabet, 0, 10)
            pad_after = _rand_str(rng, pad_alphabet, 0, 10)
            token = pad_before + _rand_case(rng, marker) + pad_after
            spec = W.ActionSpec(
                id="fuzz.sensitive", layer="maintainer",
                argv_template=("cat", token), slots={},
                effect="x", reversibility="x", blast_radius="x",
            )
            with pytest.raises(W.HardExclusionError):
                W.validate_spec(spec)


def test_fuzz_sensitive_marker_caught_when_hidden_in_a_random_enum_choice():
    rng = random.Random(97531)
    pad_alphabet = string.ascii_lowercase
    for marker in W._SENSITIVE_PATH_MARKERS:
        pad = _rand_str(rng, pad_alphabet, 0, 8)
        values = (f"{pad}{marker}{pad}", _rand_str(rng, pad_alphabet, 1, 6) or "safeval")
        spec = W.ActionSpec(
            id="fuzz.enumsensitive", layer="maintainer",
            argv_template=("cat", "{file}"),
            slots={"file": W.Slot(kind="enum", values=values)},
            effect="x", reversibility="x", blast_radius="x",
        )
        with pytest.raises(W.HardExclusionError):
            W.validate_spec(spec)


# ---------------------------------------------------------------------------
# Whole-spec round trip: many independently-generated BENIGN specs always
# validate cleanly; the same specs, each mutated to swap in exactly one
# banned binary, always fail. Guards against both over- and under-rejection
# at the validate_spec level (not just per-slot).
# ---------------------------------------------------------------------------
def _benign_spec(rng: random.Random, i: int) -> W.ActionSpec:
    return W.ActionSpec(
        id=f"fuzz.benign{i}", layer="maintainer",
        argv_template=("logger", "-t", "kratos", "{msg}"),
        slots={"msg": W.Slot(kind="token", max_length=rng.randint(8, 64))},
        effect="x", reversibility="x", blast_radius="x",
        source_recommendation=("TEST-000",),
    )


def test_fuzz_benign_specs_always_pass_and_mutated_ones_always_fail():
    rng = random.Random(31415)
    for i in range(300):
        spec = _benign_spec(rng, i)
        W.validate_spec(spec)  # must not raise

        banned = rng.choice(sorted(_ALL_BANNED_BINARIES))
        mutated = W.ActionSpec(
            id=f"fuzz.mutated{i}", layer="maintainer",
            argv_template=(banned, "-t", "kratos", "{msg}"),
            slots={"msg": W.Slot(kind="token")},
            effect="x", reversibility="x", blast_radius="x",
            source_recommendation=("TEST-000",),
        )
        with pytest.raises(W.HardExclusionError):
            W.validate_spec(mutated)


def test_fuzz_render_argv_output_never_contains_shell_metacharacters_from_valid_inputs():
    """For any accepted token-slot value (by construction, matches the
    default pattern), the rendered argv must never contain a shell
    metacharacter -- since the validator already forbids them in the value,
    this is really a check that render_argv doesn't introduce any itself
    (e.g. via unexpected str() formatting)."""
    rng = random.Random(24680)
    spec = W.ActionSpec(
        id="fuzz.rendersafety", layer="maintainer",
        argv_template=("logger", "-t", "kratos", "{msg}"),
        slots={"msg": W.Slot(kind="token")},
        effect="x", reversibility="x", blast_radius="x",
        source_recommendation=("TEST-000",),
    )
    for _ in range(300):
        n = rng.randint(1, 20)
        value = rng.choice(string.ascii_lowercase) + "".join(rng.choice(_SAFE_TOKEN_CHARS) for _ in range(n - 1))
        argv = W.render_argv(spec, {"msg": value})
        assert all(c not in tok for tok in argv for c in ";|&$`\n\0")
