"""
Review v2 F-4 / F-11: a pushed action is parsed with exact JSON types.

- Any malformed action is refused on its own and reported in the ack; the
  rest of the push still applies, and core always gets an answer (before,
  `"slots": null` raised AttributeError, the whole push was dropped with no
  ack, and core re-pushed every 2 s).
- Nothing is coerced: a string `values` is not split into characters,
  "false" is not True.

The fuzz section is the "cheap insurance" the review asked for: every field
of a valid wire action, and of its slots, replaced with every odd JSON value.
"""
from __future__ import annotations

import asyncio
import copy
import errno
import random

import pytest

from kratos.subagent import protocol as proto
from kratos.subagent import whitelist as W
from kratos.subagent import whitelist_templates as TPL

from test_subagent_execution_channel import ECHO_SPEC
from test_subagent_execution_hardening import FakeWriter, _agent, _push

ODD_VALUES = [None, True, False, 0, -1, 1.5, 2**70, "", "x", "sh", "false", [], [1], ["a", 2], [None],
              {}, {"a": 1}, {"kind": "token"}, [[]]]

SLOT_SPEC = W.ActionSpec(
    id="test.slots", layer="maintainer", argv_template=("echo", "{a}", "{b}", "{c}", "{d}"),
    slots={"a": W.Slot(kind="enum", values=("x", "y")), "b": W.Slot(kind="ip", ip_deny_private=True),
           "c": W.Slot(kind="int_range", min_value=1, max_value=9), "d": W.Slot(kind="token")},
    effect="e", reversibility="r", blast_radius="b", source_recommendation=("T",),
)


def _parse_outcome(raw):
    """spec_from_wire may accept or refuse, but only ever with ActionSpecError."""
    try:
        return W.spec_from_wire(raw)
    except W.ActionSpecError:
        return None


# --- exact cases from the review ---------------------------------------
def test_null_slots_is_a_clean_refusal_not_an_attribute_error():
    raw = W.spec_to_wire(ECHO_SPEC) | {"slots": None}
    with pytest.raises(W.ActionSpecError, match="slots must be dict"):
        W.spec_from_wire(raw)


def test_a_string_values_list_is_refused_not_split_into_characters():
    raw = W.spec_to_wire(SLOT_SPEC)
    raw["slots"]["a"]["values"] = "sh"
    with pytest.raises(W.ActionSpecError, match="values must be list"):
        W.spec_from_wire(raw)


@pytest.mark.parametrize("field", ["reversible", "disrupts_running_service", "reachability_adjacent",
                                   "requires_typed_execute"])
def test_flags_must_be_real_booleans(field):
    with pytest.raises(W.ActionSpecError, match="must be bool"):
        W.spec_from_wire(W.spec_to_wire(ECHO_SPEC) | {field: "false"})


def test_a_bool_is_not_accepted_as_a_number():
    raw = W.spec_to_wire(SLOT_SPEC)
    raw["slots"]["c"]["max_value"] = True
    with pytest.raises(W.ActionSpecError, match="must be int"):
        W.spec_from_wire(raw)


def test_round_trip_and_unknown_keys_are_ignored():
    for spec in (ECHO_SPEC, SLOT_SPEC, *W.list_builtin_action_specs()):
        assert W.spec_from_wire(W.spec_to_wire(spec)) == spec
        assert W.spec_from_wire(W.spec_to_wire(spec) | {"added_by_a_newer_core": 1}) == spec


# --- fuzz: every field x every odd value --------------------------------
def _every_mutation():
    for spec in (ECHO_SPEC, SLOT_SPEC):
        base = W.spec_to_wire(spec)
        for key in list(base) + ["slots_extra"]:
            for odd in ODD_VALUES:
                raw = copy.deepcopy(base)
                raw[key] = odd
                yield raw
            raw = copy.deepcopy(base)
            raw.pop(key, None)
            yield raw
        for slot_name in base["slots"]:
            for key in list(base["slots"][slot_name]):
                for odd in ODD_VALUES:
                    raw = copy.deepcopy(base)
                    raw["slots"][slot_name][key] = odd
                    yield raw
            for odd in ODD_VALUES:
                raw = copy.deepcopy(base)
                raw["slots"][slot_name] = odd
                yield raw
    for odd in ODD_VALUES:
        yield odd


def test_fuzz_spec_from_wire_only_ever_raises_action_spec_error():
    n = 0
    for raw in _every_mutation():
        _parse_outcome(raw)
        n += 1
    assert n > 1000


def test_fuzz_random_nested_garbage():
    rng = random.Random(4242)

    def junk(depth=0):
        r = rng.random()
        if depth > 3 or r < 0.5:
            return rng.choice(ODD_VALUES)
        if r < 0.75:
            return [junk(depth + 1) for _ in range(rng.randint(0, 3))]
        return {rng.choice(["kind", "values", "id", "slots", "x"]): junk(depth + 1) for _ in range(rng.randint(0, 3))}

    base = W.spec_to_wire(SLOT_SPEC)
    for _ in range(3000):
        raw = copy.deepcopy(base)
        target = raw if rng.random() < 0.5 else raw["slots"][rng.choice(list(raw["slots"]))]
        target[rng.choice(list(target) + ["new"])] = junk()
        _parse_outcome(raw)


def test_fuzz_every_mutated_action_through_the_agents_push_handler(tmp_path):
    """Each mutated action is pushed next to a valid one: the agent must always
    answer with an ack (never silence, never a crash), apply the valid one, and
    report the bad one by itself."""
    async def go():
        a = _agent(tmp_path)
        good = W.spec_to_wire(ECHO_SPEC)
        version = 0
        for raw in _every_mutation():
            version += 1
            if isinstance(raw, dict) and raw.get("id") == "test.echo":
                raw = raw | {"id": "test.other"}  # not a duplicate of the good one
            w = FakeWriter()
            await a._handle_whitelist_push(_push(version, [raw, good]), w)
            assert [f["type"] for f in w.frames] == [proto.MSG_WHITELIST_PUSH_ACK], raw
            assert "test.echo" in a._whitelist_specs and a._whitelist_version == version
        return version

    assert asyncio.run(go()) > 1000


def test_a_null_slots_action_is_reported_and_the_rest_applies(tmp_path):
    async def go():
        a = _agent(tmp_path)
        w = FakeWriter()
        bad = W.spec_to_wire(ECHO_SPEC) | {"id": "test.bad", "slots": None}
        await a._handle_whitelist_push(_push(3, [bad, W.spec_to_wire(ECHO_SPEC)]), w)
        return a, w

    a, w = asyncio.run(go())
    assert a._whitelist_version == 3 and set(a._whitelist_specs) == {"test.echo"}
    (ack,) = w.frames
    assert ack["type"] == proto.MSG_WHITELIST_PUSH_ACK and ack["version"] == 3
    assert [r["id"] for r in ack["rejected"]] == ["test.bad"]


def test_an_unexpected_error_checking_one_action_refuses_only_that_action(tmp_path, monkeypatch):
    from kratos.subagent import agent as agent_mod

    real = agent_mod.cl.check_spec

    def flaky(spec, ceiling):
        if spec.id == "test.boom":
            raise RuntimeError("surprise")
        return real(spec, ceiling)

    monkeypatch.setattr(agent_mod.cl, "check_spec", flaky)

    async def go():
        a = _agent(tmp_path)
        w = FakeWriter()
        boom = W.spec_to_wire(ECHO_SPEC) | {"id": "test.boom"}
        await a._handle_whitelist_push(_push(1, [boom, W.spec_to_wire(ECHO_SPEC)]), w)
        return a, w

    a, w = asyncio.run(go())
    assert set(a._whitelist_specs) == {"test.echo"}
    assert w.frames[0]["rejected"] == [{"id": "test.boom", "reason": "could not be checked (RuntimeError)"}]


def test_a_version_that_cannot_be_saved_is_not_applied(tmp_path, monkeypatch):
    async def go():
        a = _agent(tmp_path)
        w = FakeWriter()

        def full(*_a, **_k):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(a, "_persist_state", full)
        await a._handle_whitelist_push(_push(4, [W.spec_to_wire(ECHO_SPEC)]), w)
        return a, w

    a, w = asyncio.run(go())
    assert a._whitelist_version is None and a._whitelist_specs == {} and a._version_floor() is None
    (refused,) = w.frames
    assert refused["type"] == proto.MSG_WHITELIST_PUSH_REFUSED and "disk full" in refused["reason"]


# --- F-11: build_effective_spec -----------------------------------------
def _template(template_id):
    t = TPL.get_template(template_id)
    assert t is not None
    return t


def test_selected_values_given_as_one_string_are_refused():
    t = _template("service.enable_now")
    with pytest.raises(TPL.TemplateInstanceError, match="list of strings"):
        TPL.build_effective_spec(t, instance_id="e1", selected_values={"unit": "fail2ban"})


def test_values_for_a_non_enum_slot_are_refused_not_ignored():
    t = _template("fail2ban.ban_ip")
    non_enum = next(n for n, s in t.base.slots.items() if s.kind != "enum")
    for kw in ("selected_values", "extra_values"):
        with pytest.raises(TPL.TemplateInstanceError, match="can't be narrowed or extended"):
            TPL.build_effective_spec(t, instance_id="e1", **{kw: {non_enum: ("1.2.3.4",)}})


def test_a_stored_entry_with_a_string_value_is_shown_as_broken(tmp_path):
    import json
    import sqlite3

    from kratos.storage.whitelist_store import WhitelistStore

    wl = WhitelistStore(tmp_path / "kratos.db")
    entry = wl.create_user_entry("t1", "service.enable_now", selected_values={"unit": ("fail2ban",)})
    conn = sqlite3.connect(tmp_path / "kratos.db")
    conn.execute("UPDATE whitelist_user_entries SET selected_values_json = ? WHERE entry_id = ?",
                 (json.dumps({"unit": "fail2ban"}), entry))
    conn.commit()
    conn.close()
    (row,) = [r for r in wl.list_user_entries("t1") if r.entry_id == entry]
    assert row.effective_spec is None and "list of strings" in row.error
