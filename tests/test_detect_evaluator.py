"""The shared detection evaluator and pack validator (kratos.subagent.detect, C.1).

Validator: anything outside the closed schema refuses the whole pack, with the
reason. Evaluator: every operator and modifier, case rules, CIDR v4/v6, counting
windows (incl. across a window boundary and across two passes), and fixed time
bounds on hostile inputs."""
from __future__ import annotations

import copy
import time

import pytest

from kratos.subagent import detect as D


def _rule(match, *, rid="SIGMA-0000AAAA", datasets=("kratos.auth",), where=None, count=None, samples=None, **kw):
    r = {"id": rid, "title": "A test rule", "level": "high", "author": "Alice Example", "license": "DRL-1.1",
         "scope": {"datasets": list(datasets), "where": where}, "match": match}
    if count is not None:
        r["count"] = count
    if samples is not None:
        r["samples"] = samples
    r.update(kw)
    return r


def _pack(*rules, version=1):
    p = {"format": D.FORMAT, "format_version": D.FORMAT_VERSION, "pack_id": "test-pack", "pack_version": version,
         "source": {"what": "tests"}, "rules": list(rules), "skipped": []}
    p["sha256"] = D.pack_digest(p)
    return p


def _ev(eid="e1", dataset="kratos.auth", **fields):
    ev = {"event.id": eid, "event.dataset": dataset}
    ev.update({k.replace("__", "."): v for k, v in fields.items()})
    return ev


def _leaf(op, field, **kw):
    return dict(op=op, field=field, **kw)


def _matches(node, event, **rule_kw):
    pack = D.load_pack(_pack(_rule(node, **rule_kw)))
    return pack.rules[0].matches(event)


# ---------------------------------------------------------------------------- validator
def test_a_valid_pack_loads_and_its_digest_covers_everything():
    p = _pack(_rule(_leaf("eq", "user.name", value="root")))
    assert D.load_pack(p).rules[0].id == "SIGMA-0000AAAA"
    changed = copy.deepcopy(p)
    changed["rules"][0]["level"] = "low"
    with pytest.raises(D.PackError, match="SHA-256 does not match"):
        D.load_pack(changed)
    no_hash = dict(p)
    del no_hash["sha256"]
    with pytest.raises(D.PackError, match="carries no SHA-256"):
        D.load_pack(no_hash)


def _refused(rule_or_pack, reason):
    pack = rule_or_pack if "rules" in rule_or_pack else _pack(rule_or_pack)
    pack["sha256"] = D.pack_digest(pack)
    with pytest.raises(D.PackError, match=reason):
        D.load_pack(pack)


@pytest.mark.parametrize("node,reason", [
    ({"op": "regex", "field": "message", "value": "a.*b"}, "unknown operator"),
    ({"op": "re", "field": "message", "value": "x"}, "unknown operator"),
    ({"op": "eq", "field": "message", "value": "x", "regex": True}, "unknown key"),
    ({"op": "eq", "field": "nope.field", "value": "x"}, "not a field rules may use"),
    ({"op": "eq", "field": "message", "value": "x" * 2000}, "longer than"),
    ({"op": "wildcard", "field": "message", "pattern": "*a" * 40}, "more than 32 wildcards"),
    ({"op": "in", "field": "message", "values": []}, "at least one value"),
    ({"op": "in", "field": "message", "values": ["a"] * 600}, "more than 512"),
    ({"op": "cidr", "field": "source.ip", "values": ["10.0.0.0/33"]}, "not a network"),
    ({"op": "eq", "field": "message", "value": "x", "index": 1}, "positions can be chosen"),
    ({"op": "eq", "field": "process.args", "value": "x", "index": 99}, "whole number 0-63"),
    ({"op": "all_of", "args": []}, "non-empty"),
    ({"op": "not"}, "must be an object"),
    ({"op": "exists", "field": "message", "value": "yes"}, "true or false"),
    ("eq message x", "must be an object"),
])
def test_unknown_operators_regexes_and_oversize_values_are_refused(node, reason):
    _refused(_rule(node), reason)


def test_nesting_beyond_the_cap_is_refused():
    node = {"op": "eq", "field": "message", "value": "x"}
    for _ in range(D.MAX_DEPTH + 1):
        node = {"op": "not", "arg": node}
    _refused(_rule(node), "nested deeper")


def test_too_many_nodes_in_one_rule_is_refused():
    leaves = [{"op": "eq", "field": "message", "value": str(i)} for i in range(200)]
    node = {"op": "any_of", "args": [{"op": "any_of", "args": leaves[i:i + 100]} for i in range(0, 200, 100)] * 3}
    _refused(_rule(node), "nodes in one rule")


@pytest.mark.parametrize("count,reason", [
    ({"window_seconds": 300, "group_by": "message", "op": "gte", "threshold": 5}, "can't be grouped by"),
    ({"window_seconds": 300, "group_by": "process.command_line", "op": "gte", "threshold": 5}, "can't be grouped by"),
    ({"window_seconds": 0, "group_by": None, "op": "gte", "threshold": 5}, "window_seconds"),
    ({"window_seconds": 10 ** 7, "group_by": None, "op": "gte", "threshold": 5}, "window_seconds"),
    ({"window_seconds": 300, "group_by": None, "op": "lt", "threshold": 5}, "count.op"),
    ({"window_seconds": 300, "group_by": None, "op": "gte", "threshold": 10 ** 6}, "threshold"),
    ({"window_seconds": 300, "group_by": None, "op": "gte", "threshold": 5, "expr": "x"}, "unknown key"),
])
def test_unsafe_counting_rules_are_refused(count, reason):
    _refused(_rule(_leaf("eq", "event.action", value="x"), count=count), reason)


def test_a_bad_rule_refuses_the_whole_pack_not_just_itself():
    good = _rule(_leaf("eq", "user.name", value="root"), rid="SIGMA-00000001")
    bad = _rule({"op": "regex", "field": "message", "value": "x"}, rid="SIGMA-00000002")
    _refused(_pack(good, bad), "unknown operator")


@pytest.mark.parametrize("mutate,reason", [
    (lambda p: p.update(format="other"), "not a Kratos detection pack"),
    (lambda p: p.update(format_version=2), "format version"),
    (lambda p: p.update(pack_version=0), "pack_version"),
    (lambda p: p.update(pack_id="Bad ID"), "pack_id"),
    (lambda p: p.update(code="import os"), "unknown key"),
    (lambda p: p["rules"].append(copy.deepcopy(p["rules"][0])), "appears twice"),
    (lambda p: p["rules"][0].update(id="sigma-lower"), "upper case"),
    (lambda p: p["rules"][0].update(level="urgent"), "level must be"),
    (lambda p: p["rules"][0]["scope"].update(datasets=["kratos.other"]), "unknown"),
    (lambda p: p["rules"][0].update(exec="rm -rf /"), "unknown key"),
    (lambda p: p["rules"][0].pop("author"), "author is missing"),
])
def test_pack_level_problems_are_refused(mutate, reason):
    p = _pack(_rule(_leaf("eq", "user.name", value="root")))
    mutate(p)
    _refused(p, reason)


def test_an_oversize_pack_is_refused_before_parsing():
    with pytest.raises(D.PackError, match="larger than"):
        D.parse_pack_bytes(b" " * (D.MAX_PACK_BYTES + 1))
    with pytest.raises(D.PackError, match="not valid JSON"):
        D.parse_pack_bytes(b"{not json")


def test_too_many_rules_is_refused():
    rules = [_rule(_leaf("eq", "user.name", value="x"), rid=f"SIGMA-{i:08X}") for i in range(D.MAX_RULES + 1)]
    _refused(_pack(*rules), "more than 1000 rules")


# ---------------------------------------------------------------------------- operators
@pytest.mark.parametrize("node,value,want", [
    (_leaf("eq", "user.name", value="Root"), "root", True),                      # case-insensitive by default
    (_leaf("eq", "user.name", value="Root", cased=True), "root", False),
    (_leaf("eq", "user.name", value="Root", cased=True), "Root", True),
    (_leaf("contains", "message", value="Accepted"), "sshd: accepted password", True),
    (_leaf("contains", "message", value="accepted", cased=True), "Accepted", False),
    (_leaf("startswith", "message", value="/TMP/"), "/tmp/x", True),
    (_leaf("endswith", "message", value="/BASH"), "/usr/bin/bash", True),
    (_leaf("endswith", "message", value="/bash"), "/usr/bin/bash ", False),
    (_leaf("in", "message", values=["a", "B"]), "b", True),
    (_leaf("in", "message", values=["a", "B"]), "c", False),
    (_leaf("wildcard", "message", pattern="rm *-rf*/var/log*"), "rm  -rf  /var/log/syslog", True),
    (_leaf("wildcard", "message", pattern="rm *-rf*/var/log*"), "rm /var/log -rf", False),
    (_leaf("wildcard", "message", pattern="a?c"), "abc", True),
    (_leaf("wildcard", "message", pattern="a?c"), "ac", False),
    (_leaf("wildcard", "message", pattern="*a?c*"), "xxabcxx", True),
    (_leaf("wildcard", "message", pattern="*a?c"), "xxabcx", False),
    (_leaf("wildcard", "message", pattern=r"a\*b"), "a*b", True),          # escaped: a literal star
    (_leaf("wildcard", "message", pattern=r"a\*b"), "axxb", False),
    (_leaf("wildcard", "message", pattern=r"a\?b"), "axb", False),
    (_leaf("wildcard", "message", pattern="*"), "", True),
    (_leaf("wildcard", "message", pattern="ab*ba"), "aba", False),         # prefix and suffix may not overlap
    (_leaf("wildcard", "message", pattern="A*Z", cased=True), "a z", False),
])
def test_each_string_operator(node, value, want):
    assert _matches(node, _ev(message=value, user__name=value)) is want


def test_numbers_compare_as_text():
    assert _matches(_leaf("eq", "process.pid", value="42"), _ev(process__pid=42))
    assert _matches(_leaf("in", "destination.port", values=["4444", "1337"]), _ev(destination__port=1337))


@pytest.mark.parametrize("ip,want", [("10.1.2.3", True), ("11.0.0.1", False), ("fd00::1", True),
                                     ("2001:db8::1", False), ("not-an-ip", False)])
def test_cidr_v4_and_v6(ip, want):
    node = _leaf("cidr", "source.ip", values=["10.0.0.0/8", "fd00::/8"])
    assert _matches(node, _ev(source__ip=ip)) is want


def test_exists_and_missing_fields():
    assert _matches(_leaf("exists", "user.name", value=True), _ev(user__name="x"))
    assert not _matches(_leaf("exists", "user.name", value=True), _ev())
    assert not _matches(_leaf("exists", "user.name", value=True), _ev(user__name=""))
    assert _matches(_leaf("exists", "user.name", value=False), _ev())
    assert not _matches(_leaf("eq", "user.name", value="x"), _ev())       # a missing field never matches
    assert _matches({"op": "not", "arg": _leaf("eq", "user.name", value="x")}, _ev())


def test_arrays_match_any_element_or_the_chosen_position():
    ev = _ev(process__args=["/usr/bin/chattr", "-i", "/etc/passwd"])
    assert _matches(_leaf("eq", "process.args", value="-I"), ev)
    assert _matches(_leaf("eq", "process.args", value="-i", index=1), ev)
    assert not _matches(_leaf("eq", "process.args", value="-i", index=0), ev)
    assert not _matches(_leaf("eq", "process.args", value="-i", index=7), ev)
    assert _matches(_leaf("exists", "process.args", value=True), ev)
    assert not _matches(_leaf("exists", "process.args", value=True), _ev(process__args=[]))


def test_boolean_operators_and_scope():
    node = {"op": "all_of", "args": [_leaf("endswith", "process.executable", value="/useradd"),
                                     {"op": "not", "arg": _leaf("contains", "process.command_line", value="-r")},
                                     {"op": "any_of", "args": [_leaf("eq", "user.name", value="root"),
                                                               _leaf("eq", "user.name", value="admin")]}]}
    ev = _ev(dataset="kratos.auditd", process__executable="/usr/sbin/useradd",
             process__command_line="useradd bob", user__name="root")
    assert _matches(node, ev, datasets=("kratos.auditd",))
    assert not _matches(node, dict(ev, **{"process.command_line": "useradd -r svc"}), datasets=("kratos.auditd",))
    assert not _matches(node, ev, datasets=("kratos.auth",))                  # another log source
    where = _leaf("eq", "event.action", value="process_started")
    assert not _matches(node, ev, datasets=("kratos.auditd",), where=where)
    assert _matches(node, dict(ev, **{"event.action": "process_started"}), datasets=("kratos.auditd",), where=where)


# ---------------------------------------------------------------------------- counting
COUNT = {"window_seconds": 300, "group_by": "source.ip", "op": "gte", "threshold": 3}


def _failed(i, ip, ts_base=1000.0, step=10.0):
    return _ev(f"e{i}-{ip}", event__action="ssh_failed_login", source__ip=ip), ts_base + i * step


def _count_pack(**count):
    c = dict(COUNT, **count)
    return D.load_pack(_pack(_rule(_leaf("eq", "event.action", value="ssh_failed_login"), count=c)))


def test_count_fires_once_at_the_threshold_per_group():
    ev = D.Evaluator(_count_pack())
    hits = []
    for i in range(6):
        for ip in ("192.0.2.1", "192.0.2.2"):
            e, ts = _failed(i, ip)
            hits += ev.evaluate(e, ts)
    assert [(h.group, h.count) for h in hits] == [("192.0.2.1", 3), ("192.0.2.2", 3)]
    assert hits[0].event_ids == ["e0-192.0.2.1", "e1-192.0.2.1", "e2-192.0.2.1"]
    assert hits[0].first_ts == 1000.0 and hits[0].ts == 1020.0


def test_gt_needs_more_than_the_threshold():
    ev = D.Evaluator(_count_pack(op="gt"))
    hits = [h for i in range(4) for h in ev.evaluate(*_failed(i, "192.0.2.9"))]
    assert len(hits) == 1 and hits[0].count == 4


def test_events_further_apart_than_the_window_do_not_count_together():
    ev = D.Evaluator(_count_pack())
    hits = [h for i in range(10) for h in ev.evaluate(*_failed(i, "192.0.2.1", step=200.0))]
    assert hits == []


def test_a_burst_across_a_window_boundary_counts_events_inside_the_window():
    # 2 events, a long pause, then 3 more: the window ends the first pair; the later three fire.
    ev = D.Evaluator(_count_pack())
    times = [0, 10, 400, 410, 420]
    hits = [h for i, t in enumerate(times) for h in ev.evaluate(_failed(i, "192.0.2.1")[0], 1000.0 + t)]
    assert len(hits) == 1 and hits[0].count == 3 and hits[0].first_ts == 1400.0


def test_a_burst_fed_over_two_passes_is_reported_once():
    pack = _count_pack()
    first = D.Evaluator(pack)
    events = [_failed(i, "192.0.2.1") for i in range(8)]
    hits1 = [h for e, t in events[:4] for h in first.evaluate(e, t)]
    saved = first.fired_state(now=events[3][1])
    # second pass: the window re-fed from the store, then the new events
    second = D.Evaluator(pack, fired=saved)
    hits2 = [h for e, t in events[1:] for h in second.evaluate(e, t)]
    assert len(hits1) == 1 and hits2 == []
    # once the window has passed, the same group can fire again
    later = [_failed(i, "192.0.2.1", ts_base=5000.0) for i in range(3)]
    hits3 = [h for e, t in later for h in second.evaluate(e, t)]
    assert len(hits3) == 1


def test_the_same_event_fed_twice_counts_once():
    ev = D.Evaluator(_count_pack())
    e, t = _failed(0, "192.0.2.1")
    assert ev.evaluate(e, t) == [] and ev.evaluate(e, t) == [] and ev.evaluate(e, t) == []


def test_count_without_a_group_and_events_missing_the_group_field():
    ev = D.Evaluator(_count_pack(group_by=None))
    hits = [h for i in range(3) for h in ev.evaluate(*_failed(i, f"192.0.2.{i}"))]
    assert len(hits) == 1 and hits[0].group is None
    grouped = D.Evaluator(_count_pack())
    no_ip = [_ev(f"x{i}", event__action="ssh_failed_login") for i in range(5)]
    assert [h for i, e in enumerate(no_ip) for h in grouped.evaluate(e, 1000.0 + i)] == []


def test_disabled_rules_are_not_evaluated():
    pack = D.load_pack(_pack(_rule(_leaf("eq", "user.name", value="root"))))
    assert D.Evaluator(pack).evaluate(_ev(user__name="root"), 1.0)
    assert D.Evaluator(pack, disabled={"SIGMA-0000AAAA"}).evaluate(_ev(user__name="root"), 1.0) == []


def test_a_flood_of_groups_keeps_memory_bounded():
    ev = D.Evaluator(_count_pack(threshold=50))
    st = ev.counts["SIGMA-0000AAAA"]
    for i in range(D.MAX_GROUPS_PER_RULE + 500):
        ev.evaluate(_ev(f"f{i}", event__action="ssh_failed_login", source__ip=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"),
                    1000.0 + i * 0.001)
    assert len(st.groups) <= D.MAX_GROUPS_PER_RULE and st.held <= D.MAX_HELD_PER_RULE


# ---------------------------------------------------------------------------- samples
def test_check_samples_reports_a_failing_sample():
    good = {"match": [_ev(user__name="root")], "no_match": [_ev(user__name="bob")]}
    pack = D.load_pack(_pack(_rule(_leaf("eq", "user.name", value="root"), samples=good)))
    assert D.check_samples(pack) == []
    bad = {"match": [_ev(user__name="bob")], "no_match": []}
    pack = D.load_pack(_pack(_rule(_leaf("eq", "user.name", value="root"), samples=bad)))
    assert D.check_samples(pack) == ["SIGMA-0000AAAA: match sample 0 did not match"]


# ---------------------------------------------------------------------------- adversarial timing
PER_EVENT_BUDGET_SECONDS = 0.25


def _time_once(pack, event):
    ev = D.Evaluator(pack)
    t0 = time.perf_counter()
    ev.evaluate(event, 1.0)
    return time.perf_counter() - t0


@pytest.mark.parametrize("pattern", [
    "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b",           # classic backtracking killer
    "*a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?b*",            # single-character wildcards
    "*" + "?" * 30 + "b",
    "a*" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab*" * 1,
])
def test_hostile_values_against_many_wildcard_patterns_stay_within_a_fixed_budget(pattern):
    value = "a" * (64 * 1024)
    pack = D.load_pack(_pack(_rule(_leaf("wildcard", "message", pattern=pattern))))
    assert not pack.rules[0].matches(_ev(message=value))
    assert _time_once(pack, _ev(message=value)) < PER_EVENT_BUDGET_SECONDS


def test_a_value_beyond_the_evaluation_cap_is_cut_not_slowed():
    pack = D.load_pack(_pack(_rule(_leaf("wildcard", "message", pattern="*a?b*"))))
    huge = "a" * (10 * 1024 * 1024)
    assert _time_once(pack, _ev(message=huge)) < PER_EVENT_BUDGET_SECONDS


def test_a_pathological_but_valid_pack_evaluates_an_event_within_budget():
    # the largest rules the validator allows, every leaf a many-wildcard pattern
    rules = []
    for r in range(20):
        leaves = [_leaf("wildcard", "message", pattern="*a?a*a?a*a?a*a?a*a?a*a?a*a?a*b*") for _ in range(255)]
        rules.append(_rule({"op": "any_of", "args": leaves}, rid=f"SIGMA-{r:08X}"))
    pack = D.load_pack(_pack(*rules))
    value = "a" * 4096                                  # an event field at its stored cap
    elapsed = _time_once(pack, _ev(message=value))
    # 20 rules x 255 hostile leaves x 4 KiB: a fixed, generous ceiling for one event
    assert elapsed < 20.0, elapsed
