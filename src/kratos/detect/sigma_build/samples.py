"""Sample events for each compiled rule, proposed mechanically and checked.

`match`: a minimal event that satisfies the rule's condition (and its log source's).
The condition is expanded into its alternatives (bounded), each alternative's
positive tests are turned into field values, and the first event the evaluator
confirms is kept.

`no_match`: the match event with its single most specific value changed -- the
longest value first -- so that it no longer matches. A reviewer can see from the
pair exactly which value the rule hinges on.
"""
from __future__ import annotations

import ipaddress
import itertools
from typing import Any, Iterator

from kratos.subagent import detect as D

MAX_TERMS = 256
OTHER = "kratos-sample-other"


def _terms(node: dict[str, Any], positive: bool, budget: list[int]) -> Iterator[list[tuple[dict[str, Any], bool]]]:
    """The condition as alternatives (DNF), each a list of (leaf, wanted truth)."""
    if budget[0] <= 0:
        return
    op = node["op"]
    if op == "not":
        yield from _terms(node["arg"], not positive, budget)
        return
    if op in ("all_of", "any_of"):
        conjunction = (op == "all_of") == positive
        children = node["args"]
        if conjunction:
            pools = [list(itertools.islice(_terms(c, positive, [MAX_TERMS]), 16)) for c in children]
            for combo in itertools.product(*pools):
                budget[0] -= 1
                if budget[0] < 0:
                    return
                yield [lit for part in combo for lit in part]
        else:
            for c in children:
                yield from _terms(c, positive, budget)
        return
    budget[0] -= 1
    yield [(node, positive)]


def _literal(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(pattern[i + 1])
            i += 2
            continue
        out.append("x" if c == "?" else "" if c == "*" else c)
        i += 1
    return "".join(out)


def _host_in(net_text: str) -> str:
    net = ipaddress.ip_network(net_text, strict=False)
    return str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)


def _compose(tests: list[dict[str, Any]]) -> str | None:
    """One string satisfying every positive test on a single value (or None if two
    exact values disagree)."""
    exact = [t for t in tests if t["op"] in ("eq", "in")]
    if exact:
        t = exact[0]
        return t["value"] if t["op"] == "eq" else t["values"][0]
    starts = [t["value"] for t in tests if t["op"] == "startswith"]
    ends = [t["value"] for t in tests if t["op"] == "endswith"]
    middle = [t["value"] for t in tests if t["op"] == "contains"]
    middle += [_literal(t["pattern"]) for t in tests if t["op"] == "wildcard"]
    middle += [_host_in(t["values"][0]) for t in tests if t["op"] == "cidr"]
    if any(t["op"] == "exists" for t in tests) and not (starts or ends or middle):
        return "x"
    head = max(starts, key=len) if starts else ""
    tail = max(ends, key=len) if ends else ""
    body = " ".join(middle)
    return head + (" " + body + " " if body else "") + tail if (head or tail) else body


def _event_for(term: list[tuple[dict[str, Any], bool]], dataset: str, rule_id: str, n: int) -> dict[str, Any] | None:
    singles: dict[tuple[str, int | None], list[dict[str, Any]]] = {}
    arrays: dict[str, list[str]] = {}
    absent: set[str] = set()
    for leaf, want in term:
        if leaf["op"] == "exists" and want != leaf["value"]:
            absent.add(leaf["field"])
            continue
        if not want:
            continue
        field, index = leaf["field"], leaf.get("index")
        if field in D.ORDERED_FIELDS and index is None or field in ("kratos.audit.types", "kratos.audit.created_paths"):
            value = _compose([leaf])
            if value is not None:
                arrays.setdefault(field, []).append(value)
            continue
        singles.setdefault((field, index), []).append(leaf)
    ev: dict[str, Any] = {"event.id": f"{rule_id.lower()}-sample-{n}", "event.dataset": dataset}
    lists: dict[str, list[str]] = {}
    for (field, index), tests in singles.items():
        value = _compose(tests)
        if value is None:
            return None
        if index is not None:
            lst = lists.setdefault(field, [])
            while len(lst) <= index:
                lst.append("x")
            lst[index] = value
        else:
            ev[field] = value
    for field, values in arrays.items():
        real = [v for v in values if v != "x"]
        lists.setdefault(field, []).extend(real or values[:1])
    for field, values in lists.items():
        ev[field] = values
    for field in absent:
        ev.pop(field, None)
    return ev


def propose_match(rule: dict[str, Any]) -> dict[str, Any] | None:
    prepared = D.Rule(rule)
    cond: dict[str, Any] = rule["match"]
    where = rule["scope"].get("where")
    if where is not None:
        cond = {"op": "all_of", "args": [where, cond]}
    n = 0
    for dataset in rule["scope"]["datasets"]:
        for term in _terms(cond, True, [MAX_TERMS]):
            ev = _event_for(term, dataset, rule["id"], n)
            n += 1
            if ev is not None and prepared.matches(ev):
                return ev
    return None


def _fields_in(node: dict[str, Any] | None) -> set[str]:
    if not node:
        return set()
    if "field" in node:
        return {node["field"]}
    return set().union(*(_fields_in(c) for c in node.get("args") or [node.get("arg")] if c))


def propose_no_match(rule: dict[str, Any], match: dict[str, Any]) -> dict[str, Any] | None:
    prepared = D.Rule(rule)
    spots: list[tuple[int, str, int | None]] = []          # (length, field, list position or None)
    for field, value in match.items():
        if field in ("event.id", "event.dataset"):
            continue
        if isinstance(value, list):
            spots += [(len(str(v)), field, i) for i, v in enumerate(value)]
        else:
            spots.append((len(str(value)), field, None))
    # the rule's own fields first (most specific value first); the log source's last
    scope = _fields_in(rule["scope"].get("where"))
    spots.sort(key=lambda s: (s[1] in scope, -s[0], s[1], -1 if s[2] is None else s[2]))
    candidates: list[dict[str, Any]] = []
    for _length, field, pos in spots:
        ev = dict(match)
        if pos is None:
            ev[field] = OTHER
        else:
            ev[field] = [OTHER if i == pos else v for i, v in enumerate(match[field])]
        candidates.append(ev)
    others = sorted(D.DATASETS - set(rule["scope"]["datasets"]))
    if others:
        candidates.append(dict(match, **{"event.dataset": others[0]}))
    for ev in candidates:
        ev["event.id"] = match["event.id"].replace("-sample-", "-other-")
        if not prepared.matches(ev):
            return ev
    return None


def add_samples(rule: dict[str, Any]) -> str | None:
    """Put proposed samples on `rule`; returns why that failed, or None."""
    match = propose_match(rule)
    if match is None:
        return "no matching sample could be built for its condition"
    no_match = propose_no_match(rule, match)
    if no_match is None:
        return "no non-matching sample differs from the matching one by a single value"
    rule["samples"] = {"match": [match], "no_match": [no_match]}
    return None
