"""Whole Sigma rules -> Kratos pack rules (or a skip with its reason), and the pack.

Every compiled rule keeps its attribution as data (Detection Rule License 1.1):
author, SigmaHQ id, title, source file and commit, licence. Every rule that can't
be compiled faithfully is listed in `skipped` with the reason -- never shipped
half-applied.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaDetection, SigmaRule

from kratos.detect.sigma_build.backend import KratosBackend
from kratos.detect.sigma_build.pipeline import kratos_pipeline
from kratos.events import sigma_fields as SF
from kratos.subagent import detect as D

LICENSE = "DRL-1.1"
LEVELS = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
SHIP_STATUSES = ("stable", "test")
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_HEX = re.compile(r"[0-9a-f]")
_COUNT_OPS = {"gte": "gte", "gt": "gt"}


class Skip(Exception):
    def __init__(self, reason: str, kind: str):
        super().__init__(reason)
        self.reason = reason
        self.kind = kind


@dataclass
class Source:
    path: str                  # where the file comes from, e.g. rules/linux/auditd/lnx_x.yml
    text: str                  # its YAML
    url: str = ""              # a link to it (at the pinned commit)
    commit: str = ""


@dataclass
class Compiled:
    rules: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    attack_dropped: list[dict[str, Any]] = field(default_factory=list)


def kratos_id(sigma_id: str) -> str:
    """SIGMA-<first 8 hex digits of the SigmaHQ id>, upper case."""
    digits = "".join(_HEX.findall(str(sigma_id).lower()))[:8]
    if len(digits) < 8:
        raise Skip(f"its id {sigma_id!r} has too few hex digits for a Kratos rule id", "metadata")
    return "SIGMA-" + digits.upper()


def _text(value: Any, limit: int = D.MAX_TEXT_BYTES) -> str:
    raw = str(value or "").strip().encode("utf-8")
    return raw[:limit].decode("utf-8", "ignore")


def _list(values: Iterable[Any], limit: int = D.MAX_STRING_BYTES) -> list[str]:
    return [_text(v, limit) for v in list(values or [])[:D.MAX_LIST_ITEMS] if str(v or "").strip()]


def _date(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def _status(rule: Any) -> str:
    st = getattr(rule, "status", None)
    return str(st.name if hasattr(st, "name") else st or "").lower()


def attack_ids(tags: Iterable[Any], rule_id: str, dropped: list[dict[str, Any]]) -> list[str]:
    """Technique ids from `attack.tXXXX[.YYY]` tags, through the pinned v19 table; a tag the
    table rejects (unknown, revoked, deprecated) is dropped and recorded with why."""
    from kratos.attack import table

    out: list[str] = []
    for tag in tags or []:
        m = _TECHNIQUE_TAG.match(str(tag))
        if not m:
            continue
        tid = m.group(1).upper()
        t = table.technique(tid)
        if t is None:
            dropped.append({"rule": rule_id, "tag": str(tag), "reason": f"{tid} is not in ATT&CK v{table.attack_version()}"})
        elif t["revoked"] or t["deprecated"]:
            state = "revoked" if t["revoked"] else "deprecated"
            repl = f" (replaced by {t['revoked_by']})" if t.get("revoked_by") else ""
            dropped.append({"rule": rule_id, "tag": str(tag),
                            "reason": f"{tid} is {state} in ATT&CK v{table.attack_version()}{repl}"})
        elif tid not in out:
            out.append(tid)
    return out


def _items(det: Any) -> Iterable[Any]:
    for d in det.detection_items:
        if isinstance(d, SigmaDetection):
            yield from _items(d)
        else:
            yield d


def _check_audit_arguments(rule: SigmaRule) -> None:
    """auditd's aN is a program argument in an EXECVE record but a raw system-call
    argument in a SYSCALL record; Kratos keeps only program arguments. A selection that
    tests aN beside a record type other than EXECVE can't be answered faithfully."""
    for name, det in rule.detection.detections.items():
        items = list(_items(det))
        if not any(it.field and SF.AUDITD_ARG.match(it.field) for it in items):
            continue
        types = {str(v).upper() for it in items if it.field == "type" for v in it.value}
        if types - {"EXECVE"}:
            raise Skip(f"selection {name} tests a0, a1, ... on {', '.join(sorted(types - {'EXECVE'}))} records "
                       "(system-call arguments); Kratos keeps only program arguments (EXECVE)", "field")


def _logsource(rule: Any) -> SF.Logsource:
    ls = rule.logsource
    key = (ls.product, ls.service, ls.category)
    found = SF.LOGSOURCES.get(key)
    if found is None:
        reason = SF.UNSUPPORTED.get(key) or f"Kratos doesn't read the {'/'.join(p for p in key if p)} log source"
        raise Skip(reason, "logsource")
    return found


def _condition(rule: SigmaRule) -> dict[str, Any]:
    backend = KratosBackend(kratos_pipeline())
    try:
        nodes = backend.convert_rule(rule)
    except SigmaError as e:
        reason = str(e).split(" (while ")[0].strip() or type(e).__name__
        raise Skip(reason, "condition") from None
    if not nodes:
        raise Skip("no condition to evaluate", "condition")
    return nodes[0] if len(nodes) == 1 else {"op": "any_of", "args": nodes}


def _meta(rule: Any, src: Source, kind_id: str) -> dict[str, Any]:
    author = _text(rule.author, 1024)
    if not author:
        raise Skip("no author to credit (Detection Rule License 1.1 needs one)", "metadata")
    level = LEVELS.get(str(getattr(rule.level, "name", rule.level) or "").lower())
    if level is None:
        raise Skip(f"no usable level ({rule.level!r})", "metadata")
    return {
        "id": kind_id,
        "title": _text(rule.title, 256),
        "level": level,
        "author": author,
        "sigma_id": str(rule.id),
        "license": LICENSE,
        "status": _status(rule),
        "description": _text(rule.description) or None,
        "date": _date(rule.date),
        "modified": _date(rule.modified),
        "source": {"path": src.path, "commit": src.commit or None, "url": src.url or None},
        "tags": _list(str(t) for t in rule.tags or []),
        "references": _list(getattr(rule, "references", None) or []),
        "falsepositives": _list(getattr(rule, "falsepositives", None) or []),
    }


def _skip_entry(rule: Any, src: Source, skip: Skip) -> dict[str, Any]:
    ls = getattr(rule, "logsource", None)
    return {
        "sigma_id": str(getattr(rule, "id", "") or ""), "title": _text(getattr(rule, "title", ""), 256),
        "author": _text(getattr(rule, "author", ""), 1024), "path": src.path, "status": _status(rule),
        "level": LEVELS.get(str(getattr(getattr(rule, "level", None), "name", "") or "").lower()),
        "logsource": "/".join(p for p in ((ls.product, ls.service, ls.category) if ls else ()) if p),
        "kind": skip.kind, "reason": skip.reason,
    }


def compile_rule(rule: SigmaRule, src: Source, dropped: list[dict[str, Any]],
                 statuses: tuple[str, ...] | None = SHIP_STATUSES) -> dict[str, Any]:
    if statuses is not None and _status(rule) not in statuses:
        raise Skip(f"status {_status(rule) or 'unknown'} (only {' and '.join(statuses)} rules are shipped)", "status")
    ls = _logsource(rule)
    _check_audit_arguments(rule)
    match = _condition(rule)
    rid = kratos_id(str(rule.id))
    out = _meta(rule, src, rid)
    out["logsource"] = {"product": ls.key[0], "service": ls.key[1], "category": ls.key[2]}
    out["scope"] = {"datasets": list(ls.datasets), "where": ls.where}
    out["match"] = match
    out["count"] = None
    out["attack"] = attack_ids(out["tags"], rid, dropped)
    return out


def compile_correlation(corr: SigmaCorrelationRule, src: Source, dropped: list[dict[str, Any]],
                        statuses: tuple[str, ...] | None = SHIP_STATUSES) -> dict[str, Any]:
    ctype = str(getattr(corr.type, "name", corr.type)).lower()
    if ctype != "event_count":
        raise Skip(f"a {ctype} correlation (only event_count is supported)", "correlation")
    if statuses is not None and _status(corr) not in statuses:
        raise Skip(f"status {_status(corr) or 'unknown'} (only {' and '.join(statuses)} rules are shipped)", "status")
    refs = list(corr.rules or [])
    if len(refs) != 1 or getattr(refs[0], "rule", None) is None:
        raise Skip("an event_count over several rules (only one is supported)", "correlation")
    base = refs[0].rule
    group_by = list(corr.group_by or [])
    if len(group_by) > 1:
        raise Skip("grouped by more than one field", "correlation")
    ls = _logsource(base)
    match = _condition(base)
    group_field = None
    if group_by:
        mapped = SF.map_field(ls, group_by[0])
        if mapped is None or mapped[1] is not None:
            raise Skip(f"grouped by {group_by[0]}, which Kratos's events don't have for this log source", "correlation")
        group_field = mapped[0]
        if group_field not in D.GROUPABLE:
            raise Skip(f"grouped by {group_by[0]} ({group_field}), which can't be grouped by", "correlation")
    cond = corr.condition
    op = str(getattr(cond.op, "name", cond.op)).lower()
    if op not in _COUNT_OPS:
        raise Skip(f"condition {op} (only gte and gt: a count reaching a threshold)", "correlation")
    seconds = int(corr.timespan.seconds)
    if not 1 <= seconds <= D.MAX_WINDOW_SECONDS:
        raise Skip(f"a {seconds}-second window (at most {D.MAX_WINDOW_SECONDS})", "correlation")
    rid = kratos_id(str(corr.id))
    out = _meta(corr, src, rid)
    out["logsource"] = {"product": ls.key[0], "service": ls.key[1], "category": ls.key[2]}
    out["scope"] = {"datasets": list(ls.datasets), "where": ls.where}
    out["match"] = match
    out["count"] = {"window_seconds": seconds, "group_by": group_field, "op": _COUNT_OPS[op],
                    "threshold": int(cond.count)}
    out["attack"] = attack_ids(out["tags"], rid, dropped)
    return out


def compile_sources(sources: Iterable[Source], *, statuses: tuple[str, ...] | None = SHIP_STATUSES) -> Compiled:
    """Compile every rule in `sources`. Rules referenced by an event_count correlation
    are compiled as that correlation's condition; one with `generate: false` is not
    also shipped on its own."""
    out = Compiled()
    for src in sources:
        try:
            collection = SigmaCollection.from_yaml(src.text)
            collection.resolve_rule_references()
        except SigmaError as e:
            out.skipped.append({"sigma_id": "", "title": "", "author": "", "path": src.path, "status": "",
                                "level": None, "logsource": "", "kind": "parse",
                                "reason": f"pySigma could not read it: {str(e)[:300]}"})
            continue
        hidden = set()
        for item in collection.rules:
            if isinstance(item, SigmaCorrelationRule) and not getattr(item, "generate", False):
                for ref in item.rules or []:
                    if getattr(ref, "rule", None) is not None:
                        hidden.add(id(ref.rule))
        for item in collection.rules:
            if id(item) in hidden:
                continue
            try:
                if isinstance(item, SigmaCorrelationRule):
                    out.rules.append(compile_correlation(item, src, out.attack_dropped, statuses))
                else:
                    out.rules.append(compile_rule(item, src, out.attack_dropped, statuses))
            except Skip as s:
                out.skipped.append(_skip_entry(item, src, s))
    ids: dict[str, str] = {}
    for r in out.rules:
        if r["id"] in ids:
            raise ValueError(f"two rules map to {r['id']}: {ids[r['id']]} and {r['sigma_id']}")
        ids[r["id"]] = r["sigma_id"]
    return out


def build_pack(rules: list[dict[str, Any]], skipped: list[dict[str, Any]], *, pack_id: str, pack_version: int,
               source: dict[str, Any], notice: str) -> dict[str, Any]:
    """The pack, rules sorted by id, with its SHA-256. Validated before it is returned."""
    pack: dict[str, Any] = {
        "format": D.FORMAT, "format_version": D.FORMAT_VERSION, "pack_id": pack_id, "pack_version": int(pack_version),
        "source": source, "notice": notice,
        "rules": sorted(rules, key=lambda r: r["id"]),
        "skipped": sorted(skipped, key=lambda s: (s.get("path") or "", s.get("sigma_id") or "")),
    }
    pack["sha256"] = D.pack_digest(pack)
    D.validate_pack(pack)
    return pack


# ---------------------------------------------------------------------------
# Which compiled rules the shipped pack carries (README §4.1, spec §3.5)
# ---------------------------------------------------------------------------
SHIP_MIN_LEVEL = "medium"
ROUTINE_TACTICS = frozenset({"discovery", "reconnaissance"})
_TACTIC_TAG = re.compile(r"^attack\.([a-z][a-z_-]+)$")


def _tactics(rule: dict[str, Any]) -> set[str]:
    out = set()
    for tag in rule.get("tags") or []:
        m = _TACTIC_TAG.match(str(tag).lower())
        if m and not m.group(1).startswith(("t1", "g0", "s0")):
            out.add(m.group(1).replace("_", "-"))
    return out


def not_shipped_reason(rule: dict[str, Any]) -> str | None:
    """Why a faithfully compiled rule is left out of the shipped pack, or None to ship it.
    A person can still import any of these themselves (`kratos detect import`)."""
    if "esxcli" in (rule.get("source") or {}).get("path", "").lower():
        return "VMware ESXi tooling (esxcli); Kratos monitors Linux distributions, not ESXi hosts"
    order = D.LEVELS
    if order.index(rule["level"]) < order.index(SHIP_MIN_LEVEL):
        return (f"level {rule['level']}: Sigma rates these as notable only in numbers or together with others, "
                "and Kratos raises a finding for every match")
    tactics = _tactics(rule)
    if rule["level"] == "medium" and tactics and tactics <= ROUTINE_TACTICS:
        return ("a medium-level discovery/reconnaissance rule: routine admin activity on a server "
                "(reading files, listing, searching) -- too noisy as a finding per match")
    return None


def select_for_shipping(compiled: Compiled) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(rules to ship, every other compiled rule as a skipped entry with its reason)."""
    ship: list[dict[str, Any]] = []
    left: list[dict[str, Any]] = []
    for r in compiled.rules:
        reason = not_shipped_reason(r)
        if reason is None:
            ship.append(r)
            continue
        ls = r.get("logsource") or {}
        left.append({"sigma_id": r["sigma_id"], "title": r["title"], "author": r["author"],
                     "path": (r.get("source") or {}).get("path"), "status": r.get("status"), "level": r["level"],
                     "logsource": "/".join(p for p in (ls.get("product"), ls.get("service"), ls.get("category")) if p),
                     "kind": "selection", "reason": reason, "id": r["id"]})
    return ship, left
