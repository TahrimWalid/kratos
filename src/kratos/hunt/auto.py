"""Auto-hunt when the threat-intel cache learns new malicious addresses (C.3 §3.6).

`hunt_new_intel` runs after the OTX cache is updated (adapters.threat_intel calls it
once the new cache is in place; `kratos hunt auto` runs it by hand). Every address in
the cache that no earlier auto-hunt searched for is hunted over every machine's stored
events, detections and saved process reads -- code only, no model call, no network,
bounded by `hunt.auto_max_indicators` per run (the rest wait for the next). One
`hunt_runs` row records the run.

An address that WAS seen becomes `HUNT-001` on that machine (occurrence, high): "an
address a threat-intel feed now lists as malicious was seen on this machine before",
with when, where, the feed's pulse names and the coverage in its evidence. Each
machine has one current hunt snapshot (`hunt/results/hunt_<id>.json`, replaced in
place, earlier hits kept); it goes through the same findings path as the detection
snapshots (findings engine -> lifecycle -> triggers -> notify).

New CISA KEV entries are not a hunt: they re-run the package matching over the
stored package lists (A.2, `kratos vulndb-update`), which already exists.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.hunt import settings as S
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

RULE = "HUNT-001"
CATEGORY = "hunt"
RESULTS_DIR = Path("hunt") / "results"
PATTERN = "hunt_*.json"
ACTOR = "kratos (threat-intel update)"
MAX_HITS_KEPT = 500                # per machine snapshot: addresses kept (newest first-seen)
MAX_AGE_DAYS = 30                  # a hit older than this (by when Kratos found it) is not a current finding
TITLE = "An address a threat-intel feed now lists as malicious was seen on this machine before"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _when(ts: float | None) -> str:
    from kratos.hunt.coverage import fmt

    return fmt(ts)


def _snapshot_path(data_dir: Path, machine: str) -> Path:
    return data_dir / RESULTS_DIR / f"hunt_{hashlib.sha256(machine.encode('utf-8')).hexdigest()[:8]}.json"


def _read_cache(cache_file: Path | None) -> dict[str, list[dict[str, Any]]]:
    from kratos.adapters import threat_intel

    path = cache_file or threat_intel.CACHE_FILE
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    ind = payload.get("indicators") if isinstance(payload, dict) else None
    return ind if isinstance(ind, dict) else {}


def _clean_pulses(entries: Any) -> list[str]:
    from kratos import untrusted

    names = []
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get("pulse_name"):
            name = untrusted.for_display(str(e["pulse_name"]), max_len=120)
            if name not in names:
                names.append(name)
    return names[:5]


def hunt_new_intel(data_dir: Path | str, *, cache_file: Path | None = None, notifier: Any = None,
                   investigate_fn: Any = None, now: float | None = None) -> dict[str, Any]:
    """Hunt the cache's malicious addresses not hunted before. Returns what happened:
    {hunted, remaining, hits: {machine: [address]}, findings, fired, record_id}."""
    from kratos import run_context
    from kratos.hunt import store
    from kratos.hunt.indicators import IndicatorError, classify
    from kratos.hunt.search import run_hunt

    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    cache = _read_cache(cache_file)
    done = store.auto_hunted(data_dir)
    todo: list[tuple[Any, list[str]]] = []
    for raw in sorted(cache):
        try:
            ind = classify(str(raw), "ip")
        except IndicatorError:
            continue
        if ind.value in done:
            continue
        todo.append((ind, _clean_pulses(cache[raw])))
    limit = int(settings_store.get(S.AUTO_MAX_INDICATORS, data_dir=data_dir))
    batch, remaining = todo[:limit], max(0, len(todo) - limit)
    out: dict[str, Any] = {"hunted": len(batch), "remaining": remaining, "hits": {}, "findings": [], "fired": [],
                           "record_id": None}
    if not batch:
        return out
    pulses = {ind.value: names for ind, names in batch}
    with run_context.run_scope("trigger"):
        result = run_hunt(data_dir, [ind for ind, _ in batch], source="auto", actor=ACTOR, with_text=False,
                          now=now)
    out["record_id"] = result.record_id
    covs = {c.machine: c for c in result.coverage}
    per_machine: dict[str, list[dict[str, Any]]] = {}
    for res in result.indicators:
        for m in res.machines_hit():
            events = [s for s in res.summaries if s.machine == m]
            snaps = [h for h in res.snapshot_hits if h.machine == m]
            times = [t for s in events for t in (s.first, s.last) if t] + [h.ts for h in snaps]
            first, last = (min(times), max(times)) if times else (None, None)
            per_machine.setdefault(m, []).append({
                "address": res.indicator.value, "pulses": pulses.get(res.indicator.value, []),
                "first_ts": first, "last_ts": last, "count": sum(s.count for s in events) + len(snaps),
                "sources": sorted({s.source for s in events} | {h.label for h in snaps}),
                "event_ids": [h.event_id for h in res.hits if h.machine == m and h.event_id][:10],
                "coverage": covs[m].lines()[:8] if m in covs else [], "found_at": now})
    for machine, hits in per_machine.items():
        out["hits"][machine] = [h["address"] for h in hits]
        path = write_snapshot(data_dir, machine, hits, now=now)
        published = publish(data_dir, machine, path, notifier=notifier, investigate_fn=investigate_fn)
        out["findings"] += published["affected"]
        out["fired"] += published["fired"]
    return out


def write_snapshot(data_dir: Path, machine: str, hits: list[dict[str, Any]], *, now: float) -> Path:
    """The machine's one hunt snapshot: earlier hits kept, these added (an address found
    again is updated), written atomically."""
    key = target_key(machine)
    path = _snapshot_path(data_dir, key)
    old: list[dict[str, Any]] = []
    try:
        prev = json.loads(path.read_text(encoding="utf-8"))
        old = [h for h in prev.get("hits") or [] if isinstance(h, dict)]
    except (OSError, ValueError):
        pass
    by_addr = {str(h.get("address")): h for h in old}
    for h in hits:
        by_addr[h["address"]] = h
    kept = sorted(by_addr.values(), key=lambda h: h.get("found_at") or 0, reverse=True)[:MAX_HITS_KEPT]
    doc = {"target": key, "checked_at": _iso(now), "checked_at_epoch": now, "complete": True,
           "source": "threat-intel auto-hunt", "hits": kept}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    return path


def publish(data_dir: Path, machine: str, path: Path, *, notifier: Any = None,
            investigate_fn: Any = None) -> dict[str, Any]:
    """The hunt snapshot -> findings (lifecycle) -> triggers -> notify: the functions
    detections use (kratos.detect.live.publish)."""
    from kratos import run_context
    from kratos.adapters.findings_engine import _apply_lifecycle, finding_dict
    from kratos.agent.trigger_eval import evaluate_triggers

    key = target_key(machine)
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    with run_context.run_scope("trigger", target=key):
        findings = [finding_dict(f) for f in build(doc)]
        annotated, summary = _apply_lifecycle(findings, data_dir=data_dir, target=key, inputs={CATEGORY: Path(path)},
                                              auth_stats=None, patterns_stats=None, snapshots={CATEGORY: doc})
        affected = [f for f in annotated if f.get("id") == RULE and f.get("change") in ("new", "recurred", "reopened")]
        fired: list[dict[str, Any]] = []
        if affected:
            kwargs: dict[str, Any] = {}
            if notifier is not None:
                kwargs["notifier"] = notifier
            if investigate_fn is not None:
                kwargs["investigate_fn"] = investigate_fn
            fired = evaluate_triggers(data_dir, affected, key, **kwargs)
    return {"machine": key, "findings": annotated, "affected": affected, "fired": fired, "lifecycle": summary}


# --------------------------------------------------------------------------- the findings engine's side
def load_recent(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
        return None
    return data


def build(doc: dict[str, Any]) -> list[Any]:
    """HUNT-001, one per address seen, for hits Kratos found in the last MAX_AGE_DAYS."""
    import ipaddress

    from kratos.adapters.findings_engine import Finding, normalise_entities

    out: list[Any] = []
    target = doc.get("target") or "the machine"
    horizon = time.time() - MAX_AGE_DAYS * 86400
    for h in doc.get("hits") or []:
        try:
            addr = ipaddress.ip_address(str(h.get("address"))).compressed
        except ValueError:
            continue
        if float(h.get("found_at") or 0) < horizon:
            continue
        pulses = ", ".join(str(p) for p in (h.get("pulses") or [])[:5]) or "an OTX pulse"
        evidence = [
            f"Address {addr} is listed as malicious in the threat-intel cache (OTX: {pulses}).",
            f"Kratos's stored records show it on {target}: {int(h.get('count') or 0)} record(s), first "
            f"{_when(h.get('first_ts'))}, last {_when(h.get('last_ts'))}, in "
            f"{', '.join(str(s) for s in h.get('sources') or []) or 'stored records'}.",
            f"Found by an automatic hunt on {_when(h.get('found_at'))} (no model, nothing sent to the machine).",
        ]
        if h.get("event_ids"):
            evidence.append("Stored events: " + ", ".join(str(e) for e in h["event_ids"][:10]))
        evidence.append(f"Show them: kratos hunt {addr} --machine {target}")
        cov = [str(c) for c in h.get("coverage") or []]
        if cov:
            evidence.append("What the hunt could see on this machine: " + " | ".join(cov[:6]))
        out.append(Finding(
            id="HUNT-001", title=TITLE, severity="high", evidence=evidence,
            recommendation=[
                "Look at what this address did on the machine (the events listed; `kratos hunt` shows them all).",
                "If it signed in or ran anything, treat the machine as possibly compromised: check the sessions, "
                "sudo use and new persistence from that time.",
                "Block the address at the firewall if it should never reach this machine (Kratos does not block "
                "anything itself).",
            ],
            subject=addr, entities=normalise_entities("ip", [addr]), source_ips=[addr]))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return False          # an earlier sighting stays true; a person decides on it


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=str(RESULTS_DIR), pattern=PATTERN,
                                            rule_prefix="HUNT-", load=load_recent, build=build,
                                            closes_findings=closes_findings))
