"""What an A2A task (and an AG-UI run) gives back (docs/phaseE/E.5 §3.6, §3.8).

* the answer: exactly the Markdown the chat door shows for the same run
  (`serve.render.answer_markdown` / `fleet_markdown` -- Kratos's findings block, its NOTEs,
  then the model's analysis, every machine string through the A.4 Markdown exits);
* the findings, as data: built by code from the STORED finding records (state, latest
  verdict, SSVC decision, ATT&CK ids) for the findings this run produced -- never from the
  model's text -- and only for machines the caller may see. Every string is cleaned
  (`untrusted.for_model`): no escape sequence or hidden character reaches the other agent.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from kratos import untrusted

DATA_KIND = "kratos.findings.v1"
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _stored(data_dir: Path, keys: list[str]) -> dict[str, dict[str, Any]]:
    """finding_key -> {target, state} from the lifecycle store, for the keys that exist."""
    from kratos.lifecycle import store as LS

    out: dict[str, dict[str, Any]] = {}
    if not keys:
        return out
    with LS.opened(data_dir) as conn:
        for key in keys:
            rec = LS.get_record(conn, key)
            if rec is not None:
                out[key] = {"target": rec["target"], "state": rec["state"]}
    return out


def findings_data(findings: Iterable[dict[str, Any]], *, data_dir: Path, machines: Iterable[str],
                  by_machine: dict[str, str] | None = None) -> dict[str, Any]:
    """The structured findings of a run. `machines`: what the caller may see; a finding on
    any other machine is left out (and never named). `by_machine`: finding_key -> machine
    (or its target key) for a fleet run (else every finding is on the one machine in `machines`)."""
    from kratos.target_key import target_key
    from kratos.triage import store as TS

    allowed = {target_key(m): m for m in machines if m and not str(m).startswith("@")}
    items = [f for f in findings if isinstance(f, dict)]
    keys = sorted({str(f.get("finding_key") or "") for f in items if f.get("finding_key")})
    stored = _stored(data_dir, keys)
    verdicts = TS.latest_verdicts(data_dir, keys) if keys else {}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in items:
        key = str(f.get("finding_key") or "")
        rec = stored.get(key)
        machine = (by_machine or {}).get(key)
        if rec is not None:
            machine = allowed.get(rec["target"])
            if machine is None:
                continue                       # stored for a machine the caller may not see
        elif machine is None:
            machine = next(iter(allowed.values()), None) if len(allowed) == 1 else None
        if machine is None or target_key(machine) not in allowed:
            continue
        machine = allowed[target_key(machine)]
        if key and key in seen:
            continue
        seen.add(key)
        ssvc = f.get("ssvc") if isinstance(f.get("ssvc"), dict) else None
        vr = verdicts.get(key)
        attack = [a.get("technique_id") for a in (f.get("attack") or []) if isinstance(a, dict)
                  and a.get("technique_id")]
        out.append({
            "rule": str(f.get("id") or f.get("rule_id") or ""),
            "title": str(f.get("title") or ""),
            "severity": str(f.get("severity") or "info").lower(),
            "machine": machine,
            "finding_key": key or None,
            "state": (rec or {}).get("state") or f.get("state"),
            "change": f.get("change"),
            "verdict": vr.verdict.tag() if vr is not None else None,
            "ssvc": ({"outcome": ssvc.get("outcome"), "label": ssvc.get("label")} if ssvc else None),
            "attack": attack,
        })
    out.sort(key=lambda d: (-_SEV_RANK.get(d["severity"], 0), d["machine"], d["rule"]))
    return untrusted.for_model({"kind": DATA_KIND, "count": len(out), "findings": out}, field_cap=2000)


def answer_text(outcome: Any, *, data_dir: Path) -> str:
    """A single-machine run's checked answer, as the chat door renders it."""
    from kratos import settings_store
    from kratos.serve import render as R
    from kratos.serve import settings as SS

    link_hosts = settings_store.get(SS.LINK_HOSTS, data_dir=data_dir) or []
    return R.answer_markdown(outcome.final_answer, outcome.answer_parts, outcome.recommended_commands,
                             link_hosts=link_hosts)


def fleet_text(out: Any, *, data_dir: Path) -> str:
    """A group question's answer, as the chat door renders it."""
    from kratos import settings_store
    from kratos.serve import render as R
    from kratos.serve import settings as SS

    link_hosts = settings_store.get(SS.LINK_HOSTS, data_dir=data_dir) or []
    return (R.fleet_markdown(out.answer, link_hosts=link_hosts) if out.answer is not None
            else R.kratos_note_markdown(out.text))


def text_part(text: str) -> dict[str, Any]:
    return {"text": text, "mediaType": "text/markdown"}


def data_part(data: dict[str, Any]) -> dict[str, Any]:
    return {"data": data, "mediaType": "application/json"}
