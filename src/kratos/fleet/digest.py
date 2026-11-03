"""The fleet digest: what the model reads for a question about several machines (D.2 §3.3).

The question, the resolved time window, then ONE block per machine -- Kratos-written:
which machine (by its short id ``m1``, ``m2`` ...), how it was reached, what was and
wasn't read, its findings with verdicts and SSVC decisions (the single-machine digest,
``collect.digest.build_digest``), the counts measured for the question's period, and the
extra reads the model asked for on THAT machine. Each block is framed as data (A.4): a
machine's name, a hostname or an account inside it is text from the machine.

Capped at ``fleet.digest_chars``: machines with an Act decision or a HIGH/CRITICAL
finding first, then the rest; a machine that doesn't fit gets one line ("m7: 0 open
findings, fully read") and the digest says how many were shortened.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from kratos import untrusted
from kratos.fleet.collect import MachineResult

_SERIOUS = ("high", "critical")
_DECIDED = frozenset({"risk_accepted", "false_positive", "out_of_scope"})


def _open(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if str(f.get("state") or "") not in _DECIDED]


def priority(res: MachineResult) -> tuple[int, int, str]:
    """Sort key: Act decisions, then serious findings, then the rest; not-reached last."""
    found = _open(res.findings)
    act = sum(1 for f in found if str((f.get("ssvc") or {}).get("outcome") or "") == "act")
    serious = sum(1 for f in found if str(f.get("severity") or "").lower() in _SERIOUS)
    return (0 if act else 1 if serious else 2 if res.collected else 3, -(act * 100 + serious), res.machine)


def counts_line(res: MachineResult) -> str:
    found = _open(res.findings)
    by: dict[str, int] = {}
    for f in found:
        sev = str(f.get("severity") or "info").lower()
        by[sev] = by.get(sev, 0) + 1
    order = ("critical", "high", "medium", "low", "info")
    sev = ", ".join(f"{by[s]} {s}" for s in order if by.get(s))
    return f"{len(found)} open finding{'s' if len(found) != 1 else ''}" + (f" ({sev})" if sev else "")


def _measurement_lines(res: MachineResult) -> list[str]:
    """The question's periods as counted on this machine (Kratos's own numbers)."""
    out: list[str] = []
    for step in res.steps:
        if step.get("tool") != "measure_auth_activity" or not step.get("collected"):
            continue
        obs = step.get("observation") or {}
        if not isinstance(obs, dict) or obs.get("status") != "ok":
            why = obs.get("observation") if isinstance(obs, dict) else ""
            out.append(f"- period {(step.get('args') or {}).get('window', {}).get('id', '?')}: NOT measured ({why})")
            continue
        w = obs.get("window") or {}
        compact = {
            "window": w.get("id"), "period": w.get("label") or w.get("chip"),
            "coverage": {k: w.get(k) for k in ("coverage", "complete", "covered_from", "truncated") if k in w},
            "counts": obs.get("counts"),
            "failed_login_sources": (obs.get("failed_login_sources") or [])[:3],
            "bursts": (obs.get("bursts") or [])[:3],
        }
        out.append("- measured on this machine: " + json.dumps(compact, default=str))
    return out


def _extra_read_lines(res: MachineResult) -> list[str]:
    out: list[str] = []
    for step in res.steps:
        if step.get("extra_read"):
            obs = step.get("observation")
            text = json.dumps(obs, default=str)
            if len(text) > 2500:
                text = text[:2500] + f"...[truncated, {len(text) - 2500} more chars]"
            out.append(f"- extra read {step.get('tool')} {json.dumps(step.get('args') or {})}: {text}")
    return out


def machine_block(mid: str, res: MachineResult) -> str:
    """One machine's evidence, Kratos-written (machine text cleaned by the caller's frame)."""
    from kratos.collect.digest import build_digest

    name = f" ({res.label})" if res.label else ""
    head = f"MACHINE {mid} -- {res.machine}{name}: reached by {res.transport or 'unknown'}; {res.outcome_words}"
    if not res.collected:
        return head + (f" ({res.reason})" if res.reason else "") + \
            ". NOT CHECKED: Kratos writes this machine's answer itself; say nothing about it."
    lines = [head + (f" ({res.reason})" if res.reason else "") + "."]
    if res.clock_note:
        lines.append(f"- {res.clock_note}")
    digest = build_digest(res.report) if res.report is not None else ""
    if digest:
        lines.append(digest)
    lines.extend(_measurement_lines(res))
    lines.extend(_extra_read_lines(res))
    gaps = res.gaps
    if gaps:
        lines.append("- not read on this machine: " + "; ".join(g.rstrip(" .") for g in gaps[:8]))
    return "\n".join(lines)


def short_line(mid: str, res: MachineResult) -> str:
    if not res.collected:
        return f"MACHINE {mid} -- {res.machine}: {res.status_text}. NOT CHECKED."
    return f"MACHINE {mid} -- {res.machine}: {counts_line(res)}, {res.outcome_words} (shortened: no room for details)."


@dataclass
class FleetDigest:
    text: str
    ids: dict[str, str]                         # m1 -> machine (target_key)
    shortened: list[str] = field(default_factory=list)

    def id_of(self, machine: str) -> str | None:
        return next((k for k, v in self.ids.items() if v == machine), None)


def assign_ids(results: list[MachineResult]) -> dict[str, str]:
    return {f"m{i}": r.machine for i, r in enumerate(results, 1)}


def build(question: str, results: list[MachineResult], *, ids: dict[str, str], time_block: str, cap: int,
          run_tag: str, outside_scope: int = 0) -> FleetDigest:
    """The whole digest, each full machine block framed as data with its own random id.

    The cap holds by construction: room for every machine's one-line form is reserved
    first, and a full block is used only while it still fits beside the one-line forms
    of the machines after it -- so a machine is shortened, never left out. The
    shortened machines share one framed block."""
    by_machine = {r.machine: r for r in results}
    order = sorted(ids, key=lambda mid: priority(by_machine[ids[mid]]))
    shorts = {mid: short_line(mid, by_machine[ids[mid]]) for mid in order}
    frame_overhead = len(untrusted.frame_text("", kind="machine", run_id=run_tag, call_id="0-000000")) + 2
    head = [f"QUESTION (about {len(ids)} machine{'s' if len(ids) != 1 else ''}): {question}"]
    if time_block:
        head.append(time_block)
    if outside_scope:
        head.append(f"{outside_scope} machine(s) in this group are outside the asker's access and are not listed.")
    note_room = 120 + 5 * len(order)               # the "N were shortened: m7, m8 ..." line
    used = sum(len(h) + 1 for h in head) + note_room + frame_overhead
    full: dict[str, str] = {}
    shortened: list[str] = []
    for n, mid in enumerate(order):
        res = by_machine[ids[mid]]
        block = untrusted.frame_text(machine_block(mid, res), kind="machine", run_id=run_tag,
                                     call_id=untrusted.new_call_id(n + 1))
        rest_short = sum(len(shorts[m]) + 1 for m in order[n + 1:])
        if used + len(block) + 2 + rest_short <= cap:
            full[mid] = block
            used += len(block) + 2
        else:
            shortened.append(mid)
            used += len(shorts[mid]) + 1
    if shortened:
        head.append(f"{len(shortened)} machine block(s) were shortened to one line to fit: {', '.join(shortened)}. "
                    "For those, answer only from that line.")
    parts = [full[mid] for mid in order if mid in full]
    if shortened:
        parts.append(untrusted.frame_text("\n".join(shorts[mid] for mid in shortened), kind="machine",
                                          run_id=run_tag, call_id=untrusted.new_call_id(len(order) + 1)))
    return FleetDigest("\n".join(head) + "\n\n" + "\n\n".join(parts), ids, shortened)
