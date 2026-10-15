"""MITRE ATT&CK labels for Kratos findings (v19, from one pinned table).

- `table`   -- the table generated from MITRE's official STIX bundle, and `label()`
- `mapping` -- every rule's entry: behaviour (labels) or posture (none, with why)
- `navigator` -- ATT&CK Navigator layers: what Kratos can detect, what it has seen

Labels are Kratos-generated (never written by the model, never parsed from a
monitored machine's text).
"""
from __future__ import annotations

from typing import Any, Iterable

from kratos.attack.mapping import Behaviour, Posture, entry, labels, labels_for_finding
from kratos.attack.table import attack_version, technique

__all__ = ["Behaviour", "Posture", "attack_of", "attack_version", "compact_for_model", "entry", "format_label",
           "format_labels", "labels", "labels_for_finding", "technique"]


def attack_of(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """The labels to show for a finding dict: the ones it carries, else (an
    older report or record written before A.3) what its rule maps to now."""
    own = finding.get("attack")
    if isinstance(own, list) and own:
        return [a for a in own if isinstance(a, dict) and a.get("technique_id")]
    ents = finding.get("entities")
    return labels_for_finding(str(finding.get("id") or finding.get("rule_id") or ""),
                              ents if isinstance(ents, list) else ())


def _tactic_names(lab: dict[str, Any]) -> list[str]:
    tacs = lab.get("tactics")
    if isinstance(tacs, list) and tacs:
        return [str(t.get("name")) for t in tacs if isinstance(t, dict) and t.get("name")]
    return [str(lab["tactic"])] if lab.get("tactic") else []


def format_label(lab: dict[str, Any]) -> str:
    """'T1110.001 Password Guessing (Credential Access)'."""
    names = _tactic_names(lab)
    return f"{lab.get('technique_id')} {lab.get('technique')}" + (f" ({', '.join(names)})" if names else "")


def format_labels(labels_: Iterable[dict[str, Any]]) -> str:
    """One line for several labels: 'T1098 Account Manipulation (Persistence, ...); T1136.001 ...'."""
    return "; ".join(format_label(lab) for lab in labels_)


def compact_for_model(obj: Any) -> Any:
    """A copy of a tool result with every finding's `attack` labels shortened to
    'T1110.001 Password Guessing' strings. The model reads a tool result through a
    1500-character window (agent/loop.py OBSERVATION_CHAR_CAP); a full label (both
    tactics, url, version) is ~300 characters per finding that would push the next
    finding out of view. The transcript, the screen and MCP keep the full labels."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "attack" and isinstance(v, list) and v and all(isinstance(a, dict) for a in v):
                out[k] = [f"{a.get('technique_id')} {a.get('technique')}" for a in v if a.get("technique_id")]
            else:
                out[k] = compact_for_model(v)
        return out
    if isinstance(obj, list):
        return [compact_for_model(v) for v in obj]
    return obj
