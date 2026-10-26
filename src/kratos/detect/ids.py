"""Which finding ids are detection rules -- one place (Phase C audit).

A detection rule comes from a rule pack: SigmaHQ's (`SIGMA-<8 hex>`, generated from the
Sigma id) or Kratos's own (`KRATOS-<NAME>`, scripts/dev/build_kratos_pack.py). Their
findings behave the same everywhere -- occurrences, labelled from the pack, raised by
the detection pass or a watching agent -- so every place that asks "is this a detection
rule?" asks here, not by a hard-coded prefix.
"""
from __future__ import annotations

import re

SIGMA_ID = re.compile(r"^SIGMA-[0-9A-F]{8}$")
KRATOS_ID = re.compile(r"^KRATOS-[A-Z0-9]+(?:-[A-Z0-9]+){0,6}$")
PREFIXES = ("SIGMA-", "KRATOS-")


def is_detection_rule(rule_id: object) -> bool:
    rid = str(rule_id or "")
    return bool(SIGMA_ID.match(rid) or KRATOS_ID.match(rid))


def is_sigma(rule_id: object) -> bool:
    """A SigmaHQ rule: its author is credited under the Detection Rule License 1.1."""
    return bool(SIGMA_ID.match(str(rule_id or "")))
