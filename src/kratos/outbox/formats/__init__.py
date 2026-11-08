"""What a message says, in each format. Pure functions: the same input gives the same
output (the golden-file tests hold them to it), no I/O, no clock unless passed in.

Two things are rendered:

``Alert``          a text alert a trigger, schedule or notice sends to channels by name
``FindingChange``  one lifecycle change of one finding (new, worse, recurred, reopened,
                   changed, verified, mitigated, inactive, decided), forwarded to the
                   channels that receive findings
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# kratos.lifecycle event -> the change a receiver sees
NEWS = frozenset({"new", "worse", "recurred", "reopened"})
CLOSING = frozenset({"mitigated", "inactive", "decided"})
CHANGES = ("new", "worse", "recurred", "reopened", "changed", "verified", "mitigated", "inactive", "decided")


@dataclass(frozen=True)
class Alert:
    text: str
    bucket: str = "info"                 # ntfy's info | warning | critical
    worst: str | None = None             # the worst finding severity behind it, if any
    machine: str | None = None
    findings: tuple[dict[str, Any], ...] = ()     # {id, severity, title, finding_key}
    kind: str = "alert"                  # alert | notice | test
    source: str | None = None            # schedule | trigger | watch | budget | fleet | ...
    name: str | None = None              # the trigger or schedule name
    at: float = 0.0
    message_id: str = ""

    @property
    def subject(self) -> str:
        first = (self.text or "").strip().splitlines()[0] if (self.text or "").strip() else "Kratos"
        return first[:150]


@dataclass(frozen=True)
class FindingChange:
    event_id: int
    change: str
    at: float
    finding_key: str
    rule_id: str
    machine: str
    state: str
    severity: str
    title: str
    finding: dict[str, Any] = field(default_factory=dict)
    from_state: str | None = None
    to_state: str | None = None
    reason: str | None = None
    actor: str = "kratos"
    run_id: str | None = None
    machine_label: str = ""

    @property
    def message_id(self) -> str:
        return f"finding:{self.finding_key}:{self.event_id}"

    @property
    def is_news(self) -> bool:
        return self.change in NEWS
