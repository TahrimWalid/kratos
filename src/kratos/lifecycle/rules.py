"""How each finding rule behaves over time.

- **condition** -- a state that persists until fixed (an open port, a UID-0
  account, a changed file). Absent in a run that re-checked it: *mitigated*.
- **occurrence** -- something that happened in a time window (a failed-login
  burst, sudo failures). Absent in a run that re-checked it: *inactive* ("no
  recurrence since ...").
- **run_note** -- says how complete THIS run's reading was, not something about
  the machine (COV-001, VULN-003). No record, never hidden, can't be decided: a
  person must not be able to "accept" an honesty note away.

Every rule id the engine can emit must be listed here
(tests/test_lifecycle_rules.py scans findings_engine.py for them), so a new rule
has to declare its lifecycle behaviour before it ships.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from kratos.adapters.findings_engine import rule_inputs

Kind = Literal["condition", "occurrence", "run_note"]
KINDS = ("condition", "occurrence", "run_note")

# Inputs whose loss of completeness (a truncated auth read) means a run can't say a
# finding is gone: only the newest part of the window was read.
AUTH_INPUTS = frozenset({"auth_stats", "auth_patterns"})


@dataclass(frozen=True)
class RuleInfo:
    kind: Kind
    inputs: tuple[str, ...]                 # what the rule reads (findings_engine._FINDING_INPUTS)
    # The inputs whose fresh, complete re-collection is enough to say the finding is
    # gone, when that's fewer than everything the rule reads. CORR-SSH-001 reads
    # nmap + auth patterns + system context, but no failed-login burst in a fresh,
    # complete auth read already means it didn't recur -- and system context only
    # ever describes Kratos's own machine, so requiring it would mean a remote
    # target's burst could never be marked inactive.
    needs: tuple[str, ...] | None = None
    # Evidence of something done to the machine's own record (logs cleared or
    # edited, auditd stopped): a later run not seeing it again proves nothing --
    # the next check compares with the already-edited state. A sticky finding is
    # never moved to mitigated/inactive automatically; it stays open until a
    # person decides on it.
    sticky: bool = False

    @property
    def covering_inputs(self) -> tuple[str, ...]:
        return self.needs if self.needs is not None else self.inputs


def _r(rule_id: str, kind: Kind, needs: tuple[str, ...] | None = None, sticky: bool = False) -> tuple[str, RuleInfo]:
    return rule_id, RuleInfo(kind=kind, inputs=rule_inputs(rule_id), needs=needs, sticky=sticky)


_BURST = ("auth_patterns",)

RULES: dict[str, RuleInfo] = dict([
    # conditions
    _r("NET-001", "condition"),
    _r("NET-002", "condition"),
    _r("CTX-001", "condition"),
    _r("ENV-001", "condition"),
    _r("OBS-001", "condition"),
    _r("INTEG-001", "condition"),
    _r("PRIV-001", "condition"),
    _r("PRIV-002", "condition"),
    _r("PRIV-003", "condition"),
    _r("PRIV-004", "condition"),
    _r("VULN-001", "condition"),
    _r("VULN-002", "condition"),
    # 0.3: log tampering and journal sealing
    _r("LOG-001", "condition", sticky=True),
    _r("LOG-002", "condition", sticky=True),
    _r("LOG-004", "condition", sticky=True),
    _r("LOG-005", "condition", sticky=True),
    _r("SEAL-001", "condition", sticky=True),
    _r("SEAL-002", "condition"),
    _r("LOG-006", "condition"),        # auditd installed but not running: a state, closes when it runs
    # A.1: where someone could keep access. Each is a state that lasts until the item
    # is removed or a person accepts it; a fresh, complete persistence read closes it.
    _r("PERSIST-001", "condition"),
    _r("PERSIST-002", "condition"),
    _r("PERSIST-003", "condition"),
    _r("PERSIST-004", "condition"),
    _r("PERSIST-005", "condition"),
    _r("PERSIST-006", "condition"),
    _r("PERSIST-007", "condition"),
    _r("PERSIST-008", "condition"),
    # A.5: a dropped executable in a world-writable directory is a state that lasts
    # until the file is removed or a person accepts it.
    _r("LIVE-004", "condition"),
    # occurrences
    _r("AUTH-001", "occurrence"),
    _r("AUTH-003", "occurrence"),
    _r("AUTH-004", "occurrence", _BURST),
    _r("AUTH-TREND-001", "occurrence"),
    _r("CORR-001", "occurrence", _BURST),
    _r("CORR-002", "occurrence", _BURST),
    _r("CORR-SSH-001", "occurrence", _BURST),
    _r("LOG-003", "occurrence"),
    # A.5: a running process is an event in time -- a later run that re-reads and no
    # longer sees it marks it inactive ("not seen since ...").
    _r("LIVE-001", "occurrence"),
    _r("LIVE-002", "occurrence"),
    _r("LIVE-003", "occurrence"),
    _r("LIVE-005", "occurrence"),
    _r("LIVE-006", "occurrence"),
    # run notes
    _r("COV-001", "run_note"),
    _r("VULN-003", "run_note"),
    _r("SEAL-003", "run_note"),
    _r("PERSIST-009", "run_note"),     # what the persistence check could not read
    _r("LIVE-007", "run_note"),        # the restart-needed hint + what could not be read
])


def rule_info(rule_id: str) -> RuleInfo | None:
    return RULES.get(str(rule_id or ""))


def is_sticky(rule_id: str) -> bool:
    info = rule_info(rule_id)
    return info is not None and info.sticky


def is_run_note(rule_id: str) -> bool:
    info = rule_info(rule_id)
    return info is not None and info.kind == "run_note"
