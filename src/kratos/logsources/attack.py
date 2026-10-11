"""MITRE ATT&CK labels for the tamper findings (0.3), pinned to ATT&CK v19.0.

v19 split the old "Defense Evasion" tactic into "Stealth" and "Defense
Impairment" and moved log clearing and audit tampering under the new tactic
with new IDs: T1070.002 -> T1685.006, T1562.012 -> T1685.004, T1562.001 ->
T1685 (the old IDs are revoked). Every pair below was checked against the
official v19.0 STIX bundle (mitre-attack/attack-stix-data,
enterprise-attack-19.0.json); tests/test_logsources_rules.py re-checks them
against a vendored subset of it.
"""
from __future__ import annotations

ATTACK_VERSION = "19.0"
_DI = ("TA0112", "Defense Impairment")


def _t(tid: str, name: str, tactic: tuple[str, str] = _DI) -> dict[str, str]:
    return {"technique_id": tid, "technique": name, "tactic_id": tactic[0], "tactic": tactic[1],
            "version": ATTACK_VERSION, "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/")}


CLEAR_LINUX_LOGS = _t("T1685.006", "Clear Linux or Mac System Logs")
LINUX_AUDIT = _t("T1685.004", "Disable or Modify Linux Audit System Log")
DISABLE_TOOLS = _t("T1685", "Disable or Modify Tools")

RULE_ATTACK: dict[str, tuple[dict[str, str], ...]] = {
    "LOG-001": (CLEAR_LINUX_LOGS,),
    "LOG-002": (CLEAR_LINUX_LOGS,),
    "LOG-004": (CLEAR_LINUX_LOGS,),   # its description names utmp/wtmp explicitly
    "LOG-005": (LINUX_AUDIT,),
    "SEAL-001": (CLEAR_LINUX_LOGS,),
    "SEAL-002": (DISABLE_TOOLS,),
}


def labels(rule_id: str) -> list[dict[str, str]]:
    return [dict(t) for t in RULE_ATTACK.get(rule_id, ())]
