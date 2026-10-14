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
_PERSIST = ("TA0003", "Persistence")
_PRIVESC = ("TA0004", "Privilege Escalation")
_STEALTH = ("TA0005", "Stealth")
_EXEC = ("TA0002", "Execution")


def _t(tid: str, name: str, tactic: tuple[str, str] = _DI) -> dict[str, str]:
    return {"technique_id": tid, "technique": name, "tactic_id": tactic[0], "tactic": tactic[1],
            "version": ATTACK_VERSION, "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/")}


CLEAR_LINUX_LOGS = _t("T1685.006", "Clear Linux or Mac System Logs")
LINUX_AUDIT = _t("T1685.004", "Disable or Modify Linux Audit System Log")
DISABLE_TOOLS = _t("T1685", "Disable or Modify Tools")

# A.1 persistence checks. Each label is the technique as v19 names it, with the
# Persistence tactic where v19 lists it (Setuid/Setgid is Privilege Escalation only;
# Dynamic Linker Hijacking moved to Stealth/Execution in v19).
CRON = _t("T1053.003", "Cron", _PERSIST)
AT = _t("T1053.002", "At", _PERSIST)
SYSTEMD_SERVICE = _t("T1543.002", "Systemd Service", _PERSIST)
SYSTEMD_TIMER = _t("T1053.006", "Systemd Timers", _PERSIST)
SYSTEM_PROCESS = _t("T1543", "Create or Modify System Process", _PERSIST)
SSH_KEYS = _t("T1098.004", "SSH Authorized Keys", _PERSIST)
SETUID = _t("T1548.001", "Setuid and Setgid", _PRIVESC)
DYNAMIC_LINKER = _t("T1574.006", "Dynamic Linker Hijacking", _STEALTH)
KERNEL_MODULES = _t("T1547.006", "Kernel Modules and Extensions", _PERSIST)
SHELL_CONFIG = _t("T1546.004", "Unix Shell Configuration Modification", _PERSIST)
PAM = _t("T1556.003", "Pluggable Authentication Modules", _PERSIST)
RC_SCRIPTS = _t("T1037.004", "RC Scripts", _PERSIST)
LOGON_SCRIPTS = _t("T1037", "Boot or Logon Initialization Scripts", _PERSIST)
XDG_AUTOSTART = _t("T1547.013", "XDG Autostart Entries", _PERSIST)
UDEV = _t("T1546.017", "Udev Rules", _PERSIST)
INSTALLER_PACKAGES = _t("T1546.016", "Installer Packages", _PERSIST)
EVENT_TRIGGERED = _t("T1546", "Event Triggered Execution", _PERSIST)

# A.5 live-response checks. v19 tactics verified against the STIX bundle:
# Reflective Code Loading and File Deletion moved under Stealth; Unix Shell is
# Execution; Web Shell is Persistence.
REFLECTIVE_CODE_LOADING = _t("T1620", "Reflective Code Loading", _STEALTH)
FILE_DELETION = _t("T1070.004", "File Deletion", _STEALTH)
UNIX_SHELL = _t("T1059.004", "Unix Shell", _EXEC)
WEB_SHELL = _t("T1505.003", "Web Shell", _PERSIST)

PERSISTENCE_TECHNIQUES: tuple[dict[str, str], ...] = (
    CRON, AT, SYSTEMD_SERVICE, SYSTEMD_TIMER, SYSTEM_PROCESS, SSH_KEYS, SETUID, DYNAMIC_LINKER, KERNEL_MODULES,
    SHELL_CONFIG, PAM, RC_SCRIPTS, LOGON_SCRIPTS, XDG_AUTOSTART, UDEV, INSTALLER_PACKAGES, EVENT_TRIGGERED)

RULE_ATTACK: dict[str, tuple[dict[str, str], ...]] = {
    "LOG-001": (CLEAR_LINUX_LOGS,),
    "LOG-002": (CLEAR_LINUX_LOGS,),
    "LOG-004": (CLEAR_LINUX_LOGS,),   # its description names utmp/wtmp explicitly
    "LOG-005": (LINUX_AUDIT,),
    "SEAL-001": (CLEAR_LINUX_LOGS,),
    "SEAL-002": (DISABLE_TOOLS,),
    # A.1: a finding carries the label(s) of the item it is about (kratos.persist.judge);
    # these are every label each rule can carry, for coverage reporting.
    "PERSIST-001": PERSISTENCE_TECHNIQUES,
    "PERSIST-002": PERSISTENCE_TECHNIQUES,
    "PERSIST-003": (SETUID,),
    "PERSIST-004": (DYNAMIC_LINKER,),
    "PERSIST-005": (KERNEL_MODULES,),
    "PERSIST-006": (SSH_KEYS,),
    "PERSIST-007": PERSISTENCE_TECHNIQUES,
    "PERSIST-008": (PAM,),
    # A.5: a live-response finding carries the technique for the signal it is about
    # (kratos.live.judge). LIVE-004 (a dropped executable) and LIVE-005 (an
    # unexpected listener) are posture, not a named technique, so they carry none.
    "LIVE-001": (FILE_DELETION,),
    "LIVE-002": (REFLECTIVE_CODE_LOADING,),
    "LIVE-003": (DYNAMIC_LINKER,),
    "LIVE-006": (UNIX_SHELL, WEB_SHELL),
}


def labels(rule_id: str) -> list[dict[str, str]]:
    return [dict(t) for t in RULE_ATTACK.get(rule_id, ())]
