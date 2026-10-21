"""Which ATT&CK techniques each finding rule stands for -- one table for every rule.

Every rule the engine can emit has an entry here (tests/test_attack_mapping.py
fails otherwise), and it is one of two kinds:

- `Behaviour` -- the rule describes something an adversary DID (a burst of
  guessed passwords, a privilege grant, a cleared log, a new persistence item).
  It carries labels, every one checked against the pinned v19 table when this
  module is imported (kratos.attack.table.label refuses a wrong id or tactic).
- `Posture` -- the rule describes exposure, weakness, inventory, or how complete
  a run was (an open port, a vulnerable package, the list of admins, a coverage
  note). It carries no label, and says why in one line.

Some behaviour rules label each finding by the item it is about rather than the
rule as a whole (`per_item=True`): a PERSIST-001 finding is labelled by the
place it found (cron, a systemd unit, ...), an INTEG-001 finding by which file
changed. Their `labels` are every label such a finding can carry -- used for the
coverage map, never stamped onto a finding as a whole.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any, Iterable

from kratos.attack.table import label

# ---- the techniques Kratos's rules use --------------------------------------
# Tamper (0.3): v19 moved log clearing and audit tampering out of the old
# Defense Evasion into the new Defense Impairment tactic, with new ids
# (T1070.002 -> T1685.006, T1562.012 -> T1685.004, T1562.001 -> T1685).
CLEAR_LINUX_LOGS = label("T1685.006")
LINUX_AUDIT = label("T1685.004")
DISABLE_TOOLS = label("T1685")

# Accounts and passwords.
PASSWORD_GUESSING = label("T1110.001")                              # Credential Access
ACCOUNT_MANIPULATION = label("T1098", "persistence", "privilege-escalation")
LOCAL_ACCOUNT = label("T1136.001")                                  # Create Account: Local Account
SUDO = label("T1548.003")                                           # Sudo and Sudo Caching
MODIFY_AUTH = label("T1556")                                        # Modify Authentication Process

# Persistence (A.1). The Persistence tactic where v19 lists it; Setuid/Setgid is
# Privilege Escalation only, Dynamic Linker Hijacking is Stealth/Execution.
CRON = label("T1053.003", "persistence")
AT = label("T1053.002", "persistence")
SYSTEMD_SERVICE = label("T1543.002", "persistence")
SYSTEMD_TIMER = label("T1053.006", "persistence")
SYSTEM_PROCESS = label("T1543", "persistence")
SSH_KEYS = label("T1098.004", "persistence")
SETUID = label("T1548.001", "privilege-escalation")
DYNAMIC_LINKER = label("T1574.006", "stealth")
KERNEL_MODULES = label("T1547.006", "persistence")
SHELL_CONFIG = label("T1546.004", "persistence")
PAM = label("T1556.003", "persistence")
RC_SCRIPTS = label("T1037.004", "persistence")
LOGON_SCRIPTS = label("T1037", "persistence")
XDG_AUTOSTART = label("T1547.013", "persistence")
UDEV = label("T1546.017", "persistence")
INSTALLER_PACKAGES = label("T1546.016", "persistence")
EVENT_TRIGGERED = label("T1546", "persistence")

PERSISTENCE_TECHNIQUES: tuple[dict[str, Any], ...] = (
    CRON, AT, SYSTEMD_SERVICE, SYSTEMD_TIMER, SYSTEM_PROCESS, SSH_KEYS, SETUID, DYNAMIC_LINKER, KERNEL_MODULES,
    SHELL_CONFIG, PAM, RC_SCRIPTS, LOGON_SCRIPTS, XDG_AUTOSTART, UDEV, INSTALLER_PACKAGES, EVENT_TRIGGERED)

# Live response (A.5, on its own branch): Reflective Code Loading and File
# Deletion are Stealth in v19, Unix Shell is Execution, Web Shell is Persistence.
REFLECTIVE_CODE_LOADING = label("T1620")
FILE_DELETION = label("T1070.004")
UNIX_SHELL = label("T1059.004")
WEB_SHELL = label("T1505.003")


@dataclass(frozen=True)
class Behaviour:
    labels: tuple[dict[str, Any], ...]
    per_item: bool = False      # each finding carries its own item's labels; these are all it can carry
    why: str = ""


@dataclass(frozen=True)
class Posture:
    why: str


Entry = Behaviour | Posture


# ---- INTEG-001: which file changed decides the technique ---------------------
# Patterns are shell-style over the full path (`*` crosses `/`). First match
# wins; a path that matches none is posture (no label).
INTEG_PATHS: tuple[tuple[str, tuple[dict[str, Any], ...]], ...] = (
    ("/etc/passwd", (ACCOUNT_MANIPULATION,)),
    ("/etc/shadow", (ACCOUNT_MANIPULATION,)),
    ("/etc/group", (ACCOUNT_MANIPULATION,)),
    ("/etc/gshadow", (ACCOUNT_MANIPULATION,)),
    ("/etc/sudoers", (SUDO,)),
    ("/etc/sudoers.d/*", (SUDO,)),
    ("/etc/crontab", (CRON,)),
    ("/etc/anacrontab", (CRON,)),
    ("/etc/cron.d/*", (CRON,)),
    ("/etc/cron.hourly/*", (CRON,)),
    ("/etc/cron.daily/*", (CRON,)),
    ("/etc/cron.weekly/*", (CRON,)),
    ("/etc/cron.monthly/*", (CRON,)),
    ("/var/spool/cron/*", (CRON,)),
    ("/etc/ssh/sshd_config", (MODIFY_AUTH,)),
    ("/etc/ssh/sshd_config.d/*", (MODIFY_AUTH,)),
    ("/etc/pam.d/*", (PAM,)),
    ("*/.ssh/authorized_keys", (SSH_KEYS,)),
    ("*/.ssh/authorized_keys2", (SSH_KEYS,)),
    ("/etc/ld.so.preload", (DYNAMIC_LINKER,)),
    ("/etc/systemd/system/*", (SYSTEMD_SERVICE,)),
    ("/lib/systemd/system/*", (SYSTEMD_SERVICE,)),
    ("/usr/lib/systemd/system/*", (SYSTEMD_SERVICE,)),
    ("/etc/rc.local", (RC_SCRIPTS,)),
    ("/etc/init.d/*", (RC_SCRIPTS,)),
    ("/etc/profile", (SHELL_CONFIG,)),
    ("/etc/profile.d/*", (SHELL_CONFIG,)),
    ("/etc/bash.bashrc", (SHELL_CONFIG,)),
    ("/etc/bashrc", (SHELL_CONFIG,)),
    ("*/.bashrc", (SHELL_CONFIG,)),
    ("*/.bash_profile", (SHELL_CONFIG,)),
    ("*/.profile", (SHELL_CONFIG,)),
    ("/etc/modules", (KERNEL_MODULES,)),
    ("/etc/modules-load.d/*", (KERNEL_MODULES,)),
    ("/etc/modprobe.d/*", (KERNEL_MODULES,)),
    ("/etc/udev/rules.d/*", (UDEV,)),
)


def _unique(labels: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    out: dict[str, dict[str, Any]] = {}
    for lab in labels:
        out.setdefault(lab["technique_id"], lab)
    return tuple(out.values())


def integ_path_labels(path: str) -> tuple[dict[str, Any], ...]:
    p = str(path or "").strip()
    for pattern, labels in INTEG_PATHS:
        if fnmatchcase(p, pattern):
            return labels
    return ()


_BURST_WHY = ("repeated failed logins in a short window are password guessing, against SSH or "
              "against a local account's sudo password")

RULE_ATTACK: dict[str, Entry] = {
    # -- authentication ---------------------------------------------------------
    "AUTH-004": Behaviour((PASSWORD_GUESSING,), why=_BURST_WHY),
    "CORR-001": Behaviour((PASSWORD_GUESSING,), why=_BURST_WHY),
    "CORR-SSH-001": Behaviour((PASSWORD_GUESSING,), why=_BURST_WHY),
    "CORR-002": Behaviour((PASSWORD_GUESSING,), why=_BURST_WHY + " (here: one sudo user's password)"),
    "AUTH-001": Posture("any sudo password failure, usually a typo; repeated guessing is AUTH-004/CORR-002"),
    "AUTH-003": Posture("sudo sessions are normal admin activity, not by themselves an attack"),
    "AUTH-TREND-001": Posture("a count trending up across runs; the bursts behind it carry the label"),
    "COV-001": Posture("run note: how much of the window was read"),
    "OBS-001": Posture("logging services look off, usually a stripped or container system -- reduced "
                       "visibility, not an observed action (auditd stopped after it ran is LOG-005)"),
    # -- privileged accounts ----------------------------------------------------
    "PRIV-001": Behaviour((ACCOUNT_MANIPULATION,), why="an account was given admin or root rights"),
    "PRIV-003": Behaviour((ACCOUNT_MANIPULATION,), why="an account gained admin or root rights since the last check"),
    "PRIV-002": Behaviour((LOCAL_ACCOUNT, ACCOUNT_MANIPULATION),
                          why="a second UID-0 account is either created for the purpose or an existing one changed"),
    "PRIV-004": Posture("inventory of who holds admin rights"),
    # -- exposure, environment, vulnerabilities ----------------------------------
    "NET-001": Posture("no open ports: exposure, not behaviour"),
    "NET-002": Posture("open ports are attack surface, not an attack"),
    "CTX-001": Posture("inventory of sudo-capable users"),
    "ENV-001": Posture("the environment is WSL"),
    "VULN-001": Posture("a vulnerable service version is a weakness, not an action"),
    "VULN-002": Posture("an active check's issue is a weakness, not an action"),
    "VULN-003": Posture("run note: what the vulnerability check could not cover"),
    # -- tracked files ----------------------------------------------------------
    "INTEG-001": Behaviour(_unique(lab for _p, labs in INTEG_PATHS for lab in labs), per_item=True,
                           why="labelled by which file changed (INTEG_PATHS); any other file is posture"),
    # -- log tampering and sealing (0.3) ------------------------------------------
    "LOG-001": Behaviour((CLEAR_LINUX_LOGS,), why="a log file cut short or edited outside rotation"),
    "LOG-002": Behaviour((CLEAR_LINUX_LOGS,), why="a journal file removed from the middle of the history"),
    "LOG-004": Behaviour((CLEAR_LINUX_LOGS,), why="login records (wtmp/btmp) edited"),
    "LOG-005": Behaviour((LINUX_AUDIT,), why="auditd stopped, disabled or emptied of rules"),
    "SEAL-001": Behaviour((CLEAR_LINUX_LOGS,), why="a sealed journal altered"),
    "SEAL-002": Behaviour((DISABLE_TOOLS,), why="journal sealing stopped"),
    "LOG-003": Posture("an unclean shutdown is usually a crash or power cut; alone it is not an action"),
    "LOG-006": Posture("auditd installed but not running is a state; stopping it after it ran is LOG-005"),
    "SEAL-003": Posture("run note: the seal could not be verified this time"),
    # -- persistence (A.1): a finding carries the label of the place it found -----
    "PERSIST-001": Behaviour(PERSISTENCE_TECHNIQUES, per_item=True, why="new unowned item where programs start"),
    "PERSIST-002": Behaviour(PERSISTENCE_TECHNIQUES, per_item=True, why="backdoor-shaped line where programs start"),
    "PERSIST-003": Behaviour((SETUID,), why="unowned setuid/setgid program"),
    "PERSIST-004": Behaviour((DYNAMIC_LINKER,), why="/etc/ld.so.preload in use"),
    "PERSIST-005": Behaviour((KERNEL_MODULES,), why="unowned kernel module"),
    "PERSIST-006": Behaviour((SSH_KEYS,), why="new or optioned SSH key"),
    "PERSIST-007": Behaviour(PERSISTENCE_TECHNIQUES, per_item=True, why="packaged start-up file modified"),
    "PERSIST-008": Behaviour((PAM,), why="PAM rule pointing at unowned software"),
    "PERSIST-009": Posture("run note: what the persistence check could not read"),
    # -- live response (A.5) and packages (A.2) ------------------------------------
    "LIVE-001": Behaviour((FILE_DELETION,), why="a running program whose file was deleted"),
    "LIVE-002": Behaviour((REFLECTIVE_CODE_LOADING,), why="code running from memory (memfd) or a deleted temp file"),
    "LIVE-003": Behaviour((DYNAMIC_LINKER,), why="LD_PRELOAD/LD_AUDIT set on a running process"),
    "LIVE-004": Posture("an executable sitting in a temp directory: worth a look, no named technique"),
    "LIVE-005": Posture("a listener from an odd place: exposure, no named technique"),
    "LIVE-006": Behaviour((UNIX_SHELL, WEB_SHELL), why="a shell started by a network service"),
    "LIVE-007": Posture("run note: restart hint and what could not be read"),
    "PKG-001": Posture("a vulnerable installed package is a weakness, not an action"),
    "PKG-002": Posture("a vulnerable installed package is a weakness, not an action"),
    "PKG-003": Posture("a kernel update waiting for a reboot is a weakness, not an action"),
    "PKG-004": Posture("run note: what the package check could not cover"),
    "DETECT-001": Posture("run note: what the detection rules could not check"),
}


@lru_cache(maxsize=4096)
def sigma_entry(rule_id: str) -> Entry | None:
    """C.1: a SIGMA-* rule's entry, from the shipped pack: its ATT&CK tags through the v19
    table (a tag the table rejects was dropped when the pack was built), or posture when
    it names no technique. An imported rule's finding carries its own labels."""
    from kratos.detect import pack as _packs
    from kratos.detect.findings import labels as _sigma_labels

    found = _packs.load(None).rule(rule_id)
    if found is None:
        return Behaviour((), per_item=True, why="an imported detection rule: its findings carry its own labels")
    meta = found[1].meta
    labs = tuple(_sigma_labels({"attack": meta.get("attack") or [], "tags": meta.get("tags") or []}))
    if not labs:
        return Posture("this Sigma rule names no current ATT&CK technique")
    return Behaviour(labs, why=f"the Sigma rule's own tags ({meta.get('sigma_id')})")


def entry(rule_id: str) -> Entry | None:
    rid = str(rule_id or "")
    found = RULE_ATTACK.get(rid)
    if found is None and rid.startswith("SIGMA-"):
        from kratos.lifecycle.rules import SIGMA_ID

        if SIGMA_ID.match(rid):
            return sigma_entry(rid)
    return found


def labels(rule_id: str) -> list[dict[str, Any]]:
    """Every label rule `rule_id` can carry ([] for posture or an unknown rule)."""
    e = entry(rule_id)
    return [dict(lab) for lab in e.labels] if isinstance(e, Behaviour) else []


def labels_for_finding(rule_id: str, entities: Iterable[str] = ()) -> list[dict[str, Any]]:
    """The labels one finding of `rule_id` carries when nothing more specific set
    them. INTEG-001: by the changed paths in `entities`. Another per-item rule:
    none here (the item's own label is set where the finding is built). A
    whole-rule behaviour: the rule's labels. Posture: none."""
    e = entry(rule_id)
    if not isinstance(e, Behaviour):
        return []
    if rule_id == "INTEG-001":
        return [dict(lab) for lab in _unique(lab for p in entities or () for lab in integ_path_labels(p))]
    if e.per_item:
        return []
    return [dict(lab) for lab in e.labels]
