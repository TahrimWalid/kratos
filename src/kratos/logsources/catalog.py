"""The closed table of log sources Kratos reads on a monitored machine (0.3).

Every path and every journal match a read can touch is written here, per
distribution family -- never taken from the model, a parameter or the wire. A
read names a SOURCE; this table decides what that means on the machine.

Standard library only: this file also ships in the sub-agent bundle (the agent
builds its reads from the same table, so the two transports can't drift).
"""
from __future__ import annotations

from dataclasses import dataclass, field

FAMILIES: tuple[str, ...] = ("debian", "rhel", "alpine")

# The time formats the file extractor understands (logread._AWK).
FORMATS: tuple[str, ...] = (
    "syslog",        # "Oct 11 17:18:01 host prog[pid]: msg" or RFC3339 "2026-10-11T17:18:01+00:00 host ..."
    "audit",         # "type=X msg=audit(1791738725.504:143): ..."
    "clf",           # nginx/apache access: '1.2.3.4 - - [11/Oct/2026:17:12:05 +0000] "GET / ..."'
    "nginx_error",   # "2026/10/11 17:11:52 [notice] 15299#15299: ..."
    "apache_error",  # "[Sun Oct 11 17:11:52.123456 2026] [core:error] ..."
    "dpkg",          # "2026-10-11 17:17:54 install sl:amd64 <none> 5.02-1"
    "apt_history",   # "Start-Date: 2026-10-11  17:17:54" ... "End-Date: ..." blocks
    "iso",           # "2026-10-11T17:19:25+0000 SUBDEBUG Installed: tree-..." (dnf)
    "sudo_log",      # sudo's own logfile: "Oct 11 17:00:00 : alice : TTY=pts/0 ; ..." (+ indented continuations)
)


@dataclass(frozen=True)
class FileSpec:
    path: str
    fmt: str
    # A fixed awk regex a line must match to be kept ("" = every line). Lets a
    # shared file (/var/log/messages) give up only the lines of one source.
    keep: str = ""
    # "always": read it; "no_journal": read it only when the machine has no
    # journalctl (the journal already holds the same lines).
    when: str = "always"


@dataclass(frozen=True)
class Source:
    name: str
    dataset: str
    doc: str                                        # one plain sentence: what it tells you
    journal: dict[str, tuple[str, ...]] = field(default_factory=dict)   # family -> journal matches
    files: dict[str, tuple[FileSpec, ...]] = field(default_factory=dict)  # family -> files
    gaps: dict[str, str] = field(default_factory=dict)                  # family -> why nothing is read
    access: str = ""                                 # how to give the SSH user read access (setup text)
    access_by_family: dict[str, str] = field(default_factory=dict)      # a different fix on some distributions

    def access_for(self, family: str | None) -> str:
        return self.access_by_family.get(family or "", self.access)


# Closed journal matches: a name -> the journalctl match arguments. Repeating a
# field ORs it (verified on systemd 249 and 252).
JOURNAL_MATCHES: dict[str, tuple[str, ...]] = {
    "sudo": ("_COMM=sudo",),
    "auth": ("_COMM=sshd", "_COMM=sshd-session", "_COMM=sudo"),
    "cron": ("SYSLOG_IDENTIFIER=CRON", "SYSLOG_IDENTIFIER=cron", "SYSLOG_IDENTIFIER=CROND",
             "SYSLOG_IDENTIFIER=crond", "SYSLOG_IDENTIFIER=crontab"),   # crontab: a user's table changed (C.1)
    "systemd_pid1": ("_PID=1",),
    "kernel": ("_TRANSPORT=kernel",),
}

_FW_KEEP = r"\[UFW |IN=[^ ]* OUT=[^ ]* .*SRC="
_ADM = ("add the SSH user to the adm group (sudo usermod -aG adm <user>) so it can read "
        "/var/log files without sudo")
# Where the classic log files are NOT adm-readable by default.
_FILE_ACCESS = {
    "rhel": ("these files are root-only on Rocky/RHEL (the journal holds the same lines -- add the SSH user to "
             "systemd-journal); to read the files too, have rsyslog create them group-readable "
             "($FileGroup/$FileCreateMode) for a group the SSH user is in"),
    "alpine": ("/var/log/messages belongs to the wheel group on Alpine, which is usually also the admin "
               "(doas/sudo) group -- don't add Kratos's SSH user to it; read this machine through its sub-agent "
               "(it reads logs as root) instead"),
}

SOURCES: dict[str, Source] = {s.name: s for s in (
    Source(
        "auditd", "kratos.auditd",
        "Every program run, login and account change auditd recorded (needs auditd installed and rules loaded).",
        files={f: (FileSpec("/var/log/audit/audit.log", "audit"),) for f in ("debian", "rhel", "alpine")},
        access=("set log_group = adm in /etc/audit/auditd.conf, make /var/log/audit mode 0750 root:adm, "
                "restart auditd, and add the SSH user to adm"),
    ),
    Source(
        "sudo", "kratos.auth",
        "Who ran what as root through sudo, and failed sudo attempts.",
        journal={"debian": ("sudo",), "rhel": ("sudo",)},
        files={
            "debian": (FileSpec("/var/log/sudo.log", "sudo_log"),),
            "rhel": (FileSpec("/var/log/sudo.log", "sudo_log"), FileSpec("/var/log/secure", "syslog", keep=" sudo")),
            "alpine": (FileSpec("/var/log/messages", "syslog", keep=" sudo"),),
        },
        access=_ADM, access_by_family=_FILE_ACCESS,
    ),
    Source(
        "cron", "kratos.cron",
        "Scheduled jobs that ran (cron), with the user and command.",
        journal={"debian": ("cron",), "rhel": ("cron",)},
        files={
            "rhel": (FileSpec("/var/log/cron", "syslog"),),
            "alpine": (FileSpec("/var/log/messages", "syslog", keep=" crond?\\["),),
        },
        access=_ADM, access_by_family=_FILE_ACCESS,
    ),
    Source(
        "systemd", "kratos.systemd",
        "Services that started, stopped, failed or were reloaded.",
        journal={"debian": ("systemd_pid1",), "rhel": ("systemd_pid1",)},
        gaps={"alpine": "this machine uses OpenRC, not systemd, so there is no unit activity log"},
    ),
    Source(
        "firewall", "kratos.firewall",
        "Connections the firewall blocked or allowed and logged (ufw / nftables log lines).",
        journal={"debian": ("kernel",), "rhel": ("kernel",)},
        files={
            "debian": (FileSpec("/var/log/ufw.log", "syslog", keep=_FW_KEEP, when="no_journal"),),
            "alpine": (FileSpec("/var/log/messages", "syslog", keep=_FW_KEEP),),
        },
        access=_ADM, access_by_family=_FILE_ACCESS,
    ),
    Source(
        "packages", "kratos.package",
        "Software that was installed, upgraded or removed, and the command that did it.",
        files={
            "debian": (FileSpec("/var/log/dpkg.log", "dpkg", keep=r"^[0-9-]+ [0-9:]+ (install|upgrade|remove|purge) "),
                       FileSpec("/var/log/apt/history.log", "apt_history")),
            "rhel": (FileSpec("/var/log/dnf.rpm.log", "iso",
                              keep=r" (Installed|Upgraded|Upgrade|Erased|Removed|Downgraded|Downgrade|Reinstalled|Obsoleted): "),
                     FileSpec("/var/log/dnf.log", "iso", keep=r" Command: ")),
        },
        gaps={"alpine": "apk keeps no install history log on Alpine"},
    ),
    Source(
        "web", "kratos.web",
        "Requests to the web server (nginx / Apache) and its errors.",
        files={
            "debian": (FileSpec("/var/log/nginx/access.log", "clf"), FileSpec("/var/log/nginx/error.log", "nginx_error"),
                       FileSpec("/var/log/apache2/access.log", "clf"),
                       FileSpec("/var/log/apache2/error.log", "apache_error")),
            "rhel": (FileSpec("/var/log/nginx/access.log", "clf"), FileSpec("/var/log/nginx/error.log", "nginx_error"),
                     FileSpec("/var/log/httpd/access_log", "clf"), FileSpec("/var/log/httpd/error_log", "apache_error")),
            "alpine": (FileSpec("/var/log/nginx/access.log", "clf"),
                       FileSpec("/var/log/nginx/error.log", "nginx_error")),
        },
        access=_ADM, access_by_family={"rhel": "nginx/httpd logs are root-only on Rocky/RHEL by default: make "
                                               "them group-readable for a group the SSH user is in"},
    ),
)}

SOURCE_NAMES: tuple[str, ...] = tuple(SOURCES)

# ---------------------------------------------------------------------------
# Incremental sync (phase A.0): which sources Kratos keeps up to date by itself.
# One journal match per source (read forward from a saved cursor) when the machine
# has journalctl, else its classic files (read forward from a saved inode + offset).
# Same closed-table rule as everything above: names and paths live here only.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SyncSource:
    name: str
    dataset: str
    doc: str
    journal: str | None = None                      # a JOURNAL_MATCHES key; used when the machine has journalctl
    files: dict[str, tuple[FileSpec, ...]] = field(default_factory=dict)   # family -> files (no journal / no match)
    default: bool = True                            # in the default `collect.sync_sources`


_AUTH_FILES = {
    "debian": (FileSpec("/var/log/auth.log", "syslog"),),
    "rhel": (FileSpec("/var/log/secure", "syslog"),),
    "alpine": (FileSpec("/var/log/messages", "syslog", keep=r" (sshd|sudo)(\[|:)"),),
}

SYNC_SOURCES: dict[str, SyncSource] = {s.name: s for s in (
    SyncSource("auth", "kratos.auth", "SSH and sudo activity: logins, failures, who ran what as root.",
               journal="auth", files=_AUTH_FILES),
    SyncSource("cron", "kratos.cron", SOURCES["cron"].doc, journal="cron", files=SOURCES["cron"].files),
    SyncSource("systemd", "kratos.systemd", SOURCES["systemd"].doc, journal="systemd_pid1"),
    SyncSource("firewall", "kratos.firewall", SOURCES["firewall"].doc, journal="kernel",
               files=SOURCES["firewall"].files),
    SyncSource("auditd", "kratos.auditd", SOURCES["auditd"].doc, files=SOURCES["auditd"].files),
    SyncSource("packages", "kratos.package", SOURCES["packages"].doc, files=SOURCES["packages"].files),
    SyncSource("web", "kratos.web", SOURCES["web"].doc, files=SOURCES["web"].files, default=False),
)}
SYNC_SOURCE_NAMES: tuple[str, ...] = tuple(SYNC_SOURCES)
DEFAULT_SYNC_SOURCES: tuple[str, ...] = tuple(n for n, s in SYNC_SOURCES.items() if s.default)


def sync_files(source: str, family: str | None) -> tuple[FileSpec, ...]:
    """The classic files a sync of `source` reads on a `family` machine."""
    return SYNC_SOURCES[source].files.get(family or "", ())


# Log files watched for truncation / replacement (tamper check, §6.1), per family.
# Each is compared with its own previous state and with its first rotation.
TRACKED_FILES: dict[str, tuple[str, ...]] = {
    "debian": ("/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log", "/var/log/audit/audit.log",
               "/var/log/dpkg.log", "/var/log/wtmp", "/var/log/btmp"),
    "rhel": ("/var/log/secure", "/var/log/messages", "/var/log/cron", "/var/log/audit/audit.log",
             "/var/log/dnf.rpm.log", "/var/log/wtmp", "/var/log/btmp"),
    "alpine": ("/var/log/messages", "/var/log/wtmp", "/var/log/btmp"),
}
# logrotate's state file (records when it last rotated each log), by distro.
LOGROTATE_STATUS_FILES: tuple[str, ...] = ("/var/lib/logrotate/status", "/var/lib/logrotate/logrotate.status")
HEAD_HASH_BYTES = 4096

# Login records (§6.4): the name a read uses -> the file.
UTMP_FILES: dict[str, str] = {"wtmp": "/var/log/wtmp", "btmp": "/var/log/btmp"}

# Where journald keeps its files: persistent first, then volatile.
JOURNAL_DIRS: tuple[str, ...] = ("/var/log/journal", "/run/log/journal")

ALL_PATHS: frozenset[str] = frozenset(
    {fs.path for s in SOURCES.values() for specs in s.files.values() for fs in specs}
    | {p for ps in TRACKED_FILES.values() for p in ps} | set(LOGROTATE_STATUS_FILES) | set(UTMP_FILES.values()))


def family_from_os_release(text: str) -> str | None:
    """'debian' / 'rhel' / 'alpine' from /etc/os-release, or None. Mirrors the
    shell in FAMILY_SH exactly (tests/test_logsources_catalog.py)."""
    values: dict[str, str] = {}
    for line in (text or "").splitlines():
        key, sep, val = line.partition("=")
        if sep:
            values[key.strip()] = val.strip().strip("'\"")
    words = " " + values.get("ID", "") + " " + values.get("ID_LIKE", "") + " "
    for family, ids in _FAMILY_IDS:
        if any(f" {i} " in words for i in ids):
            return family
    return None


_FAMILY_IDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("alpine", ("alpine",)),
    ("debian", ("debian", "ubuntu")),
    ("rhel", ("rhel", "fedora", "centos", "rocky", "almalinux")),
)


def _family_sh() -> str:
    # (bundle code runs on Python 3.8: no backslashes inside f-string expressions)
    cases = "\n".join(
        "  " + "|".join('*" ' + i + ' "*' for i in ids) + ") FAMILY=" + fam + " ;;" for fam, ids in _FAMILY_IDS)
    return (
        "FAMILY=unknown\n"
        "if [ -r /etc/os-release ]; then\n"
        "  _ID=$(sed -n 's/^ID=//p' /etc/os-release | tr -d \"'\\\"\")\n"
        "  _LIKE=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d \"'\\\"\")\n"
        "  case \" $_ID $_LIKE \" in\n"
        f"{cases}\n"
        "  esac\n"
        "fi\n"
    )


FAMILY_SH = _family_sh()
