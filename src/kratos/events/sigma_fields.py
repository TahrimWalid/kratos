"""Sigma -> Kratos event mapping for the log sources Kratos feeds (data only).

The rule compiler (kratos.detect.sigma_build, build time only) reads this table: a
Sigma rule is compiled only when its log source is listed in LOGSOURCES and every
field it references has a mapping there; anything else is skipped with the reason
recorded (UNSUPPORTED, UNMAPPED) -- never approximated. tests/test_sigma_fields.py
checks the table against the real parsers' output and the vendored SigmaHQ rules.

Each log source names the datasets that feed it (events/fields.py `event.dataset`),
an optional extra condition in the evaluator's closed-operator form
(kratos.subagent.detect), and its Sigma field -> event field map. Keyword searches
(Sigma's unnamed search terms) look in the log message and the raw line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

KEYWORDS = "keywords"
# Where a keyword is looked for: the message, and the raw line it came from.
KEYWORD_FIELDS: tuple[str, ...] = ("message", "event.original")

# auditd's EXECVE arguments a0, a1, ... -> process.args[N] (argv, in order).
AUDITD_ARG = re.compile(r"^a(\d{1,2})$")

LogsourceKey = tuple[str, "str | None", "str | None"]


@dataclass(frozen=True)
class Logsource:
    key: LogsourceKey                      # Sigma (product, service, category)
    label: str                             # plain words, for coverage lines ("program starts")
    datasets: tuple[str, ...]              # the Kratos datasets that feed it
    where: dict[str, Any] | None = None    # extra condition (closed operators) an event must meet
    fields: dict[str, str] = field(default_factory=dict)   # Sigma field -> event field
    needs: str = ""                        # what a machine needs for these rules to see anything
    partial: str = ""                      # what is seen when that need is not met (if anything)


def _eq(f: str, v: str) -> dict[str, Any]:
    return {"op": "eq", "field": f, "value": v, "cased": True}


_SYSLOGISH = ("kratos.auth", "kratos.journal", "kratos.privileged_accounts", "kratos.cron", "kratos.systemd",
              "kratos.firewall")

# Sign-in logs carry no Sigma fields of their own (SigmaHQ's sshd rules are keyword searches);
# these let a person's counting rule group by the address a login came from (C.1).
_AUTH = {"SourceIp": "source.ip"}

# Process-start fields shared by the process and file rules.
_PROCESS = {
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "CurrentDirectory": "process.working_directory",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
}

LOGSOURCES: dict[LogsourceKey, Logsource] = {ls.key: ls for ls in (
    Logsource(("linux", None, None), "Linux logs",
              (*_SYSLOGISH, "kratos.auditd", "kratos.package"),
              needs="logs Kratos collects (log sync)"),
    Logsource(("linux", "auth", None), "sign-in and account logs", ("kratos.auth", "kratos.privileged_accounts"),
              fields=dict(_AUTH), needs="the SSH/sudo log (log sync)"),
    Logsource(("linux", "sshd", None), "SSH server log", ("kratos.auth",),
              where={"op": "in", "field": "event.provider", "values": ["sshd", "sshd-session"], "cased": True},
              fields=dict(_AUTH), needs="the SSH server's log (log sync)"),
    Logsource(("linux", "sudo", None), "sudo log", ("kratos.auth",), where=_eq("event.provider", "sudo"),
              needs="sudo's log (log sync)"),
    Logsource(("linux", "syslog", None), "system log", _SYSLOGISH, needs="the system log (log sync)"),
    Logsource(("linux", "cron", None), "cron log", ("kratos.cron",), needs="cron's log (log sync)"),
    Logsource(("linux", "auditd", None), "audit log", ("kratos.auditd",),
              fields={
                  "type": "kratos.audit.types",
                  "key": "kratos.audit.key",
                  "SYSCALL": "kratos.audit.syscall",
                  "exe": "process.executable",
                  "comm": "process.name",
                  "name": "kratos.audit.paths",
                  "euid": "user.effective.id",
                  "unit": "service.name",
                  # a0, a1, ... : AUDITD_ARG -> process.args[N], only beside type EXECVE
              },
              needs="auditd running with its log readable (log sync)"),
    Logsource(("linux", None, "process_creation"), "program starts", ("kratos.auditd", "kratos.auth"),
              where={"op": "any_of", "args": [
                  {"op": "all_of", "args": [_eq("event.dataset", "kratos.auditd"),
                                            _eq("event.action", "process_started")]},
                  {"op": "all_of", "args": [_eq("event.dataset", "kratos.auth"),
                                            _eq("event.action", "sudo_command")]}]},
              fields=dict(_PROCESS),
              needs="auditd recording every program start (an execve audit rule)",
              partial="only commands run through sudo are checked"),
    Logsource(("linux", None, "file_event"), "file creation", ("kratos.auditd",),
              where={"op": "exists", "field": "kratos.audit.created_paths", "value": True},
              fields={"TargetFilename": "kratos.audit.created_paths", "Image": "process.executable"},
              needs="auditd watching the files (audit watch rules recording creation)"),
)}

# Log sources Kratos can't feed, and why -- a rule for one of these is skipped.
UNSUPPORTED: dict[LogsourceKey, str] = {
    ("linux", None, "network_connection"):
        "needs every outgoing connection with the destination's name; Kratos reads no connection log",
    ("linux", "clamav", None): "Kratos doesn't collect ClamAV's log",
    ("linux", "guacamole", None): "Kratos doesn't collect Apache Guacamole's log",
    ("linux", "vsftpd", None): "Kratos doesn't collect vsftpd's log",
}

# Sigma fields Kratos's events can't answer, and why -- a rule naming one is skipped.
UNMAPPED: dict[str, str] = {
    "ParentImage": "needs the parent program's path; auditd records only the parent's process ID",
    "ParentCommandLine": "needs the parent program's command line; auditd records only the parent's process ID",
    "User": "needs the user each program runs as for every start; Kratos keeps the login user (auditd auid)",
    "LogonId": "Sysmon for Linux's logon id (0 for root logins); auditd's session number is a different thing",
    "OriginalFileName": "Windows file metadata; no Linux equivalent",
    "Hashes": "needs a hash of every program started; auditd doesn't record one",
    "nametype": "needs each PATH record's name and type together; Kratos keeps the names, and the created ones",
    "DestinationHostname": "needs the destination's name for each connection",
    "DestinationIp": "needs a connection log",
    "DestinationPort": "needs a connection log",
    "Initiated": "needs a connection log",
}


def logsource_for(product: str | None, service: str | None, category: str | None) -> Logsource | None:
    return LOGSOURCES.get((product or "", service, category))


def map_field(ls: Logsource, sigma_field: str) -> tuple[str, int | None] | None:
    """(event field, index or None) for a Sigma field under log source `ls`, or None."""
    if sigma_field in ls.fields:
        return ls.fields[sigma_field], None
    if ls.key == ("linux", "auditd", None):
        m = AUDITD_ARG.match(sigma_field)
        if m and int(m.group(1)) < 64:
            return "process.args", int(m.group(1))
    return None
