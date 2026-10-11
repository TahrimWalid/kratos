"""Sigma -> ECS field mapping for the log sources Kratos can feed (data only).

C.1 (Sigma rule evaluation) turns this into a pySigma processing pipeline;
here it is only the table, checked by tests/test_sigma_fields.py against real
SigmaHQ Linux rules: every field those rules reference is either mapped to an
ECS field Kratos's events carry, or listed as unmapped with the reason.
"""
from __future__ import annotations

# Sigma's unnamed search terms ("keywords") match the log message text. The
# SigmaHQ linux/auth, sshd, sudo, syslog and cron rules are keyword searches;
# the field names below are Sigma's Linux process_creation taxonomy.
KEYWORDS = "keywords"

# Sigma field -> ECS field, every target present in events/fields.py.
SIGMA_TO_ECS: dict[str, str] = {
    KEYWORDS: "message",
    # process_creation (Linux taxonomy). Today only sudo-run commands are
    # process events (event.action sudo_command); 0.3's auditd EXECVE adds the rest.
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ProcessId": "process.pid",
    "ParentProcessId": "process.parent.pid",
    # The user the process runs as. For a sudo-run command that is sudo's target
    # user (user.effective.name); user.name stays the person who ran sudo.
    "User": "user.effective.name",
}

# Sigma fields Kratos's events can't answer yet, and why -- no silent gaps.
UNMAPPED: dict[str, str] = {
    "ParentImage": "needs the parent process's executable: auditd EXECVE records with PPID resolution (0.3)",
    "ParentCommandLine": "needs the parent process's command line: auditd EXECVE (0.3)",
    "CurrentDirectory": "needs the process's working directory: auditd CWD records (0.3); "
                        "sudo's PWD= is the invoking shell's, not recorded as an ECS field",
    "LogonId": "needs the audit session (auid/ses): auditd (0.3)",
    "OriginalFileName": "Windows PE metadata; no Linux equivalent",
    "Hashes": "process image hashes need auditd + hashing on the target (0.3 or later)",
}

# Sigma logsource (product, service, category) -> the Kratos datasets that feed it.
LOGSOURCES: dict[tuple[str, str | None, str | None], tuple[str, ...]] = {
    ("linux", None, None): ("kratos.auth", "kratos.journal", "kratos.privileged_accounts"),
    ("linux", "auth", None): ("kratos.auth", "kratos.privileged_accounts"),
    ("linux", "sshd", None): ("kratos.auth",),       # process.name sshd / sshd-session
    ("linux", "sudo", None): ("kratos.auth",),       # event.provider sudo
    ("linux", "syslog", None): ("kratos.journal",),
    ("linux", "cron", None): ("kratos.journal",),    # service.name cron.service / crond.service
    ("linux", None, "process_creation"): ("kratos.auth",),  # sudo_command events only, see UNSUPPORTED
}

# Logsources (or partial coverage) Kratos can't feed yet, and why.
UNSUPPORTED: dict[tuple[str, str | None, str | None], str] = {
    ("linux", None, "process_creation"):
        "partial: only commands run through sudo are seen today; every exec needs auditd EXECVE (0.3)",
    ("linux", "auditd", None): "auditd is 0.3",
    ("linux", None, "file_event"): "needs auditd PATH records or a file-watch read (0.3)",
    ("linux", None, "network_connection"): "needs auditd connect() records (0.3)",
}
