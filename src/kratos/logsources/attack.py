"""Moved to kratos.attack (A.3): one pinned ATT&CK v19 table for every rule.

This module only re-exports the label constants 0.3 and A.1 code imported from
here, so older imports keep working. New code imports kratos.attack.
"""
from __future__ import annotations

from kratos.attack.mapping import (  # noqa: F401
    AT, CLEAR_LINUX_LOGS, CRON, DISABLE_TOOLS, DYNAMIC_LINKER, EVENT_TRIGGERED, FILE_DELETION,
    INSTALLER_PACKAGES, KERNEL_MODULES, LINUX_AUDIT, LOGON_SCRIPTS, PAM, PERSISTENCE_TECHNIQUES, RC_SCRIPTS,
    REFLECTIVE_CODE_LOADING, SETUID, SHELL_CONFIG, SSH_KEYS, SYSTEM_PROCESS, SYSTEMD_SERVICE, SYSTEMD_TIMER, UDEV,
    UNIX_SHELL, WEB_SHELL, XDG_AUTOSTART, labels,
)
from kratos.attack.table import attack_version

ATTACK_VERSION = attack_version()
