"""sudo activity: the journal (`_COMM=sudo`), RHEL's /var/log/secure, Alpine's
/var/log/messages, and sudo's own logfile (`Defaults logfile=`).

Classified by the same function as the target's sshd/sudo journal read
(adapters/auth_log_parse.classify_auth_message), so a sudo command found here
is the same event type whichever read found it (dataset kratos.auth).

sudo's own logfile writes "user : TTY=... ; PWD=... ; USER=... ; COMMAND=..."
without "TTY=" when there is no terminal; that is filled in so the shared
classifier recognises the command.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kratos.logsources.parsers import record_parts


def to_auth_event(rec: Any, target: str) -> Any | None:
    from kratos.adapters.auth_log_parse import classify_auth_message

    prog, _pid, msg, _orig, _cursor = record_parts(rec)
    if rec.kind == "file" and prog is None:
        # sudo's own logfile: "Oct 11 17:17:24 : ubuntu : PWD=... ; USER=root ; COMMAND=/usr/bin/ls\x1f/root"
        parts = rec.text.split(" : ", 1)
        if len(parts) != 2:
            return None
        msg = parts[1].replace("\x1f", " ")
        user, sep, rest = msg.partition(" : ")
        if sep and "TTY=" not in rest:
            msg = f"{user} : TTY=unknown ; {rest}"
        prog = "sudo"
    if prog != "sudo":
        return None
    ts = datetime.fromtimestamp(rec.ts, timezone.utc).isoformat()
    return classify_auth_message(ts, target, "sudo", msg, msg)


def parse(read: Any, target: str = "") -> list[Any]:
    return [e for e in (to_auth_event(r, target) for r in read.records) if e is not None]
