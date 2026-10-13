"""SSH and sudo activity for the incremental sync (phase A.0): the journal's sshd /
sshd-session / sudo entries, or the classic auth log (auth.log, secure, messages).

Classified by the same function as the target auth read (adapters/auth_log_parse
.classify_auth_message) and handed to the same converter, so a line both reads find
is one event (kratos.auth, content ID).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kratos.logsources.parsers import record_parts

AUTH_PROGRAMS = frozenset({"sshd", "sshd-session", "sudo"})


def to_auth_event(rec: Any, target: str) -> Any | None:
    from kratos.adapters.auth_log_parse import classify_auth_message

    prog, _pid, msg, _orig, _cursor = record_parts(rec)
    if prog not in AUTH_PROGRAMS or not msg:
        return None
    ts = datetime.fromtimestamp(rec.ts, timezone.utc).isoformat()
    if prog == "sudo":
        from kratos.logsources.parsers.sudo import _with_tty

        return classify_auth_message(ts, target, prog, _with_tty(msg), msg)
    return classify_auth_message(ts, target, prog, msg, msg)


def parse(read: Any, target: str = "") -> list[Any]:
    return [e for e in (to_auth_event(r, target) for r in read.records) if e is not None]
