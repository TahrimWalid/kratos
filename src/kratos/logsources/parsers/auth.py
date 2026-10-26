"""SSH and sudo activity for the incremental sync (phase A.0): the journal's sshd /
sshd-session / sudo entries, or the classic auth log (auth.log, secure, messages).

Classified by the same function as the target auth read (adapters/auth_log_parse
.classify_auth_message) and handed to the same converter, so a line both reads find
is one event (kratos.auth, content ID).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:  # in the agent bundle (C.2): sibling modules
    from .parsers_base import record_parts  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources.parsers import record_parts
    except ImportError:  # run directly
        from parsers_base import record_parts  # type: ignore[no-redef]
try:  # in the agent bundle (C.2)
    from .auth_log_parse import ACCOUNT_PROGRAMS, classify_auth_message  # type: ignore[import-not-found]
    from .lp_sudo import _with_tty  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    try:
        from kratos.adapters.auth_log_parse import ACCOUNT_PROGRAMS, classify_auth_message
        from kratos.logsources.parsers.sudo import _with_tty
    except ImportError:  # run directly
        from auth_log_parse import ACCOUNT_PROGRAMS, classify_auth_message  # type: ignore[no-redef]
        from lp_sudo import _with_tty  # type: ignore[no-redef]

AUTH_PROGRAMS = frozenset({"sshd", "sshd-session", "sudo"}) | ACCOUNT_PROGRAMS   # + account management (audit)


def to_auth_event(rec: Any, target: str) -> Any | None:
    import dataclasses

    prog, pid, msg, _orig, _cursor = record_parts(rec)
    if prog not in AUTH_PROGRAMS or not msg:
        return None
    ts = datetime.fromtimestamp(rec.ts, timezone.utc).isoformat()
    if prog == "sudo":
        ev = classify_auth_message(ts, target, prog, _with_tty(msg), msg)
    else:
        ev = classify_auth_message(ts, target, prog, msg, msg)
    # the journal gives the pid apart from the message (C.1: an sshd login's pid ties it to its audit session)
    return dataclasses.replace(ev, pid=pid) if pid is not None else ev


def parse(read: Any, target: str = "") -> list[Any]:
    return [e for e in (to_auth_event(r, target) for r in read.records) if e is not None]
