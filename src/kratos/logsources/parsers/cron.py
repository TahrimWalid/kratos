"""Scheduled-job activity: cron's own lines (journal or /var/log/cron, BusyBox crond).

    (root) CMD (run-parts /etc/cron.hourly)          Debian cron / cronie: a job started
    (root) CMDEND (run-parts /etc/cron.hourly)       cronie: it finished
    pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
    USER root pid 48302 cmd run-parts /etc/periodic/15min      BusyBox crond
    (root) REPLACE (ubuntu)                          crontab: root replaced ubuntu's table (also DELETE,
                                                     BEGIN EDIT / END EDIT, LIST)
"""
from __future__ import annotations

import re
from typing import Any

try:  # in the agent bundle (C.2): sibling modules
    from .parsers_base import Parsed, record_parts  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources.parsers import Parsed, record_parts
    except ImportError:  # run directly
        from parsers_base import Parsed, record_parts  # type: ignore[no-redef]

_CMD = re.compile(r"^\((?P<user>[^)\s]+)\) (?P<kind>CMD|CMDEND) \((?P<cmd>.*)\)\s*$", re.DOTALL)
_SESSION = re.compile(r"pam_unix\(cron[^)]*:session\): session (?P<state>opened|closed) for user "
                      r"(?P<user>[^\s(]+)")
_BUSYBOX = re.compile(r"^USER (?P<user>\S+) pid (?P<pid>\d+) cmd (?P<cmd>.*)$", re.DOTALL)
_TABLE = re.compile(r"^\((?P<by>[^)\s]+)\) (?P<op>REPLACE|DELETE|BEGIN EDIT|END EDIT|LIST) \((?P<owner>[^)\s]+)\)\s*$")
_TABLE_ACTIONS = {"REPLACE": "crontab_replaced", "DELETE": "crontab_deleted", "BEGIN EDIT": "crontab_edit_started",
                  "END EDIT": "crontab_edited", "LIST": "crontab_listed"}
_CRON_PROGS = {"cron", "CRON", "crond", "CROND", "crontab"}


def _first_word(cmd: str) -> str | None:
    word = cmd.strip().split(None, 1)[0] if cmd.strip() else ""
    return word.rsplit("/", 1)[-1] or None


def to_parsed(rec: Any) -> Parsed | None:
    prog, pid, msg, original, cursor = record_parts(rec)
    if prog not in _CRON_PROGS:
        return None
    fields: dict[str, Any] = {}
    msg = msg.strip()
    if m := _CMD.match(msg):
        action = "cron_command" if m.group("kind") == "CMD" else "cron_command_ended"
        fields.update(user_name=m.group("user"), process_command_line=m.group("cmd"),
                      process_name=_first_word(m.group("cmd")), process_parent_pid=pid)
    elif m := _BUSYBOX.match(msg):
        action = "cron_command"
        fields.update(user_name=m.group("user"), process_command_line=m.group("cmd"),
                      process_name=_first_word(m.group("cmd")), process_pid=int(m.group("pid")),
                      process_parent_pid=pid)
    elif m := _TABLE.match(msg):
        action = _TABLE_ACTIONS[m.group("op")]
        fields.update(user_name=m.group("by"), user_target_name=m.group("owner"), process_pid=pid,
                      process_name="crontab")
    elif m := _SESSION.search(msg):
        action = "cron_session_opened" if m.group("state") == "opened" else "cron_session_closed"
        fields.update(user_name=m.group("user"), process_pid=pid)
    else:
        action = "cron_other"
        fields.update(process_pid=pid)
    return Parsed(ts=rec.ts, action=action, provider=prog, message=msg, original=original,
                  fields={k: v for k, v in fields.items() if v not in (None, "")}, log_file_path=rec.path,
                  cursor=cursor, zone_assumed=rec.zone_assumed)


def parse(read: Any) -> list[Parsed]:
    return [p for p in (to_parsed(r) for r in read.records) if p is not None]
