"""auditd's log (/var/log/audit/audit.log), RAW or ENRICHED format.

One audit event is several records sharing an event serial
(`msg=audit(<epoch>:<serial>)`): e.g. SYSCALL + EXECVE + CWD + PATH... +
PROCTITLE for one program run. Records are grouped by serial into one event.
Hex-encoded values (`proctitle=`, unquoted `aN=`, split `aN[i]=` arguments) are
decoded. ENRICHED adds resolved names after a 0x1d separator (`UID="root"`).

CONFIG_CHANGE, DAEMON_* and an `audit_enabled=0` change are what the tamper
check (LOG-005) looks for.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

try:  # in the agent bundle (C.2): sibling modules
    from .parsers_base import Parsed  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.logsources.parsers import Parsed
    except ImportError:  # run directly
        from parsers_base import Parsed  # type: ignore[no-redef]

_REC = re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s?(?P<body>.*)$",
                  re.DOTALL)
_KV = re.compile(r"""(?P<k>[A-Za-z_][\w\-]*(?:\[\d+\])?)=(?P<v>"[^"]*"|'[^']*'|\S*)""")
_HEX = re.compile(r"^(?:[0-9A-F]{2})+$")
_UNSET = {"4294967295", "-1", ""}
MAX_RECORDS_PER_EVENT = 32

ACTIONS = {
    "USER_LOGIN": "user_login", "USER_AUTH": "user_auth", "USER_START": "session_started",
    "USER_END": "session_ended", "ADD_USER": "user_added", "DEL_USER": "user_deleted", "ADD_GROUP": "group_added",
    "DEL_GROUP": "group_deleted", "USER_MGMT": "user_changed", "GRP_MGMT": "group_changed",
    "USER_CHAUTHTOK": "password_changed", "DAEMON_START": "auditd_started", "DAEMON_END": "auditd_stopped",
    "DAEMON_ABORT": "auditd_aborted", "DAEMON_CONFIG": "auditd_reconfigured", "SERVICE_START": "service_started",
    "SERVICE_STOP": "service_stopped", "USER_CMD": "sudo_command",
}


def _unquote(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def decode(v: str | None) -> str | None:
    """A field value as text: quoted -> as is; `(null)` -> None; upper-case hex
    (how auditd writes values with spaces or special bytes) -> decoded."""
    if v is None:
        return None
    if v[:1] in "\"'":
        return _unquote(v)
    if v in ("(null)", "?"):
        return None
    if _HEX.fullmatch(v):
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def fields_of(body: str) -> tuple[dict[str, str], dict[str, str]]:
    """(raw fields, enriched fields). A USER_* record's msg='...' is opened up."""
    raw_part, _, enriched_part = body.partition("\x1d")
    raw: dict[str, str] = {}
    for m in _KV.finditer(raw_part):
        k, v = m.group("k"), m.group("v")
        if k == "msg" and v[:1] == "'":
            for inner in _KV.finditer(_unquote(v)):
                raw.setdefault(inner.group("k"), inner.group("v"))
            continue
        raw.setdefault(k, v)
    enriched = {m.group("k"): _unquote(m.group("v")) for m in _KV.finditer(enriched_part)}
    return raw, enriched


def _argv(execve: dict[str, str]) -> list[str]:
    try:
        argc = int(execve.get("argc", "0"))
    except ValueError:
        argc = 0
    args: list[str] = []
    for i in range(min(argc, 256)):
        if f"a{i}" in execve:
            args.append(decode(execve[f"a{i}"]) or "")
            continue
        parts = []
        j = 0
        while f"a{i}[{j}]" in execve and j < 4096:
            parts.append(execve[f"a{i}[{j}]"])
            j += 1
        if parts:
            args.append(decode("".join(p.strip('"') for p in parts)) or "")
    return args


def _ip(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _num(v: str | None) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except ValueError:
        return None


def group(lines: list[tuple[str, str | None, bool]]) -> list[dict[str, Any]]:
    """[(raw line, file path, zone assumed)] -> events: {ts, serial, records:
    [(type, raw, enriched)], lines, path}. Records past MAX_RECORDS_PER_EVENT are
    dropped; malformed lines are skipped."""
    events: dict[tuple[str, int], dict[str, Any]] = {}
    for raw, path, _assumed in lines:
        m = _REC.match(raw)
        if not m:
            continue
        key = (m.group("ts"), int(m.group("serial")))
        ev = events.setdefault(key, {"ts": float(m.group("ts")), "serial": key[1], "records": [], "lines": [],
                                     "path": path})
        if len(ev["records"]) >= MAX_RECORDS_PER_EVENT:
            continue
        fr, fe = fields_of(m.group("body"))
        ev["records"].append((m.group("type"), fr, fe))
        ev["lines"].append(raw.replace("\x1d", " "))
    return list(events.values())


MAX_PATHS = 32


def to_parsed(ev: dict[str, Any]) -> Parsed:
    by_type: dict[str, tuple[dict[str, str], dict[str, str]]] = {}
    paths: list[str] = []
    all_paths: list[str] = []          # every PATH name in record order (Sigma's auditd `name`)
    created: list[str] = []            # PATH names with nametype=CREATE (Sigma's file_event)
    for rtype, fr, fe in ev["records"]:
        by_type.setdefault(rtype, (fr, fe))
        if rtype == "PATH":
            name = decode(fr.get("name"))
            if not name:
                continue
            if fr.get("item") == "0":
                paths.append(name)
            if len(all_paths) < MAX_PATHS:
                all_paths.append(name)
            if (decode(fr.get("nametype")) or "").upper() == "CREATE" and name not in created:
                created.append(name)
    types = [t for t, _, _ in ev["records"]]
    main = types[0] if types else "UNKNOWN"
    fr, fe = by_type.get(main, ({}, {}))
    sc_raw, sc_enr = by_type.get("SYSCALL", ({}, {}))
    fields: dict[str, Any] = {"sequence": ev["serial"]}
    outcome = None
    if "EXECVE" in by_type:
        action = "process_started"
        args = _argv(by_type["EXECVE"][0])
        if not args and "PROCTITLE" in by_type:
            title = decode(by_type["PROCTITLE"][0].get("proctitle")) or ""
            args = [a for a in title.split("\x00") if a]
        fields["process_command_line"] = " ".join(args) if args else None
        fields["process_args"] = args or None          # capped (and flagged) at conversion
        fr, fe = sc_raw or fr, sc_enr or fe
        outcome = {"yes": "success", "no": "failure"}.get(sc_raw.get("success", ""))
    elif main == "CONFIG_CHANGE":
        op = decode(fr.get("op")) or ""
        if fr.get("audit_enabled") == "0":
            action = "audit_disabled"
        elif op == "remove_rule":
            action = "audit_rule_removed"
        elif op == "add_rule":
            action = "audit_rule_added"
        else:
            action = "audit_config_change"
    else:
        action = ACTIONS.get(main, "audit_other")
    if outcome is None:
        res = (decode(fr.get("res")) or "").lower()
        outcome = {"success": "success", "1": "success", "failed": "failure", "0": "failure"}.get(res)
    auid = fr.get("auid")
    if auid not in _UNSET and auid is not None:
        fields["user_id"] = auid
        name = fe.get("AUID")
        if name and name != "unset":
            fields["user_name"] = name
    elif fr.get("uid") not in (None, ""):
        fields["user_id"] = fr.get("uid")
        if fe.get("UID"):
            fields["user_name"] = fe["UID"]
    acct = decode(fr.get("acct"))
    if acct and action in ("user_login", "user_auth", "session_started", "session_ended", "password_changed"):
        fields["user_name"] = acct
    if action in ("user_added", "user_deleted", "user_changed", "group_added", "group_deleted", "group_changed"):
        target = acct or (fe.get("ID") if fe.get("ID") and not fe["ID"].startswith("unknown(") else None)
        if target:
            fields["group_name" if action.startswith("group") else "user_target_name"] = target
    fields["source_ip"] = _ip(decode(fr.get("addr")))
    exe = decode(fr.get("exe"))
    fields["process_executable"] = exe
    fields["process_name"] = decode(fr.get("comm")) or (exe.rsplit("/", 1)[-1] if exe else None)
    fields["process_pid"] = _num(fr.get("pid"))
    fields["process_parent_pid"] = _num(fr.get("ppid"))
    if "CWD" in by_type:
        fields["process_working_directory"] = decode(by_type["CWD"][0].get("cwd"))
    if paths:
        fields["file_path"] = paths[0]
    fields["audit_types"] = list(dict.fromkeys(types)) or None
    fields["audit_paths"] = all_paths or None
    fields["audit_created_paths"] = created or None
    key = decode(sc_raw.get("key")) if sc_raw else None
    fields["audit_key"] = key or decode(fr.get("key"))
    fields["audit_syscall"] = (sc_enr.get("SYSCALL") or None) if sc_enr else None
    ses = fr.get("ses") if fr.get("ses") is not None else (sc_raw.get("ses") if sc_raw else None)
    fields["audit_session"] = ses if ses not in _UNSET and ses is not None and ses.isdigit() else None
    euid = sc_raw.get("euid") if sc_raw else None
    fields["user_effective_id"] = euid if euid not in _UNSET and euid is not None else None
    if action == "sudo_command":
        cmd = decode(fr.get("cmd"))
        fields["process_command_line"] = cmd
    unit = decode(fr.get("unit"))
    if unit and action.startswith("service_"):
        fields["service_name"] = unit
    message = f"{main} " + " ".join(sorted(set(types) - {main}))
    return Parsed(ts=ev["ts"], action=action, provider="auditd", outcome=outcome, message=message.strip(),
                  original="\n".join(ev["lines"]), fields={k: v for k, v in fields.items() if v not in (None, "")},
                  log_file_path=ev.get("path"))


def parse(read: Any) -> list[Parsed]:
    lines = [(r.text, r.path, r.zone_assumed) for r in reversed(read.records) if r.kind == "file"]
    out = [to_parsed(ev) for ev in group(lines)]
    out.sort(key=lambda p: p.ts, reverse=True)
    return out
