"""The closed list of things Kratos learns per machine (E.3 §3.1), and how each one is
read out of stored events or saved running-process reads.

Every dimension has a rule (BASE-00N), a subject (whose normal it is: an account or a
program) and a key (the thing that is or isn't usual for that subject). Keys are plain
text, canonical, and are also the finding's entity -- "this is normal" is decided per key.

Persistence items (cron, units, keys, ...) are not a dimension: A.1 keeps its own
first-look baseline of them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, tzinfo
from typing import Any, Iterable

from kratos.baseline import buckets as B

EVENT, SNAPSHOT = "events", "snapshots"


@dataclass(frozen=True)
class Dim:
    name: str
    rule: str
    label: str                  # plain words ("where each account signs in from")
    source: str                 # EVENT | SNAPSHOT
    sync_source: str | None     # log sync source whose coverage counts learning days (events)
    min_samples: int            # before judging: per subject (sign-ins) or per machine (sudo, snapshots)
    per_subject: bool           # min_samples counted per subject (True) or for the whole machine
    subject_word: str           # "account", "user", "program"
    min_snapshot_days: int = 0  # snapshot dimensions: the samples must span this many days


DIMS: tuple[Dim, ...] = (
    Dim("login_source", "BASE-001", "where each account signs in from", EVENT, "auth", 20, True, "account"),
    Dim("login_time", "BASE-002", "when each account signs in (machine time)", EVENT, "auth", 30, True, "account"),
    Dim("login_method", "BASE-003", "how each account signs in (key, password, certificate)", EVENT, "auth", 10,
        True, "account"),
    Dim("sudo_use", "BASE-004", "who runs what as whom with sudo", EVENT, "auth", 10, False, "user"),
    Dim("listener", "BASE-005", "which programs listen on which ports", SNAPSHOT, None, 10, False, "program",
        min_snapshot_days=7),
    Dim("outbound", "BASE-006", "which programs talk to which outside peers", SNAPSHOT, None, 10, False, "program",
        min_snapshot_days=7),
    Dim("program", "BASE-008", "which programs start under which parent programs (needs auditd)", EVENT, "auditd",
        200, False, "program", min_snapshot_days=7),
)
BY_NAME = {d.name: d for d in DIMS}
BY_RULE = {d.rule: d for d in DIMS}
RUN_NOTE = "BASE-007"
LOGIN_DIMS = ("login_source", "login_time", "login_method")
EVENT_ACTIONS = ("ssh_success_login", "sudo_command", "process_started")


@dataclass
class Obs:
    """One observation: `subject` did `key` (in dimension `dim`) at `ts`."""
    dim: str
    subject: str
    key: str
    ts: float
    detail: dict[str, Any] = field(default_factory=dict)    # the exact address, method, command... (evidence)
    row_id: int = 0


# ---------------------------------------------------------------------------
# Keys (text, canonical; also the finding entity)
# ---------------------------------------------------------------------------
_CERT = re.compile(r"-CERT SHA256:", re.IGNORECASE)
_METHOD = re.compile(r"\bAccepted (password|keyboard-interactive(?:/pam)?|publickey|gssapi-with-mic|hostbased)\b",
                     re.IGNORECASE)


def login_method(message: str) -> str:
    m = _METHOD.search(message or "")
    if not m:
        return "other"
    word = m.group(1).lower()
    if word.startswith("keyboard-interactive"):
        return "keyboard-interactive"
    if word == "publickey" and _CERT.search(message or ""):
        return "certificate"
    return {"publickey": "key"}.get(word, word)


def hour_key(ts: float, tz: tzinfo) -> str:
    local = datetime.fromtimestamp(ts, tz)
    return f"{local.hour:02d} {'weekend' if local.weekday() >= 5 else 'weekday'}"


def hour_words(key: str) -> str:
    hh, _, kind = key.partition(" ")
    return f"{hh}:00-{hh}:59 on {kind}s"


def _short(text: Any, cap: int = 200) -> str:
    return "".join(ch for ch in str(text or "") if ch.isprintable())[:cap].strip()


def sudo_key(run_as: str, program: str) -> str:
    return f"as {run_as or '?'}: {program or '?'}"


def listener_key(proto: str, port: Any) -> str:
    return f"{proto or '?'}/{port}"


def outbound_key(bucket: B.Bucket, port: Any) -> str:
    return f"{bucket.bucket} port {port}"


def program_key(parent: str) -> str:
    return f"under {parent or '?'}"


# ---------------------------------------------------------------------------
# Events -> observations
# ---------------------------------------------------------------------------
def from_login(*, ts: float, user: str, source_ip: str, message: str, tz: tzinfo | None,
               row_id: int = 0) -> list[Obs]:
    account = _short(user, 64)
    if not account:
        return []
    bucket = B.bucket(source_ip)
    method = login_method(message)
    base = {"address": _short(source_ip, 64), "bucket": bucket.bucket, "class": bucket.cls, "method": method}
    out = [Obs("login_source", account, bucket.bucket, ts, base, row_id),
           Obs("login_method", account, method, ts, base, row_id)]
    if tz is not None:
        out.append(Obs("login_time", account, hour_key(ts, tz), ts, {**base, "zone": str(tz)}, row_id))
    return out


def from_sudo(*, ts: float, user: str, run_as: str, program: str, command: str, row_id: int = 0) -> list[Obs]:
    who = _short(user, 64)
    if not who:
        return []
    prog = _short((program or "").rsplit("/", 1)[-1], 64) or "?"
    return [Obs("sudo_use", who, sudo_key(_short(run_as, 64) or "root", prog), ts,
                {"command": _short(command, 200), "run_as": _short(run_as, 64) or "root"}, row_id)]


def from_program(*, ts: float, exe: str, parent: str | None, row_id: int = 0) -> list[Obs]:
    path = _short(exe, 200)
    if not path or not parent:
        return []
    return [Obs("program", path, program_key(_short(parent, 200)), ts, {"parent": _short(parent, 200)}, row_id)]


# ---------------------------------------------------------------------------
# Saved running-process reads -> observations
# ---------------------------------------------------------------------------
def from_snapshot(doc: dict[str, Any]) -> tuple[list[Obs], list[str]]:
    """(observations, notes) from one saved live-response read (kratos.live.record)."""
    ts = float(doc.get("checked_at_epoch") or 0)
    out: list[Obs] = []
    notes: list[str] = []
    unknown = 0
    for li in doc.get("listeners") or []:
        if not isinstance(li, dict) or not isinstance(li.get("port"), int):
            continue
        exe = _short(li.get("exe"), 200)
        if not li.get("seen") or not exe:
            unknown += 1
            continue
        out.append(Obs("listener", exe, listener_key(str(li.get("proto") or ""), li["port"]), ts,
                       {"address": _short(li.get("address"), 64), "package": _short(li.get("package"), 80)}))
    if unknown:
        notes.append(f"{unknown} listening port(s) whose program this read couldn't see")
    outbound = doc.get("outbound")
    if isinstance(outbound, list):
        for o in outbound:
            if not isinstance(o, dict) or not isinstance(o.get("remote_port"), int):
                continue
            exe = _short(o.get("exe"), 200)
            if not exe:
                continue
            bucket = B.bucket(o.get("remote"))
            if bucket.cls == "loopback":
                continue
            out.append(Obs("outbound", exe, outbound_key(bucket, o["remote_port"]), ts,
                           {"address": _short(o.get("remote"), 64), "class": bucket.cls}))
    return out, notes


def subjects(obs: Iterable[Obs]) -> set[tuple[str, str]]:
    return {(o.dim, o.subject) for o in obs}
