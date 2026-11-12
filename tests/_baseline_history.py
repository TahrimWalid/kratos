"""Test helper: a machine's stored history for baselining, written through the generator in
scripts/dev/generate_baseline_history.py (the real classifier, converters and event store)."""
from __future__ import annotations

import importlib.util
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

END = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)      # a Thursday
_GEN = Path(__file__).resolve().parents[1] / "scripts" / "dev" / "generate_baseline_history.py"


def gen():
    spec = importlib.util.spec_from_file_location("generate_baseline_history", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = gen()
OWN_FP = G._fp("kratos-own-key")


def identity():
    from kratos.detect.own import OwnIdentity

    return OwnIdentity(frozenset({OWN_FP}))


def machine(i: int = 0, *, zone: str = "UTC", target: str | None = None, seed: int = 1):
    m = G.Machine(i, random.Random(f"{seed}:{i}"), zone, OWN_FP, "ubuntu")
    if target:
        m.target = target
    return m


def normal_days(m, *, days: int = 21, end: datetime = END) -> None:
    local_end = end.astimezone(m.zone)
    d = (local_end - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    while d < local_end - timedelta(days=1):
        m.day(d)
        d = (d + timedelta(days=1, hours=3)).replace(hour=0)


def write(home: Path, machines, *, days: int = 21, end: datetime = END, gaps=None, note=None) -> Path:
    home.mkdir(parents=True, exist_ok=True)
    kw = {"gaps": gaps}
    if note:
        kw["note"] = note
    G.write(home, list(machines), end, days, **kw)
    return home / "data"


def set_zone(data: Path, target: str, zone: str, *, stamp: int = 1) -> None:
    logs = data / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / f"auth_stats_w1_zz_{stamp}.json"
    path.write_text(json.dumps({"source": f"ssh_target_measurement:ubuntu@{target}", "measurement": "exhaustive",
                                "target_timezone": {"name": zone, "offset": None}}), encoding="utf-8")
    import os
    import time

    t = time.time() + stamp
    os.utime(path, (t, t))


def at(local: str, zone: str = "UTC") -> float:
    from zoneinfo import ZoneInfo

    return datetime.fromisoformat(local).replace(tzinfo=ZoneInfo(zone)).timestamp()


def run(data: Path, target: str, *, now: float | None = None):
    import kratos.collect.checks  # noqa: F401 -- registers the snapshot sources
    from kratos.baseline import record

    return record.run(data, target, now=END.timestamp() if now is None else now, fingerprint=identity())


def raised(doc) -> set[tuple[str, str, str]]:
    return {(d["rule"], d["subject"], d["key"]) for d in doc.get("deviations") or []}


def add_logins(data: Path, target: str, rows, sudo=()) -> None:
    """Store more sign-ins (ts, user, ip, method) and sudo uses (ts, user, run_as, command)
    the way log sync would."""
    from kratos.adapters.auth_log_parse import classify_auth_message
    from kratos.events import converters as C
    from kratos.events.store import EventStore

    m = machine(0, target=target)
    ctx = C.ReadContext(target=target, transport="ssh", read=C.READ_JOURNAL_AUTH)
    events = []
    for ts, user, ip, method in rows:
        msg = G._login_message(m, user, ip, method)
        iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
        events.append(C.from_auth_event(classify_auth_message(iso, None, "sshd", msg, msg), ctx=ctx))
    for ts, user, run_as, cmd in sudo:
        msg = f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER={run_as} ; COMMAND={cmd}"
        iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
        events.append(C.from_auth_event(classify_auth_message(iso, None, "sudo", msg, msg), ctx=ctx))
    EventStore(data / "kratos.db").add(events)
