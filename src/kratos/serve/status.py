"""The chat server's status file: `data_dir/serve/status.json` (0600, folder 0700).

Written by the running server (start, every investigation start/finish, clean stop) and
read by `kratos serve status` and `/doctor` -- separate processes, so a file, not memory.
Never deleted: a clean stop writes `running: false`; a crash leaves `running: true` with a
pid that is no longer alive, which the reader reports as "not running (last seen …)".
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

FILENAME = "status.json"


def path(data_dir: Path) -> Path:
    return Path(data_dir) / "serve" / FILENAME


def write(data_dir: Path, **fields: Any) -> None:
    from kratos.paths import write_private_text

    record = {"pid": os.getpid(), "updated_at": time.time(), **fields}
    try:
        write_private_text(path(data_dir), json.dumps(record, sort_keys=True))
    except OSError:
        pass                                   # a status file never stops the server


def _alive(pid: Any) -> bool:
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError, TypeError):
        return False
    return True


def read(data_dir: Path) -> dict[str, Any]:
    """{"running": bool, "host", "port", "active", "waiting", "started_at", "updated_at",
    "pid"}; {"running": False} when the server has never run here."""
    try:
        record = json.loads(path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"running": False}
    if not isinstance(record, dict):
        return {"running": False}
    record["running"] = bool(record.get("running")) and _alive(record.get("pid"))
    return record


def summary(data_dir: Path) -> str:
    """One plain line: "running on 127.0.0.1:8770, 1 investigation running, 2 tokens"."""
    from kratos.serve import store as _store

    st = read(data_dir)
    try:
        tokens = sum(1 for t in _store.list_tokens(data_dir) if not t.get("revoked_at"))
    except Exception:  # noqa: BLE001
        tokens = 0
    tok = f"{tokens} token{'s' if tokens != 1 else ''}"
    if not st.get("running"):
        return f"not running ({tok})"
    active = int(st.get("active") or 0)
    waiting = int(st.get("waiting") or 0)
    runs = f"{active} investigation{'s' if active != 1 else ''} running" + (f", {waiting} waiting" if waiting else "")
    return f"running on {st.get('host')}:{st.get('port')}, {runs}, {tok}"
