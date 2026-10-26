"""Kratos's own SSH logins on a machine, so its reads are not mistaken for an attacker's.

With an execve audit rule, auditd records every program Kratos runs over SSH: the
persistence check's `find / -perm -4000`, the configuration audit's `grep -i
^passwordauthentication` -- which SigmaHQ rules rightly call reconnaissance and
credential hunting. Those events are set aside, and only those:

- sshd logs each login with the key's fingerprint and its own pid
  (`sshd[5180]: Accepted publickey for ubuntu ... SHA256:<fingerprint>`);
- auditd's login records for that sshd pid carry the login's session id
  (`USER_START pid=5180 ... ses=168`), and every program started in that login
  carries the same `ses=168` -- assigned by the kernel, so another login on the same
  account can't take it on.

A login is Kratos's when it used Kratos's own SSH key (its fingerprint, computed here
from the public key). Nothing is sent to the machine; both logs are already synced.
Someone holding Kratos's private key would be treated as Kratos: that key is the
credential Kratos is trusted with.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_LOGIN_ACTIONS = ("user_login", "session_started", "user_auth")
WINDOW_DAYS = 7


def fingerprint(pubkey_text: str) -> str | None:
    """'SHA256:<base64, no padding>' of an OpenSSH public key line, as sshd logs it."""
    parts = (pubkey_text or "").strip().split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def kratos_fingerprint() -> str | None:
    """The fingerprint of the key Kratos logs in with (SSH_TARGET_KEY_PATH + .pub)."""
    from kratos import kratos_config

    key = getattr(kratos_config, "SSH_TARGET_KEY_PATH", None)
    if not key:
        return None
    try:
        return fingerprint(Path(str(key) + ".pub").expanduser().read_text(encoding="utf-8"))
    except OSError:
        return None


_FP = re.compile(r"\bSHA256:[A-Za-z0-9+/]{43}\b")


def is_own_login(action: Any, message: Any, fp: str | None) -> bool:
    """An sshd "Accepted ..." line for a login made with Kratos's own key -- Kratos logging
    in to read the machine, not something that happened on it (a root-login rule would
    otherwise fire on every collection where Kratos's SSH user is root)."""
    if not fp or action != "ssh_success_login" or not isinstance(message, str):
        return False
    return fp in _FP.findall(message)


LOGIN_SLACK_SECONDS = 120.0       # the audit login records follow sshd's "Accepted" line within this
MAX_SESSION_SECONDS = 3600.0      # a Kratos login lasts a collection plus 60 s idle; an hour bounds it
RECORDED_SLACK_SECONDS = 600.0    # around a session id read directly (Kratos's clock vs the machine's)

Intervals = dict[str, list[tuple[float, float]]]


def own_sessions(conn: Any, target_key: str, *, since: float, fp: str | None) -> Intervals:
    """Audit session ids of the logins made with Kratos's key on this machine since `since`,
    each with when it was Kratos's: from the login to its logout (or an hour). Session ids
    restart at every boot, so an id counts only within that interval. A login is matched by
    sshd's pid AND time (pids are reused too)."""
    if not fp:
        return {}
    accepted: dict[int, list[float]] = {}
    for ts, doc in conn.execute(
            "SELECT ts, doc FROM host_events WHERE target = ? AND dataset = 'kratos.auth' AND action = "
            "'ssh_success_login' AND ts >= ?", (target_key, since)):
        d = json.loads(doc)
        pid = (d.get("process") or {}).get("pid")
        if isinstance(pid, int) and fp in _FP.findall(str(d.get("message") or "")):
            accepted.setdefault(pid, []).append(float(ts))
    if not accepted:
        return {}
    starts: dict[tuple[int, str], float] = {}
    ends: dict[tuple[int, str], float] = {}
    marks = ",".join("?" for _ in (*_LOGIN_ACTIONS, "session_ended"))
    for ts, action, doc in conn.execute(
            f"SELECT ts, action, doc FROM host_events WHERE target = ? AND dataset = 'kratos.auditd' "
            f"AND action IN ({marks}) AND ts >= ?", (target_key, *_LOGIN_ACTIONS, "session_ended", since)):
        d = json.loads(doc)
        pid = (d.get("process") or {}).get("pid")
        ses = ((d.get("kratos") or {}).get("audit") or {}).get("session")
        if not (isinstance(pid, int) and ses and pid in accepted):
            continue
        key = (pid, str(ses))
        if action == "session_ended":
            ends[key] = max(ends.get(key, 0.0), float(ts))
        elif any(-LOGIN_SLACK_SECONDS <= float(ts) - t <= LOGIN_SLACK_SECONDS for t in accepted[pid]):
            starts[key] = min(starts.get(key, float(ts)), float(ts))
    out: Intervals = {}
    for (pid, ses), start in starts.items():
        end = ends.get((pid, ses))
        end = end if end is not None and end >= start else start + MAX_SESSION_SECONDS
        out.setdefault(ses, []).append((start - 5.0, min(end, start + MAX_SESSION_SECONDS) + 5.0))
    return out


def merge(a: Intervals, b: Intervals) -> Intervals:
    out: Intervals = {k: list(v) for k, v in a.items()}
    for k, v in b.items():
        out.setdefault(k, []).extend(v)
    return out


def is_own(session: str | None, ts: float, own: Intervals) -> bool:
    return bool(session) and any(lo <= ts <= hi for lo, hi in own.get(str(session), ()))


_SESSION = re.compile(r"^\d{1,10}$")
UNSET_SESSION = "4294967295"


def read_current_session(target: str, data_dir: Path) -> str | None:
    """Ask the machine which audit session Kratos's own SSH login has (a fixed, read-only
    command over Kratos's shared connection) and record it. The logs say the same once
    synced; this covers the first collection on a machine, whose sync may start after the
    login record (an execve-audited machine logs tens of thousands of lines per collection)."""
    from kratos import kratos_config
    from kratos.adapters import ssh_remote
    from kratos.detect import store

    with kratos_config.pinned_target(target):
        res = ssh_remote.run_remote_command("cat /proc/self/sessionid", timeout=15)
    value = (res.stdout or "").strip() if getattr(res, "ok", False) else ""
    if not _SESSION.match(value) or value == UNSET_SESSION:
        return None
    store.record_own_session(data_dir, target, value)
    return value


def audited(data_dir: Path, target: str) -> bool:
    """Does Kratos hold audit-log events for this machine from the last WINDOW_DAYS? Only
    then can Kratos's own commands show up in what the rules read."""
    import time

    from kratos.storage.sqlite_files import connect_store
    from kratos.target_key import target_key

    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return False
    conn = connect_store(db)
    try:
        row = conn.execute("SELECT 1 FROM host_events WHERE target = ? AND dataset = 'kratos.auditd' AND ts >= ? "
                           "LIMIT 1", (target_key(target), time.time() - WINDOW_DAYS * 86400)).fetchone()
    except Exception:  # noqa: BLE001 -- no event table yet
        return False
    finally:
        conn.close()
    return row is not None
