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
from the public key), or -- on a machine enrolled in SSH certificates (D.1) -- a
certificate signed by one of Kratos's user CA keys (active, next, or retired within
WINDOW_DAYS) whose key id starts with ``kratos:``. sshd logs both:
``Accepted publickey ... ssh2: ED25519-CERT SHA256:<key> ID kratos:<m>:<run>:<n>
(serial <n>) CA ED25519 SHA256:<ca>``. The key id alone is never enough: anyone with
any CA can write it. Nothing is sent to the machine; both logs are already synced.
Someone holding Kratos's private key or CA would be treated as Kratos: those are the
credentials Kratos is trusted with.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
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
# sshd's certificate login: "<KEY>-CERT SHA256:<key> ID <key id> (serial <n>) CA <CAKEY> SHA256:<ca>"
_CERT = re.compile(r"-CERT SHA256:[A-Za-z0-9+/]{43} ID (?P<id>\S+) \(serial \d+\) CA \S+ "
                   r"(?P<ca>SHA256:[A-Za-z0-9+/]{43})\b")
KEY_ID_PREFIX = "kratos:"


@dataclass(frozen=True)
class OwnIdentity:
    """What makes an sshd "Accepted" line Kratos's own: its long-lived key, or a
    certificate from one of its user CAs with a ``kratos:`` key id."""
    key_fingerprints: frozenset[str] = frozenset()
    ca_fingerprints: frozenset[str] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.key_fingerprints or self.ca_fingerprints)

    def matches(self, message: str) -> bool:
        if self.key_fingerprints and any(fp in self.key_fingerprints for fp in _FP.findall(message)):
            # a certificate line names the certified key first; that key is a one-run key,
            # never the long-lived one, so a key match here is a plain-key login
            return True
        if self.ca_fingerprints:
            for m in _CERT.finditer(message):
                if m.group("id").startswith(KEY_ID_PREFIX) and m.group("ca") in self.ca_fingerprints:
                    return True
        return False


def kratos_identity(data_dir: Path | str | None = None, *, now: float | None = None) -> OwnIdentity:
    """Kratos's long-lived key fingerprint, plus its user CA keys when `data_dir` has a CA."""
    fp = kratos_fingerprint()
    cas: frozenset[str] = frozenset()
    if data_dir is not None:
        try:
            from kratos.sshca import ca

            cas = frozenset(ca.trusted_user_fingerprints(Path(data_dir), now=now))
        except Exception:  # noqa: BLE001 -- an unreadable CA record must not break detection
            cas = frozenset()
    return OwnIdentity(frozenset({fp}) if fp else frozenset(), cas)


def _identity(fp: "str | OwnIdentity | None") -> OwnIdentity:
    if isinstance(fp, OwnIdentity):
        return fp
    return OwnIdentity(frozenset({fp}) if fp else frozenset())


def is_own_login(action: Any, message: Any, fp: "str | OwnIdentity | None") -> bool:
    """An sshd "Accepted ..." line for a login made by Kratos itself -- Kratos logging
    in to read the machine, not something that happened on it (a root-login rule would
    otherwise fire on every collection where Kratos's SSH user is root). `fp` is the old
    key's fingerprint, or an OwnIdentity that also knows Kratos's CAs."""
    ident = _identity(fp)
    if not ident or action != "ssh_success_login" or not isinstance(message, str):
        return False
    return ident.matches(message)


LOGIN_SLACK_SECONDS = 120.0       # the audit login records follow sshd's "Accepted" line within this
MAX_SESSION_SECONDS = 3600.0      # a Kratos login lasts a collection plus 60 s idle; an hour bounds it
RECORDED_SLACK_SECONDS = 600.0    # around a session id read directly (Kratos's clock vs the machine's)

Intervals = dict[str, list[tuple[float, float]]]


def own_sessions(conn: Any, target_key: str, *, since: float, fp: "str | OwnIdentity | None") -> Intervals:
    """Audit session ids of the logins made with Kratos's key on this machine since `since`,
    each with when it was Kratos's: from the login to its logout (or an hour). Session ids
    restart at every boot, so an id counts only within that interval. A login is matched by
    sshd's pid AND time (pids are reused too)."""
    ident = _identity(fp)
    if not ident:
        return {}
    accepted: dict[int, list[float]] = {}
    for ts, doc in conn.execute(
            "SELECT ts, doc FROM host_events WHERE target = ? AND dataset = 'kratos.auth' AND action = "
            "'ssh_success_login' AND ts >= ?", (target_key, since)):
        d = json.loads(doc)
        pid = (d.get("process") or {}).get("pid")
        if isinstance(pid, int) and ident.matches(str(d.get("message") or "")):
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
