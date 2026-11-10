"""Shared fixtures for the D.8 backup tests: a scratch Kratos home with real stores and keys,
and a builder for hand-made (hostile) backup archives. Neutral values only."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
from typing import Any

from kratos.backup import agefmt as A
from kratos.backup.plan import Roots
from kratos.lifecycle.decide import Actor

CLI = Actor(user="tester", interface="cli", user_id="owner")
TUI = Actor(user="tester", interface="tui", user_id="owner")


def home(tmp: Path, name: str = "home") -> Roots:
    h = tmp / name
    (h / "data").mkdir(parents=True, exist_ok=True)
    return Roots(h / "data", h, h)


def seed(roots: Roots, *, with_keys: bool = True, events: int = 20) -> None:
    """Real stores in a scratch home: sessions, a finding decision trail, host events, the
    agent-link keys, a signing key, a journal seal key, a kept tool and a settings file."""
    from kratos.events.store import EventStore
    from kratos.storage.session_store import SessionStore

    dd = roots.data
    ss = SessionStore(dd / "kratos.db")
    sid = ss.create_session(["192.0.2.10"], "test")
    ss.start_turn(sid, "check the logins of alice")
    (dd / "sessions").mkdir(exist_ok=True)
    (dd / "sessions" / "s1_turn1.json").write_text(json.dumps({"goal": "check alice@example.com"}))
    (dd / "reports").mkdir(exist_ok=True)
    (dd / "reports" / "findings_x.json").write_text(json.dumps({"findings": []}))
    if events:
        EventStore(dd / "kratos.db").add([event(i) for i in range(events)])
    (dd / "presets").mkdir(exist_ok=True)
    (dd / "presets" / "p.toml").write_text('name = "p"\nkind = "goal"\ngoal = "look"\n')
    (roots.state / "kept_tools").mkdir(parents=True, exist_ok=True)
    (roots.state / "kept_tools" / "tool_x.py").write_text("X = 1\n")
    env = roots.config / ".env"
    env.write_text("LLM_MODEL=example-model\nLLM_API_KEY=test-key-" + "z" * 20 + "\n")
    os.chmod(env, 0o600)
    if with_keys:
        from kratos import signing
        from kratos.subagent import tls

        tls.ensure_keys(dd)
        signing.load_key(dd, create=True)
        fss = dd / "fss"
        fss.mkdir(mode=0o700, exist_ok=True)
        (fss / "m1.json").write_text(json.dumps({"target": "192.0.2.10", "key": "a1b2c3-d4e5f6-a7b8c9-d0e1f2/1a2b3c-35a4e900"}))
        os.chmod(fss / "m1.json", 0o600)


def event(minute: int, user: str = "alice") -> Any:
    from datetime import datetime, timedelta, timezone

    from kratos.adapters.auth_log_parse import classify_auth_message
    from kratos.events import converters as C

    t0 = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
    msg = f"Failed password for invalid user {user} from 198.51.100.7 port {1000 + minute} ssh2"
    ts = (t0 + timedelta(minutes=minute)).isoformat()
    ctx = C.ReadContext(target="192.0.2.10", transport="ssh", read=C.READ_JOURNAL_AUTH, created=t0, run_id="r1")
    return C.from_auth_event(classify_auth_message(ts, "192.0.2.10", "sshd", msg, msg), ctx=ctx)


def identity() -> A.X25519Identity:
    return A.X25519Identity.generate()


def set_recipient(roots: Roots, ident: A.X25519Identity) -> None:
    from kratos.backup import keys as K

    K.add_recipient(roots.data, str(ident.recipient()), actor="test")


def all_files(root: Path) -> dict[str, bytes]:
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = Path(dirpath) / f
            if p.is_file() and not p.is_symlink():
                out[str(p.relative_to(root))] = p.read_bytes()
    return out


def craft(dest: Path, recipient: A.X25519Recipient, members: list[tuple[tarfile.TarInfo, bytes | None]],
          manifest: dict[str, Any] | None = None, *, manifest_first: bool = True) -> Path:
    """A backup file built by hand: `members` go in as given (a TarInfo and its bytes), after
    a manifest that lists `manifest` (default: every regular member with its real hash)."""
    if manifest is None:
        files = []
        for ti, data in members:
            if ti.isreg() and data is not None:
                files.append({"path": ti.name, "category": "sessions", "kind": "file", "size": len(data),
                              "mode": 0o600, "sha256": hashlib.sha256(data).hexdigest(), "mtime": 0})
        manifest = {"format": "kratos-backup/1", "kratos_version": "0.1.0", "files": files,
                    "totals": {"files": len(files), "bytes": sum(f["size"] for f in files)}}
    blob = json.dumps(manifest).encode()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            mti = tarfile.TarInfo("MANIFEST.json")
            mti.size = len(blob)
            if manifest_first:
                tar.addfile(mti, io.BytesIO(blob))
            for ti, data in members:
                tar.addfile(ti, io.BytesIO(data) if data is not None else None)
            if not manifest_first:
                tar.addfile(mti, io.BytesIO(blob))
    dest.write_bytes(A.encrypt_bytes(buf.getvalue(), [recipient]))
    return dest


def reg(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = 0o600
    return ti, data
