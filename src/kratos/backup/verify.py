"""Checking a backup, at two depths, and the restore drill (docs/phaseD/D.8 §3.8).

- `quick(file)` needs NO secret: the age header's shape, the file's size and the public
  sidecar (the encrypted file's SHA-256). It catches truncation and bit rot on a backup
  drive.
- `full(file, identities)` decrypts the whole stream (nothing written but the database
  copies, inside ``<data>/.backup-work``, removed afterwards) and checks every chunk, every
  file against the manifest's hash, each database's integrity and that it opens with this
  Kratos's migrations, that the agent-link keys match the recorded pins, and that the
  journal-seal keys parse.
- `drill(file, identities)` is `full` plus a real restore into a scratch Kratos home
  (inside ``.backup-work``) and `kratos doctor --offline` run against it, then the
  scratch home is removed. A backup counts as VERIFIED only once a drill has passed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.backup import agefmt as A
from kratos.backup import archive as AR
from kratos.backup import store as BR

Progress = Callable[[str], None]


def _noop(_t: str) -> None:
    return None


@dataclass
class Check:
    ok: bool
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    manifest: dict[str, Any] | None = None
    seconds: float = 0.0
    origin: Any = None

    def fail(self, text: str) -> None:
        self.ok = False
        self.problems.append(text)


def _sha(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def quick(path: Path | str, *, data_dir: Path | None = None) -> Check:
    """No secret needed. With `data_dir`, also says whether this Kratos signed it."""
    from kratos.backup import origin as O
    from kratos.backup.create import read_sidecar

    t0 = time.monotonic()
    path = Path(path)
    c = Check(True)
    if not path.is_file():
        c.fail(f"{path} is not a file")
        return c
    if path.name.endswith(".partial"):
        c.fail("this is an unfinished backup (.partial): the run that wrote it was interrupted")
    try:
        with open(path, "rb") as f:
            header, hlen = A.read_header_only(f)
    except A.AgeError as e:
        c.fail(f"not a readable age file: {e}")
        return c
    kinds = [s.args[0].decode("ascii", "replace") for s in header.stanzas]
    c.notes.append("locked with a passphrase" if kinds == ["scrypt"] else
                   f"encrypted to {kinds.count('X25519')} recipient key(s)")
    size = path.stat().st_size
    if size < hlen + A.NONCE_LEN + A.TAG:
        c.fail("the file is shorter than an age file can be: it is truncated")
    side = path.with_name(path.name + ".sha256")
    meta = read_sidecar(side)
    sha = n = None
    if meta is None:
        c.notes.append(f"no sidecar ({side.name}); only the header and size were checked")
    else:
        sha, n = _sha(path)
        if meta.get("size") != n:
            c.fail(f"the file is {n} bytes, its sidecar says {meta.get('size')}: it was truncated or changed")
        if meta["sha256"] != sha:
            c.fail("the file's SHA-256 doesn't match its sidecar: the file is damaged (bit rot or a bad copy)")
        if meta.get("name") and meta["name"] != path.name:
            c.notes.append(f"the sidecar names {meta['name']} (this file was renamed)")
        c.notes.append(f"made by Kratos {meta.get('kratos', '?')} at {meta.get('created', '?')}")
    c.origin = O.origin_of(meta, sha, n, data_dir)
    if c.origin.status == "bad":
        c.fail(f"who made it: {c.origin.describe()}")
    elif data_dir is not None or c.origin.status == "unsigned":
        c.notes.append(c.origin.describe())
    else:
        c.notes.append(f"signed by {c.origin.signer}")
    c.seconds = time.monotonic() - t0
    return c


def _check_db(db: Path) -> list[str]:
    from kratos.backup import stores

    problems = []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        res = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
        if res != ["ok"]:
            problems.append(f"{db.name}: SQLite integrity check failed: {'; '.join(map(str, res[:3]))}")
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        versions = ({r[0]: int(r[1]) for r in conn.execute("SELECT component, version FROM schema_versions")}
                    if "schema_versions" in names else {})
    finally:
        conn.close()
    newer = stores.newer_components(versions)
    if newer:
        problems.append("written by a newer Kratos: " + ", ".join(f"{c} {v[0]} > {v[1]}" for c, v in newer.items()))
    elif db.name == "kratos.db":
        try:
            stores.migrate_all(db)
        except Exception as e:  # noqa: BLE001 -- said in plain words
            problems.append(f"kratos.db doesn't open with this Kratos's migrations: {type(e).__name__}: {e}")
    return problems


def _check_key(member: AR.Member, data: bytes, manifest: dict[str, Any]) -> str | None:
    rel = member.rel
    keys = manifest.get("keys") or {}
    if rel.startswith("subagent-tls/key-") and rel.endswith(".pem"):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        from kratos.subagent import tls

        try:
            pin = tls.public_key_pin(load_pem_private_key(data, password=None))
        except Exception as e:  # noqa: BLE001
            return f"{member.path}: not a readable private key ({type(e).__name__})"
        pins = (keys.get("agent_link") or {}).get("pins") or []
        if pin not in pins:
            return f"{member.path}: this agent-link key doesn't match the pins the agents were given"
    elif rel.startswith("fss/") and rel.endswith(".json"):
        from kratos.logsources import seal

        try:
            doc = json.loads(data)
            seal.validate_key(str(doc.get("key", "")))
        except Exception as e:  # noqa: BLE001
            return f"{member.path}: the journal-seal key doesn't parse ({type(e).__name__})"
    elif rel == "signing/ed25519.key":
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key

        try:
            try:
                load_pem_private_key(data, password=None)
            except ValueError:
                load_ssh_private_key(data, password=None)
        except Exception as e:  # noqa: BLE001
            return f"{member.path}: the signing key doesn't load ({type(e).__name__})"
    return None


def _is_key_file(rel: str) -> bool:
    return ((rel.startswith("subagent-tls/key-") and rel.endswith(".pem")) or
            (rel.startswith("fss/") and rel.endswith(".json")) or rel == "signing/ed25519.key")


def full(path: Path | str, identities: list[object], *, data_dir: Path, progress: Progress = _noop,
         _lock_held: bool = False) -> Check:
    """Decrypt and check everything. Database copies go to `<data>/.backup-work` only."""
    from kratos.backup.create import work_dir

    t0 = time.monotonic()
    path = Path(path)
    c = quick(path, data_dir=Path(data_dir))
    if not c.ok and any("not a readable" in p for p in c.problems):
        return c
    from kratos.backup import inuse

    lock = None if _lock_held else inuse.backup_lock(Path(data_dir))
    if lock is None and not _lock_held:
        c.fail("another backup, check, drill or restore of this data is running; try again when it has finished")
        return c
    scratch = work_dir(Path(data_dir)) / f"verify-{uuid.uuid4().hex[:12]}"
    os.mkdir(scratch, 0o700)
    try:
        with AR.opened(path, identities) as ar:
            m = ar.read_manifest()
            c.manifest = m
            need = AR.newer_than_this(m)
            if need:
                c.fail(f"made by Kratos {need}, newer than this one: update Kratos before restoring it")
            progress(f"checking {m['totals']['files']} files")
            pins_seen: set[str] = set()
            for member in ar.members():
                if member.entry.get("kind") == "db":
                    dst = scratch / member.rel
                    os.makedirs(dst.parent, mode=0o700, exist_ok=True)
                    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as w:
                        for block in member.chunks():
                            w.write(block)
                    c.problems += _check_db(dst)
                elif member.prefix == "data" and _is_key_file(member.rel):
                    data = member.read_all(cap=1 << 20)
                    problem = _check_key(member, data, m)
                    if problem:
                        c.problems.append(problem)
                    elif member.rel.startswith("subagent-tls/key-"):
                        pins_seen.add(member.rel)
                else:
                    for _ in member.chunks():
                        pass
            ar.finish()
            pins = ((m.get("keys") or {}).get("agent_link") or {}).get("pins") or []
            if pins and len(pins_seen) < len(set(pins)):
                c.problems.append(f"the agent links are pinned to {len(set(pins))} keys but the backup holds "
                                  f"{len(pins_seen)}")
    except A.PayloadError as e:
        c.fail(f"the backup is damaged at chunk {e.chunk} (about {(e.chunk or 0) * 64} KiB into the encrypted "
               f"data): {e}")
    except A.NoMatchError:
        c.fail("the key or passphrase given doesn't open this backup (wrong key)")
    except A.AgeError as e:
        c.fail(f"the backup can't be decrypted: {e}")
    except AR.ArchiveError as e:
        c.fail(str(e))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)   # deletion-scan: this check's own scratch copies
        inuse.release(lock)
    c.ok = not c.problems
    c.seconds = time.monotonic() - t0
    return c


def _authorize(actor: Any, data_dir: Path, what: str) -> None:
    from kratos import authz
    from kratos.backup.create import BackupError

    try:
        authz.require(actor, authz.P.BACKUP_MANAGE, data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise BackupError(f"refused: {e}") from None


def record_verify(data_dir: Path, path: Path, actor: Any, c: Check, *, depth: str) -> None:
    BR.record(Path(data_dir), "verify", actor, "ok" if c.ok else "failed", file=str(path),
              size=path.stat().st_size if path.exists() else None,
              detail={"depth": depth, "notes": c.notes, "seconds": round(c.seconds, 2)},
              error="; ".join(c.problems) or None)


@dataclass
class DrillResult(Check):
    doctor: list[str] = field(default_factory=list)
    restored_files: int = 0


def drill(path: Path | str, identities: list[object], *, data_dir: Path, actor: Any,
          progress: Progress = _noop, accept_signer: str | None = None,
          accept_unsigned: bool = False) -> DrillResult:
    """`full`, then a real restore into a scratch home, then `kratos doctor --offline`
    against it; the scratch home is removed. Recorded in this Kratos's backup_runs.

    Only a backup this Kratos signed (or one whose signer the person confirms) is drilled,
    and the health check never runs code or settings from the backup: kept tools are not
    imported, the restored .env is not loaded, and Python runs isolated (-I)."""
    from kratos.backup import restore as RS
    from kratos.backup.create import work_dir
    from kratos.backup.plan import Roots

    data_dir = Path(data_dir)
    path = Path(path)
    _authorize(actor, data_dir, "backup drill")
    from kratos.backup import inuse

    run_id = BR.start(data_dir, "drill", actor, file=str(path))
    t0 = time.monotonic()
    res = DrillResult(True)
    home = work_dir(data_dir) / f"drill-{uuid.uuid4().hex[:12]}"
    lock = inuse.backup_lock(data_dir)
    try:
        if lock is None:
            raise RuntimeError("another backup, check, drill or restore of this data is running; try again later")
        from kratos.backup import origin as O

        meta = _sidecar_of(path) if path.is_file() else None
        o = O.origin_of(meta, *(_sha(path) if meta else (None, None)), data_dir)
        O.require_trusted(o, accept_signer=accept_signer, accept_unsigned=accept_unsigned, action="drill it",
                          has_local_key=O.signer_fingerprint(data_dir) is not None)
        progress("checking every file")
        c = full(path, identities, data_dir=data_dir, progress=progress, _lock_held=True)
        res.problems, res.notes, res.manifest = list(c.problems), list(c.notes), c.manifest
        if c.problems:
            res.ok = False
        else:
            progress("restoring into a scratch home")
            os.mkdir(home, 0o700)
            roots = Roots(home / "data", home, home)
            r = RS.restore(path, identities, roots=roots, actor=actor, authorize=False, check_running=False,
                           kind="drill")    # who made it was checked above, before anything was decrypted
            res.restored_files = r.files
            env = roots.config / ".env"
            if env.exists():
                os.rename(env, env.with_name(".env.restored-not-loaded"))   # the check never loads its settings
            progress("running `kratos doctor --offline` on the restored copy")
            code, lines = _doctor(home)
            res.doctor = lines
            fails = [ln for ln in lines if ln.startswith("FAIL")]
            if code != 0 or fails:
                res.fail("the restored copy's health check failed: " + ("; ".join(fails[:5]) or f"exit {code}"))
        res.ok = not res.problems
    except Exception as e:  # noqa: BLE001 -- the drill says why it failed
        from kratos.backup.origin import UntrustedBackup

        res.fail(str(e) if isinstance(e, UntrustedBackup) else f"{type(e).__name__}: {e}")
    finally:
        if home.exists():
            shutil.rmtree(home, ignore_errors=True)   # deletion-scan: the drill's own scratch home
        inuse.release(lock)
        res.seconds = time.monotonic() - t0
        BR.finish(data_dir, run_id, "ok" if res.ok else "failed", file=str(path),
                  size=path.stat().st_size if path.exists() else None,
                  detail={"seconds": round(res.seconds, 2), "files": res.restored_files,
                          "doctor_fails": [ln for ln in res.doctor if ln.startswith("FAIL")][:10]},
                  error="; ".join(res.problems) or None)
    return res


def _sidecar_of(path: Path) -> dict[str, Any] | None:
    from kratos.backup.create import read_sidecar

    return read_sidecar(path.with_name(path.name + ".sha256"))


def _doctor(home: Path) -> tuple[int, list[str]]:
    """`kratos doctor --offline` against the scratch home, without running anything the
    backup brought: KRATOS_NO_KEPT_TOOLS keeps its kept tools unimported, -I keeps the
    scratch folder (and PYTHON* variables) off the import path."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("KRATOS_", "LLM_", "XDG_", "PYTHON", "LD_"))}
    env.update(KRATOS_HOME=str(home), HOME=os.environ.get("HOME", str(home)), NO_COLOR="1",
               KRATOS_NO_KEPT_TOOLS="1")
    proc = subprocess.run([sys.executable, "-I", "-m", "kratos.cli.app", "doctor", "--offline"], env=env,
                          capture_output=True, timeout=300, stdin=subprocess.DEVNULL, cwd=str(home))
    text = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, [ln.rstrip() for ln in text.splitlines() if ln.strip()]
