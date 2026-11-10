"""Making a backup (docs/phaseD/D.8 §3.4–§3.7, §3.10).

1. The databases are copied with SQLite's online backup API from a read-only connection,
   in one step, so each copy is one consistent state while the listener keeps writing.
   The copy is checked (`PRAGMA integrity_check`, row counts) before it goes in.
2. Every other file is read once, hashed while it is copied into the owner-only work
   folder ``<data>/.backup-work`` (same disk as the data, which is plaintext already).
   A TPM-sealed CA key is unsealed in memory and never written anywhere.
3. ``tar`` (PAX) → gzip (level 6) → age STREAM → ``<name>.age.partial``; the first member is
   ``MANIFEST.json`` (every file's path, size, mode and SHA-256, database row counts, key
   fingerprints, the paired agents and the addresses they dial). Renamed to ``<name>.age``
   only after the last chunk is written and fsynced: a crash never leaves a file that
   looks complete. A public sidecar ``<name>.age.sha256`` (`sha256sum -c` reads it) holds
   the encrypted file's hash, its size and the Kratos version -- nothing personal.
4. The work folder is emptied when the backup ends and swept when the next one starts.

The encryption is to the recipients' PUBLIC keys: nothing on this computer can open a
backup made in recipient mode.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import tarfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable

from kratos import paths
from kratos.backup import agefmt as A
from kratos.backup import inuse, plan as P
from kratos.backup import store as BR

FORMAT = "kratos-backup/1"
WORK = ".backup-work"
DEFAULT_DEST = Path.home() / "kratos-backups"
NAME_RE = re.compile(r"^kratos-backup-\d{8}T\d{6}Z(?:-\d+)?\.age$")
MANIFEST = "MANIFEST.json"
GZIP_LEVEL = 6
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class BackupError(RuntimeError):
    """A backup that can't be made, said in plain words with the fix."""


@dataclass
class Result:
    file: Path
    sidecar: Path
    sha256: str
    size: int
    manifest: dict[str, Any]
    same_disk: bool
    copies: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    run_id: int | None = None
    seconds: float = 0.0
    stages: dict[str, float] = field(default_factory=dict)


Progress = Callable[[str, str], None]


def _noop(stage: str, detail: str) -> None:
    return None


# --------------------------------------------------------------------------- work folder
def work_dir(data_dir: Path) -> Path:
    """`<data>/.backup-work`, owner-only. Refuses a link or a folder others can read."""
    w = Path(data_dir) / WORK
    if os.path.islink(w):
        raise BackupError(f"{w} is a link; remove it -- the backup's scratch folder must be a real folder")
    paths.ensure_private_dir(w)
    st = os.lstat(w)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise BackupError(f"{w} is not a folder owned by you")
    if stat.S_IMODE(st.st_mode) & 0o077:
        os.chmod(w, 0o700)
    return w


def sweep_work(data_dir: Path) -> None:
    """Empty the scratch folder: what a killed backup left there (plaintext copies) goes."""
    w = Path(data_dir) / WORK
    if not w.is_dir() or os.path.islink(w):
        return
    for entry in os.listdir(w):
        p = w / entry
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)   # deletion-scan: the backup's own scratch copies
        else:
            os.unlink(p)       # deletion-scan: the backup's own scratch copies


def sweep_partials(dest: Path) -> list[str]:
    """A killed backup leaves only `<name>.age.partial` (never a final name); the next run
    removes them (it holds the backup lock, so none is being written)."""
    out = []
    if not dest.is_dir():
        return out
    for p in dest.iterdir():
        if p.name.startswith("kratos-backup-") and p.name.endswith(".age.partial") and p.is_file():
            p.unlink()        # deletion-scan: an unfinished backup from a killed run
            out.append(p.name)
    return out


def resolve_destination(data_dir: Path, dest: Path | str | None) -> Path:
    from kratos.backup import settings as BS

    text = str(dest or BS.get(BS.DESTINATION, data_dir) or "").strip()
    d = Path(text).expanduser() if text else DEFAULT_DEST
    if not d.is_absolute():
        raise BackupError("the backup folder must be an absolute path")
    real = Path(os.path.realpath(d))
    data_real = Path(os.path.realpath(data_dir))
    if real == data_real or _inside(real, data_real):
        raise BackupError(f"{d} is inside Kratos's data folder -- a backup there would be lost with the data; "
                          "choose another folder (the default is ~/kratos-backups)")
    paths.ensure_private_dir(d)
    return d


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.relative_to(folder)
        return True
    except ValueError:
        return False


def same_disk(a: Path, b: Path) -> bool:
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


# --------------------------------------------------------------------------- databases
def copy_database(src: Path, dst: Path, *, emptied: list[str] = (), scrub: bool = False) -> dict[str, Any]:
    """One consistent copy of a live SQLite database (WAL included), then checked."""
    if not src.is_file():
        raise BackupError(f"{src} is missing")
    uri = f"file:{src}?mode=ro"
    source = sqlite3.connect(uri, uri=True, timeout=30)
    try:
        source.execute("PRAGMA busy_timeout=30000")
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        target = sqlite3.connect(dst)
        try:
            source.backup(target, pages=-1)          # one step: a single read transaction
        finally:
            target.close()
    finally:
        source.close()
    conn = sqlite3.connect(dst, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")   # the copy is one file, no WAL
        changed = False
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        done_empty = []
        if emptied or scrub:
            conn.execute("PRAGMA secure_delete=ON")
        for t in emptied:
            if t in names and _IDENT.match(t):
                _empty_table(conn, t)
                done_empty.append(t)
                changed = True
        scrubbed = []
        if scrub:
            for table, what, _words in P.DB_SECRETS:
                if table not in names:
                    continue
                if what == "rows":
                    _empty_table(conn, table)
                else:
                    conn.execute(f"UPDATE {table} SET {what} = 'withheld:' || rowid")  # noqa: S608 -- names from DB_SECRETS
                scrubbed.append(f"{table}.{what}")
                changed = True
        if changed:
            conn.execute("VACUUM")                    # no freed page keeps a removed value
        check = conn.execute("PRAGMA integrity_check").fetchall()
        if [r[0] for r in check] != ["ok"]:
            raise BackupError(f"the copy of {src.name} failed SQLite's integrity check: "
                              + "; ".join(str(r[0]) for r in check[:3]))
        counts = {}
        for (t,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                                 "ORDER BY name"):
            if _IDENT.match(t):
                counts[t] = int(conn.execute(f"SELECT COUNT(*) FROM \"{t}\"").fetchone()[0])  # noqa: S608
        versions = {}
        if "schema_versions" in counts:
            versions = {r[0]: int(r[1]) for r in conn.execute("SELECT component, version FROM schema_versions")}
    finally:
        conn.close()
    return {"tables": counts, "schema_versions": versions, "integrity": "ok", "emptied": done_empty,
            "scrubbed": scrubbed}


def _empty_table(conn: sqlite3.Connection, table: str) -> None:
    """Empty a table in the scratch COPY, even one an append-only trigger guards: the
    triggers are taken off, the rows deleted, the triggers put back exactly as they were."""
    triggers = conn.execute("SELECT name, sql FROM sqlite_schema WHERE type='trigger' AND tbl_name = ?",
                            (table,)).fetchall()
    for name, _sql in triggers:
        conn.execute(f'DROP TRIGGER "{name}"')
    conn.execute(f'DELETE FROM "{table}"')  # deletion-scan: the scratch copy only, never the live database
    for _name, sql in triggers:
        if sql:
            conn.execute(sql)


# --------------------------------------------------------------------------- files
def _copy_file(src: Path, dst: Path, expect_size: int) -> tuple[str, int, int]:
    """Copy `src` into the work folder, hashing as it streams. (sha256, size, mode)."""
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as r:
        st = os.fstat(r.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise BackupError(f"{src} is no longer a regular file")
        dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        out = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h = hashlib.sha256()
        n = 0
        with os.fdopen(out, "wb") as w:
            for block in iter(lambda: r.read(1 << 20), b""):
                h.update(block)
                w.write(block)
                n += len(block)
    return h.hexdigest(), n, stat.S_IMODE(st.st_mode)


def _unseal(item: P.Item, data_dir: Path) -> bytes:
    from kratos.sshca import ca as _ca

    priv_path = item.source.with_name(item.source.name[: -len(".cred")])
    try:
        return _ca._unseal_private(data_dir, priv_path)
    except Exception as e:  # noqa: BLE001 -- explained below
        raise BackupError(f"this computer's TPM could not unseal the SSH CA key {priv_path.name} for the backup "
                          f"({e}); fix the TPM, or make a backup --without-secrets") from None


# --------------------------------------------------------------------------- manifest pieces
def _host_name() -> str:
    try:
        return socket.gethostname()[:255]
    except OSError:
        return "unknown"


def _key_fingerprints(data_dir: Path, db_copy: Path | None, plan: P.Plan) -> dict[str, Any]:
    out: dict[str, Any] = {}
    included = {d.key for d in plan.decisions if d.included}
    if "agent_link_keys" in included:
        try:
            from kratos.subagent import tls

            ks = tls.load_keys(data_dir)
            if ks is not None:
                out["agent_link"] = ks.as_pin_set()
        except Exception as e:  # noqa: BLE001 -- the manifest says it couldn't read them
            out["agent_link"] = {"error": f"{type(e).__name__}"}
    if "signing_key" in included:
        try:
            from kratos import signing

            info = signing.info(data_dir, create=False)
            if info is not None:
                out["signing"] = info.fingerprint
        except Exception:  # noqa: BLE001
            pass
    if "seal_keys" in included:
        try:
            from kratos.logsources import seal

            out["fss_machines"] = sorted({str(k.get("target")) for k in seal.keys_on_file(data_dir)})
        except Exception:  # noqa: BLE001
            pass
    if db_copy is not None:
        conn = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
        try:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            if "ssh_ca_keys" in names:
                rows = conn.execute("SELECT * FROM ssh_ca_keys").fetchall()
                cols = [d[0] for d in conn.execute("SELECT * FROM ssh_ca_keys LIMIT 0").description]
                cas = []
                for r in rows:
                    d = dict(zip(cols, r))
                    cas.append({k: d.get(k) for k in ("fingerprint", "kind", "role", "mode", "key_ref")})
                out["ssh_ca"] = cas
        finally:
            conn.close()
    return out


def _agents(db_copy: Path | None) -> list[dict[str, Any]]:
    if db_copy is None:
        return []
    conn = sqlite3.connect(f"file:{db_copy}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        if "subagent_targets" not in names:
            return []
        cols = {r[1] for r in conn.execute("PRAGMA table_info(subagent_targets)")}
        has_codes = "subagent_pairing_codes" in names and "core_host" in {
            r[1] for r in conn.execute("PRAGMA table_info(subagent_pairing_codes)")}
        out = []
        for r in conn.execute("SELECT * FROM subagent_targets WHERE revoked_at IS NULL ORDER BY target_id"):
            dial = r["core_addr"] if "core_addr" in cols else None
            paired = None
            if has_codes:
                row = conn.execute("SELECT core_host FROM subagent_pairing_codes WHERE used_by_target_id = ? "
                                   "AND core_host IS NOT NULL ORDER BY used_at DESC LIMIT 1",
                                   (r["target_id"],)).fetchone()
                paired = row[0] if row else None
            out.append({"target_id": r["target_id"], "name": r["name"], "hostname": r["hostname"],
                        "agent_version": r["agent_version"], "dials": dial or paired, "paired_with": paired})
        return out
    finally:
        conn.close()


def _agent_version() -> str | None:
    try:
        from kratos.subagent.agent import AGENT_VERSION

        return AGENT_VERSION
    except Exception:  # noqa: BLE001
        return None


def utc_stamp(t: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso(t: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).isoformat(timespec="seconds") \
        .replace("+00:00", "Z")


# --------------------------------------------------------------------------- the stream
class _HashingFile:
    """The destination file: counts and hashes every encrypted byte written."""

    def __init__(self, f: BinaryIO) -> None:
        self._f = f
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, data: bytes) -> int:
        self._f.write(data)
        self.h.update(data)
        self.n += len(data)
        return len(data)

    def flush(self) -> None:
        self._f.flush()


class _EncWriter(io.RawIOBase):
    """gzip writes here; it feeds the age Encryptor."""

    def __init__(self, enc: A.Encryptor) -> None:
        self._enc = enc

    def writable(self) -> bool:
        return True

    def write(self, b: Any) -> int:
        data = bytes(b)
        self._enc.write(data)
        return len(data)


def _tarinfo(name: str, size: int, mtime: float) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mode = 0o600
    ti.mtime = int(mtime)
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.type = tarfile.REGTYPE
    return ti


def _sidecar_text(name: str, sha: str, size: int, created: str) -> str:
    from kratos import __version__

    return (f"{sha}  {name}\n# kratos-backup-sidecar 1\n# size: {size}\n# kratos: {__version__}\n"
            f"# created: {created}\n")


def read_sidecar(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    out: dict[str, Any] = {}
    for line in text.splitlines():
        if line.startswith("# "):
            k, _, v = line[2:].partition(": ")
            if k in ("size", "kratos", "created"):
                out[k] = v.strip()
        elif re.match(r"^[0-9a-f]{64}  \S", line):
            out["sha256"], out["name"] = line[:64], line[66:]
    if "size" in out:
        try:
            out["size"] = int(out["size"])
        except ValueError:
            return None
    return out if "sha256" in out else None


# --------------------------------------------------------------------------- create
def _authorize(actor: Any, data_dir: Path, what: str) -> None:
    """D.7: backups are the owner's, at the Kratos host (an admin action, local only)."""
    from kratos import authz

    try:
        authz.require(actor, authz.P.BACKUP_MANAGE, data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise BackupError(f"refused: {e}") from None


def _lock_recipients(data_dir: Path, recipients: list[str] | None, passphrase: str | None,
                     scheduled: bool) -> tuple[list[Any], str, list[str]]:
    from kratos.backup import keys as K

    if passphrase is not None:
        if scheduled:
            raise BackupError("a scheduled backup can't use a passphrase (nobody is there to type it); set up a "
                              "backup key with `kratos backup key new`")
        if recipients:
            raise BackupError("use either recipient keys or a passphrase, not both (the age format forbids mixing)")
        K.check_passphrase(passphrase)
        return [A.ScryptRecipient(passphrase.encode("utf-8"))], "passphrase", []
    recs = list(recipients) if recipients else K.recipients(data_dir)
    if not recs:
        raise BackupError("no backup key is set up: run `kratos backup key new` (recommended -- the secret half "
                          "stays off this computer), or make a one-off backup with --passphrase")
    objs = [A.X25519Recipient.parse(r) for r in recs]
    return objs, "recipients", [K.fingerprint(r) for r in recs]


def create(data_dir: Path | str, *, actor: Any, dest: Path | str | None = None, recipients: list[str] | None = None,
           passphrase: str | None = None, exclude: tuple[str, ...] = (), include_rebuildable: bool = False,
           without_secrets: bool = False, copy_to: list[str] | None = None, scheduled: bool = False,
           progress: Progress = _noop, roots: P.Roots | None = None, fail_at: str | None = None,
           lock_held: bool = False) -> Result:
    """Make one encrypted backup. `fail_at` (tests only) raises at a named stage."""
    data_dir = Path(data_dir)
    t0 = time.monotonic()
    _authorize(actor, data_dir, "backup create")
    objs, lock, fps = _lock_recipients(data_dir, recipients, passphrase, scheduled)
    dest_dir = resolve_destination(data_dir, dest)
    lockfd = None if lock_held else inuse.backup_lock(data_dir)
    if lockfd is None and not lock_held:
        raise BackupError("another backup, check, drill or restore of this data is running; try again when it has "
                          "finished")
    run_id = BR.start(data_dir, "create", actor, scheduled=scheduled, lock=lock)
    stages: dict[str, float] = {}
    partial: Path | None = None
    work: Path | None = None
    try:
        if not lock_held:        # inside a restore, the restore's own staging folder is in there
            sweep_work(data_dir)
        swept = sweep_partials(dest_dir)
        work = work_dir(data_dir) / f"create-{os.getpid()}-{int(time.time() * 1000)}"
        os.mkdir(work, 0o700)
        the_plan = P.build(data_dir, exclude=tuple(exclude), include_rebuildable=include_rebuildable,
                           without_secrets=without_secrets, roots=roots)
        _check_space(work, dest_dir, the_plan)
        # 1. databases
        s = time.monotonic()
        progress("database", "copying the databases (consistent while Kratos keeps writing)")
        members: list[dict[str, Any]] = []
        memory: dict[str, bytes] = {}
        databases = []
        db_copy: Path | None = None
        for item in the_plan.items:
            if item.kind != "db":
                continue
            local = work / "files" / item.archive
            local.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            is_main = item.archive == f"data/{P.datainv.DB}"
            info = copy_database(item.source, local, emptied=the_plan.emptied_tables if is_main else [],
                                 scrub=without_secrets and is_main)
            if is_main:
                db_copy = local
            sha, size = _sha_file(local)
            members.append({"path": item.archive, "category": item.category, "kind": "db", "size": size,
                            "mode": 0o600, "sha256": sha, "mtime": int(time.time())})
            databases.append({"path": item.archive, **info})
        stages["database"] = time.monotonic() - s
        _maybe_fail(fail_at, "database")
        # 2. files
        s = time.monotonic()
        progress("files", f"reading {sum(1 for i in the_plan.items if i.kind != 'db')} files")
        for item in the_plan.items:
            if item.kind == "db":
                continue
            if item.kind == "ca_sealed":
                plain = _unseal(item, data_dir)
                name = item.archive[: -len(".cred")]
                memory[name] = plain
                members.append({"path": name, "category": item.category, "kind": "ca_unsealed",
                                "size": len(plain), "mode": 0o600, "sha256": hashlib.sha256(plain).hexdigest(),
                                "mtime": int(item.source.stat().st_mtime), "sealed_from": "tpm"})
                continue
            local = work / "files" / item.archive
            try:
                sha, size, mode = _copy_file(item.source, local, item.size)
            except FileNotFoundError:
                the_plan.skipped.append(f"{item.archive} (removed while the backup ran)")
                continue
            members.append({"path": item.archive, "category": item.category, "kind": "file", "size": size,
                            "mode": mode, "sha256": sha, "mtime": int(item.source.stat().st_mtime)
                            if item.source.exists() else int(time.time())})
        stages["files"] = time.monotonic() - s
        _maybe_fail(fail_at, "files")
        created = utc_iso()
        manifest = {
            "format": FORMAT, "kratos_version": _kratos_version(), "agent_version": _agent_version(),
            "layout": paths.LAYOUT, "created": created, "host": _host_name(),
            "lock": {"mode": lock, "recipients": fps},
            "options": the_plan.options,
            "categories": [{"key": d.key, "name": d.name, "class": d.cls, "included": d.included,
                            "reason": d.reason} for d in the_plan.decisions],
            "files": members, "databases": databases,
            "keys": _key_fingerprints(data_dir, db_copy, the_plan),
            "agents": _agents(db_copy),
            "not_included": the_plan.not_included, "skipped": the_plan.skipped,
            "totals": {"files": len(members), "bytes": sum(m["size"] for m in members)},
        }
        # 3. encrypt
        s = time.monotonic()
        progress("encrypt", "compressing and encrypting")
        name = _free_name(dest_dir)
        final = dest_dir / name
        partial = dest_dir / (name + ".partial")
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as raw:
            hf = _HashingFile(raw)
            enc = A.Encryptor(hf, objs)  # type: ignore[arg-type]
            gz = gzip.GzipFile(fileobj=_EncWriter(enc), mode="wb", compresslevel=GZIP_LEVEL, mtime=0)
            with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                blob = json.dumps(manifest, sort_keys=True, indent=1).encode("utf-8")
                tar.addfile(_tarinfo(MANIFEST, len(blob), time.time()), io.BytesIO(blob))
                for m in members:
                    _maybe_fail(fail_at, "encrypt-mid")
                    if m["path"] in memory:
                        data = memory[m["path"]]
                        tar.addfile(_tarinfo(m["path"], len(data), m["mtime"]), io.BytesIO(data))
                        continue
                    with open(work / "files" / m["path"], "rb") as f:
                        tar.addfile(_tarinfo(m["path"], m["size"], m["mtime"]), f)
            gz.close()
            enc.close()
            raw.flush()
            os.fsync(raw.fileno())
            sha, size = hf.h.hexdigest(), hf.n
        memory.clear()
        _maybe_fail(fail_at, "before-rename")
        os.rename(partial, final)
        partial = None
        side = dest_dir / (name + ".sha256")
        side_tmp = dest_dir / (name + ".sha256.partial")
        fd = os.open(side_tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_sidecar_text(name, sha, size, created))
            f.flush()
            os.fsync(f.fileno())
        os.replace(side_tmp, side)
        _fsync_dir(dest_dir)
        stages["encrypt"] = time.monotonic() - s
        # 4. copies
        s = time.monotonic()
        copies = []
        targets = list(copy_to) if copy_to is not None else _copy_targets(data_dir)
        for t in targets:
            progress("copies", f"copying to {t}")
            from kratos.backup import copies as C

            copies.append(C.copy(t, final, side, sha, data_dir=data_dir, work=work))
        stages["copies"] = time.monotonic() - s
        on_same = same_disk(dest_dir, data_dir)
        warnings = []
        if on_same:
            off = [c for c in copies if c.get("ok") and not c.get("same_disk")]
            if not off:
                warnings.append("this backup is on the same disk as the data it protects -- copy it somewhere "
                                "else (another disk, another computer: --copy-to, or `kratos backup schedule "
                                "--copy-to`)")
        for c in copies:
            if not c.get("ok"):
                warnings.append(f"the copy to {c['target']} failed: {c.get('error')}")
            elif c.get("same_disk"):
                warnings.append(f"the copy in {c['target']} is on the same disk as the data")
        if swept:
            warnings.append(f"removed {len(swept)} unfinished backup file(s) left by an interrupted run")
        result = Result(final, side, sha, size, manifest, on_same, copies, warnings, run_id,
                        time.monotonic() - t0, stages)
        categories = {"in": [d.key for d in the_plan.decisions if d.included],
                      "out": {d.key: d.reason for d in the_plan.decisions if not d.included}}
        BR.finish(data_dir, run_id, "ok" if all(c.get("ok") for c in copies) else "failed", file=str(final),
                  sha256=sha, size=size, lock=lock, recipients=fps, categories=categories, same_disk=on_same,
                  copies=copies, detail={"stages": stages, "files": len(members), "plain_bytes":
                                         manifest["totals"]["bytes"], "warnings": warnings},
                  error=None if all(c.get("ok") for c in copies) else "a copy failed")
        return result
    except BaseException as e:
        BR.finish(data_dir, run_id, "failed", lock=lock, recipients=fps, error=_plain_error(e))
        raise
    finally:
        try:
            if partial is not None and partial.exists():
                partial.unlink()   # deletion-scan: this run's own unfinished output
        except OSError:
            pass
        try:
            if work is not None and work.exists():
                shutil.rmtree(work)   # deletion-scan: this run's own scratch copies
        finally:
            inuse.release(lockfd)


def _plain_error(e: BaseException) -> str:
    if isinstance(e, KeyboardInterrupt):
        return "interrupted"
    if isinstance(e, OSError) and e.errno is not None and e.errno == 28:
        return "no space left on the disk"
    return f"{type(e).__name__}: {e}"


def _maybe_fail(fail_at: str | None, stage: str) -> None:
    if fail_at == stage:
        raise BackupError(f"test: stopped at {stage}")


def _sha_file(p: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def _fsync_dir(folder: Path) -> None:
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _free_name(dest: Path) -> str:
    base = f"kratos-backup-{utc_stamp()}"
    name, n = f"{base}.age", 1
    while (dest / name).exists() or (dest / (name + ".partial")).exists():
        n += 1
        name = f"{base}-{n}.age"
    return name


def _copy_targets(data_dir: Path) -> list[str]:
    from kratos.backup import settings as BS

    return list(BS.get(BS.COPY_TARGETS, data_dir))


def _check_space(work: Path, dest: Path, the_plan: P.Plan) -> None:
    need = the_plan.total_bytes
    free_work = shutil.disk_usage(work).free
    if free_work < need * 1.1 + 50_000_000:
        raise BackupError(f"not enough free space for the backup's scratch copy next to the data: needs about "
                          f"{need // 1_000_000 + 50} MB, {free_work // 1_000_000} MB free")
    free_dest = shutil.disk_usage(dest).free
    if free_dest < need * 0.5 + 10_000_000 and free_dest < need:
        raise BackupError(f"not enough free space in {dest}: up to {need // 1_000_000} MB may be needed, "
                          f"{free_dest // 1_000_000} MB free")


def _kratos_version() -> str:
    from kratos import __version__

    return __version__


def dry_run(data_dir: Path | str, *, dest: Path | str | None = None, exclude: tuple[str, ...] = (),
            include_rebuildable: bool = False, without_secrets: bool = False,
            roots: P.Roots | None = None) -> dict[str, Any]:
    """What a backup would take, without reading a file's contents or writing anything."""
    data_dir = Path(data_dir)
    the_plan = P.build(data_dir, exclude=tuple(exclude), include_rebuildable=include_rebuildable,
                       without_secrets=without_secrets, roots=roots)
    from kratos.backup import keys as K

    d = the_plan.as_dict()
    text = str(dest or "").strip()
    try:
        from kratos.backup import settings as BS

        text = text or str(BS.get(BS.DESTINATION, data_dir) or "")
    except Exception:  # noqa: BLE001 -- a dry run reads what it can
        pass
    destination = Path(text).expanduser() if text else DEFAULT_DEST
    probe = destination if destination.exists() else destination.parent
    d.update(destination=str(destination), same_disk=same_disk(probe, data_dir),
             inside_data=_inside(Path(os.path.realpath(destination)), Path(os.path.realpath(data_dir))),
             recipients=[K.fingerprint(r) for r in _safe_recipients(data_dir)],
             copy_targets=_safe_copy_targets(data_dir), data_dir=str(data_dir), layout=paths.LAYOUT,
             kratos_version=_kratos_version())
    return d


def _safe_recipients(data_dir: Path) -> list[str]:
    try:
        from kratos.backup import keys as K

        return K.recipients(data_dir)
    except Exception:  # noqa: BLE001
        return []


def _safe_copy_targets(data_dir: Path) -> list[str]:
    try:
        return _copy_targets(data_dir)
    except Exception:  # noqa: BLE001
        return []
