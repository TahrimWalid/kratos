"""Downloaded datasets: one helper for every outside dataset (docs/phaseE/README.md §4.2).

The pattern is A.2's vulnerability-data update (kratos.pkgvuln.update), shared:

- a dataset is downloaded only by an explicit update command (or the systemd timer
  that runs that command) -- never during an investigation;
- it is built into ``<file>.tmp`` (a big download resumes there with an HTTP Range
  request), checked, then ``os.replace``d over the old copy, which is kept on any
  failure;
- free space is checked BEFORE a large download: the file plus a margin
  (``FREE_MARGIN_BYTES``), so a nearly full disk never ends up holding half a gigabyte
  of useless partial file;
- each dataset has one row in ``datasets`` (kratos.db): version or date, source URL,
  sha256, size, licence, when it was fetched -- shown by `/doctor` with its age;
- a dataset's credential (MalwareBazaar's Auth-Key) lives in an owner-only file under
  ``data_dir/dataset-secrets/`` (folder 0700, file 0600), is never logged or stored in
  the database, and is sent only to the dataset's own host.

Rows here describe files that are `rebuildable` in a backup (kratos.datainv): a restored
computer has neither the files nor the rows, and the restore names the update command.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from kratos import paths
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

DIR_NAME = "hashdb"
SECRETS_DIR = "dataset-secrets"
COMPONENT = "datasets"
FREE_MARGIN_BYTES = 2 * 1024 ** 3          # owner decision 2026-11-11: the file plus 2 GB to spare
HTTP_TIMEOUT = 60
CHUNK = 1 << 20


class DatasetError(RuntimeError):
    """The update could not be completed; the previous copy is untouched."""


class NotEnoughSpace(DatasetError):
    pass


@dataclass(frozen=True)
class Dataset:
    name: str                 # "circl" | "malwarebazaar"
    label: str                # plain words
    file: str                 # file name under data_dir/hashdb/
    source_url: str           # where it comes from (shown; a credential is never part of it)
    licence: str
    terms_url: str
    warn_days: int            # older than this: still used, but /doctor warns
    update_hint: str          # the command that fetches it


@dataclass
class Row:
    name: str
    version: str
    source_url: str
    sha256: str
    size: int
    licence: str
    fetched_at: float
    detail: dict[str, Any]
    last_attempt_at: float | None
    last_error: str

    def age_days(self, now: float | None = None) -> float:
        return max(0.0, ((time.time() if now is None else now) - self.fetched_at) / 86400.0)


# --------------------------------------------------------------------------- the table
def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS datasets (
          name TEXT PRIMARY KEY,           -- circl | malwarebazaar
          version TEXT NOT NULL,           -- the dataset's own version/date, or when Kratos fetched it
          source_url TEXT NOT NULL,        -- never carries a credential
          sha256 TEXT NOT NULL,            -- of the file as installed
          size INTEGER NOT NULL,
          licence TEXT NOT NULL,
          fetched_at REAL NOT NULL,        -- epoch UTC, when the installed copy was fetched
          detail TEXT NOT NULL DEFAULT '{}',   -- JSON: per-dataset facts (rows, hash case, ...)
          last_attempt_at REAL,            -- the last update attempt, ok or not
          last_error TEXT NOT NULL DEFAULT ''
        )
        """
    )


STEPS = (_step_1,)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def get(data_dir: Path | str, name: str) -> Row | None:
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return None
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT name, version, source_url, sha256, size, licence, fetched_at, detail, "
                         "last_attempt_at, last_error FROM datasets WHERE name = ?", (name,)).fetchone()
    finally:
        conn.close()
    if r is None:
        return None
    try:
        detail = json.loads(r[7] or "{}")
    except ValueError:
        detail = {}
    return Row(r[0], r[1], r[2], r[3], int(r[4]), r[5], float(r[6]), detail if isinstance(detail, dict) else {},
               r[8], r[9] or "")


def record_installed(data_dir: Path | str, ds: Dataset, *, version: str, sha256: str, size: int,
                     fetched_at: float, detail: dict[str, Any]) -> None:
    conn = connect(data_dir)
    try:
        with conn:
            conn.execute(
                "INSERT INTO datasets (name, version, source_url, sha256, size, licence, fetched_at, detail, "
                "last_attempt_at, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '') ON CONFLICT(name) DO UPDATE SET "
                "version=excluded.version, source_url=excluded.source_url, sha256=excluded.sha256, "
                "size=excluded.size, licence=excluded.licence, fetched_at=excluded.fetched_at, "
                "detail=excluded.detail, last_attempt_at=excluded.last_attempt_at, last_error=''",
                (ds.name, version, ds.source_url, sha256, int(size), ds.licence, fetched_at,
                 json.dumps(detail, sort_keys=True), fetched_at))
    finally:
        conn.close()


def record_attempt(data_dir: Path | str, ds: Dataset, *, at: float, error: str) -> None:
    """Note a failed (or skipped) attempt without touching the installed copy's row."""
    conn = connect(data_dir)
    try:
        with conn:
            cur = conn.execute("UPDATE datasets SET last_attempt_at = ?, last_error = ? WHERE name = ?",
                               (at, error[:500], ds.name))
            if cur.rowcount == 0:
                conn.execute("INSERT INTO datasets (name, version, source_url, sha256, size, licence, fetched_at, "
                             "detail, last_attempt_at, last_error) VALUES (?, '', ?, '', 0, ?, 0, '{}', ?, ?)",
                             (ds.name, ds.source_url, ds.licence, at, error[:500]))
    finally:
        conn.close()


def last_attempt(data_dir: Path | str, name: str) -> float | None:
    row = get(data_dir, name)
    return row.last_attempt_at if row else None


# --------------------------------------------------------------------------- files
def folder(data_dir: Path | str) -> Path:
    d = Path(data_dir) / DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def installed_path(data_dir: Path | str, ds: Dataset) -> Path | None:
    """The installed file, when it is there AND its row says it was installed (a row with
    fetched_at 0 only records failed attempts)."""
    p = Path(data_dir) / DIR_NAME / ds.file
    row = get(data_dir, ds.name)
    if not p.is_file() or row is None or not row.fetched_at:
        return None
    return p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def check_free_space(where: Path, need_bytes: int, *, margin: int = FREE_MARGIN_BYTES,
                     usage: Callable[[str], Any] = shutil.disk_usage) -> None:
    """Refuse before downloading when the disk can't hold the file plus `margin`."""
    free = usage(str(where)).free
    if free < need_bytes + margin:
        raise NotEnoughSpace(
            f"not enough disk space: the download needs {need_bytes / 1e9:.1f} GB plus {margin / 1e9:.0f} GB to spare "
            f"({(need_bytes + margin) / 1e9:.1f} GB), and {free / 1e9:.1f} GB is free on the disk holding {where}. "
            "Free some space and run the update again.")


def swap_in(tmp: Path, final: Path) -> None:
    os.chmod(tmp, 0o600)
    os.replace(tmp, final)
    try:
        dfd = os.open(final.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


@contextmanager
def update_lock(data_dir: Path | str, name: str) -> Iterator[None]:
    """One update of a dataset at a time (a timer run and a person's run)."""
    lock_path = folder(data_dir) / f".{name}.lock"
    with open(lock_path, "a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise DatasetError(f"another update of this dataset is already running") from None
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _session(session: Any, agent: str) -> Any:
    if session is not None:
        return session
    import requests

    s = requests.Session()
    s.headers["User-Agent"] = agent
    return s


def remote_size(session: Any, url: str, *, headers: dict[str, str] | None = None) -> int | None:
    """Content-Length from a HEAD request (None when the server doesn't say)."""
    import requests

    try:
        r = session.head(url, timeout=HTTP_TIMEOUT, allow_redirects=True, headers=headers or {})
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    n = r.headers.get("content-length")
    return int(n) if n and n.isdigit() else None


def download(session: Any, url: str, tmp: Path, *, max_bytes: int, resume: bool,
             headers: dict[str, str] | None = None, redact: str = "",
             progress: Callable[[int, int | None], None] | None = None) -> int:
    """Stream `url` into `tmp`. With `resume` and a partial `tmp` already there, ask for
    the rest (HTTP Range) and append; a server that answers 200 instead starts over.
    Returns the file's size. Raises DatasetError (the partial file is kept for the next
    resume when `resume`, else removed). `redact` is a credential to blank out of any
    message (never shown, never logged)."""
    import requests

    def clean(text: str) -> str:
        return text.replace(redact, "<key>") if redact else text

    have = tmp.stat().st_size if resume and tmp.exists() else 0
    if not resume:
        tmp.unlink(missing_ok=True)
    hdrs = dict(headers or {})
    if have:
        hdrs["Range"] = f"bytes={have}-"
    try:
        with session.get(url, stream=True, timeout=HTTP_TIMEOUT, headers=hdrs) as resp:
            if resp.status_code == 416 and have:           # already complete
                return have
            if resp.status_code == 206 and have:
                mode, size = "ab", have
                total_txt = str(resp.headers.get("content-range") or "").rpartition("/")[2]
                total = int(total_txt) if total_txt.isdigit() else None
            elif resp.status_code == 200:
                mode, size = "wb", 0
                declared = resp.headers.get("content-length")
                total = int(declared) if declared and declared.isdigit() else None
            elif resp.status_code in (401, 403):
                raise DatasetError(f"the server refused the request (HTTP {resp.status_code}) -- the key was refused "
                                   "or has no access")
            elif resp.status_code == 429:
                raise DatasetError("the server says too many requests (HTTP 429) -- try again later")
            else:
                raise DatasetError(f"HTTP {resp.status_code} from {clean(url)}")
            if total is not None and total > max_bytes:
                raise DatasetError(f"larger than expected ({total} bytes), not downloaded")
            with open(tmp, mode) as fh:
                for chunk in resp.iter_content(chunk_size=CHUNK):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_bytes:
                        raise DatasetError("larger than expected, download stopped")
                    fh.write(chunk)
                    if progress:
                        progress(size, total)
            encoded = str(resp.headers.get("content-encoding") or "identity").lower() not in ("", "identity")
            if total is not None and not encoded and size != total:
                raise DatasetError(f"download ended early ({size} of {total} bytes) -- run the update again to resume")
            return size
    except requests.RequestException as e:
        if not resume:
            tmp.unlink(missing_ok=True)
        raise DatasetError(f"{clean(str(url))}: {e.__class__.__name__} (no network?)") from None
    except OSError as e:
        raise DatasetError(f"could not write the download ({e.strerror or e})") from None
    except DatasetError:
        if not resume:
            tmp.unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- credentials
def _secret_path(data_dir: Path | str, name: str) -> Path:
    if name not in ("malwarebazaar",):
        raise ValueError(f"no credential is known for dataset {name!r}")
    return Path(data_dir) / SECRETS_DIR / f"{name}.key"


def read_key(data_dir: Path | str, name: str) -> str | None:
    p = _secret_path(data_dir, name)
    try:
        text = p.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def write_key(data_dir: Path | str, name: str, key: str) -> None:
    """People-only (kratos.hashdb.cli checks the actor): store the credential owner-only."""
    key = key.strip()
    if not key or len(key) > 512 or any(c.isspace() or not c.isprintable() for c in key):
        raise ValueError("that doesn't look like an Auth-Key (one line of printable characters, no spaces)")
    p = _secret_path(data_dir, name)
    paths.ensure_private_dir(p.parent)
    paths.write_private_text(p, key + "\n")


def remove_key(data_dir: Path | str, name: str) -> bool:
    p = _secret_path(data_dir, name)
    if p.exists():
        p.unlink()       # removed on the person's request: `kratos hashdb-key remove`
        return True
    return False
