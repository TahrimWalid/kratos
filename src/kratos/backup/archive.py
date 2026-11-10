"""Reading a backup back: decrypt → gunzip → tar, with every member checked against the
manifest before a byte of it is used (docs/phaseD/D.8 §3.9).

Anyone who knows a recipient's PUBLIC key can make a file that decrypts with the matching
secret key, so a backup is untrusted input until it checks out:

- the first member must be ``MANIFEST.json`` (closed schema, capped size);
- every later member is a regular file (never a link, hard link, device, FIFO or
  folder entry), with a relative name under ``data/``, ``state/`` or ``config/`` that a
  Kratos data category owns, no ``..``, no control characters, listed in the manifest
  exactly once, of exactly the manifest's size -- and its SHA-256 is checked as it is
  read (`Member.chunks` raises at the end on a mismatch, so a writer can remove what it
  wrote);
- the total is the manifest's total.

`tarfile`'s own extraction filter is applied as one more check where the Python has it,
but nothing here relies on it: nothing is ever extracted by `tarfile`.
"""
from __future__ import annotations

import fnmatch
import gzip
import hashlib
import json
import re
import tarfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kratos import datainv
from kratos.backup import agefmt as A

MANIFEST = "MANIFEST.json"
FORMAT = "kratos-backup/1"
MANIFEST_MAX = 64 << 20
MAX_FILES = 2_000_000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^\d{1,4}(\.\d{1,6}){0,3}$")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")
KINDS = ("file", "db", "ca_unsealed")
PREFIXES = ("data", "state", "config")


class ArchiveError(ValueError):
    """The backup can't be trusted or read, in plain words."""


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in str(text).split("."))


def _allowed(prefix: str, rel: str) -> bool:
    """Is `rel` (under data/state/config) somewhere a Kratos category keeps data?"""
    if prefix == "data":
        if rel == datainv.DB:
            return True
        owner = datainv.owner_of(rel.split("/")[0])
        if owner is None or owner in ("runtime", "database"):
            return False
        return datainv.category(owner).backup != datainv.BACKUP_NEVER
    patterns = [p for c in datainv.CATEGORIES if c.backup != datainv.BACKUP_NEVER
                for p in (c.state_files if prefix == "state" else c.config_files)]
    return any(rel == p or rel.startswith(p + "/") or fnmatch.fnmatch(rel, p) for p in patterns)


def check_path(path: Any) -> tuple[str, str]:
    """(prefix, relative path) of an archive member name, or ArchiveError."""
    if not isinstance(path, str) or not path or len(path) > 4096 or _BAD_CHARS.search(path):
        raise ArchiveError(f"a member name that isn't allowed: {path!r:.80}")
    if path.startswith("/"):
        raise ArchiveError(f"an absolute member name: {path!r:.80}")
    parts = path.split("/")
    if parts[0] not in PREFIXES or len(parts) < 2:
        raise ArchiveError(f"a member outside data/, state/ or config/: {path!r:.80}")
    if any(p in ("", ".", "..") or len(p) > 255 for p in parts):
        raise ArchiveError(f"a member name with an empty, '.' or '..' part: {path!r:.80}")
    rel = "/".join(parts[1:])
    if not _allowed(parts[0], rel):
        raise ArchiveError(f"a member Kratos never backs up: {path!r:.80}")
    return parts[0], rel


def validate_manifest(m: Any) -> dict[str, Any]:
    """The closed schema; raises ArchiveError. Returns {path: entry}."""
    if not isinstance(m, dict) or m.get("format") != FORMAT:
        raise ArchiveError("not a Kratos backup manifest (unknown format)")
    if not isinstance(m.get("kratos_version"), str) or not _VERSION.match(m["kratos_version"]):
        raise ArchiveError("the manifest's Kratos version is missing or malformed")
    files = m.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise ArchiveError("the manifest's file list is missing or too long")
    index: dict[str, Any] = {}
    total = 0
    for e in files:
        if not isinstance(e, dict):
            raise ArchiveError("a manifest file entry is not an object")
        path = e.get("path")
        check_path(path)
        if path in index:
            raise ArchiveError(f"the manifest lists {path!r:.80} twice")
        size, mode, sha, kind = e.get("size"), e.get("mode"), e.get("sha256"), e.get("kind")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > (1 << 40):
            raise ArchiveError(f"bad size for {path!r:.80}")
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
            raise ArchiveError(f"bad mode for {path!r:.80}")
        if not isinstance(sha, str) or not _HEX64.match(sha):
            raise ArchiveError(f"bad SHA-256 for {path!r:.80}")
        if kind not in KINDS:
            raise ArchiveError(f"bad kind for {path!r:.80}")
        if kind == "db" and not path.startswith("data/"):
            raise ArchiveError(f"a database outside data/: {path!r:.80}")
        index[path] = e
        total += size
    totals = m.get("totals")
    if not isinstance(totals, dict) or totals.get("files") != len(files) or totals.get("bytes") != total:
        raise ArchiveError("the manifest's totals don't match its file list")
    for key in ("categories", "databases", "agents", "not_included"):
        if key in m and not isinstance(m[key], list):
            raise ArchiveError(f"the manifest's {key} is not a list")
    if "keys" in m and not isinstance(m["keys"], dict):
        raise ArchiveError("the manifest's keys are not an object")
    return index


def newer_than_this(m: dict[str, Any]) -> str | None:
    """The version needed when the backup was made by a newer Kratos, else None."""
    from kratos import __version__

    try:
        if version_tuple(m["kratos_version"]) > version_tuple(__version__):
            return m["kratos_version"]
    except (KeyError, ValueError):
        return "unknown"
    return None


@dataclass
class Member:
    path: str
    prefix: str
    rel: str
    entry: dict[str, Any]
    _f: Any

    def chunks(self, size: int = 1 << 20) -> Iterator[bytes]:
        """The member's bytes, checked: raises ArchiveError at the end if the size or the
        SHA-256 differs from the manifest (write to a temporary place; remove it then)."""
        h = hashlib.sha256()
        n = 0
        while True:
            block = self._f.read(size)
            if not block:
                break
            n += len(block)
            if n > self.entry["size"]:
                raise ArchiveError(f"{self.path} is longer than the manifest says")
            h.update(block)
            yield block
        if n != self.entry["size"] or h.hexdigest() != self.entry["sha256"]:
            raise ArchiveError(f"{self.path} doesn't match the hash the manifest recorded")

    def read_all(self, cap: int = 64 << 20) -> bytes:
        if self.entry["size"] > cap:
            raise ArchiveError(f"{self.path} is too large to read into memory")
        return b"".join(self.chunks())


@contextmanager
def opened(path: Path, identities: list[object]) -> Iterator["Archive"]:
    with open(path, "rb") as raw:
        dec = A.Decryptor(raw, identities)
        gz = gzip.GzipFile(fileobj=dec, mode="rb")
        try:
            tar = tarfile.open(fileobj=gz, mode="r|", format=tarfile.PAX_FORMAT)
        except tarfile.ReadError as e:
            raise ArchiveError(f"the decrypted data is not a Kratos backup archive ({e})") from None
        except (OSError, EOFError) as e:
            raise _wrap(e) from None
        try:
            yield Archive(tar, gz)
        finally:
            tar.close()


def _wrap(e: BaseException) -> BaseException:
    if isinstance(e, A.AgeError):
        return e
    if isinstance(e, (OSError, EOFError, tarfile.TarError, gzip.BadGzipFile, json.JSONDecodeError)):
        return ArchiveError(f"the backup's content is damaged ({type(e).__name__}: {e})")
    return e


class Archive:
    def __init__(self, tar: tarfile.TarFile, gz: Any = None) -> None:
        self._tar = tar
        self._gz = gz
        self.manifest: dict[str, Any] = {}
        self.index: dict[str, Any] = {}
        self._seen: set[str] = set()
        self._total = 0

    def read_manifest(self) -> dict[str, Any]:
        try:
            ti = self._tar.next()
        except (OSError, EOFError, tarfile.TarError) as e:
            raise _wrap(e) from None
        if ti is None or ti.name != MANIFEST or not ti.isreg() or ti.size > MANIFEST_MAX:
            raise ArchiveError("the backup doesn't start with its manifest")
        f = self._tar.extractfile(ti)
        try:
            m = json.loads(f.read())   # type: ignore[union-attr]
        except (ValueError, OSError, EOFError, tarfile.TarError) as e:
            raise _wrap(e) if not isinstance(e, ValueError) else ArchiveError(
                "the manifest is not valid JSON") from None
        self.index = validate_manifest(m)
        self.manifest = m
        return m

    def members(self) -> Iterator[Member]:
        """Each member, checked. Call `read_manifest` first."""
        filt = getattr(tarfile, "data_filter", None)
        while True:
            try:
                ti = self._tar.next()
            except (OSError, EOFError, tarfile.TarError, A.AgeError) as e:
                raise _wrap(e) from None
            if ti is None:
                break
            if not ti.isreg() or ti.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                kind = ("a symbolic link" if ti.issym() else "a hard link" if ti.islnk() else "a device" if
                        ti.isdev() else "a folder entry" if ti.isdir() else "a special file")
                raise ArchiveError(f"the backup holds {kind} ({ti.name!r:.80}); Kratos backups hold files only")
            prefix, rel = check_path(ti.name)
            if ti.name not in self.index:
                raise ArchiveError(f"{ti.name!r:.80} is in the backup but not in its manifest")
            if ti.name in self._seen:
                raise ArchiveError(f"{ti.name!r:.80} appears twice in the backup")
            entry = self.index[ti.name]
            if ti.size != entry["size"]:
                raise ArchiveError(f"{ti.name!r:.80} has a different size than the manifest says")
            self._total += ti.size
            if self._total > self.manifest["totals"]["bytes"]:
                raise ArchiveError("the backup holds more data than its manifest says")
            if filt is not None:
                try:
                    filt(ti, "/nonexistent-kratos-restore")
                except tarfile.FilterError as e:
                    raise ArchiveError(f"{ti.name!r:.80} was refused by Python's tar data filter ({e})") from None
            self._seen.add(ti.name)
            yield Member(ti.name, prefix, rel, entry, self._tar.extractfile(ti))

    def missing(self) -> list[str]:
        return sorted(set(self.index) - self._seen)

    def finish(self) -> None:
        """After the last member: everything the manifest lists arrived, and the stream ended
        cleanly (the age layer checks its final chunk; trailing data is an error)."""
        gone = self.missing()
        if gone:
            raise ArchiveError(f"{len(gone)} file(s) listed in the manifest are not in the backup, e.g. {gone[0]!r:.80}")
        if self._gz is not None:   # read to the very end: gzip's CRC and age's final chunk are checked there
            try:
                while self._gz.read(1 << 20):
                    pass
            except (OSError, EOFError, A.AgeError) as e:
                raise _wrap(e) from None
