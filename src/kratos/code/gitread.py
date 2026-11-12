"""Read a git repository's own files -- never by running git (E.7a §3.3).

A hostile ``.git/config`` (``core.fsmonitor``, hooks, ``core.sshCommand``) runs code as
whoever runs ``git`` in that folder; the sub-agent reads as root. So Kratos reads the
repository's files itself and never starts a ``git`` process anywhere:

- ``config``      only ``extensions.objectformat`` (sha1 / sha256) and ``core.worktree``;
- ``HEAD``, loose refs and ``packed-refs`` -> the commit HEAD names (detached supported);
- the **index** (``DIRC`` versions 2, 3, 4 with v4 path compression; the ``link``
  extension of a split index with its ``sharedindex.<id>``; sparse directory entries);
- **objects**: loose (zlib) and packed (``.idx`` v1/v2 + ``.pack`` with OFS/REF deltas,
  chains capped at ``MAX_DELTA_DEPTH``) -> the HEAD commit's tree;
- ``.gitignore`` patterns (git's documented rules) and ``filter=`` attributes;
- **drift**: modified, deleted, untracked, staged-not-committed, mode change.

The same file runs in the sub-agent bundle (on the machine, as root, over the
repository's files opened through the hardened opener) and on Kratos (over raw files
fetched by the SSH read). Standard library only, Python 3.8.

Formats: https://git-scm.com/docs/index-format, https://git-scm.com/docs/gitformat-pack,
https://git-scm.com/docs/gitignore (checked 2026-11-12, git 2.43).
"""
from __future__ import annotations

import hashlib
import re
import struct
import zlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

MAX_DELTA_DEPTH = 50
MAX_OBJECT_BYTES = 64 * 1024 * 1024        # one inflated tree / commit / delta base
MAX_REF_DEPTH = 5
MAX_TREE_DEPTH = 64
MAX_IGNORE_FILES = 2000
MAX_IGNORE_BYTES = 256 * 1024
HEX = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_REFNAME = re.compile(r"^refs/[A-Za-z0-9._/+@-]{1,240}$")

MODE_FILE, MODE_EXEC, MODE_LINK, MODE_GITLINK, MODE_DIR = 0o100644, 0o100755, 0o120000, 0o160000, 0o040000


class GitError(Exception):
    """The repository could not be read for this reason (plain words, no file contents)."""


# --------------------------------------------------------------------------- sources
class RangeReader:
    """Random access to one file's bytes."""

    def __init__(self, pread: Callable[[int, int], bytes], size: int):
        self._pread = pread
        self.size = size

    def pread(self, offset: int, n: int) -> bytes:
        if offset < 0 or offset >= self.size:
            return b""
        return self._pread(offset, min(n, self.size - offset))


class Source:
    """The files of one git directory, by path relative to it ("HEAD", "objects/pack/x.idx")."""

    def read(self, rel: str, limit: int) -> Optional[bytes]:   # pragma: no cover -- interface
        raise NotImplementedError

    def ranged(self, rel: str) -> Optional[RangeReader]:       # pragma: no cover -- interface
        raise NotImplementedError

    def listdir(self, rel: str) -> Optional[List[str]]:        # pragma: no cover -- interface
        raise NotImplementedError

    def close(self) -> None:
        return None


class DictSource(Source):
    """Raw files fetched from the machine (Kratos side): {relpath: bytes}. A file that
    wasn't fetched reads as missing."""

    def __init__(self, files: Dict[str, bytes]):
        self.files = dict(files)

    def read(self, rel: str, limit: int) -> Optional[bytes]:
        data = self.files.get(rel)
        if data is None:
            return None
        if len(data) > limit:
            raise GitError(f"{rel} is larger than Kratos reads ({len(data)} bytes)")
        return data

    def ranged(self, rel: str) -> Optional[RangeReader]:
        data = self.files.get(rel)
        if data is None:
            return None
        return RangeReader(lambda off, n, d=data: d[off:off + n], len(data))

    def listdir(self, rel: str) -> Optional[List[str]]:
        pre = rel.rstrip("/") + "/" if rel else ""
        names = sorted({k[len(pre):].split("/", 1)[0] for k in self.files if k.startswith(pre) and k != pre})
        return names if names else None


class FileSource(Source):
    """A git directory on this machine (the sub-agent side, or tests). Every file is opened
    through `opener(abs_path) -> (fd, stat)` -- the hardened opener in the agent (no symlink
    anywhere in the path, a regular file, one link) -- and `lister(abs_path) -> names | None`.
    Paths are built only from the git directory and fixed or validated relative names."""

    def __init__(self, gitdir: str, opener: Callable[[str], Tuple[int, Any]],
                 lister: Callable[[str], Optional[List[str]]]):
        self.gitdir = gitdir.rstrip("/")
        self.opener, self.lister = opener, lister
        self._fds: List[int] = []

    def _path(self, rel: str) -> str:
        if not rel or rel.startswith("/") or any(p in ("", ".", "..") for p in rel.split("/")):
            raise GitError("not a plain relative name")
        return f"{self.gitdir}/{rel}"

    def _open(self, rel: str) -> Optional[Tuple[int, Any]]:
        path = self._path(rel)
        try:
            return self.opener(path)
        except FileNotFoundError:
            return None
        except Exception as e:  # noqa: BLE001 -- the opener refuses (missing, symlink, ...)
            status = getattr(e, "status", "")
            if status == "missing":
                return None
            raise GitError(f"{rel} not readable ({status or type(e).__name__})") from None

    def read(self, rel: str, limit: int) -> Optional[bytes]:
        import os
        got = self._open(rel)
        if got is None:
            return None
        fd, st = got
        try:
            if st.st_size > limit:
                raise GitError(f"{rel} is larger than Kratos reads ({st.st_size} bytes)")
            chunks = []
            left = st.st_size
            while left > 0:
                b = os.read(fd, min(left, 1 << 20))
                if not b:
                    break
                chunks.append(b)
                left -= len(b)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def ranged(self, rel: str) -> Optional[RangeReader]:
        import os
        got = self._open(rel)
        if got is None:
            return None
        fd, st = got
        self._fds.append(fd)
        return RangeReader(lambda off, n, f=fd: os.pread(f, n, off), st.st_size)

    def listdir(self, rel: str) -> Optional[List[str]]:
        return self.lister(self._path(rel))

    def close(self) -> None:
        import os
        for fd in self._fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds = []


# --------------------------------------------------------------------------- config
def _config_value(raw: str) -> str:
    v = raw.strip()
    out, quoted, i = [], False, 0
    while i < len(v):
        c = v[i]
        if c == '"':
            quoted = not quoted
        elif c == "\\" and i + 1 < len(v):
            i += 1
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(v[i], v[i]))
        elif c in "#;" and not quoted:
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).strip()


def parse_config(data: bytes) -> Dict[str, str]:
    """The two settings Kratos reads (``extensions.objectformat``, ``core.worktree``) plus
    ``core.bare`` -- lowercase "section.key" -> value. Everything else is ignored."""
    wanted = {"extensions.objectformat", "core.worktree", "core.bare", "core.repositoryformatversion"}
    out: Dict[str, str] = {}
    section = ""
    for line in data.decode("utf-8", "replace").splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("["):
            end = s.find("]")
            head = s[1:end if end > 0 else len(s)].strip()
            section = head.split(None, 1)[0].lower() if head else ""
            if '"' in head:      # [remote "origin"] -- a subsection, never one of ours
                section = section + ".sub"
            continue
        key, eq, val = s.partition("=")
        name = f"{section}.{key.strip().lower()}"
        if name in wanted:
            out[name] = _config_value(val) if eq else "true"
    return out


def object_format(cfg: Dict[str, str]) -> str:
    fmt = (cfg.get("extensions.objectformat") or "sha1").lower()
    if fmt not in ("sha1", "sha256"):
        raise GitError(f"unknown object format {fmt!r}")
    return fmt


def hash_len(fmt: str) -> int:
    return 32 if fmt == "sha256" else 20


def blob_id(data: bytes, fmt: str = "sha1") -> str:
    """The id git gives this content as a blob: hash of ``blob <size>\\0`` + content."""
    h = hashlib.sha256() if fmt == "sha256" else hashlib.sha1()
    h.update(b"blob %d\x00" % len(data))
    h.update(data)
    return h.hexdigest()


# --------------------------------------------------------------------------- refs
def _packed_refs(src: Source) -> Dict[str, str]:
    data = src.read("packed-refs", 64 * 1024 * 1024)
    out: Dict[str, str] = {}
    for line in (data or b"").decode("utf-8", "replace").splitlines():
        if not line or line[0] in "#^":
            continue
        oid, _, name = line.partition(" ")
        if HEX.match(oid) and _REFNAME.match(name):
            out[name] = oid
    return out


def resolve_head(src: Source) -> Dict[str, Any]:
    """{ref, commit, detached, unborn}. ``commit`` None for a branch with no commit yet."""
    raw = src.read("HEAD", 4096)
    if raw is None:
        raise GitError("HEAD missing")
    text = raw.decode("utf-8", "replace").strip()
    if HEX.match(text):
        return {"ref": None, "commit": text, "detached": True, "unborn": False}
    packed: Optional[Dict[str, str]] = None
    ref = None
    for _depth in range(MAX_REF_DEPTH):
        if not text.startswith("ref: "):
            raise GitError("HEAD is not a ref or a commit id")
        name = text[5:].strip()
        if not _REFNAME.match(name) or ".." in name:
            raise GitError("HEAD names a ref Kratos won't follow")
        ref = ref or name
        loose = src.read(name, 4096)
        if loose is not None:
            text = loose.decode("utf-8", "replace").strip()
            if HEX.match(text):
                return {"ref": ref, "commit": text, "detached": False, "unborn": False}
            continue
        if packed is None:
            packed = _packed_refs(src)
        if name in packed:
            return {"ref": ref, "commit": packed[name], "detached": False, "unborn": False}
        return {"ref": ref, "commit": None, "detached": False, "unborn": True}
    raise GitError("HEAD's ref chain is too long")


# --------------------------------------------------------------------------- index
class IndexEntry:
    __slots__ = ("path", "mode", "oid", "stage", "skip_worktree", "intent_to_add", "size")

    def __init__(self, path: str, mode: int, oid: str, stage: int, skip_worktree: bool, intent_to_add: bool,
                 size: int):
        self.path, self.mode, self.oid, self.stage = path, mode, oid, stage
        self.skip_worktree, self.intent_to_add, self.size = skip_worktree, intent_to_add, size


def _varint_v4(data: bytes, pos: int) -> Tuple[int, int]:
    """The offset encoding of index v4 path prefixes (the same as OFS_DELTA's)."""
    b = data[pos]
    pos += 1
    val = b & 0x7F
    while b & 0x80:
        if pos >= len(data):
            raise GitError("git index: truncated path prefix")
        b = data[pos]
        pos += 1
        val = ((val + 1) << 7) | (b & 0x7F)
    return val, pos


def _ewah(data: bytes, pos: int) -> Tuple[List[bool], int]:
    """git's EWAH bitmap (ewah/ewah_io.c): bit size, word count, 64-bit words, rlw position."""
    if pos + 8 > len(data):
        raise GitError("git index: truncated bitmap")
    bit_size, words = struct.unpack(">II", data[pos:pos + 8])
    pos += 8
    if words > 1 << 24 or pos + words * 8 + 4 > len(data):
        raise GitError("git index: bitmap too large or truncated")
    buf = struct.unpack(">%dQ" % words, data[pos:pos + words * 8])
    pos += words * 8 + 4
    bits: List[bool] = []
    i = 0
    while i < len(buf) and len(bits) < bit_size:
        rlw = buf[i]
        i += 1
        running_bit = bool(rlw & 1)
        run_len = (rlw >> 1) & 0xFFFFFFFF
        literals = rlw >> 33
        bits.extend([running_bit] * (run_len * 64))
        for _ in range(literals):
            if i >= len(buf):
                break
            w = buf[i]
            i += 1
            bits.extend(bool((w >> b) & 1) for b in range(64))
    return bits[:bit_size], pos


def _parse_index_raw(data: bytes, fmt: str, max_entries: int) -> Dict[str, Any]:
    hl = hash_len(fmt)
    if len(data) < 12 + hl or data[:4] != b"DIRC":
        raise GitError("git index not readable (not an index file)")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        raise GitError(f"git index not readable (version {version})")
    trailer = data[-hl:]
    if trailer != b"\x00" * hl:
        h = hashlib.sha256() if fmt == "sha256" else hashlib.sha1()
        h.update(data[:-hl])
        if h.digest() != trailer:
            raise GitError("git index not readable (its checksum doesn't match)")
    if count > max_entries:
        raise GitError(f"git index has {count} entries, more than Kratos reads ({max_entries})")
    pos = 12
    end = len(data) - hl
    entries: List[IndexEntry] = []
    prev = b""
    for _ in range(count):
        start = pos
        if pos + 40 + hl + 2 > end:
            raise GitError("git index not readable (truncated entry)")
        mode = struct.unpack(">I", data[pos + 24:pos + 28])[0]
        size = struct.unpack(">I", data[pos + 36:pos + 40])[0]
        oid = data[pos + 40:pos + 40 + hl].hex()
        pos += 40 + hl
        flags = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        extended = bool(flags & 0x4000)
        stage = (flags >> 12) & 0x3
        name_len = flags & 0x0FFF
        skip_wt = ita = False
        if extended:
            if version < 3:
                raise GitError("git index not readable (extended flag in version 2)")
            f2 = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            skip_wt, ita = bool(f2 & 0x4000), bool(f2 & 0x2000)
        if version == 4:
            strip, pos = _varint_v4(data, pos)
            nul = data.find(b"\x00", pos, end)
            if nul < 0 or strip > len(prev):
                raise GitError("git index not readable (bad path)")
            name = prev[:len(prev) - strip] + data[pos:nul]
            pos = nul + 1
        else:
            nul = data.find(b"\x00", pos, end)
            if nul < 0:
                raise GitError("git index not readable (bad path)")
            name = data[pos:nul]
            if name_len < 0xFFF and len(name) != name_len:
                raise GitError("git index not readable (path length mismatch)")
            pos = start + ((nul - start) // 8 + 1) * 8
        prev = name
        entries.append(IndexEntry(name.decode("utf-8", "surrogateescape"), mode, oid, stage, skip_wt, ita, size))
    exts: Dict[bytes, bytes] = {}
    while pos + 8 <= end:
        sig = data[pos:pos + 4]
        n = struct.unpack(">I", data[pos + 4:pos + 8])[0]
        if pos + 8 + n > end:
            raise GitError("git index not readable (truncated extension)")
        exts[sig] = data[pos + 8:pos + 8 + n]
        pos += 8 + n
    return {"version": version, "entries": entries, "extensions": exts}


def read_index(src: Source, fmt: str, max_entries: int) -> Dict[str, Any]:
    """{version, entries: {path: IndexEntry} (stage 0 only), conflicts: [path],
    sparse_dirs: [dir/], split: bool}. Raises GitError for an unreadable index."""
    data = src.read("index", 512 * 1024 * 1024)
    if data is None:
        return {"version": None, "entries": {}, "conflicts": [], "sparse_dirs": [], "split": False, "missing": True}
    raw = _parse_index_raw(data, fmt, max_entries)
    entries = raw["entries"]
    split = False
    link = raw["extensions"].get(b"link")
    if link is not None:
        split = True
        hl = hash_len(fmt)
        shared_id = link[:hl].hex()
        shared_data = src.read(f"sharedindex.{shared_id}", 512 * 1024 * 1024)
        if shared_data is None:
            raise GitError("git index not readable (split index: its shared index is missing)")
        shared = _parse_index_raw(shared_data, fmt, max_entries)["entries"]
        delete_bits: List[bool] = []
        replace_bits: List[bool] = []
        if len(link) > hl:
            delete_bits, p = _ewah(link, hl)
            replace_bits, _p = _ewah(link, p)
        merged: List[IndexEntry] = []
        it = iter(entries)
        for i, e in enumerate(shared):
            if i < len(delete_bits) and delete_bits[i]:
                continue
            if i < len(replace_bits) and replace_bits[i]:
                rep = next(it, None)
                if rep is None:
                    raise GitError("git index not readable (split index: replacements missing)")
                rep.path = e.path
                merged.append(rep)
            else:
                merged.append(e)
        merged.extend(it)
        entries = sorted(merged, key=lambda x: (x.path.encode("utf-8", "surrogateescape"), x.stage))
    out: Dict[str, IndexEntry] = {}
    conflicts: List[str] = []
    sparse_dirs: List[str] = []
    for e in entries:
        if e.mode == MODE_DIR or (e.skip_worktree and e.path.endswith("/")):
            sparse_dirs.append(e.path if e.path.endswith("/") else e.path + "/")
            continue
        if e.stage != 0:
            if e.path not in conflicts:
                conflicts.append(e.path)
            continue
        out[e.path] = e
    return {"version": raw["version"], "entries": out, "conflicts": conflicts, "sparse_dirs": sparse_dirs,
            "split": split, "missing": False}


# --------------------------------------------------------------------------- objects
_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag", 6: "ofs_delta", 7: "ref_delta"}


class _Pack:
    def __init__(self, name: str, idx: bytes, pack: RangeReader, hl: int):
        self.name, self.pack, self.hl = name, pack, hl
        self.offsets: Dict[bytes, int] = {}
        if idx[:4] == b"\xfftOc":
            ver = struct.unpack(">I", idx[4:8])[0]
            if ver != 2:
                raise GitError(f"pack index version {ver} not supported")
            n = struct.unpack(">I", idx[8 + 255 * 4:8 + 256 * 4])[0]
            base = 8 + 256 * 4
            oids = idx[base:base + n * hl]
            offs_at = base + n * hl + n * 4
            large_at = offs_at + n * 4
            if len(idx) < large_at:
                raise GitError("pack index truncated")
            for i in range(n):
                off = struct.unpack(">I", idx[offs_at + i * 4:offs_at + i * 4 + 4])[0]
                if off & 0x80000000:
                    j = off & 0x7FFFFFFF
                    off = struct.unpack(">Q", idx[large_at + j * 8:large_at + j * 8 + 8])[0]
                self.offsets[oids[i * hl:(i + 1) * hl]] = off
        else:                                   # version 1: fan-out then (offset, oid)
            n = struct.unpack(">I", idx[255 * 4:256 * 4])[0]
            base = 256 * 4
            step = 4 + hl
            if len(idx) < base + n * step:
                raise GitError("pack index truncated")
            for i in range(n):
                rec = idx[base + i * step:base + (i + 1) * step]
                self.offsets[rec[4:]] = struct.unpack(">I", rec[:4])[0]
        head = pack.pread(0, 12)
        if head[:4] != b"PACK" or struct.unpack(">I", head[4:8])[0] not in (2, 3):
            raise GitError("not a pack file")


class ObjectStore:
    """Loose objects and packs of one repository, read on demand within caps."""

    def __init__(self, src: Source, fmt: str, max_pack_bytes: int):
        self.src, self.fmt, self.hl = src, fmt, hash_len(fmt)
        self.packs: List[_Pack] = []
        self.skipped: List[str] = []
        names = src.listdir("objects/pack") or []
        total = 0
        for n in sorted(names):
            if not n.endswith(".idx"):
                continue
            stem = n[:-4]
            rr = src.ranged(f"objects/pack/{stem}.pack")
            if rr is None:
                self.skipped.append(f"{stem}.pack missing")
                continue
            total += rr.size
            if total > max_pack_bytes:
                self.skipped.append("pack too large")
                continue
            idx = src.read(f"objects/pack/{n}", 256 * 1024 * 1024)
            if idx is None:
                self.skipped.append(f"{n} missing")
                continue
            self.packs.append(_Pack(stem, idx, rr, self.hl))
        self.inflated = 0

    def _inflate(self, rr: RangeReader, off: int, want: int) -> bytes:
        """`want` bytes inflated from the zlib stream at `off`; never more than want + 1
        bytes of output are produced (a bomb stops at once)."""
        d = zlib.decompressobj()
        out = bytearray()
        pos = off
        while not d.eof:
            chunk = rr.pread(pos, 65536)
            if not chunk:
                break
            pos += len(chunk)
            out += d.decompress(chunk, want + 1 - len(out))
            if len(out) > want:
                raise GitError("a packed object is larger than its header says")
        if not d.eof or len(out) != want:
            raise GitError("a packed object is malformed")
        self.inflated += want
        return bytes(out)

    def _pack_object(self, pack: _Pack, off: int, depth: int) -> Tuple[str, bytes]:
        if depth > MAX_DELTA_DEPTH:
            raise GitError("delta chain too deep")
        head = pack.pack.pread(off, 64)
        if not head:
            raise GitError("a packed object is outside its pack")
        b = head[0]
        typ = (b >> 4) & 7
        size = b & 0x0F
        shift = 4
        i = 1
        while b & 0x80:
            b = head[i]
            i += 1
            size |= (b & 0x7F) << shift
            shift += 7
        if size > MAX_OBJECT_BYTES:
            raise GitError("an object is larger than Kratos reads")
        if typ == 6:
            b = head[i]
            i += 1
            rel = b & 0x7F
            while b & 0x80:
                b = head[i]
                i += 1
                rel = ((rel + 1) << 7) | (b & 0x7F)
            base_t, base = self._pack_object(pack, off - rel, depth + 1)
            return base_t, _apply_delta(base, self._inflate(pack.pack, off + i, size))
        if typ == 7:
            base_id = head[i:i + self.hl]
            base_t, base = self.get(base_id.hex(), depth + 1)
            return base_t, _apply_delta(base, self._inflate(pack.pack, off + i + self.hl, size))
        if typ not in (1, 2, 3, 4):
            raise GitError("a packed object has an unknown type")
        return _TYPES[typ], self._inflate(pack.pack, off + i, size)

    def get(self, oid: str, depth: int = 0) -> Tuple[str, bytes]:
        if not HEX.match(oid) or len(oid) != self.hl * 2:
            raise GitError("not an object id")
        raw = bytes.fromhex(oid)
        for pack in self.packs:
            off = pack.offsets.get(raw)
            if off is not None:
                return self._pack_object(pack, off, depth)
        data = self.src.read(f"objects/{oid[:2]}/{oid[2:]}", MAX_OBJECT_BYTES)
        if data is None:
            raise GitError("object not found" + (" (" + "; ".join(self.skipped) + ")" if self.skipped else ""))
        try:
            d = zlib.decompressobj()
            full = d.decompress(data, MAX_OBJECT_BYTES + 64)
        except zlib.error:
            raise GitError("a loose object is not readable") from None
        nul = full.find(b"\x00")
        if nul < 0:
            raise GitError("a loose object is malformed")
        typ, _, size = full[:nul].decode("ascii", "replace").partition(" ")
        body = full[nul + 1:]
        if not size.isdigit() or int(size) != len(body):
            raise GitError("a loose object is malformed")
        self.inflated += len(body)
        return typ, body


def _delta_size(data: bytes, pos: int) -> Tuple[int, int]:
    val = shift = 0
    while True:
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return val, pos


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    try:
        src_size, pos = _delta_size(delta, 0)
        dst_size, pos = _delta_size(delta, pos)
        if src_size != len(base) or dst_size > MAX_OBJECT_BYTES:
            raise GitError("a delta doesn't fit its base")
        out = bytearray()
        while pos < len(delta):
            op = delta[pos]
            pos += 1
            if op & 0x80:
                off = n = 0
                for k in range(4):
                    if op & (1 << k):
                        off |= delta[pos] << (8 * k)
                        pos += 1
                for k in range(3):
                    if op & (0x10 << k):
                        n |= delta[pos] << (8 * k)
                        pos += 1
                n = n or 0x10000
                if off + n > len(base):
                    raise GitError("a delta copies outside its base")
                out += base[off:off + n]
            elif op:
                out += delta[pos:pos + op]
                pos += op
            else:
                raise GitError("a delta has a reserved instruction")
        if len(out) != dst_size:
            raise GitError("a delta has the wrong size")
        return bytes(out)
    except IndexError:
        raise GitError("a delta is truncated") from None


def commit_tree(store: ObjectStore, commit: str) -> str:
    typ, body = store.get(commit)
    if typ == "tag":
        m = re.match(rb"object ([0-9a-f]+)", body)
        if not m:
            raise GitError("a tag without an object")
        typ, body = store.get(m.group(1).decode())
    if typ != "commit":
        raise GitError("HEAD does not name a commit")
    m = re.match(rb"tree ([0-9a-f]{40,64})\n", body)
    if not m:
        raise GitError("a commit without a tree")
    return m.group(1).decode()


def read_tree(store: ObjectStore, tree: str, max_entries: int) -> Dict[str, Tuple[int, str]]:
    """{path: (mode, oid)} of every file, symlink and submodule in the tree."""
    out: Dict[str, Tuple[int, str]] = {}
    hl = store.hl
    stack: List[Tuple[str, str, int]] = [("", tree, 0)]
    while stack:
        prefix, oid, depth = stack.pop()
        if depth > MAX_TREE_DEPTH:
            raise GitError("the tree is nested too deeply")
        typ, body = store.get(oid)
        if typ != "tree":
            raise GitError("a tree entry is not a tree")
        pos = 0
        while pos < len(body):
            sp = body.find(b" ", pos)
            nul = body.find(b"\x00", sp + 1)
            if sp < 0 or nul < 0 or nul + 1 + hl > len(body):
                raise GitError("a tree is malformed")
            mode = int(body[pos:sp], 8)
            name = body[sp + 1:nul].decode("utf-8", "surrogateescape")
            child = body[nul + 1:nul + 1 + hl].hex()
            pos = nul + 1 + hl
            if not name or "/" in name or name in (".", ".."):
                raise GitError("a tree entry has a bad name")
            path = prefix + name
            if mode == MODE_DIR:
                stack.append((path + "/", child, depth + 1))
            else:
                out[path] = (mode, child)
                if len(out) > max_entries:
                    raise GitError(f"the HEAD tree has more than {max_entries} files")
    return out


# --------------------------------------------------------------------------- .gitignore
def _glob_re(pat: str) -> str:
    """One gitignore glob (no leading/trailing slash handling) as a regex body."""
    out = []
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if pat[i:i + 2] == "**":
                before = i == 0 or pat[i - 1] == "/"
                after = i + 2 == n or pat[i + 2] == "/"
                if before and after:
                    if i + 2 == n:
                        out.append(".*")
                        i += 2
                        continue
                    out.append("(?:.*/)?")
                    i += 3
                    continue
            out.append("[^/]*")
            while i < n and pat[i] == "*":
                i += 1
            continue
        if c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and pat[j] in "!^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j]
                neg = body[:1] in ("!", "^")
                if neg:
                    body = body[1:]
                body = body.replace("\\", "\\\\")
                out.append("[" + ("^/" if neg else "") + body + "]")
                i = j
        elif c == "\\" and i + 1 < n:
            i += 1
            out.append(re.escape(pat[i]))
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


class _Rule:
    __slots__ = ("base", "neg", "dir_only", "rx")

    def __init__(self, base: str, neg: bool, dir_only: bool, rx: Any):
        self.base, self.neg, self.dir_only, self.rx = base, neg, dir_only, rx


def _strip_trailing(line: str) -> str:
    while line.endswith(" ") and not line.endswith("\\ "):
        line = line[:-1]
    return line


def parse_patterns(text: str, base: str) -> List[_Rule]:
    """Rules of one ignore file whose folder (relative to the work tree) is `base` ("" for
    the top, else "dir/sub/")."""
    rules: List[_Rule] = []
    for raw in text.splitlines():
        line = _strip_trailing(raw.rstrip("\r"))
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        if neg:
            line = line[1:]
        elif line.startswith("\\!") or line.startswith("\\#"):
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
        if not line:
            continue
        anchored = "/" in line
        line = line.lstrip("/")
        body = _glob_re(line)
        rx = re.compile("^" + ("" if anchored else "(?:.*/)?") + body + "$", re.DOTALL)
        rules.append(_Rule(base, neg, dir_only, rx))
    return rules


class Ignore:
    """git's ignore rules for one work tree: ``.gitignore`` files (deeper wins) over
    ``.git/info/exclude``; the last matching pattern of a file wins; a file under an
    ignored folder can't be re-included."""

    def __init__(self) -> None:
        self.by_dir: Dict[str, List[_Rule]] = {}
        self.exclude: List[_Rule] = []

    def add(self, base: str, text: str) -> None:
        self.by_dir.setdefault(base, []).extend(parse_patterns(text, base))

    def add_exclude(self, text: str) -> None:
        self.exclude.extend(parse_patterns(text, ""))

    def _match(self, path: str, is_dir: bool) -> Optional[bool]:
        parts = path.split("/")
        bases = [""] + ["/".join(parts[:k]) + "/" for k in range(1, len(parts))]
        for base in reversed(bases):              # deepest .gitignore first
            for rule in reversed(self.by_dir.get(base, [])):
                if rule.dir_only and not is_dir:
                    continue
                if rule.rx.match(path[len(base):]):
                    return not rule.neg
        for rule in reversed(self.exclude):
            if rule.dir_only and not is_dir:
                continue
            if rule.rx.match(path):
                return not rule.neg
        return None

    def is_ignored(self, path: str, is_dir: bool = False) -> bool:
        parts = path.split("/")
        for k in range(1, len(parts)):
            if self._match("/".join(parts[:k]), True):
                return True
        return bool(self._match(path, is_dir))


def filter_rules(text: str, base: str) -> List[_Rule]:
    """``.gitattributes`` lines that set ``filter=`` (Git LFS and other clean/smudge
    filters change what is checked out, so those files can't be compared by blob id)."""
    rules: List[_Rule] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        pat, _, attrs = s.partition(" ")
        if pat.startswith("[attr]"):
            continue
        if any(a.startswith("filter=") for a in attrs.split()):
            rules.extend(parse_patterns(pat, base))
    return rules


# --------------------------------------------------------------------------- drift
def work_mode(st_mode: int, is_link: bool) -> int:
    if is_link:
        return MODE_LINK
    return MODE_EXEC if st_mode & 0o100 else MODE_FILE


def drift(work: Dict[str, Tuple[int, str]], index: Dict[str, IndexEntry],
          tree: Optional[Dict[str, Tuple[int, str]]], ignore: Ignore, *,
          covered: Callable[[str], bool], filtered: Callable[[str], bool] = lambda _p: False,
          sparse_dirs: Iterable[str] = (), conflicts: Iterable[str] = ()) -> Dict[str, Any]:
    """Compare the work tree with the index and the index with HEAD's tree.

    work: {path: (git mode, blob id)} of every file and symlink the walk saw.
    covered(path): did the walk look where `path` would be (not a skipped folder, not past
    a cap)? A tracked file outside what the walk covered is never "deleted".
    Returns {entries: [(class, path, detail)], counts}. Classes: modified, mode_change,
    deleted, untracked, ignored, staged, filtered."""
    sparse = tuple(sparse_dirs)
    unmerged = set(conflicts)          # a merge in progress: shown as conflicts, not as drift
    entries: List[Tuple[str, str, str]] = []
    counts: Dict[str, int] = {}

    def add(cls: str, path: str, detail: str = "") -> None:
        counts[cls] = counts.get(cls, 0) + 1
        entries.append((cls, path, detail))

    submodules = tuple(p + "/" for p, e in index.items() if e.mode == MODE_GITLINK)
    for path, e in sorted(index.items()):
        if e.mode == MODE_GITLINK or e.skip_worktree or path.startswith(sparse):
            continue
        w = work.get(path)
        if w is None:
            if covered(path):
                add("deleted", path)
            continue
        if filtered(path):
            add("filtered", path)
            continue
        wmode, wblob = w
        if e.intent_to_add:            # `git add -N`: the content is not in the index yet
            add("untracked", path, "intent-to-add")
            continue
        if wblob != e.oid:
            add("modified", path)
        elif wmode != e.mode and MODE_LINK not in (wmode, e.mode):
            add("mode_change", path, "executable bit added" if wmode == MODE_EXEC else "executable bit removed")
    for path in sorted(work):
        if path in index or path in unmerged or path.startswith(submodules) or path.startswith(sparse):
            continue
        add("ignored" if ignore.is_ignored(path) else "untracked", path)
    if tree is not None:
        for path, e in sorted(index.items()):
            if e.intent_to_add:
                continue
            t = tree.get(path)
            if t is None:
                add("staged", path, "added to the index, never committed")
            elif t[1] != e.oid:
                add("staged", path, "changed in the index, not committed")
            elif t[0] != e.mode and e.mode != MODE_GITLINK:
                add("staged", path, "mode changed in the index, not committed")
        for path in sorted(tree):
            if (path not in index and path not in unmerged and not path.startswith(submodules)
                    and not path.startswith(sparse)):
                add("staged", path, "removed from the index, not committed")
    return {"entries": entries, "counts": counts}


# --------------------------------------------------------------------------- one call
def read_repo(src: Source, *, max_entries: int, max_pack_bytes: int) -> Dict[str, Any]:
    """Everything Kratos reads from one git directory, without the work tree:
    {format, head, index, tree, tree_reason, index_reason, worktree, gaps}. Each part that
    couldn't be read carries its reason; nothing is guessed."""
    out: Dict[str, Any] = {"format": None, "head": None, "index": None, "tree": None, "tree_reason": "",
                           "index_reason": "", "worktree": None, "gaps": []}
    cfg = parse_config(src.read("config", 1024 * 1024) or b"")
    fmt = object_format(cfg)
    out["format"] = fmt
    out["worktree"] = cfg.get("core.worktree")
    try:
        out["head"] = resolve_head(src)
    except GitError as e:
        out["gaps"].append(f"HEAD not readable: {e}")
    try:
        out["index"] = read_index(src, fmt, max_entries)
    except GitError as e:
        out["index_reason"] = str(e)
    head = out["head"]
    if head and head.get("commit"):
        try:
            store = ObjectStore(src, fmt, max_pack_bytes)
            if "pack too large" in store.skipped:
                out["tree_reason"] = "HEAD comparison skipped: pack too large; index comparison done"
            else:
                out["tree"] = read_tree(store, commit_tree(store, head["commit"]), max_entries)
        except GitError as e:
            out["tree_reason"] = f"HEAD tree not fully read: {e}"
    elif head and head.get("unborn"):
        out["tree"] = {}
    return out
