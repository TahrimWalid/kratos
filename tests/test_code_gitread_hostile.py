"""E.7a §6: the git reader on hostile input -- caps hold and a bad repository is a stated reason,
never a crash or a guess."""
from __future__ import annotations

import hashlib
import struct
import zlib

import pytest

from kratos.code import gitread as G


def _src(files: dict[str, bytes]) -> G.DictSource:
    return G.DictSource(files)


def _index(entries: list[tuple[str, bytes]], version: int = 2) -> bytes:
    body = b"DIRC" + struct.pack(">II", version, len(entries))
    for path, oid in entries:
        e = struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 1) + oid + struct.pack(">H", len(path))
        e += path.encode() + b"\x00"
        while len(e) % 8:
            e += b"\x00"
        body += e
    return body + hashlib.sha1(body).digest()


def test_unknown_index_version_and_bad_checksum():
    with pytest.raises(G.GitError, match="version 9"):
        G.read_index(_src({"index": b"DIRC" + struct.pack(">II", 9, 0) + b"\x00" * 20}), "sha1", 100)
    good = _index([("a.txt", b"\x01" * 20)])
    assert "a.txt" in G.read_index(_src({"index": good}), "sha1", 100)["entries"]
    bad = good[:-1] + bytes([good[-1] ^ 1])
    with pytest.raises(G.GitError, match="checksum"):
        G.read_index(_src({"index": bad}), "sha1", 100)


def test_index_entry_cap():
    idx = _index([(f"f{i}", b"\x01" * 20) for i in range(50)])
    with pytest.raises(G.GitError, match="more than Kratos reads"):
        G.read_index(_src({"index": idx}), "sha1", 10)


def test_truncated_index():
    good = _index([("a.txt", b"\x01" * 20)])
    with pytest.raises(G.GitError):
        G.read_index(_src({"index": good[:30] + b"\x00" * 20}), "sha1", 100)


def test_head_ref_loop_and_escape_refused():
    files = {"HEAD": b"ref: refs/heads/a\n", "refs/heads/a": b"ref: refs/heads/b\n", "refs/heads/b": b"ref: refs/heads/a\n"}
    with pytest.raises(G.GitError, match="too long"):
        G.resolve_head(_src(files))
    with pytest.raises(G.GitError, match="won't follow"):
        G.resolve_head(_src({"HEAD": b"ref: refs/../../etc/passwd\n"}))
    assert G.resolve_head(_src({"HEAD": b"ref: refs/heads/main\n"}))["unborn"]


def test_config_reads_only_its_keys():
    cfg = G.parse_config(b'[core]\n\tfsmonitor = "rm -rf /"\n\tworktree = ../x\n[extensions]\n\tobjectFormat = sha256\n'
                         b'[remote "origin"]\n\tworktree = /nope\n')
    assert cfg == {"core.worktree": "../x", "extensions.objectformat": "sha256"}
    with pytest.raises(G.GitError):
        G.object_format({"extensions.objectformat": "md5"})


def _loose(data: bytes, typ: bytes = b"blob") -> tuple[str, bytes]:
    raw = typ + b" %d\x00" % len(data) + data
    return hashlib.sha1(raw).hexdigest(), zlib.compress(raw)


def test_loose_object_bomb_and_size_lie():
    oid, comp = _loose(b"x" * 100)
    store = G.ObjectStore(_src({f"objects/{oid[:2]}/{oid[2:]}": comp}), "sha1", 1 << 20)
    assert store.get(oid) == ("blob", b"x" * 100)
    liar = zlib.compress(b"blob 5\x00" + b"x" * 100)
    store = G.ObjectStore(_src({f"objects/{oid[:2]}/{oid[2:]}": liar}), "sha1", 1 << 20)
    with pytest.raises(G.GitError, match="malformed"):
        store.get(oid)


def _pack_with_delta_chain(depth: int) -> tuple[bytes, bytes, bytes]:
    """A pack whose last object is a chain of `depth` OFS_DELTAs on a blob; returns (idx, pack, last oid)."""
    objs = []
    base = b"hello world\n"
    offsets = []
    body = b"PACK" + struct.pack(">II", 2, depth + 1)

    def header(typ: int, size: int) -> bytes:
        b = [(typ << 4) | (size & 0x0F)]
        size >>= 4
        while size:
            b[-1] |= 0x80
            b.append(size & 0x7F)
            size >>= 7
        return bytes(b)

    offsets.append(len(body))
    body += header(3, len(base)) + zlib.compress(base)
    content = base
    for _ in range(depth):
        new = content + b"!"
        delta = bytes([len(content), len(new), 0x90, len(content), 1]) + b"!"   # copy all, insert "!"
        off = len(body)
        rel = off - offsets[-1]
        enc = [rel & 0x7F]
        rel >>= 7
        while rel:
            rel -= 1
            enc.insert(0, 0x80 | (rel & 0x7F))
            rel >>= 7
        body += header(6, len(delta)) + bytes(enc) + zlib.compress(delta)
        offsets.append(off)
        content = new
        objs.append(content)
    oid = hashlib.sha1(b"blob %d\x00" % len(content) + content).digest()
    body += hashlib.sha1(body).digest()
    fan = [0] * 256
    for i in range(oid[0], 256):
        fan[i] = 1
    idx = b"\xfftOc" + struct.pack(">I", 2) + b"".join(struct.pack(">I", f) for f in fan) + oid + b"\x00" * 4 + \
        struct.pack(">I", offsets[-1]) + b"\x00" * 40
    return idx, body, oid


def test_delta_chain_within_cap_and_too_deep():
    idx, pack, oid = _pack_with_delta_chain(5)
    store = G.ObjectStore(_src({"objects/pack/pack-x.idx": idx, "objects/pack/pack-x.pack": pack}), "sha1", 1 << 20)
    typ, data = store.get(oid.hex())
    assert typ == "blob" and data == b"hello world\n!!!!!"
    idx, pack, oid = _pack_with_delta_chain(G.MAX_DELTA_DEPTH + 5)
    store = G.ObjectStore(_src({"objects/pack/pack-x.idx": idx, "objects/pack/pack-x.pack": pack}), "sha1", 1 << 20)
    with pytest.raises(G.GitError, match="too deep"):
        store.get(oid.hex())


def test_pack_cap():
    idx, pack, _oid = _pack_with_delta_chain(1)
    store = G.ObjectStore(_src({"objects/pack/pack-x.idx": idx, "objects/pack/pack-x.pack": pack}), "sha1", 10)
    assert store.packs == [] and "pack too large" in store.skipped
    files = {"HEAD": b"0" * 40 + b"\n", "config": b"", "objects/pack/pack-x.idx": idx, "objects/pack/pack-x.pack": pack}
    info = G.read_repo(_src(files), max_entries=100, max_pack_bytes=10)
    assert info["tree_reason"] == "HEAD comparison skipped: pack too large; index comparison done"


def test_malformed_delta_and_pack():
    with pytest.raises(G.GitError):
        G._apply_delta(b"abc", bytes([3, 5, 0x90, 9, 9]))           # copies outside its base
    with pytest.raises(G.GitError):
        G._apply_delta(b"abc", bytes([3, 4, 0x00]))                 # reserved instruction
    with pytest.raises(G.GitError):
        G._Pack("x", b"\xfftOc" + struct.pack(">I", 2) + b"\x00" * 1024, G.RangeReader(lambda o, n: b"NOPE"[o:o + n], 4), 20)


def test_tree_entry_with_a_bad_name_is_refused():
    blob_id, blob = _loose(b"x")
    bad_tree = b"100644 ../../etc/passwd\x00" + bytes.fromhex(blob_id)
    tree_id = hashlib.sha1(b"tree %d\x00" % len(bad_tree) + bad_tree).hexdigest()
    files = {f"objects/{tree_id[:2]}/{tree_id[2:]}": zlib.compress(b"tree %d\x00" % len(bad_tree) + bad_tree)}
    with pytest.raises(G.GitError, match="bad name"):
        G.read_tree(G.ObjectStore(_src(files), "sha1", 1 << 20), tree_id, 100)


def test_gitignore_rules():
    ig = G.Ignore()
    ig.add("", "*.log\n!keep.log\n/build/\nuploads/*\n!uploads/.gitkeep\n**/tmp/**\n")
    ig.add("sub/", "*.tmp\n")
    assert ig.is_ignored("x.log") and not ig.is_ignored("keep.log")
    assert ig.is_ignored("build/a.o") and not ig.is_ignored("src/build/a.o")
    assert ig.is_ignored("uploads/cmd.php") and not ig.is_ignored("uploads/.gitkeep")
    assert ig.is_ignored("a/tmp/b/c") and ig.is_ignored("sub/x.tmp") and not ig.is_ignored("x.tmp")
