"""E.7a §8: Kratos's git reader agrees with git itself on 34 repositories made by real git
(scripts/dev/build_gitread_fixtures.py), without ever running git."""
from __future__ import annotations

import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from kratos.code import gitread as G

FIX = Path(__file__).parent / "fixtures" / "gitread"
EXPECTED = json.loads((FIX / "expected.json").read_text(encoding="utf-8"))
NAMES = sorted(EXPECTED["repos"])


@pytest.fixture(scope="module")
def repos(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("gitread")
    with tarfile.open(FIX / "repos.tar.gz") as tar:
        tar.extractall(base, filter="tar")
    return base


def _opener(path: str):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    return fd, os.fstat(fd)


def _lister(path: str):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return None


def source(repo: Path) -> G.Source:
    return G.FileSource(str(repo / ".git"), _opener, _lister)


def walk(repo: Path) -> dict[str, tuple[int, str]]:
    """{path: (git mode, blob id)} -- what the inventory walk records."""
    fmt = EXPECTED["repos"][repo.name]["format"]
    out: dict[str, tuple[int, str]] = {}
    for dirpath, dirnames, filenames in os.walk(repo, followlinks=False):
        rel_dir = os.path.relpath(dirpath, repo)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != ".git"]
        links = [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        dirnames[:] = [d for d in dirnames if d not in links]
        for f in filenames + links:
            p = os.path.join(dirpath, f)
            rel = os.path.normpath(os.path.join(rel_dir, f))
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                data = os.fsencode(os.readlink(p))
                out[rel] = (G.MODE_LINK, G.blob_id(data, fmt))
            elif stat.S_ISREG(st.st_mode):
                out[rel] = (G.work_mode(st.st_mode, False), G.blob_id(Path(p).read_bytes(), fmt))
    return out


def ignore_for(repo: Path) -> G.Ignore:
    ig = G.Ignore()
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        if ".gitignore" in filenames:
            rel = os.path.relpath(dirpath, repo)
            ig.add("" if rel == "." else rel + "/", Path(dirpath, ".gitignore").read_text())
    exc = repo / ".git" / "info" / "exclude"
    if exc.is_file():
        ig.add_exclude(exc.read_text())
    return ig


def filters_for(repo: Path):
    attrs = repo / ".gitattributes"
    rules = G.filter_rules(attrs.read_text(), "") if attrs.is_file() else []
    return lambda p: any(r.rx.match(p) for r in rules)


def parse_status(text: str, work: dict) -> dict[str, set[str]]:
    out = {k: set() for k in ("staged", "wt_modified", "wt_deleted", "ita", "untracked", "ignored", "conflict")}
    for rec in text.split("\0"):
        if not rec:
            continue
        kind = rec[0]
        if kind == "1":
            parts = rec.split(" ", 8)
            xy, path = parts[1], parts[8]
            if xy[0] != ".":
                out["staged"].add(path)
            if xy[1] in "MT":
                out["wt_modified"].add(path)
            elif xy[1] == "D":
                out["wt_deleted"].add(path)
            elif xy[1] == "A":
                out["ita"].add(path)
        elif kind == "u":
            out["conflict"].add(rec.split(" ", 10)[10])
        elif kind in "?!":
            path = rec[2:]
            key = "untracked" if kind == "?" else "ignored"
            if path.endswith("/"):
                out[key].update(p for p in work if p.startswith(path))
            else:
                out[key].add(path)
    return out


@pytest.mark.parametrize("name", NAMES)
def test_drift_agrees_with_git_status(repos: Path, name: str) -> None:
    repo = repos / name
    exp = EXPECTED["repos"][name]
    src = source(repo)
    info = G.read_repo(src, max_entries=50_000, max_pack_bytes=512 * 1024 * 1024)
    src.close()
    assert info["format"] == exp["format"]
    assert (info["head"] or {}).get("commit") == exp["head"]
    assert info["index_reason"] == ""
    index = info["index"]
    # ls-files -s: every stage-0 entry, same mode and blob
    want = {}
    for rec in exp["ls_files_z"].split("\0"):
        if rec:
            meta, path = rec.split("\t", 1)
            mode, oid, stage = meta.split()
            if stage == "0":
                want[path] = (int(mode, 8), oid)
    got = {p: (e.mode, e.oid) for p, e in index["entries"].items()}
    sparse = tuple(index["sparse_dirs"])        # a sparse index keeps these folders as one entry
    assert got == {p: v for p, v in want.items() if not p.startswith(sparse)}
    # ls-tree -r HEAD
    if exp["head"]:
        tree = {}
        for rec in exp["ls_tree_z"].split("\0"):
            if rec:
                meta, path = rec.split("\t", 1)
                mode, _typ, oid = meta.split()
                tree[path] = (int(mode, 8), oid)
        assert info["tree"] == tree, info["tree_reason"]
    work = walk(repo)
    d = G.drift(work, index["entries"], info["tree"], ignore_for(repo), covered=lambda _p: True,
                filtered=filters_for(repo), sparse_dirs=index["sparse_dirs"],
                conflicts=index["conflicts"])
    by = {}
    for cls, path, detail in d["entries"]:
        by.setdefault(cls, set()).add(path)
        if detail == "intent-to-add":
            by.setdefault("ita", set()).add(path)
    git = parse_status(exp["status_z"], work)
    assert by.get("staged", set()) == git["staged"]
    assert by.get("deleted", set()) == git["wt_deleted"]
    assert set(index["conflicts"]) == git["conflict"]
    ours_mod = by.get("modified", set()) | by.get("mode_change", set())
    filtered = by.get("filtered", set())
    assert ours_mod == git["wt_modified"] - filtered - git["conflict"]
    assert by.get("ita", set()) == git["ita"]
    assert by.get("untracked", set()) - by.get("ita", set()) == git["untracked"]
    assert by.get("ignored", set()) == git["ignored"]


@pytest.mark.parametrize("name", [n for n in NAMES if "check_ignore" in EXPECTED["repos"][n]])
def test_ignore_matcher_agrees_with_git_check_ignore(repos: Path, name: str) -> None:
    repo = repos / name
    exp = EXPECTED["repos"][name]
    ig = ignore_for(repo)
    ours = sorted(p for p in exp["check_ignore_asked"] if ig.is_ignored(p, (repo / p).is_dir()
                                                                           and not (repo / p).is_symlink()))
    assert ours == exp["check_ignore"]


def test_fixture_set_is_large_and_small() -> None:
    assert len(NAMES) >= 30
    assert sum(p.stat().st_size for p in FIX.iterdir()) <= 1024 * 1024
    assert EXPECTED["git_version"].startswith("git version")
