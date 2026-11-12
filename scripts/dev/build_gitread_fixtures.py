#!/usr/bin/env python3
"""Build the git fixture repositories for tests/test_code_gitread.py (E.7a §8).

Every repository is made by the real `git` (index versions 2/3/4, a split index, a
sparse index, SHA-256, loose and packed objects with OFS and REF deltas, packed refs,
detached HEAD, intent-to-add, skip-worktree, conflicts, submodule links, ignore rules,
filter attributes, odd file names, a hostile config). Beside each repository the script
saves what git itself says about it -- `git status --porcelain=v2`, `git ls-files -s`,
`git ls-tree -r HEAD`, `git check-ignore --no-index` -- so the test compares Kratos's
parser with git's own answer. Kratos never runs git; only this build script does.

Run:  python scripts/dev/build_gitread_fixtures.py tests/fixtures/gitread
Writes <out>/repos.tar.gz (all repositories) and <out>/expected.json.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ENV = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.test",
       "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.test",
       "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
       "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null",
       "LC_ALL": "C"}


def git(repo: Path, *args: str, check: bool = True, input: bytes | None = None) -> bytes:
    # core.fsmonitor/hooksPath are overridden on the command line: the hostile_config
    # fixture plants both, and git would run them (it did, once, while this was written).
    r = subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always",
                        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                       cwd=repo, env=ENV, capture_output=True, input=input)
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed in {repo.name}: {r.stderr.decode()}")
    return r.stdout


def w(repo: Path, rel: str, text: str | bytes, mode: int | None = None) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode() if isinstance(text, str) else text)
    if mode is not None:
        p.chmod(mode)


def new(base: Path, name: str, *init: str) -> Path:
    repo = base / name
    repo.mkdir()
    git(repo, "init", "-q", "--template=", *init)
    git(repo, "config", "core.autocrlf", "false")
    return repo


def commit(repo: Path, msg: str = "c") -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


def build(base: Path) -> list[str]:
    names: list[str] = []

    def add(name: str) -> None:
        names.append(name)

    r = new(base, "empty")
    add("empty")
    r = new(base, "unborn_with_index")
    w(r, "a.txt", "a\n")
    git(r, "add", "a.txt")
    add("unborn_with_index")

    r = new(base, "clean")
    w(r, "app.py", "print('hi')\n")
    w(r, "lib/util.py", "x = 1\n")
    commit(r)
    add("clean")

    r = new(base, "modified")
    w(r, "app.py", "a\n")
    w(r, "web/index.php", "<?php echo 1;\n")
    commit(r)
    w(r, "web/index.php", "<?php echo 2;\n")
    add("modified")

    r = new(base, "deleted")
    w(r, "a.txt", "a\n")
    w(r, "b.txt", "b\n")
    commit(r)
    (r / "b.txt").unlink()
    add("deleted")

    r = new(base, "untracked")
    w(r, "a.txt", "a\n")
    commit(r)
    w(r, "shell.php", "<?php system($_GET['c']); // fixture\n")
    w(r, "deep/new/x.py", "y\n")
    add("untracked")

    r = new(base, "staged_new")
    w(r, "a.txt", "a\n")
    commit(r)
    w(r, "uploads/s.php", "<?php // staged, not committed\n")
    git(r, "add", "uploads/s.php")
    add("staged_new")

    r = new(base, "staged_modify")
    w(r, "a.txt", "a\n")
    commit(r)
    w(r, "a.txt", "b\n")
    git(r, "add", "a.txt")
    w(r, "a.txt", "c\n")
    add("staged_modify")

    r = new(base, "staged_delete")
    w(r, "a.txt", "a\n")
    w(r, "b.txt", "b\n")
    commit(r)
    git(r, "rm", "-q", "--cached", "b.txt")
    add("staged_delete")

    r = new(base, "mode_change")
    w(r, "run.sh", "#!/bin/sh\necho\n")
    commit(r)
    (r / "run.sh").chmod(0o755)
    add("mode_change")

    r = new(base, "symlinks")
    w(r, "real.txt", "r\n")
    os.symlink("real.txt", r / "link")
    os.symlink("nowhere", r / "dangling")
    commit(r)
    (r / "link").unlink()
    os.symlink("other.txt", r / "link")
    add("symlinks")

    r = new(base, "index_v3_ita")
    w(r, "a.txt", "a\n")
    commit(r)
    w(r, "later.py", "pass\n")
    git(r, "add", "-N", "later.py")
    add("index_v3_ita")

    r = new(base, "index_v4")
    for i in range(30):
        w(r, f"src/module_{i:02d}/handler.py", f"h{i}\n")
    commit(r)
    git(r, "update-index", "--index-version", "4")
    w(r, "src/module_07/handler.py", "changed\n")
    w(r, "src/module_99/new.py", "n\n")
    add("index_v4")

    r = new(base, "split_index")
    for i in range(20):
        w(r, f"f{i:02d}.txt", f"{i}\n")
    commit(r)
    git(r, "update-index", "--split-index")
    w(r, "f03.txt", "changed\n")
    git(r, "add", "f03.txt")
    w(r, "f30.txt", "new\n")
    git(r, "add", "f30.txt")
    git(r, "rm", "-q", "--cached", "f05.txt")
    w(r, "f07.txt", "worktree only\n")
    add("split_index")

    r = new(base, "sparse_index")
    for d in ("keep", "away"):
        for i in range(4):
            w(r, f"{d}/sub/f{i}.txt", f"{d}{i}\n")
    w(r, "top.txt", "t\n")
    commit(r)
    git(r, "sparse-checkout", "init", "--cone", "--sparse-index")
    git(r, "sparse-checkout", "set", "keep")
    w(r, "keep/sub/f1.txt", "changed\n")
    add("sparse_index")

    r = new(base, "skip_worktree")
    w(r, "a.txt", "a\n")
    w(r, "b.txt", "b\n")
    commit(r)
    git(r, "update-index", "--skip-worktree", "b.txt")
    (r / "b.txt").unlink()
    add("skip_worktree")

    r = new(base, "sha256_clean", "--object-format=sha256")
    w(r, "app.py", "a\n")
    commit(r)
    add("sha256_clean")

    r = new(base, "sha256_drift", "--object-format=sha256")
    w(r, "app.py", "a\n")
    w(r, "web/x.php", "<?php 1;\n")
    commit(r)
    git(r, "gc", "-q")
    w(r, "web/x.php", "<?php 2;\n")
    w(r, "web/y.php", "<?php 3;\n")
    git(r, "add", "web/y.php")
    add("sha256_drift")

    r = new(base, "packed_ofs_delta")
    big = "".join(f"line {i} of a file that changes a little each commit\n" for i in range(400))
    for k in range(6):
        w(r, "big.txt", big + f"version {k}\n")
        w(r, f"v{k}.txt", f"{k}\n")
        commit(r, f"c{k}")
    git(r, "gc", "-q", "--aggressive")
    w(r, "big.txt", big + "edited on the server\n")
    add("packed_ofs_delta")

    r = new(base, "packed_ref_delta")
    for k in range(5):
        w(r, "big.txt", big + f"rev {k}\n")
        commit(r, f"c{k}")
    git(r, "-c", "repack.useDeltaBaseOffset=false", "repack", "-a", "-d", "-f", "-q")
    w(r, "extra.sh", "#!/bin/sh\n")
    add("packed_ref_delta")

    r = new(base, "two_packs")
    w(r, "a.txt", "a\n")
    commit(r)
    git(r, "repack", "-q")
    w(r, "b.txt", "b\n")
    commit(r)
    git(r, "repack", "-q")
    w(r, "c.txt", "c\n")
    commit(r)          # one loose commit on top of two packs
    add("two_packs")

    r = new(base, "packed_refs_detached")
    w(r, "a.txt", "a\n")
    commit(r)
    git(r, "tag", "-a", "v1", "-m", "v1")
    w(r, "a.txt", "b\n")
    commit(r)
    git(r, "pack-refs", "--all")
    git(r, "checkout", "-q", "--detach", "v1")
    add("packed_refs_detached")

    r = new(base, "branch_packed")
    w(r, "a.txt", "a\n")
    commit(r)
    git(r, "checkout", "-q", "-b", "feature")
    w(r, "f.txt", "f\n")
    commit(r)
    git(r, "pack-refs", "--all")
    add("branch_packed")

    r = new(base, "ignore_rules")
    w(r, ".gitignore", "\n".join([
        "# comment", "*.log", "!keep.log", "/build/", "cache/", "**/tmp/**", "a/**/z.txt", "*.py[co]",
        "secret?.txt", "\\#notcomment", "trailing   ", "uploads/*", "!uploads/.gitkeep", "dir_only/",
        "[Dd]ebug*", "", "logs/", "!logs/important.txt",
    ]) + "\n")
    w(r, "sub/.gitignore", "*.tmp\n!special.tmp\n/local_only\n")
    w(r, "tracked.log", "t\n")
    commit(r)
    w(r, ".git/info/exclude", "excluded_by_info\n*.bak\n")
    for rel in ["x.log", "keep.log", "build/out.o", "src/build/out.o", "cache/c", "deep/cache/c", "q/tmp/r/s",
                "a/z.txt", "a/b/c/z.txt", "m.pyc", "m.py", "secret1.txt", "secret10.txt", "#notcomment",
                "trailing", "uploads/shell.php", "uploads/.gitkeep", "dir_only", "Debug.txt", "debugx",
                "logs/a.txt", "logs/important.txt", "sub/a.tmp", "sub/special.tmp", "sub/local_only",
                "sub/x/local_only", "excluded_by_info", "file.bak", "plain.txt"]:
        w(r, rel, "u\n")
    add("ignore_rules")

    r = new(base, "ignored_served_shell")
    w(r, ".gitignore", "uploads/\n")
    w(r, "index.php", "<?php 1;\n")
    commit(r)
    w(r, "uploads/avatar.png", "\x89PNG fixture\n")
    w(r, "uploads/cmd.php", "<?php // a harmless fixture file\n")
    add("ignored_served_shell")

    r = new(base, "submodule_link")
    w(r, "a.txt", "a\n")
    commit(r)
    sha = "0123456789abcdef0123456789abcdef01234567"
    git(r, "update-index", "--add", "--cacheinfo", f"160000,{sha},vendor/lib")
    git(r, "commit", "-q", "-m", "submodule")
    (r / "vendor" / "lib").mkdir(parents=True, exist_ok=True)
    add("submodule_link")

    r = new(base, "conflict")
    w(r, "a.txt", "base\n")
    commit(r)
    git(r, "checkout", "-q", "-b", "other")
    w(r, "a.txt", "other\n")
    commit(r)
    git(r, "checkout", "-q", "main")
    w(r, "a.txt", "mine\n")
    commit(r)
    git(r, "merge", "-q", "other", check=False)
    add("conflict")

    r = new(base, "many_files")
    for i in range(400):
        w(r, f"d{i % 17}/e{i % 5}/file_{i}.py", f"v{i}\n")
    commit(r)
    git(r, "gc", "-q")
    for i in (3, 77, 205):
        w(r, f"d{i % 17}/e{i % 5}/file_{i}.py", "changed\n")
    add("many_files")

    r = new(base, "odd_names")
    w(r, "with space.txt", "s\n")
    w(r, "ünïcødé.py", "u\n")
    w(r, "tab\there.txt", "t\n")
    w(r, "-dash.txt", "d\n")
    commit(r)
    w(r, "ünïcødé.py", "changed\n")
    w(r, "new\nline.txt", "n\n")
    add("odd_names")

    r = new(base, "filter_attrs")
    w(r, ".gitattributes", "*.bin filter=lfs diff=lfs merge=lfs -text\n")
    w(r, "data.bin", "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 3\n")
    commit(r)
    w(r, "data.bin", "abc")        # what a smudge filter would have written
    add("filter_attrs")

    r = new(base, "hostile_config")
    w(r, "a.txt", "a\n")
    commit(r)
    with open(r / ".git" / "config", "a") as fh:
        fh.write('[core]\n\tfsmonitor = /nonexistent/kratos-fixture-must-never-run\n'
                 '\thooksPath = /nonexistent\n[alias]\n\tst = !touch /nonexistent/x\n')
    add("hostile_config")

    r = new(base, "skip_hash")
    w(r, "a.txt", "a\n")
    git(r, "config", "index.skipHash", "true")
    commit(r)
    w(r, "b.txt", "b\n")
    add("skip_hash")

    r = new(base, "worktree_inside")
    w(r, "a.txt", "a\n")
    commit(r)
    git(r, "worktree", "add", "-q", "wt", "-b", "wt")
    w(r, "wt/new.php", "<?php // fixture\n")
    add("worktree_inside")

    r = new(base, "exec_untracked")
    w(r, "index.html", "<h1>x</h1>\n")
    commit(r)
    w(r, "cgi-bin/run.cgi", "#!/bin/sh\necho fixture\n", 0o755)
    add("exec_untracked")
    return names


def porcelain(repo: Path) -> str:
    return git(repo, "-c", "status.renames=false", "status", "--porcelain=v2", "-z", "--untracked-files=all",
               "--ignored=matching", "--ignore-submodules=none").decode("utf-8", "surrogateescape")


def expected_for(repo: Path) -> dict:
    head = git(repo, "rev-parse", "--verify", "-q", "HEAD", check=False).decode().strip()
    out: dict = {"head": head or None,
                 "format": git(repo, "rev-parse", "--show-object-format").decode().strip(),
                 "status_z": porcelain(repo),
                 "ls_files_z": git(repo, "ls-files", "-s", "-z").decode("utf-8", "surrogateescape"),
                 "ls_tree_z": git(repo, "ls-tree", "-r", "-z", "HEAD", check=False).decode("utf-8", "surrogateescape")
                 if head else ""}
    paths = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for f in filenames + [d for d in dirnames]:
            rel = os.path.relpath(os.path.join(dirpath, f), repo)
            paths.append(rel)
    if (repo / ".gitignore").exists() or (repo / ".git" / "info" / "exclude").exists():
        data = "\0".join(paths).encode("utf-8", "surrogateescape") + b"\0"
        res = git(repo, "check-ignore", "--no-index", "-z", "--stdin", input=data, check=False)
        out["check_ignore"] = sorted(p for p in res.decode("utf-8", "surrogateescape").split("\0") if p)
        out["check_ignore_asked"] = sorted(paths)
    return out


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/gitread")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "repos"
        base.mkdir()
        names = build(base)
        expected = {"git_version": git(base, "--version").decode().strip(), "repos": {}}
        for n in names:
            expected["repos"][n] = expected_for(base / n)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tar:
            for n in names:
                tar.add(base / n, arcname=n, filter=lambda ti: (setattr(ti, "mtime", 0), setattr(ti, "uname", ""),
                                                               setattr(ti, "gname", ""), setattr(ti, "uid", 0),
                                                               setattr(ti, "gid", 0), ti)[-1])
        (out / "repos.tar.gz").write_bytes(buf.getvalue())
        (out / "expected.json").write_text(json.dumps(expected, indent=1, sort_keys=True), encoding="utf-8")
    print(f"{len(names)} repositories -> {out} ({(out / 'repos.tar.gz').stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
