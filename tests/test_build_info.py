"""Running build vs. the code on disk (connection-UX WS8)."""
from __future__ import annotations

import asyncio
import os
import time

import pytest

from kratos.utils import build_info as B


def _repo(tmp_path, head="ref: refs/heads/main\n"):
    git = tmp_path / "repo" / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text(head)
    pkg = tmp_path / "repo" / "src" / "kratos"
    pkg.mkdir(parents=True)
    return git, pkg


def test_branch_ref(tmp_path):
    git, pkg = _repo(tmp_path)
    (git / "refs" / "heads" / "main").write_text("abcdef1234567890\n")
    assert B._git_head(pkg) == "abcdef1234"


def test_packed_ref_and_detached_head(tmp_path):
    git, pkg = _repo(tmp_path)
    (git / "packed-refs").write_text("# pack-refs\n1111111111aaaa refs/heads/main\n")
    assert B._git_head(pkg) == "1111111111"
    (git / "HEAD").write_text("2222222222bbbb\n")
    assert B._git_head(pkg) == "2222222222"


def test_worktree_reads_refs_from_the_common_dir(tmp_path):
    main_git, _ = _repo(tmp_path)
    (main_git / "packed-refs").write_text("3333333333cccc refs/heads/feature\n")
    wt_git = main_git / "worktrees" / "wt"
    wt_git.mkdir(parents=True)
    (wt_git / "HEAD").write_text("ref: refs/heads/feature\n")
    (wt_git / "commondir").write_text("../..\n")
    wt = tmp_path / "wt"
    (wt / "src" / "kratos").mkdir(parents=True)
    (wt / ".git").write_text(f"gitdir: {wt_git}\n")
    assert B._git_head(wt / "src" / "kratos") == "3333333333"


def test_no_git_is_fine(tmp_path):
    (tmp_path / "x").mkdir()
    assert B._git_head(tmp_path / "x") is None


@pytest.mark.parametrize("bid,shown", [
    ("0.3.0+abcdef1234.1790000000", "0.3.0 (abcdef1)"),
    ("0.3.0+src.1790000000", "0.3.0"),
    ("0.3.0", "0.3.0"),
    (None, "?"),
])
def test_display_build(bid, shown):
    assert B.display_build(bid) == shown


def test_an_uncommitted_edit_counts_as_a_changed_build(tmp_path, monkeypatch):
    git, pkg = _repo(tmp_path)
    (git / "refs" / "heads" / "main").write_text("abcdef1234567890\n")
    src = pkg / "mod.py"
    src.write_text("x = 1\n")
    old = time.time() - 100
    os.utime(src, (old, old))
    monkeypatch.setattr(B, "_PKG_DIR", pkg)
    monkeypatch.setattr(B, "_cache", None)
    monkeypatch.setattr(B, "RUNNING_BUILD", B.current_disk_build())
    assert B.newer_build_on_disk() is None and B.restart_hint() is None
    src.write_text("x = 2\n")  # same commit, edited file
    monkeypatch.setattr(B, "_cache", None)
    assert B.newer_build_on_disk() is not None
    assert "Quit and run `kratos` again" in B.restart_hint()


def test_doctor_reports_the_build(monkeypatch):
    from kratos.agent import doctor

    rows: list = []
    monkeypatch.setattr(B, "newer_build_on_disk", lambda: None)
    doctor._check_build(rows)
    assert rows[-1]["status"] == "info" and "matches the code on disk" in rows[-1]["detail"]
    monkeypatch.setattr(B, "newer_build_on_disk", lambda: "9.9.9+ffffffffff.1")
    doctor._check_build(rows)
    assert rows[-1]["status"] == "warn" and "9.9.9 (fffffff)" in rows[-1]["detail"] and rows[-1]["fix"]


def test_app_says_it_once(monkeypatch):
    from kratos.tui_mk2.app import KratosTUI

    notes: list = []
    monkeypatch.setattr(B, "restart_hint", lambda: "Kratos on disk changed")
    app = KratosTUI.__new__(KratosTUI)
    app._build_change_noted = False
    app.notify = lambda msg, **kw: notes.append(msg)
    app._check_build_on_disk()
    app._check_build_on_disk()
    assert notes == ["Kratos on disk changed"]


def test_subagent_screen_shows_this_windows_staleness(tmp_path, monkeypatch):
    import io

    from rich.console import Console
    from textual.app import App

    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    monkeypatch.setattr(B, "restart_hint", lambda: "Kratos on disk changed since this window opened")
    screen = SubAgentScreen(tmp_path)
    out = {}

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with Host().run_test() as pilot:
            await pilot.pause()
            buf = io.StringIO()
            Console(file=buf, width=200).print(screen.query_one("#sa-listener")._Static__content)
            out["line"] = buf.getvalue()

    asyncio.run(run())
    assert "changed since this window opened" in out["line"]


def test_a_docs_only_commit_is_not_a_code_change(tmp_path, monkeypatch):
    """Seen live: the always-on listener said it 'runs older code than is on disk'
    after a commit that only touched docs -- the id included the commit hash."""
    git, pkg = _repo(tmp_path)
    head = git / "refs" / "heads" / "main"
    head.write_text("abcdef1234567890\n")
    (pkg / "mod.py").write_text("x = 1\n")
    monkeypatch.setattr(B, "_PKG_DIR", pkg)
    monkeypatch.setattr(B, "_cache", None)
    monkeypatch.setattr(B, "_digest_cache", None)
    monkeypatch.setattr(B, "RUNNING_BUILD", B.current_disk_build())
    head.write_text("fedcba9876543210\n")             # a new commit, code untouched
    monkeypatch.setattr(B, "_cache", None)
    assert B.newer_build_on_disk() is None
    (pkg / "mod.py").write_text("x = 3\n")            # the code itself changes
    monkeypatch.setattr(B, "_cache", None)
    assert B.newer_build_on_disk() is not None


@pytest.mark.parametrize("a,b,same", [
    ("0.1.0+aaaa.f1", "0.1.0+bbbb.f1", True),         # different commit, same code
    ("0.1.0+aaaa.f1", "0.1.0+aaaa.f2", False),        # same commit, edited code
    ("0.1.0+aaaa.f1", "0.2.0+aaaa.f1", False),        # different version
    ("0.1.0+src.f1", "0.1.0+aaaa.f1", True),          # installed vs checkout, same code
    (None, "0.1.0+a.f", False),
])
def test_same_code(a, b, same):
    assert B.same_code(a, b) is same
