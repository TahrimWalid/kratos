"""
Which build of Kratos is running, and whether a newer one is on disk
(docs/subagent_connection_ux.md WS8). A long-lived process -- the TUI, or the
always-on listener service -- keeps running the code it started with, so a
user can be looking at an old build without knowing it.

The build id is `<version>+<git short hash>` when running from a git checkout
(read from .git directly, no subprocess), else `<version>+<newest source
mtime>`. `RUNNING_BUILD` is captured once at import; `current_disk_build()`
re-reads it cheaply, so the two can be compared at any time.
"""
from __future__ import annotations

from pathlib import Path

from kratos import __version__

_PKG_DIR = Path(__file__).resolve().parent.parent  # src/kratos


def _git_head(start: Path) -> str | None:
    for d in (start, *start.parents):
        git = d / ".git"
        if git.is_file():  # a worktree: "gitdir: <path>"
            try:
                git = Path(git.read_text().split(":", 1)[1].strip())
            except (OSError, IndexError):
                return None
        if git.is_dir():
            try:
                head = (git / "HEAD").read_text().strip()
                if head.startswith("ref:"):
                    ref = head.split(":", 1)[1].strip()
                    ref_file = git / ref
                    if not ref_file.exists():  # a worktree's refs live in the common dir
                        common = git / "commondir"
                        if common.exists():
                            ref_file = (git / common.read_text().strip()).resolve() / ref
                    if ref_file.exists():
                        return ref_file.read_text().strip()[:10]
                    packed = git / "packed-refs"
                    for line in packed.read_text().splitlines() if packed.exists() else []:
                        if line.endswith(" " + ref):
                            return line.split()[0][:10]
                    return None
                return head[:10]
            except OSError:
                return None
    return None


def _newest_source_mtime() -> str:
    try:
        return str(int(max(p.stat().st_mtime for p in _PKG_DIR.rglob("*.py"))))
    except (OSError, ValueError):
        return "unknown"


def current_disk_build() -> str:
    return f"{__version__}+{_git_head(_PKG_DIR) or _newest_source_mtime()}"


RUNNING_BUILD = current_disk_build()


def newer_build_on_disk() -> str | None:
    """The on-disk build id if it differs from the one running, else None."""
    disk = current_disk_build()
    return disk if disk != RUNNING_BUILD else None
