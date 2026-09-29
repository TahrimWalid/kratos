"""
Which build of Kratos is running, and whether a newer one is on disk
(docs/subagent_connection_ux.md WS8). A long-lived process -- the TUI, or the
always-on listener service -- keeps running the code it started with, so a
user can be looking at an old build without knowing it.

The build id is `<version>+<git short hash>.<newest source mtime>` (the hash
read from .git directly, no subprocess; `src` outside a checkout). The mtime part
makes an uncommitted edit, a checkout or a reinstall count as a different build,
which the commit hash alone would miss. Compare ids for equality only; show
them with `display_build`. `RUNNING_BUILD` is captured once at import;
`current_disk_build()` re-reads the disk (cached for a few seconds).
"""
from __future__ import annotations

import time
from pathlib import Path

from kratos import __version__

_PKG_DIR = Path(__file__).resolve().parent.parent  # src/kratos


def _git_dir(start: Path) -> Path | None:
    for d in (start, *start.parents):
        git = d / ".git"
        if git.is_file():  # a worktree: "gitdir: <path>"
            try:
                git = (d / git.read_text().split(":", 1)[1].strip()).resolve()
            except (OSError, IndexError):
                return None
        if git.is_dir():
            return git
    return None


def _git_head(start: Path) -> str | None:
    git = _git_dir(start)
    if git is None:
        return None
    try:
        common = git
        if (git / "commondir").exists():  # worktree: branch refs live in the main repo's git dir
            common = (git / (git / "commondir").read_text().strip()).resolve()
        head = (git / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head[:10]  # detached HEAD
        ref = head.split(":", 1)[1].strip()
        for base in (git, common):
            if (base / ref).exists():
                return (base / ref).read_text().strip()[:10]
        for base in (git, common):
            packed = base / "packed-refs"
            if packed.exists():
                for line in packed.read_text().splitlines():
                    if line.endswith(" " + ref):
                        return line.split()[0][:10]
    except OSError:
        return None
    return None


def _newest_source_mtime() -> str:
    try:
        return str(int(max(p.stat().st_mtime for p in _PKG_DIR.rglob("*.py"))))
    except (OSError, ValueError):
        return "unknown"


_CACHE_SECONDS = 5.0
_cache: tuple[float, str] | None = None


def current_disk_build() -> str:
    global _cache
    now = time.monotonic()
    if _cache is None or now - _cache[0] > _CACHE_SECONDS:
        _cache = (now, f"{__version__}+{_git_head(_PKG_DIR) or 'src'}.{_newest_source_mtime()}")
    return _cache[1]


def display_build(build_id: str | None) -> str:
    """'0.3.0 (abc1234)' for a git build, '0.3.0' otherwise; '?' for None."""
    if not build_id:
        return "?"
    version, _, rest = build_id.partition("+")
    rev = rest.split(".", 1)[0]
    return f"{version} ({rev[:7]})" if rev and rev not in ("src", "unknown") and not rev.isdigit() else version


RUNNING_BUILD = current_disk_build()


def newer_build_on_disk() -> str | None:
    """The on-disk build id if the code on disk differs from what this process
    loaded (newer or not -- a checkout of an older branch counts too), else None."""
    disk = current_disk_build()
    return disk if disk != RUNNING_BUILD else None


def restart_hint() -> str | None:
    disk = newer_build_on_disk()
    if disk is None:
        return None
    return (f"Kratos on disk changed since this window opened (running {display_build(RUNNING_BUILD)}, on disk "
            f"{display_build(disk)}). Quit and run `kratos` again to use it.")
