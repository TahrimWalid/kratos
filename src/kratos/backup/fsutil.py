"""Small file helpers the backup modules share: hash a file, flush a folder, compare disks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


def sha_file(path: Path) -> tuple[str, int]:
    """(SHA-256 hex, size) of a file, read in 1 MiB blocks."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
            n += len(block)
    return h.hexdigest(), n


def fsync_dir(folder: Path) -> None:
    """Make a rename or a new file in `folder` durable (best effort)."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inside(path: Path, folder: Path) -> bool:
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
