"""A deterministic ``.tar.gz`` of a bundle folder: the same folder always gives the same
archive bytes, so its hash can be noted down or sent separately from the file.

Sorted entries, owner/group 0 with empty names, files 0644 and folders 0755, every
modification time set to the manifest's creation time, PAX format (long names without
GNU extensions), gzip with that same time in its header, no file name, level 9.
"""
from __future__ import annotations

import gzip
import hashlib
import tarfile
from pathlib import Path


def _info(name: str, *, size: int = 0, is_dir: bool = False, mtime: int) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mtime = mtime
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.mode = 0o755 if is_dir else 0o644
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    return ti


def write(bundle: Path, out: Path, *, mtime: int) -> str:
    """Write ``out`` (the archive of ``bundle``, entries under ``<bundle name>/``); return its sha256."""
    top = bundle.name
    entries = sorted(p for p in bundle.rglob("*"))
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "wb") as fo, gzip.GzipFile(filename="", mode="wb", fileobj=fo, mtime=mtime,
                                              compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(_info(top, is_dir=True, mtime=mtime))
            for p in entries:
                rel = f"{top}/{p.relative_to(bundle).as_posix()}"
                if p.is_dir():
                    tar.addfile(_info(rel, is_dir=True, mtime=mtime))
                elif p.is_file():
                    with open(p, "rb") as fh:
                        tar.addfile(_info(rel, size=p.stat().st_size, mtime=mtime), fh)
    tmp.replace(out)
    h = hashlib.sha256()
    with open(out, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
