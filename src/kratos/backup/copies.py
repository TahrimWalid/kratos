"""Copies of a backup somewhere else (docs/phaseD/D.8 §3.10).

A copy target is a folder (a mounted drive, a synced folder) or
``sftp://user@host[:port]/path``. SFTP runs the system ``sftp`` in batch mode with a
batch file Kratos writes holding fixed, validated lines -- no shell, no text from
anywhere but this parser. Every copy is verified where it landed: a local copy by its
full SHA-256, a remote one by downloading its sidecar back and reading its size.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.paths import ensure_private_dir
from kratos.utils.hostnames import is_ip_or_hostname

_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/+~-]{1,512}$")
SFTP_TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class Target:
    text: str                 # as the person wrote it (normalised)
    kind: str                 # folder | sftp
    folder: Path | None = None
    user: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""            # remote folder ("" = the login's own folder)


def parse_target(text: str) -> Target:
    text = str(text or "").strip()
    if not text:
        raise ValueError("an empty copy target")
    if text.startswith("sftp://"):
        from urllib.parse import urlsplit

        try:
            u = urlsplit(text)
            port = u.port
        except ValueError as e:
            raise ValueError(f"not a valid sftp://user@host/path target ({e})") from None
        if u.query or u.fragment or u.password is not None:
            raise ValueError("an sftp target is sftp://user@host[:port]/path (no password, query or #)")
        user, host = u.username or "", u.hostname or ""
        if not _USER_RE.match(user):
            raise ValueError("an sftp target needs a valid login name: sftp://user@host/path")
        if not is_ip_or_hostname(host):
            raise ValueError(f"{host!r} is not an address or host name")
        path = u.path[1:] if u.path.startswith("/") else u.path
        home_relative = path.startswith("~/") or path == "~"
        path = path[2:] if home_relative else path
        path = path.rstrip("/")
        if path and (not _PATH_RE.match(path) or ".." in path.split("/") or "~" in path
                     or any(part.startswith("-") for part in path.split("/"))):
            raise ValueError("the remote folder may use only letters, digits and . _ / + - (no ..)")
        if path and not home_relative:
            path = "/" + path
        shown_host = f"[{host}]" if ":" in host else host
        norm = (f"sftp://{user}@{shown_host}{':' + str(port) if port else ''}/"
                + (("~/" + path) if home_relative and path else path.lstrip("/")))
        return Target(norm, "sftp", user=user, host=host, port=port, path=path)
    p = Path(text).expanduser()
    if not p.is_absolute():
        raise ValueError("a copy folder must be an absolute path (or sftp://user@host/path)")
    return Target(str(p), "folder", folder=p)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def copy_to_folder(target: Target, backup: Path, sidecar: Path, sha256: str, *, data_dir: Path) -> dict[str, Any]:
    assert target.folder is not None
    dest = target.folder
    real = Path(os.path.realpath(dest))
    if _inside(real, Path(os.path.realpath(data_dir))):
        return {"target": target.text, "ok": False, "error": "a copy can't go inside Kratos's data folder"}
    ensure_private_dir(dest)
    out = dest / backup.name
    tmp = dest / (backup.name + ".partial")
    if out.exists():
        return {"target": target.text, "ok": False, "error": f"{out} already exists"}
    h = hashlib.sha256()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as w, open(backup, "rb") as r:
        for block in iter(lambda: r.read(1 << 20), b""):
            h.update(block)
            w.write(block)
        w.flush()
        os.fsync(w.fileno())
    if h.hexdigest() != sha256 or _sha256_file(tmp) != sha256:
        return {"target": target.text, "ok": False, "error": "the copy's SHA-256 doesn't match (left as "
                f"{tmp.name} for you to look at)"}
    os.replace(tmp, out)
    side = dest / sidecar.name
    side_tmp = dest / (sidecar.name + ".partial")
    fd = os.open(side_tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as w:
        w.write(sidecar.read_bytes())
    os.replace(side_tmp, side)
    _fsync_dir(dest)
    same = _same_disk(dest, data_dir)
    return {"target": target.text, "ok": True, "file": str(out), "verified": "sha256", "same_disk": same}


def _inside(path: Path, folder: Path) -> bool:
    try:
        path.relative_to(folder)
        return True
    except ValueError:
        return False


def _fsync_dir(folder: Path) -> None:
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_disk(a: Path, b: Path) -> bool:
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return False


def _sftp_argv(target: Target, batch: Path) -> list[str]:
    argv = ["sftp", "-b", str(batch), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if target.port:
        argv += ["-P", str(target.port)]
    host = f"[{target.host}]" if ":" in target.host else target.host
    return argv + [f"{target.user}@{host}"]


def _remote(target: Target, name: str) -> str:
    return f"{target.path}/{name}" if target.path else name


def copy_to_sftp(target: Target, backup: Path, sidecar: Path, *, work: Path) -> dict[str, Any]:
    for p in (backup, sidecar):
        if not _PATH_RE.match(str(p)):
            return {"target": target.text, "ok": False,
                    "error": f"the backup's own path ({p}) has characters an sftp batch can't take safely"}
    ensure_private_dir(work)
    batch = work / "sftp-put.batch"
    remote_file = _remote(target, backup.name)
    lines = []
    if target.path:
        lines.append(f"-mkdir {target.path}")        # '-': already there is fine
    lines += [f"put {backup} {remote_file}.partial",
              f"put {sidecar} {_remote(target, sidecar.name)}",
              f"rename {remote_file}.partial {remote_file}"]
    batch.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        proc = subprocess.run(_sftp_argv(target, batch), capture_output=True, timeout=SFTP_TIMEOUT_SECONDS,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return {"target": target.text, "ok": False, "error": f"sftp could not run: {e}"}
    if proc.returncode != 0:
        return {"target": target.text, "ok": False, "error": "sftp failed: " + _last(proc.stderr)}
    check = work / "sftp-check.batch"
    back = work / "sidecar.check"
    check.write_text(f"ls -l {remote_file}\nget {_remote(target, sidecar.name)} {back}\n", encoding="utf-8")
    try:
        proc = subprocess.run(_sftp_argv(target, check), capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return {"target": target.text, "ok": False, "error": f"copied, but the check could not run: {e}"}
    size = backup.stat().st_size
    listed = proc.stdout.decode("utf-8", "replace")
    size_ok = any(str(size) in line.split() for line in listed.splitlines() if backup.name in line)
    side_ok = back.is_file() and back.read_bytes() == sidecar.read_bytes()
    if proc.returncode != 0 or not size_ok or not side_ok:
        return {"target": target.text, "ok": False,
                "error": "copied, but the copy didn't check out (size or sidecar differ): " + _last(proc.stderr)}
    return {"target": target.text, "ok": True, "file": f"{target.text.rstrip('/')}/{backup.name}",
            "verified": "size and sidecar"}


def _last(stderr: bytes) -> str:
    lines = [ln for ln in stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
    return (lines[-1] if lines else "no error text")[:300]


def copy(target_text: str, backup: Path, sidecar: Path, sha256: str, *, data_dir: Path, work: Path) -> dict[str, Any]:
    try:
        target = parse_target(target_text)
    except ValueError as e:
        return {"target": target_text, "ok": False, "error": str(e)}
    try:
        if target.kind == "folder":
            return copy_to_folder(target, backup, sidecar, sha256, data_dir=data_dir)
        return copy_to_sftp(target, backup, sidecar, work=work)
    except OSError as e:
        return {"target": target.text, "ok": False, "error": f"{type(e).__name__}: {e.strerror or e}"}
