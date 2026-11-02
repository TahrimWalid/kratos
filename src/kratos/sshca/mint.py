"""One short-lived SSH certificate per run and machine (Phase D.1).

For a machine enrolled in certificates, every SSH connection uses a **fresh
Ed25519 key pair made for this run**, signed by the user CA (kratos.sshca.ca)
into a certificate valid for minutes, bound to the machine's own principal and to
the address the machine sees Kratos from, with no terminal and no forwarding. The
ephemeral private key lives only in a per-run owner-only folder under
``ssh-ca/runs/`` and is deleted when the run ends (and stale folders are swept).

`connection_options` in ``adapters/ssh_remote.py`` calls `credentials_for`:

- a machine not enrolled (or still mid-enrolment) → ``None`` → today's long-lived key;
- an enrolled machine → a `Minted` (ephemeral key + certificate), reused within the
  run until it is close to expiry, then re-minted;
- an enrolled machine Kratos can't sign for right now (CA locked) → `CertUnavailable`,
  so the caller fails loudly rather than ever falling back to the old key.

The certificate's multiplexing master uses a per-run control socket so the end of a
run can close it (``ssh -O exit``) without touching another run; ``ControlPersist``
never outlives the certificate.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat as _stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import run_context, settings_store
from kratos.settings_store import SettingError, SettingSpec
from kratos.sshca import ca as _ca
from kratos.sshca import store as _store
from kratos.target_key import target_key

logger = logging.getLogger("kratos.sshca.mint")

DEFAULT_VALIDITY_MINUTES = 10
MAX_VALIDITY_MINUTES = 60
RENEW_MARGIN_SECONDS = 60          # re-mint when this little validity is left
RUN_SWEEP_AGE_SECONDS = 2 * 3600   # a run folder older than this is from a crashed run


class CertUnavailable(RuntimeError):
    """A machine is enrolled in certificates but Kratos can't produce one right now
    (CA locked, signing failed). The caller must NOT fall back to any other key."""


def _validity_minutes(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise SettingError("a whole number of minutes") from None
    if not 1 <= n <= MAX_VALIDITY_MINUTES:
        raise SettingError(f"1 to {MAX_VALIDITY_MINUTES} minutes")
    return n


settings_store.register(SettingSpec(
    "ssh.cert.minutes", DEFAULT_VALIDITY_MINUTES, _validity_minutes,
    f"How long each SSH login certificate is valid, in minutes (1-{MAX_VALIDITY_MINUTES}; a longer run re-mints).",
))


def validity_minutes(data_dir: Path) -> int:
    try:
        return int(settings_store.get("ssh.cert.minutes", data_dir=data_dir))
    except Exception:  # noqa: BLE001
        return DEFAULT_VALIDITY_MINUTES


# --------------------------------------------------------------------------- the glue's view of an enrolment
def enrolment(data_dir: Path | None, host: str) -> _store.Enrolment | None:
    """The enrolment row for `host`, or None. `None`/empty data_dir → None (callers that
    have no data folder treat every machine as not enrolled)."""
    if data_dir is None or not host:
        return None
    try:
        return _store.get_enrolment(Path(data_dir), host)
    except Exception:  # noqa: BLE001 -- a bad record must never break an SSH connection build
        logger.warning("could not read the enrolment for %s", host, exc_info=True)
        return None


# --------------------------------------------------------------------------- minted material
@dataclass(frozen=True)
class Minted:
    machine: str
    key_path: Path
    cert_path: Path
    control_path: Path
    valid_to: float
    validity_minutes: int
    serial: int


def ssh_options(minted: Minted, data_dir: Path | None = None) -> list[str]:
    """The ssh options that use a minted certificate: the ephemeral key, its
    certificate, only that key, and a per-run multiplexing master whose ControlPersist
    never outlives the certificate."""
    persist = max(1, min(_ca_control_persist(minted), minted.validity_minutes * 60))
    return ["-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ControlMaster=auto", "-o", f"ControlPath={minted.control_path}",
            "-o", f"ControlPersist={persist}",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2"]


def _ca_control_persist(minted: Minted) -> int:
    # The multiplexing master is closed at run end regardless; ControlPersist is the
    # backstop so a master from a run that never closed cleanly still dies by expiry.
    return minted.validity_minutes * 60


# --------------------------------------------------------------------------- run folders + cache
_LOCK = threading.Lock()
_CACHE: dict[tuple[str, str], Minted] = {}       # (run_key, machine) -> Minted
_RUN_CONTROL_PATHS: dict[str, set[str]] = {}     # run_key -> control sockets opened


def _run_key() -> str:
    rid = run_context.current_run_id()
    return rid if rid else f"p{os.getpid()}"


def _runs_root(data_dir: Path) -> Path:
    return _ca.ca_dir(data_dir) / "runs"


def _run_folder(data_dir: Path, run_key: str) -> Path:
    folder = _runs_root(data_dir) / run_key
    _ca._ensure_dir(_ca.ca_dir(data_dir))
    parent = _runs_root(data_dir)
    if not parent.exists():
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
    if not folder.exists():
        folder.mkdir(mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
    return folder


def _machine_tag(machine: str) -> str:
    return hashlib.sha256(machine.encode("utf-8")).hexdigest()[:8]


def _control_socket(machine_tag: str, run_key: str) -> Path:
    """A short multiplexing socket path (sockets have a ~104-char limit), under this
    user's private runtime folder, named so run-end can close it."""
    from kratos.utils import ssh_slots

    base = ssh_slots._folder("ssh-mux")
    if base is None:
        import tempfile
        base = Path(tempfile.gettempdir()) / f"kratos-{os.getuid()}-mux"
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base / f"c{run_key[:12]}-{machine_tag}"


def _sweep_stale_runs(data_dir: Path) -> None:
    root = _runs_root(data_dir)
    if not root.exists():
        return
    cutoff = time.time() - RUN_SWEEP_AGE_SECONDS
    for child in root.iterdir():
        try:
            st = child.lstat()
            if _stat.S_ISDIR(st.st_mode) and st.st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)  # deletion-scan: a crashed run's ephemeral keys, by age
        except OSError:
            continue


# --------------------------------------------------------------------------- minting
def credentials_for(data_dir: Path | None, host: str) -> Minted | None:
    """The minted certificate for this run and `host`, or None when `host` isn't using
    certificates. Reused within the run until close to expiry. Raises CertUnavailable
    when `host` is enrolled but Kratos can't sign right now."""
    if data_dir is None or not host:
        return None
    data_dir = Path(data_dir)
    enr = enrolment(data_dir, host)
    if enr is None or not enr.uses_cert:
        return None
    machine = target_key(host)
    run_key = _run_key()
    with _LOCK:
        cached = _CACHE.get((run_key, machine))
        if cached is not None and cached.valid_to - time.time() > RENEW_MARGIN_SECONDS \
                and cached.key_path.exists() and cached.cert_path.exists():
            return cached
        minted = _mint(data_dir, enr, machine, run_key)
        _CACHE[(run_key, machine)] = minted
        _RUN_CONTROL_PATHS.setdefault(run_key, set()).add(str(minted.control_path))
        return minted


def _mint(data_dir: Path, enr: _store.Enrolment, machine: str, run_key: str) -> Minted:
    _sweep_stale_runs(data_dir)
    folder = _run_folder(data_dir, run_key)
    tag = _machine_tag(machine)
    key_path = folder / tag
    # A fresh ephemeral key for every (re-)mint, so a cert never outlives its key's folder.
    for p in (key_path, key_path.with_name(tag + ".pub"), key_path.with_name(tag + "-cert.pub")):
        try:
            p.unlink()  # deletion-scan: this run's own previous ephemeral key before re-minting
        except FileNotFoundError:
            pass
    gen = _ca._run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    f"kratos-ephemeral-{tag}", "-f", str(key_path)])
    if gen.returncode != 0:
        raise CertUnavailable("could not make an ephemeral key: "
                              + gen.stderr.decode("utf-8", "replace").strip())
    os.chmod(key_path, 0o600)
    minutes = validity_minutes(data_dir)
    serial = _store.next_serial(data_dir)
    run_id = run_context.current_run_id()
    key_id = f"kratos:{tag}:{run_key}:{serial}"
    actor = _actor()
    try:
        cert_path = _ca.sign_user_cert(
            data_dir, pubkey_path=key_path.with_name(tag + ".pub"), key_id=key_id,
            principals=[enr.principal], validity_minutes=minutes,
            source_addresses=enr.source_addresses, serial=serial)
    except _ca.CALocked as e:
        raise CertUnavailable(str(e)) from e
    except _ca.CAError as e:
        raise CertUnavailable(str(e)) from e
    ca_rec = _ca.active_user_ca(data_dir)
    now = time.time()
    valid_to = now + minutes * 60
    _store.record_cert(
        data_dir, key_id=key_id, machine=machine, principals=[enr.principal],
        valid_from=now - 60, valid_to=valid_to, source_addresses=enr.source_addresses,
        ca_fingerprint=ca_rec.fingerprint if ca_rec else "", actor=actor, run_id=run_id, serial=serial)
    logger.info("minted a %d-min certificate (serial %d) for %s", minutes, serial, enr.host)
    return Minted(machine=machine, key_path=key_path, cert_path=cert_path,
                  control_path=_control_socket(tag, run_key), valid_to=valid_to,
                  validity_minutes=minutes, serial=serial)


def _actor() -> str:
    ctx = run_context.current()
    if ctx is not None:
        return f"{ctx.source}:{ctx.run_id[:8]}"
    try:
        import getpass
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "kratos"


# --------------------------------------------------------------------------- run-end cleanup
def _cleanup_run(ctx: run_context.RunContext) -> None:
    """Close this run's multiplexing masters and delete its ephemeral keys."""
    run_key = ctx.run_id
    with _LOCK:
        controls = _RUN_CONTROL_PATHS.pop(run_key, set())
        for key in [k for k in _CACHE if k[0] == run_key]:
            _CACHE.pop(key, None)
    for sock in controls:
        try:
            subprocess.run(["ssh", "-o", f"ControlPath={sock}", "-O", "exit", "x"],
                           capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            os.unlink(sock)  # deletion-scan: this run's own multiplexing socket at run end
        except OSError:
            pass
    # Delete this run's ephemeral key folder in whichever data dir it was made in.
    from kratos import kratos_config as _kconfig
    data_dir = _kconfig.get_active_data_dir()
    if data_dir is not None:
        folder = _runs_root(Path(data_dir)) / run_key
        if folder.exists():
            shutil.rmtree(folder, ignore_errors=True)  # deletion-scan: this run's ephemeral keys at run end


run_context.on_run_end(_cleanup_run)
