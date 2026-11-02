"""Kratos's SSH certificate authority keys (Phase D.1).

Kratos signs a short-lived user certificate per run and machine (kratos.sshca.mint)
with a **user CA** key, and signs each enrolled machine's host key once with a
separate **host CA** key (so Kratos trusts machines by ``@cert-authority`` instead
of first-contact TOFU). Both CA keys live in ``data_dir/ssh-ca/`` (folder 0700,
files 0600) and NEVER leave the Kratos host. This module makes, loads, protects,
fingerprints, backs up and rotates them, and signs with OpenSSH's own
``ssh-keygen -s`` (never a hand-made certificate encoder).

The CA private key is the most valuable secret on the Kratos host. Four protection
modes, chosen at setup:

- **file** — the private key is an owner-only file in ``ssh-ca/``. A copy of that
  file can sign for every enrolled machine (the power the old key had), but
  certificates still expire and stay bound to Kratos's address. Always available,
  so unattended runs work after a reboot.
- **agent** — the private key is passphrase-protected on disk and held in a
  dedicated ssh-agent; signing uses ``ssh-keygen -Us``. After a reboot the agent is
  empty and runs stop with "CA locked" until ``kratos ssh-ca unlock`` — never a
  silent fall back to the old key.
- **token** — the CA key on a PKCS#11 token; signing uses ``ssh-keygen -s <ca.pub> -D <lib>``.
- **tpm** — the private key is stored only sealed to this machine's TPM
  (``systemd-creds encrypt --with-key=tpm2``). Signing decrypts it into memory,
  feeds it to the dedicated agent (``ssh-add -``) with a lifetime, and signs with
  ``-U``; the plaintext key never touches disk. A sealed credential copied to
  another machine fails to decrypt.

The record of which fingerprints are Kratos's is in ``ssh_ca_keys`` (kratos.sshca.store);
own-login recognition reads it. Two user CA keys are trusted at a time (active +
next) so rotation never locks Kratos out, as C.4's TLS pins do.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import stat as _stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.sshca import store as _store

logger = logging.getLogger("kratos.sshca.ca")

CA_DIR_NAME = "ssh-ca"
CONFIG_NAME = "config.json"
README_NAME = "README.txt"
AGENT_SOCK_NAME = "agent.sock"
AGENT_PID_NAME = "agent.pid"

MODES = ("file", "agent", "token", "tpm")
DEFAULT_AGENT_LIFETIME_SECONDS = 24 * 3600   # tpm: how long a decrypted key stays in the agent

_README = """\
Kratos SSH certificate authority -- SECRET, owner-only.

These keys sign the short-lived SSH certificates Kratos uses to log in to your
machines, and the host certificates your machines present back. The user CA key
is the most valuable secret on this computer: a copy of it can sign a login
certificate for every machine enrolled in certificates. The certificates it signs
still expire in minutes and stay bound to this computer's address, but keep this
folder private and keep a copy somewhere safe (with your Kratos database backup):
losing it means re-enrolling every machine.

Protection mode is shown by `kratos ssh-ca status`. In 'agent' mode, after a
reboot run `kratos ssh-ca unlock` before scheduled runs can sign again.
"""


class CAError(RuntimeError):
    """The CA folder is missing/unsafe, no CA key exists, or signing failed."""


class CALocked(CAError):
    """The CA key can't sign right now (agent mode: not unlocked after a reboot;
    tpm mode: sealed credential can't be decrypted on this machine)."""


# --------------------------------------------------------------------------- folder + files
def ca_dir(data_dir: Path) -> Path:
    return Path(data_dir) / CA_DIR_NAME


def _check_private(path: Path, *, directory: bool) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise CAError(f"{path} is missing") from None
    if _stat.S_ISLNK(st.st_mode):
        raise CAError(f"{path} is a symbolic link -- the CA keys must be plain files")
    if directory != _stat.S_ISDIR(st.st_mode):
        raise CAError(f"{path} is not a {'folder' if directory else 'file'}")
    if st.st_uid != os.geteuid():
        raise CAError(f"{path} belongs to another user (uid {st.st_uid}) -- the CA keys must be yours")
    if st.st_mode & 0o077:
        want = "700" if directory else "600"
        raise CAError(f"{path} can be read by other users (mode {st.st_mode & 0o777:o}); "
                      f"run `chmod {want} {path}` -- the CA keys are secret")


def _ensure_dir(path: Path) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        os.chmod(path, 0o700)
    _check_private(path, directory=True)


def _write_private(path: Path, data: bytes) -> None:
    """Atomic, 0600 from the first byte, never through a symlink."""
    if path.is_symlink():
        raise CAError(f"{path} is a symbolic link -- refusing to write a key through it")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)  # deletion-scan: our own half-written temp file, never a kept key
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- config (mode, token lib)
def _config_path(data_dir: Path) -> Path:
    return ca_dir(data_dir) / CONFIG_NAME


def read_config(data_dir: Path) -> dict[str, Any]:
    path = _config_path(data_dir)
    if not path.exists():
        return {}
    try:
        _check_private(path, directory=False)
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_config(data_dir: Path, **updates: Any) -> dict[str, Any]:
    _ensure_dir(ca_dir(data_dir))
    doc = read_config(data_dir)
    doc.update(updates)
    _write_private(_config_path(data_dir), (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    return doc


def configured_mode(data_dir: Path) -> str:
    """The CA protection mode this install uses for new keys (default 'file')."""
    mode = read_config(data_dir).get("mode")
    return mode if mode in MODES else "file"


# --------------------------------------------------------------------------- ssh-keygen helpers
def _run(argv: list[str], *, env: dict[str, str] | None = None, timeout: int = 30,
         stdin: bytes | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(argv, capture_output=True, timeout=timeout,
                          input=stdin, env=full_env,
                          stdin=None if stdin is not None else subprocess.DEVNULL)


def fingerprint_of_pubkey(pub_line: str) -> str:
    """The SHA256 fingerprint (``SHA256:...``) of an OpenSSH public key line."""
    import tempfile

    fd, tmp = tempfile.mkstemp(suffix=".pub")
    try:
        os.write(fd, (pub_line.strip() + "\n").encode("utf-8"))
        os.close(fd)
        proc = _run(["ssh-keygen", "-lf", tmp])
        if proc.returncode != 0:
            raise CAError("ssh-keygen -lf failed: " + proc.stderr.decode("utf-8", "replace").strip())
        parts = proc.stdout.decode("utf-8", "replace").split()
        for p in parts:
            if p.startswith("SHA256:"):
                return p
        raise CAError("could not read a SHA256 fingerprint from ssh-keygen -lf")
    finally:
        try:
            os.unlink(tmp)  # deletion-scan: our own temporary copy of a PUBLIC key
        except OSError:
            pass


# --------------------------------------------------------------------------- the dedicated agent (agent / tpm modes)
def _agent_sock(data_dir: Path) -> Path:
    return ca_dir(data_dir) / AGENT_SOCK_NAME


def _agent_env(data_dir: Path) -> dict[str, str]:
    return {"SSH_AUTH_SOCK": str(_agent_sock(data_dir))}


def _agent_running(data_dir: Path) -> bool:
    sock = _agent_sock(data_dir)
    if not sock.exists():
        return False
    proc = _run(["ssh-add", "-l"], env=_agent_env(data_dir), timeout=10)
    # rc 0 = has keys, 1 = running but empty, 2 = could not connect
    return proc.returncode in (0, 1)


def ensure_agent(data_dir: Path) -> None:
    """Start the dedicated ssh-agent if it isn't running (agent / tpm modes)."""
    _ensure_dir(ca_dir(data_dir))
    if _agent_running(data_dir):
        return
    sock = _agent_sock(data_dir)
    try:
        sock.unlink()
    except FileNotFoundError:
        pass
    proc = _run(["ssh-agent", "-a", str(sock)], timeout=10)
    if proc.returncode != 0:
        raise CAError("could not start the CA ssh-agent: " + proc.stderr.decode("utf-8", "replace").strip())
    out = proc.stdout.decode("utf-8", "replace")
    for line in out.splitlines():
        if line.startswith("SSH_AGENT_PID="):
            pid = line.split("=", 1)[1].split(";", 1)[0]
            _write_private(ca_dir(data_dir) / AGENT_PID_NAME, (pid + "\n").encode("utf-8"))
    os.chmod(sock, 0o600)


def _agent_has(data_dir: Path, fingerprint: str) -> bool:
    if not _agent_sock(data_dir).exists():
        return False
    proc = _run(["ssh-add", "-l"], env=_agent_env(data_dir), timeout=10)
    if proc.returncode != 0:
        return False
    return fingerprint in proc.stdout.decode("utf-8", "replace")


# --------------------------------------------------------------------------- key records
@dataclass(frozen=True)
class LoadedCA:
    record: _store.CAKeyRecord
    data_dir: Path

    @property
    def fingerprint(self) -> str:
        return self.record.fingerprint

    @property
    def mode(self) -> str:
        return self.record.mode

    @property
    def pub_path(self) -> Path:
        return ca_dir(self.data_dir) / (self.record.key_ref + ".pub")

    @property
    def private_path(self) -> Path:
        return ca_dir(self.data_dir) / self.record.key_ref


def active_user_ca(data_dir: Path) -> LoadedCA | None:
    rec = _store.ca_key(data_dir, kind="user", role="active")
    return LoadedCA(rec, Path(data_dir)) if rec else None


def host_ca(data_dir: Path) -> LoadedCA | None:
    rec = _store.ca_key(data_dir, kind="host", role="active")
    return LoadedCA(rec, Path(data_dir)) if rec else None


def trusted_user_fingerprints(data_dir: Path, *, now: float | None = None) -> list[str]:
    """Active + next + recently-retired user CA fingerprints (own-login recognition)."""
    try:
        return _store.trusted_user_fingerprints(data_dir, now=now)
    except Exception:  # noqa: BLE001 -- an unreadable record must never break detection
        logger.warning("could not read the CA records", exc_info=True)
        return []


def public_ca_lines(data_dir: Path, *, kind: str) -> list[str]:
    """The OpenSSH public key lines a machine trusts for `kind` ('user'/'host'):
    active + next (both go in the machine's CA file so rotation never locks out)."""
    out = []
    for role in ("active", "next"):
        rec = _store.ca_key(data_dir, kind=kind, role=role)
        if rec:
            out.append(rec.public_key)
    return out


# --------------------------------------------------------------------------- creation
def _new_ca_key(data_dir: Path, *, kind: str, mode: str, actor: str | None, role: str = "active") -> LoadedCA:
    """Make one CA key pair of `kind` under protection `mode`, record it, return it.
    The private half is written once; for tpm it is then sealed and the plaintext
    removed; for agent it stays passphrase-protected on disk."""
    _ensure_dir(ca_dir(data_dir))
    tmp_base = ca_dir(data_dir) / f".newca-{secrets.token_hex(6)}"
    try:
        comment = f"kratos-{kind}-ca"
        _run_gen = _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(tmp_base)])
        if _run_gen.returncode != 0:
            raise CAError("ssh-keygen could not make a CA key: " + _run_gen.stderr.decode("utf-8", "replace").strip())
        pub_line = (tmp_base.parent / (tmp_base.name + ".pub")).read_text(encoding="utf-8").strip()
        fp = fingerprint_of_pubkey(pub_line)
        fp16 = fp.split(":", 1)[1][:16].replace("/", "_").replace("+", "-")
        key_ref = f"{kind}_ca-{fp16}"
        priv_path = ca_dir(data_dir) / key_ref
        pub_path = ca_dir(data_dir) / (key_ref + ".pub")
        priv_bytes = tmp_base.read_bytes()
        _write_private(pub_path, (pub_line + "\n").encode("utf-8"))
        if mode == "tpm":
            _seal_private(data_dir, priv_path, priv_bytes)
        else:
            _write_private(priv_path, priv_bytes)
    finally:
        for p in (tmp_base, tmp_base.parent / (tmp_base.name + ".pub")):
            try:
                os.unlink(p)  # deletion-scan: the throwaway freshly-generated key before it is stored/sealed
            except OSError:
                pass
    _store.record_ca_key(data_dir, fingerprint=fp, kind=kind, role=role, mode=mode,
                         public_key=pub_line, key_ref=key_ref)
    logger.info("made a %s CA key (%s, mode=%s) for %s", kind, fp, mode, str(actor or "")[:80])
    return LoadedCA(_store.ca_key(data_dir, kind=kind, role=role), Path(data_dir))  # type: ignore[arg-type]


def ensure_user_ca(data_dir: Path, *, mode: str | None = None, actor: str | None = None) -> LoadedCA:
    """The active user CA, made once on first use under `mode` (default: configured)."""
    existing = active_user_ca(data_dir)
    if existing is not None:
        return existing
    mode = mode or configured_mode(data_dir)
    if mode not in MODES:
        raise CAError(f"unknown CA mode {mode!r}; one of {MODES}")
    _write_config(data_dir, mode=mode)
    _write_private(ca_dir(data_dir) / README_NAME, _README.encode("utf-8"))
    return _new_ca_key(data_dir, kind="user", mode=mode, actor=actor)


def ensure_host_ca(data_dir: Path, *, actor: str | None = None) -> LoadedCA:
    """The active host CA, made once on first use (same mode as the user CA)."""
    existing = host_ca(data_dir)
    if existing is not None:
        return existing
    return _new_ca_key(data_dir, kind="host", mode=configured_mode(data_dir), actor=actor)


# --------------------------------------------------------------------------- tpm sealing
def has_tpm2() -> bool:
    """systemd-creds reports full TPM2 support (binary present, libraries present)."""
    try:
        proc = _run(["systemd-creds", "has-tpm2"], timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.decode("utf-8", "replace").strip().startswith("yes")


def _seal_private(data_dir: Path, priv_path: Path, priv_bytes: bytes) -> None:
    """Seal a private key to this machine's TPM with systemd-creds and store only the
    sealed blob (``<key>.cred``). No PCR binding by default (a firmware/kernel update
    must not lock Kratos out)."""
    cred_path = priv_path.with_name(priv_path.name + ".cred")
    proc = _run(["systemd-creds", "encrypt", "--with-key=tpm2", "--name=kratos-ssh-ca", "-", "-"],
                stdin=priv_bytes, timeout=30)
    if proc.returncode != 0:
        raise CAError("systemd-creds could not seal the CA key to the TPM: "
                      + proc.stderr.decode("utf-8", "replace").strip())
    _write_private(cred_path, proc.stdout)


def _unseal_private(data_dir: Path, priv_path: Path) -> bytes:
    cred_path = priv_path.with_name(priv_path.name + ".cred")
    if not cred_path.exists():
        raise CALocked(f"the sealed CA key {cred_path} is missing")
    proc = _run(["systemd-creds", "decrypt", "--name=kratos-ssh-ca", str(cred_path), "-"], timeout=30)
    if proc.returncode != 0:
        raise CALocked("this machine's TPM could not decrypt the CA key (a sealed credential is useless on "
                       "another computer, and a TPM reset or moved disk means re-creating the CA): "
                       + proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


# --------------------------------------------------------------------------- unlocking (agent / tpm)
def ensure_signable(data_dir: Path, ca: LoadedCA) -> None:
    """Raise CALocked if `ca` can't sign right now. For file/token nothing is needed;
    for agent the key must be loaded; for tpm the sealed key is loaded on demand."""
    if ca.mode in ("file", "token"):
        return
    ensure_agent(data_dir)
    if _agent_has(data_dir, ca.fingerprint):
        return
    if ca.mode == "tpm":
        priv = _unseal_private(data_dir, ca.private_path)
        _agent_add_stdin(data_dir, priv, lifetime=DEFAULT_AGENT_LIFETIME_SECONDS)
        if not _agent_has(data_dir, ca.fingerprint):
            raise CALocked("the TPM-sealed CA key would not load into the agent")
        return
    raise CALocked("CA locked -- unlock it with `kratos ssh-ca unlock`")


def _agent_add_stdin(data_dir: Path, priv_bytes: bytes, *, lifetime: int | None = None) -> None:
    argv = ["ssh-add"]
    if lifetime:
        argv += ["-t", str(lifetime)]
    argv += ["-"]
    proc = _run(argv, env=_agent_env(data_dir), stdin=priv_bytes, timeout=20)
    if proc.returncode != 0:
        raise CAError("ssh-add could not load the CA key into the agent: "
                      + proc.stderr.decode("utf-8", "replace").strip())


def unlock(data_dir: Path, ca: LoadedCA | None = None) -> None:
    """Load the CA private key into the dedicated agent (agent mode: prompts for the
    passphrase on the terminal; tpm mode: unseals it). People-only, interactive."""
    ca = ca or active_user_ca(data_dir)
    if ca is None:
        raise CAError("there is no CA key yet")
    ensure_agent(data_dir)
    if ca.mode == "tpm":
        priv = _unseal_private(data_dir, ca.private_path)
        _agent_add_stdin(data_dir, priv, lifetime=DEFAULT_AGENT_LIFETIME_SECONDS)
        return
    if ca.mode != "agent":
        return  # file/token: nothing to unlock
    # Let ssh-add prompt for the passphrase on the real terminal.
    proc = subprocess.run(["ssh-add", str(ca.private_path)], env={**os.environ, **_agent_env(data_dir)})
    if proc.returncode != 0:
        raise CAError("ssh-add could not load the CA key (wrong passphrase?)")


def is_unlocked(data_dir: Path, ca: LoadedCA | None = None) -> bool:
    ca = ca or active_user_ca(data_dir)
    if ca is None:
        return False
    if ca.mode in ("file", "token"):
        return True
    return _agent_has(data_dir, ca.fingerprint)


# --------------------------------------------------------------------------- signing
def sign_user_cert(data_dir: Path, *, pubkey_path: Path, key_id: str, principals: list[str],
                   validity_minutes: int, source_addresses: list[str], serial: int) -> Path:
    """Sign the ephemeral public key at `pubkey_path` into a user certificate
    (``<pubkey>-cert.pub``) with the active user CA, and return the cert path. Raises
    CALocked when the CA can't sign (never falls back to any other key)."""
    ca = active_user_ca(data_dir)
    if ca is None:
        raise CAError("there is no user CA yet -- set up certificates first")
    ensure_signable(data_dir, ca)
    argv = ["ssh-keygen"]
    env: dict[str, str] | None = None
    if ca.mode in ("agent", "tpm"):
        argv += ["-U", "-s", str(ca.pub_path)]
        env = _agent_env(data_dir)
    elif ca.mode == "token":
        lib = read_config(data_dir).get("pkcs11_lib")
        if not lib:
            raise CAError("token mode but no PKCS#11 library is configured (kratos ssh-ca set-token <lib>)")
        argv += ["-D", str(lib), "-s", str(ca.pub_path)]
    else:  # file
        argv += ["-s", str(ca.private_path)]
    argv += ["-I", key_id, "-n", ",".join(principals), "-V", f"-1m:+{int(validity_minutes)}m",
             "-z", str(serial), "-O", "clear"]
    if source_addresses:
        argv += ["-O", "source-address=" + ",".join(source_addresses)]
    argv.append(str(pubkey_path))
    proc = _run(argv, env=env, timeout=30)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        if ca.mode in ("agent", "tpm") and ("agent" in err.lower() or "no identities" in err.lower()):
            raise CALocked("CA locked -- unlock it with `kratos ssh-ca unlock`")
        raise CAError("ssh-keygen could not sign the certificate: " + err)
    cert_path = pubkey_path.with_name(pubkey_path.name[:-4] + "-cert.pub" if pubkey_path.name.endswith(".pub")
                                      else pubkey_path.name + "-cert.pub")
    if not cert_path.exists():
        raise CAError(f"ssh-keygen reported success but {cert_path} is missing")
    return cert_path


def sign_host_cert(data_dir: Path, *, host_pubkey_path: Path, principals: list[str],
                   validity_days: int = 3650, serial: int | None = None) -> Path:
    """Sign a machine's host public key (``-h``) with the host CA. Long validity; the
    principals are the names and addresses Kratos uses to reach the machine."""
    ca = ensure_host_ca(data_dir)
    ensure_signable(data_dir, ca)
    serial = serial if serial is not None else int(time.time())
    argv = ["ssh-keygen", "-h"]
    env: dict[str, str] | None = None
    if ca.mode in ("agent", "tpm"):
        argv += ["-U", "-s", str(ca.pub_path)]
        env = _agent_env(data_dir)
    elif ca.mode == "token":
        lib = read_config(data_dir).get("pkcs11_lib")
        if not lib:
            raise CAError("token mode but no PKCS#11 library is configured")
        argv += ["-D", str(lib), "-s", str(ca.pub_path)]
    else:
        argv += ["-s", str(ca.private_path)]
    argv += ["-I", "kratos-host:" + (principals[0] if principals else "host"),
             "-n", ",".join(principals), "-V", f"-1h:+{int(validity_days)}d", "-z", str(serial)]
    argv.append(str(host_pubkey_path))
    proc = _run(argv, env=env, timeout=30)
    if proc.returncode != 0:
        raise CAError("ssh-keygen could not sign the host certificate: "
                      + proc.stderr.decode("utf-8", "replace").strip())
    cert = host_pubkey_path.with_name(host_pubkey_path.name[:-4] + "-cert.pub")
    if not cert.exists():
        raise CAError(f"ssh-keygen reported success but {cert} is missing")
    return cert


# --------------------------------------------------------------------------- rotation
def rotate_user_ca(data_dir: Path, *, actor: str) -> LoadedCA:
    """Make the 'next' user CA key (people-only). Both active and next go in every
    machine's CA file, so signing can switch to it later without a locked-out window.
    `promote_next` finishes the switch once every enrolled machine trusts it."""
    tool = settings_store.in_tool_call()
    if tool:
        raise CAError(f"rotating the CA is a person's decision -- refused inside the tool call {tool!r}")
    if _store.ca_key(data_dir, kind="user", role="next") is not None:
        raise CAError("a 'next' CA key already exists -- finish the rotation (promote it) or discard it first")
    if active_user_ca(data_dir) is None:
        raise CAError("there is no active CA to rotate")
    return _new_ca_key(data_dir, kind="user", mode=configured_mode(data_dir), actor=actor, role="next")


def rotation_blockers(data_dir: Path) -> list[str]:
    """Enrolled machines that don't trust the 'next' user CA yet; the switch waits for
    them (named), like C.4's pin rotation."""
    nxt = _store.ca_key(data_dir, kind="user", role="next")
    if nxt is None:
        return []
    out = []
    for enr in _store.list_enrolments(data_dir):
        if enr.uses_cert and nxt.fingerprint not in enr.trusted_ca_fingerprints:
            out.append(enr.host)
    return out


def promote_next(data_dir: Path, *, actor: str, force: bool = False) -> LoadedCA:
    """Switch signing to the 'next' user CA: it becomes active, the old active becomes
    retired (still trusted for the 7-day window). Refuses while any enrolled machine
    doesn't trust 'next' yet, unless `force`."""
    tool = settings_store.in_tool_call()
    if tool:
        raise CAError(f"promoting the CA is a person's decision -- refused inside the tool call {tool!r}")
    nxt = _store.ca_key(data_dir, kind="user", role="next")
    if nxt is None:
        raise CAError("there is no 'next' CA to promote -- run `kratos ssh-ca rotate` first")
    blockers = rotation_blockers(data_dir)
    if blockers and not force:
        raise CAError("these machines don't trust the next CA key yet: " + ", ".join(blockers)
                      + " -- add its line on each (shown by `kratos ssh-ca rotate`), or re-run with --force")
    old = active_user_ca(data_dir)
    if old is not None:
        _store.set_ca_role(data_dir, old.fingerprint, "retired", retired_at=time.time())
    _store.set_ca_role(data_dir, nxt.fingerprint, "active")
    logger.info("promoted the next user CA to active by %s", str(actor)[:80])
    return LoadedCA(_store.ca_key(data_dir, kind="user", role="active"), Path(data_dir))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- backup
def backup_user_ca(data_dir: Path, dest: Path, *, passphrase: str) -> Path:
    """Write a passphrase-protected copy of the active user CA private key to `dest`
    (for file/agent modes). The person keeps it off this machine. tpm mode's backup is
    the sealed credential plus this export made once at creation."""
    ca = active_user_ca(data_dir)
    if ca is None:
        raise CAError("there is no user CA to back up")
    if not passphrase:
        raise CAError("a backup copy must be passphrase-protected")
    dest = Path(dest)
    if ca.mode == "tpm":
        priv = _unseal_private(data_dir, ca.private_path)
    else:
        priv = ca.private_path.read_bytes()
    _write_private(dest, priv)
    proc = _run(["ssh-keygen", "-p", "-f", str(dest), "-N", passphrase, "-P", ""], timeout=30)
    if proc.returncode != 0:
        # The source key may already be passphrase-protected (agent mode): try old passphrase empty failed.
        raise CAError("could not passphrase-protect the backup copy: "
                      + proc.stderr.decode("utf-8", "replace").strip())
    try:
        (dest.parent / (dest.name + ".pub")).write_text(ca.record.public_key + "\n", encoding="utf-8")
    except OSError:
        pass
    return dest
