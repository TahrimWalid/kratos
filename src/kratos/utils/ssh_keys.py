"""
This machine's SSH key for reaching targets (kratos_config.SSH_TARGET_KEY_PATH):
read its public half, build the line that authorizes it ON a target, and --
only when the operator explicitly asks -- create it.

The same key is used by the direct-SSH investigation tools and the sub-agent
SSH deploy, so authorizing it once on a target covers both. Kratos never sends
this key anywhere itself and never handles a password.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _key_path() -> Path:
    from kratos import kratos_config as _kc

    return Path(_kc.SSH_TARGET_KEY_PATH)


def pubkey_path() -> Path:
    key = _key_path()
    return key.with_name(key.name + ".pub")


def read_local_pubkey() -> str | None:
    try:
        text = pubkey_path().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    # One well-formed line only ("<type> <base64> [comment]"); anything else is
    # not something to hand a user to paste into authorized_keys.
    if not text or "\n" in text or len(text.split()) < 2:
        return None
    return text


def _sh_squote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def authorize_key_command(pubkey: str | None = None) -> str | None:
    """The idempotent line to run ON the target, as the login user, that lets
    this machine's key in (creates ~/.ssh with the perms sshd insists on, and
    doesn't add the key twice). None when there's no local key yet."""
    key = pubkey if pubkey is not None else read_local_pubkey()
    if not key:
        return None
    q = _sh_squote(key)
    f = "~/.ssh/authorized_keys"
    # A file whose last line has no newline would glue the new key onto the
    # previous one (breaking both), so add the missing newline first.
    return (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch {f} && "
        f"{{ grep -qxF {q} {f} || {{ [ ! -s {f} ] || [ -z \"$(tail -c1 {f})\" ] || echo >> {f}; "
        f"echo {q} >> {f}; }}; }} && chmod 600 {f}"
    )


class KeyGenError(RuntimeError):
    pass


def generate_local_key(comment: str | None = None) -> str:
    """Create the key (ed25519, no passphrase -- Kratos runs unattended) and
    return its public half. Refuses to overwrite anything that already exists."""
    key = _key_path()
    if key.exists() or pubkey_path().exists():
        raise KeyGenError(f"{key} already exists -- not overwriting it")
    key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)]
    if comment:
        args += ["-C", comment]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyGenError(f"could not run ssh-keygen: {exc}") from exc
    if proc.returncode != 0:
        raise KeyGenError((proc.stderr or proc.stdout).strip() or "ssh-keygen failed")
    pub = read_local_pubkey()
    if not pub:
        raise KeyGenError("ssh-keygen ran but no public key was written")
    return pub


def derive_public_key() -> str:
    """Rebuild a missing/unreadable .pub from the existing private key. Fails
    (never prompts) if the key has a passphrase."""
    key = _key_path()
    if not key.exists():
        raise KeyGenError(f"{key} doesn't exist")
    try:
        proc = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(key)], capture_output=True, text=True,
                              timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyGenError(f"could not run ssh-keygen: {exc}") from exc
    pub = proc.stdout.strip()
    if proc.returncode != 0 or not pub:
        raise KeyGenError((proc.stderr or "").strip() or "could not read the key (is it passphrase-protected?)")
    try:
        pubkey_path().write_text(pub + "\n", encoding="utf-8")
    except OSError as exc:
        raise KeyGenError(f"could not write {pubkey_path()}: {exc}") from exc
    return pub
