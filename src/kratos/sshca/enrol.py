"""Enrolling a machine in SSH certificates (Phase D.1): the person's one-time setup,
the apparent-address probe, Kratos's verification sequence and the state machine.

Enrolment is a person's job on the machine (observe-and-recommend: Kratos never edits
a machine's ``sshd_config``). `build_checklist` produces a copy-safe shell block the
person runs with sudo; it trusts Kratos's user CA, grants the machine's principal to
Kratos's login, and (optionally) adds a Kratos-signed host certificate. Kratos then
verifies, in order:

1. the certificate logs in and runs a probe  → state ``cert`` (the old key still works);
2. the old key still logs in (nothing is broken yet);
3. the person removes the old key from ``authorized_keys``;
4. **a login with the old key alone is refused** — one deliberate failed attempt, from
   an address the checklist already puts in fail2ban's ``ignoreip`` → state ``cert_only``.

Only after step 4 is a machine "certificate-only". The state is in ``ssh_enrolment``
(kratos.sshca.store). Host certificates let Kratos trust a machine by ``@cert-authority``
in its own ``known_hosts`` (``known_hosts_path``) instead of first-contact trust.
"""
from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from kratos import kratos_config as _kconfig
from kratos.kratos_config import SSH_CONNECT_TIMEOUT_SECONDS, SSH_TARGET_KEY_PATH
from kratos.sshca import ca as _ca
from kratos.sshca import mint as _mint
from kratos.sshca import store as _store
from kratos.target_key import target_key

logger = logging.getLogger("kratos.sshca.enrol")

PROBE = "echo KRATOS_CERT_PROBE_OK; id -un"
CA_FILE_ON_MACHINE = "/etc/ssh/kratos_user_ca.pub"
PRINCIPALS_DIR_ON_MACHINE = "/etc/ssh/kratos_principals"
HOST_CERT_ON_MACHINE = "/etc/ssh/ssh_host_ed25519_key-cert.pub"


def known_hosts_path(data_dir: Path) -> Path:
    """Kratos's own known_hosts for enrolled machines with host certificates
    (``@cert-authority`` lines). Rebuilt from the enrolment records."""
    return _ca.ca_dir(data_dir) / "known_hosts"


def principal_for(host: str) -> str:
    """The per-machine principal: ``kratos-<short id>``. A certificate for machine A
    therefore fails on machine B (decision 3)."""
    return "kratos-" + hashlib.sha256(target_key(host).encode("utf-8")).hexdigest()[:12]


# --------------------------------------------------------------------------- explicit logins (bypass routing)
def _simple_host_key_opts() -> list[str]:
    return ["-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}"]


def _ssh(argv_opts: list[str], login: str, host: str, command: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", *argv_opts, f"{login}@{host}", command],
                          capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)


def _cert_login(data_dir: Path, host: str, login: str) -> tuple[bool, str]:
    """Try a real certificate login (minting one for this attempt) and run the probe."""
    try:
        minted = _mint.mint_for_verification(data_dir, host)
    except _mint.CertUnavailable as e:
        return False, str(e)
    opts = ["-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
            "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
    try:
        proc = _ssh(opts, login, host, PROBE)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return (proc.returncode == 0 and "KRATOS_CERT_PROBE_OK" in proc.stdout,
            (proc.stdout + proc.stderr).strip())


def _old_key_login(host: str, login: str, *, expect_refused: bool) -> tuple[bool, str]:
    """A login offering ONLY the long-lived key and no certificate. With
    `expect_refused`, success means the old key still works (bad)."""
    opts = ["-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes",
            "-o", "CertificateFile=none", "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            *_simple_host_key_opts()]
    try:
        proc = _ssh(opts, login, host, "echo KRATOS_OLDKEY_OK")
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    worked = proc.returncode == 0 and "KRATOS_OLDKEY_OK" in proc.stdout
    return worked, (proc.stdout + proc.stderr).strip()


# --------------------------------------------------------------------------- the apparent-address probe
def probe_apparent_address(data_dir: Path, host: str, login: str) -> str | None:
    """SSH to the machine and print the client address it sees Kratos from
    (``$SSH_CONNECTION``'s first field). Stored per machine; a certificate's
    ``source-address`` is built from it. Uses whatever login works today (old key for a
    not-yet-enrolled machine)."""
    enr = _store.get_enrolment(data_dir, host)
    if enr is not None and enr.uses_cert:
        try:
            minted = _mint.mint_for_verification(data_dir, host)
            opts = ["-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
                    "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
        except _mint.CertUnavailable:
            opts = ["-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
    else:
        opts = ["-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
    try:
        proc = _ssh(opts, login, host, 'printf "%s\\n" "${SSH_CONNECTION%% *}"')
    except (OSError, subprocess.SubprocessError):
        return None
    addr = proc.stdout.strip().splitlines()[-1].strip() if proc.stdout.strip() else ""
    if not addr:
        return None
    try:
        import ipaddress
        ipaddress.ip_address(addr)
    except ValueError:
        return None
    _store.set_apparent_address(data_dir, host, addr)
    return addr


def read_trusted_ca_fingerprints(data_dir: Path, host: str, login: str) -> list[str]:
    """Read the CA file on the machine (world-readable) and record which CA fingerprints
    it trusts — so rotation knows which machines already trust the next key."""
    enr = _store.get_enrolment(data_dir, host)
    if enr is not None and enr.uses_cert:
        try:
            minted = _mint.mint_for_verification(data_dir, host)
            opts = ["-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
                    "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
        except _mint.CertUnavailable:
            opts = ["-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
    else:
        opts = ["-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes", *_simple_host_key_opts()]
    try:
        proc = _ssh(opts, login, host, f"cat {CA_FILE_ON_MACHINE} 2>/dev/null || true")
    except (OSError, subprocess.SubprocessError):
        return []
    fps: list[str] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            fps.append(_ca.fingerprint_of_pubkey(line))
        except _ca.CAError:
            continue
    _store.set_trusted_ca_fingerprints(data_dir, host, fps)
    return fps


# --------------------------------------------------------------------------- the checklist
@dataclass
class EnrolmentPlan:
    host: str
    login: str
    principal: str
    simple: bool
    host_cert: bool
    checklist: str
    enrolment: _store.Enrolment


def _sign_host_cert_line(data_dir: Path, host: str, login: str, principals: list[str]) -> str | None:
    """ssh-keyscan the machine's ed25519 host key, sign it with the host CA, return the
    certificate line for the checklist. None if the host key can't be read."""
    try:
        scan = subprocess.run(["ssh-keyscan", "-t", "ssh-ed25519", "-T",
                               str(SSH_CONNECT_TIMEOUT_SECONDS), host],
                              capture_output=True, text=True, timeout=SSH_CONNECT_TIMEOUT_SECONDS + 5)
    except (OSError, subprocess.SubprocessError):
        return None
    hostkey = ""
    for line in scan.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "ssh-ed25519":
            hostkey = f"{parts[1]} {parts[2]}\n"
            break
    if not hostkey:
        return None
    fd, pub = tempfile.mkstemp(suffix=".pub")
    try:
        os.write(fd, hostkey.encode("utf-8"))
        os.close(fd)
        cert = _ca.sign_host_cert(data_dir, host_pubkey_path=Path(pub), principals=principals)
        line = cert.read_text(encoding="utf-8").strip()
        host_ca = _ca.host_ca(data_dir)
        _store.set_host_cert(data_dir, host, state="none",
                             cert_fingerprint=_ca.fingerprint_of_pubkey(" ".join(line.split()[:2])) if line else None,
                             ca_fingerprint=host_ca.fingerprint if host_ca else None)
        return line
    except _ca.CAError:
        return None
    finally:
        for p in (pub, pub + "-cert.pub"):
            try:
                os.unlink(p)
            except OSError:
                pass


def build_checklist(data_dir: Path, host: str, *, login: str | None = None, simple: bool = False,
                    host_cert: bool = True, actor: str | None = None) -> EnrolmentPlan:
    """Make the CA keys if needed, (optionally) sign this machine's host key, record the
    enrolment at state 'pending', and return the copy-safe setup block for the person."""
    _authorize_change(data_dir, f"ssh-ca build_checklist {host}")
    data_dir = Path(data_dir)
    login = login or _kconfig.ssh_user_for(host, data_dir)
    _ca.ensure_user_ca(data_dir, actor=actor)
    user_ca_lines = _ca.public_ca_lines(data_dir, kind="user")
    principal = login if simple else principal_for(host)
    host_cert_line = None
    if host_cert:
        _ca.ensure_host_ca(data_dir, actor=actor)
        host_cert_line = _sign_host_cert_line(data_dir, host, login, [host, principal_for(host)])
    enr = _store.upsert_enrolment(data_dir, host, login=login, principal=principal,
                                  principal_mode="simple" if simple else "machine", actor=actor)
    checklist = _render_checklist(host, login, principal, simple, user_ca_lines,
                                  host_cert_line if host_cert else None)
    return EnrolmentPlan(host=host, login=login, principal=principal, simple=simple,
                         host_cert=bool(host_cert_line), checklist=checklist, enrolment=enr)


def _render_checklist(host: str, login: str, principal: str, simple: bool,
                      user_ca_lines: list[str], host_cert_line: str | None) -> str:
    ca_block = "\n".join(user_ca_lines)
    kratos_ip = _kconfig_ip(host)
    parts = [f"""\
# Enrol {login}@{host} in Kratos SSH certificates -- run ON THE MACHINE, with sudo.
# Nothing Kratos runs for you. Idempotent: safe to re-run. It trusts Kratos's
# certificate authority and keeps your existing key working until Kratos proves
# the certificate path, so you are never locked out mid-setup.
set -e

# 1. Trust Kratos's user CA (active + next, so key rotation never locks Kratos out).
sudo tee {CA_FILE_ON_MACHINE} > /dev/null << 'KRATOS_CA_EOF'
{ca_block}
KRATOS_CA_EOF
sudo chmod 644 {CA_FILE_ON_MACHINE}
"""]
    if simple:
        block = f"TrustedUserCAKeys {CA_FILE_ON_MACHINE}"
        parts.append(f"""\
# 2. Accept certificates signed by it for login "{login}" (simple mode: the login
#    name is the principal -- weaker, as a certificate is not bound to one machine).
""")
    else:
        parts.append(f"""\
# 2. Grant this machine's own principal to Kratos's login, so a certificate for this
#    machine cannot be used on another one.
sudo mkdir -p {PRINCIPALS_DIR_ON_MACHINE}
printf '%s\\n' '{principal}' | sudo tee {PRINCIPALS_DIR_ON_MACHINE}/{login} > /dev/null
sudo chmod 644 {PRINCIPALS_DIR_ON_MACHINE}/{login}
""")
        block = (f"TrustedUserCAKeys {CA_FILE_ON_MACHINE}\\n"
                 f"Match User {login}\\n"
                 f"    AuthorizedPrincipalsFile {PRINCIPALS_DIR_ON_MACHINE}/%u")
    parts.append(f"""\
# 3. Tell sshd to use it (a drop-in where Include is present, else appended).
block={_sh_squote_nl(block)}
if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d' /etc/ssh/sshd_config; then
  printf '%b\\n' "$block" | sudo tee /etc/ssh/sshd_config.d/60-kratos-ca.conf > /dev/null
else
  printf '\\n%b\\n' "$block" | sudo tee -a /etc/ssh/sshd_config > /dev/null
fi
""")
    if host_cert_line:
        parts.append(f"""\
# 4. Host certificate: Kratos signed this machine's host key, so Kratos trusts it
#    without first-contact prompts and refuses a swapped host key.
sudo tee {HOST_CERT_ON_MACHINE} > /dev/null << 'KRATOS_HOSTCERT_EOF'
{host_cert_line}
KRATOS_HOSTCERT_EOF
sudo chmod 644 {HOST_CERT_ON_MACHINE}
hc='HostCertificate {HOST_CERT_ON_MACHINE}'
if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d' /etc/ssh/sshd_config; then
  printf '%s\\n' "$hc" | sudo tee /etc/ssh/sshd_config.d/61-kratos-hostcert.conf > /dev/null
else
  printf '\\n%s\\n' "$hc" | sudo tee -a /etc/ssh/sshd_config > /dev/null
fi
""")
    parts.append(f"""\
# 5. Make sure Kratos won't ban itself for the one deliberate "old key refused" test
#    (if you run fail2ban). {kratos_ip} is Kratos's address.
if [ -f /etc/fail2ban/jail.local ] || [ -d /etc/fail2ban ]; then
  echo "  (ensure fail2ban's ignoreip includes {kratos_ip})"
fi

# 6. Check the config and reload sshd.
sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null \\
  || sudo service ssh reload 2>/dev/null || sudo service sshd reload 2>/dev/null || sudo rcctl reload sshd)
echo "Kratos CA setup applied. Keep your existing key in authorized_keys until Kratos says 'old key refused'."
""")
    return "".join(parts)


def _sh_squote_nl(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def _kconfig_ip(host: str) -> str:
    from kratos.adapters.target_setup import _detect_local_ip

    return _detect_local_ip(host) or "<the Kratos host's address>"


# --------------------------------------------------------------------------- verification sequence
@dataclass
class VerifyStep:
    key: str
    label: str
    ok: bool
    detail: str = ""


@dataclass
class VerifyResult:
    host: str
    state: str
    steps: list[VerifyStep] = field(default_factory=list)
    done: bool = False      # reached cert-only


def verify_cert_login(data_dir: Path, host: str) -> VerifyStep:
    """Step 1: a certificate logs in and runs the probe. On success, state → 'cert'
    (unless already 'cert_only'), and the machine's trusted CA fingerprints are read."""
    data_dir = Path(data_dir)
    enr = _store.get_enrolment(data_dir, host)
    if enr is None:
        return VerifyStep("cert_login", "Certificate login", False, "not enrolled")
    ok, detail = _cert_login(data_dir, host, enr.login)
    if ok:
        if enr.state == "pending":
            _store.set_state(data_dir, host, "cert")
        read_trusted_ca_fingerprints(data_dir, host, enr.login)
        probe_apparent_address(data_dir, host, enr.login)
    return VerifyStep("cert_login", "Certificate login works", ok, detail[:500])


def verify_old_key_works(data_dir: Path, host: str) -> VerifyStep:
    """Step 2: the old long-lived key still logs in (nothing is broken yet)."""
    enr = _store.get_enrolment(Path(data_dir), host)
    login = enr.login if enr else _kconfig.ssh_user_for(host, Path(data_dir))
    ok, detail = _old_key_login(host, login, expect_refused=False)
    return VerifyStep("old_key_works", "Old key still works (nothing broken yet)", ok, detail[:500])


def verify_old_key_refused(data_dir: Path, host: str) -> VerifyStep:
    """Step 4: a login with the old key alone is REFUSED. On success (refused), state →
    'cert_only' — the machine is certificate-only. A real failed login, not a claim."""
    data_dir = Path(data_dir)
    enr = _store.get_enrolment(data_dir, host)
    if enr is None:
        return VerifyStep("old_key_refused", "Old key refused", False, "not enrolled")
    worked, detail = _old_key_login(host, enr.login, expect_refused=True)
    refused = not worked
    if refused and enr.state in ("cert", "cert_only"):
        _store.set_state(data_dir, host, "cert_only")
    step = VerifyStep("old_key_refused", "Old key alone is refused", refused,
                      ("the old key still logs in -- remove it from authorized_keys on the machine first"
                       if worked else detail)[:500])
    return step


def verify_host_cert(data_dir: Path, host: str) -> VerifyStep:
    """Confirm the machine presents its Kratos-signed host certificate and that Kratos
    accepts it through @cert-authority with strict checking. On success, host-cert state
    → 'active' and the known_hosts file is rebuilt."""
    data_dir = Path(data_dir)
    enr = _store.get_enrolment(data_dir, host)
    if enr is None:
        return VerifyStep("host_cert", "Host certificate", False, "not enrolled")
    # Build a throwaway known_hosts with only the @cert-authority line and connect strictly.
    hc = _ca.host_ca(data_dir)
    if hc is None:
        return VerifyStep("host_cert", "Host certificate", False, "no host CA")
    fd, kh = tempfile.mkstemp(suffix=".known_hosts")
    try:
        os.write(fd, f"@cert-authority {host},{enr.apparent_address or '*'} {hc.record.public_key}\n".encode())
        os.close(fd)
        opts = ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={kh}",
                "-o", "BatchMode=yes", "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
                "-i", str(SSH_TARGET_KEY_PATH), "-o", "IdentitiesOnly=yes"]
        if enr.uses_cert:
            try:
                minted = _mint.mint_for_verification(data_dir, host)
                opts = ["-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
                        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                        "-o", f"UserKnownHostsFile={kh}", "-o", "BatchMode=yes",
                        "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}"]
            except _mint.CertUnavailable:
                pass
        try:
            proc = _ssh(opts, enr.login, host, "echo KRATOS_HOSTCERT_OK")
        except (OSError, subprocess.SubprocessError) as e:
            return VerifyStep("host_cert", "Host certificate accepted", False, str(e)[:500])
        ok = proc.returncode == 0 and "KRATOS_HOSTCERT_OK" in proc.stdout
    finally:
        try:
            os.unlink(kh)
        except OSError:
            pass
    if ok:
        _store.set_host_cert(data_dir, host, state="active",
                             cert_fingerprint=enr.host_cert_fingerprint,
                             ca_fingerprint=hc.fingerprint)
        rebuild_known_hosts(data_dir)
    return VerifyStep("host_cert", "Host certificate accepted (first-contact trust removed)", ok,
                      (proc.stdout + proc.stderr).strip()[:500] if ok else "host certificate not accepted")


def rebuild_known_hosts(data_dir: Path) -> Path:
    """Write Kratos's known_hosts: one ``@cert-authority`` line per enrolled machine with
    an active host certificate, so strict host-key checking trusts them by CA."""
    data_dir = Path(data_dir)
    hc = _ca.host_ca(data_dir)
    path = known_hosts_path(data_dir)
    _ca._ensure_dir(_ca.ca_dir(data_dir))
    lines = []
    if hc is not None:
        for enr in _store.list_enrolments(data_dir):
            if enr.host_cert_active:
                patterns = enr.host
                if enr.apparent_address:
                    patterns += "," + enr.apparent_address
                lines.append(f"@cert-authority {patterns} {hc.record.public_key}")
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    os.chmod(path, 0o644)
    return path


def run_full_verification(data_dir: Path, host: str, *, include_old_key_refused: bool) -> VerifyResult:
    """Steps 1–2 (and the host cert if one was added), and — only when
    `include_old_key_refused` — step 4. Caller gates step 4 on the person confirming the
    old key was removed."""
    data_dir = Path(data_dir)
    result = VerifyResult(host=host, state="pending")
    result.steps.append(verify_cert_login(data_dir, host))
    enr = _store.get_enrolment(data_dir, host)
    if enr and enr.host_cert_fingerprint:
        result.steps.append(verify_host_cert(data_dir, host))
    result.steps.append(verify_old_key_works(data_dir, host))
    if include_old_key_refused:
        result.steps.append(verify_old_key_refused(data_dir, host))
    enr = _store.get_enrolment(data_dir, host)
    result.state = enr.state if enr else "pending"
    result.done = result.state == "cert_only"
    return result


def unenrol(data_dir: Path, host: str) -> None:
    """Forget an enrolment (does not touch the machine). The person removes the Kratos CA
    lines from the machine's sshd_config themselves if they want to."""
    _authorize_change(data_dir, f"ssh-ca unenrol {host}")
    _store.delete_enrolment(Path(data_dir), host)
    rebuild_known_hosts(Path(data_dir))


def _authorize_change(data_dir, what: str) -> None:
    """D.7: the owner, at the Kratos host -- recorded in the audit trail."""
    from kratos import authz

    try:
        authz.require_person(authz.P.ENROL, data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise PermissionError(str(e)) from None
