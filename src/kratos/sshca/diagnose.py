"""Why a certificate login failed (Phase D.1 §5.2).

A failed certificate login has a small set of causes, each with a clear fix:

- **address changed** — the machine now sees Kratos from a different address than the
  certificate's ``source-address`` allows (a new network, a NAT change); re-enrol.
- **principal missing** — the machine no longer grants Kratos's principal to the login.
- **CA not trusted** — the machine's CA file no longer lists Kratos's active CA (e.g.
  after a rotation the person didn't finish, or the file was reset); add the line.
- **clock skew** — the certificate is not yet valid or already expired against one of the
  clocks (checked locally from the cert's own validity window).
- **sshd too old** — the server is older than certificates need.

`classify_verbose` reads ``ssh -v`` output (tested against fixtures). `diagnose` runs a
live attempt and combines it with local cert inspection, a fresh apparent-address probe
and a read of the machine's CA file.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from kratos.sshca import ca as _ca
from kratos.sshca import enrol as _enrol
from kratos.sshca import mint as _mint
from kratos.sshca import store as _store

CAUSE_ADDRESS = "address_changed"
CAUSE_PRINCIPAL = "principal_missing"
CAUSE_CA = "ca_not_trusted"
CAUSE_SKEW = "clock_skew"
CAUSE_SSHD_OLD = "sshd_too_old"
CAUSE_UNKNOWN = "unknown"

_FIX = {
    CAUSE_ADDRESS: "Kratos is connecting from a different address than this certificate allows. "
                   "Re-enrol the machine so the new address is recorded (`kratos ssh-ca enrol <machine>`).",
    CAUSE_PRINCIPAL: "The machine no longer grants Kratos's principal to its login. Re-run the enrolment "
                     "checklist's principal step.",
    CAUSE_CA: "The machine's CA file no longer lists Kratos's active CA key. Re-run the enrolment checklist "
              "(step 1), or, after a rotation, add the new CA line.",
    CAUSE_SKEW: "The certificate is outside its validity window against one of the clocks. Check the clock on "
                "the Kratos host and the machine (and re-mint -- certificates are short-lived).",
    CAUSE_SSHD_OLD: "The machine's SSH server is too old for certificates. Use the long-lived key there.",
    CAUSE_UNKNOWN: "Kratos could not tell why from the connection output; see the detail.",
}

_EXPIRED = re.compile(r"certificate.*(expired|not yet valid|invalid.*valid)", re.IGNORECASE)
_DENIED = re.compile(r"Permission denied \(publickey", re.IGNORECASE)
_OLD_SSHD = re.compile(r"remote software version OpenSSH_(\d+)\.(\d+)", re.IGNORECASE)
_SOURCE_ADDR = re.compile(r"not permitted to (connect )?from|source.address", re.IGNORECASE)


@dataclass(frozen=True)
class Diagnosis:
    cause: str
    message: str
    fix: str
    detail: str = ""


def classify_verbose(text: str) -> str:
    """Best cause from ``ssh -v`` output alone. Returns a CAUSE_* constant."""
    text = text or ""
    if _SOURCE_ADDR.search(text):
        return CAUSE_ADDRESS
    if _EXPIRED.search(text):
        return CAUSE_SKEW
    m = _OLD_SSHD.search(text)
    if m and (int(m.group(1)), int(m.group(2))) < (6, 5):
        return CAUSE_SSHD_OLD
    if _DENIED.search(text):
        return CAUSE_UNKNOWN  # the server refused the key; the live checks below say why
    return CAUSE_UNKNOWN


def _cert_window(cert_path: Path) -> tuple[float, float] | None:
    try:
        proc = subprocess.run(["ssh-keygen", "-L", "-f", str(cert_path)], capture_output=True, text=True,
                              timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Valid:\s+from\s+(\S+)\s+to\s+(\S+)", proc.stdout)
    if not m:
        return None

    def _parse(s: str) -> float | None:
        try:
            import datetime
            return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").timestamp()
        except ValueError:
            return None

    a, b = _parse(m.group(1)), _parse(m.group(2))
    return (a, b) if a is not None and b is not None else None


def diagnose(data_dir: Path, host: str) -> Diagnosis:
    """Run a live certificate attempt and work out why it failed (or report that it
    actually works). Combines verbose output, local cert inspection, a fresh
    apparent-address probe and a read of the machine's CA file."""
    data_dir = Path(data_dir)
    enr = _store.get_enrolment(data_dir, host)
    if enr is None:
        return Diagnosis(CAUSE_UNKNOWN, "this machine is not enrolled in certificates", _FIX[CAUSE_UNKNOWN])
    try:
        minted = _mint.mint_for_verification(data_dir, host)
    except _mint.CertUnavailable as e:
        return Diagnosis(CAUSE_UNKNOWN, f"Kratos could not mint a certificate: {e}", _FIX[CAUSE_UNKNOWN], str(e))

    # Local clock check first (needs nothing on the machine).
    window = _cert_window(minted.cert_path)
    now = time.time()
    if window is not None and (now < window[0] - 5 or now > window[1] + 5):
        return Diagnosis(CAUSE_SKEW, "the certificate is outside its validity window", _FIX[CAUSE_SKEW],
                         f"now={now:.0f} valid={window[0]:.0f}..{window[1]:.0f}")

    opts = ["-v", "-i", str(minted.key_path), "-o", f"CertificateFile={minted.cert_path}",
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15"]
    try:
        proc = subprocess.run(["ssh", *opts, f"{enr.login}@{host}", "echo KRATOS_DIAG_OK"],
                              capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return Diagnosis(CAUSE_UNKNOWN, "the connection could not be made", _FIX[CAUSE_UNKNOWN], str(e))
    verbose = proc.stdout + proc.stderr
    if proc.returncode == 0 and "KRATOS_DIAG_OK" in proc.stdout:
        return Diagnosis("ok", "the certificate login works", "")

    cause = classify_verbose(verbose)
    if cause == CAUSE_UNKNOWN:
        cause = _live_cause(data_dir, host, enr)
    return Diagnosis(cause, _CAUSE_MESSAGE.get(cause, "the certificate login failed"), _FIX.get(cause, _FIX[CAUSE_UNKNOWN]),
                     verbose.strip()[-800:])


_CAUSE_MESSAGE = {
    CAUSE_ADDRESS: "the machine sees Kratos from a different address than the certificate allows",
    CAUSE_PRINCIPAL: "the machine no longer grants Kratos's principal to its login",
    CAUSE_CA: "the machine's CA file no longer lists Kratos's active CA key",
    CAUSE_SKEW: "the certificate is outside its validity window",
    CAUSE_SSHD_OLD: "the machine's SSH server is too old for certificates",
    CAUSE_UNKNOWN: "the certificate login failed",
}


def _live_cause(data_dir: Path, host: str, enr: _store.Enrolment) -> str:
    """When the verbose output only says 'denied', ask the machine why: is the active CA
    still trusted, and (re-probed) has the address changed?"""
    active = _ca.active_user_ca(data_dir)
    if active is not None:
        trusted = _enrol.read_trusted_ca_fingerprints(data_dir, host, enr.login)
        if trusted and active.fingerprint not in trusted:
            return CAUSE_CA
    if enr.source_address_enabled and enr.apparent_address:
        current = _enrol.probe_apparent_address(data_dir, host, enr.login)
        if current and current != enr.apparent_address:
            return CAUSE_ADDRESS
    return CAUSE_UNKNOWN
