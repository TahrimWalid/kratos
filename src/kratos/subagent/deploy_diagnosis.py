"""
Why a deploy or an SSH connection to a target failed, and what to do next
(docs/subagent_connection_ux.md WS3 + WS4).

Pure: the caller passes the real stderr of `scp`/`ssh`/the installer and gets
back a `Diagnosis` -- a kind, a plain-language summary, the next step, and
(when the operator has to act somewhere) the exact command, with WHERE to run
it, for a copy-safe box. Patterns are taken from real OpenSSH and installer
output (captured on real hosts; see tests/test_subagent_deploy_diagnosis.py).

Kratos never takes a password and never pushes a key to a box it can't log
into; several diagnoses say so plainly, because that one bootstrap step is the
operator's.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Where a suggested command runs.
ON_TARGET = "target"
ON_THIS_MACHINE = "this machine"

_INSTALL_ERROR_RE = re.compile(r"KRATOS_INSTALL_ERROR:\s*([a-z_]+):\s*(.+)")
_AUTH_METHODS_RE = re.compile(r"Permission denied \(([^)]*)\)")
_INSTALL_OK_RE = re.compile(r"KRATOS_INSTALL_OK\s+(.*)")


@dataclass(frozen=True)
class Diagnosis:
    kind: str
    summary: str
    next_step: str
    command: str | None = None
    run_on: str | None = None
    retry: bool = True  # worth retrying once the next step is done


def _host_of(ssh_addr: str) -> str:
    host = ssh_addr.split("@", 1)[-1]
    return host.split(":", 1)[0]


def install_python_command() -> str:
    return ("if command -v apt-get >/dev/null; then sudo apt-get install -y python3; "
            "elif command -v dnf >/dev/null; then sudo dnf install -y python3; "
            "elif command -v yum >/dev/null; then sudo yum install -y python3; "
            "elif command -v apk >/dev/null; then sudo apk add python3; "
            "elif command -v zypper >/dev/null; then sudo zypper -n install python3; fi")


def diagnose(stderr: str, *, ssh_addr: str, authorize_command: str | None = None) -> Diagnosis:
    """Classify one failed scp/ssh/installer run. `authorize_command` is the
    line that adds THIS machine's key on the target (None if there's no key)."""
    text = stderr or ""
    low = text.lower()
    host = _host_of(ssh_addr)
    login = ssh_addr.split("@", 1)[0] if "@" in ssh_addr else "the login user"

    m = _INSTALL_ERROR_RE.search(text)
    if m:
        return _install_error(m.group(1), m.group(2).strip())

    if "no space left on device" in low:
        return Diagnosis("disk_full", f"{host} is out of disk space.",
                         "Free some space on the target, then retry.", "df -h", ON_TARGET)

    if "remote host identification has changed" in low or ("host key for" in low and "has changed" in low):
        return Diagnosis(
            "host_key_changed",
            f"{host} presented a DIFFERENT host key than the one this machine remembers.",
            "This happens after a reinstall -- or during a man-in-the-middle attack. Confirm the new key is "
            "genuine (e.g. from the provider's console), then forget the old one on this machine and retry.",
            f"ssh-keygen -R {host}", ON_THIS_MACHINE)
    if "host key verification failed" in low:
        return Diagnosis(
            "host_key_unknown",
            f"This machine doesn't know {host}'s host key yet and strict checking refused it.",
            "Connect once by hand to check and accept the key, then retry.", f"ssh {ssh_addr} true", ON_THIS_MACHINE)

    denied = _AUTH_METHODS_RE.search(text)
    if denied:
        methods = {x.strip() for x in denied.group(1).split(",")}
        if "publickey" in methods:
            if authorize_command is None:
                return Diagnosis(
                    "no_local_key", f"{host} wants a key, but this machine has no SSH key for Kratos yet.",
                    "Create one (Kratos can do it for you), then add it on the target.", retry=False)
            also_pw = " It also accepts passwords -- Kratos never uses them; log in with yours to run this." \
                if {"password", "keyboard-interactive"} & methods else ""
            return Diagnosis(
                "key_not_authorized", f"{host} doesn't accept this machine's SSH key yet.",
                f"Run this ON the target as {login} (from wherever you can log in today), then retry.{also_pw}",
                authorize_command, ON_TARGET)
        if {"password", "keyboard-interactive"} & methods:
            return Diagnosis(
                "password_only", f"{host} only accepts passwords; Kratos only uses SSH keys.",
                f"Log in with your password as {login}, run this to add Kratos's key, then retry. If it still says "
                "password only, key logins are switched off in the target's sshd_config (PubkeyAuthentication).",
                authorize_command, ON_TARGET)
        return Diagnosis("auth_failed", f"{host} refused the login ({denied.group(1)}).",
                         "Check the user name and the target's SSH settings.", retry=False)

    if "too many authentication failures" in low:
        return Diagnosis(
            "too_many_keys", f"{host} gave up before trying Kratos's key (too many other keys were offered).",
            "Retry -- Kratos offers only its own key now. If it persists, raise MaxAuthTries on the target.")
    if "could not resolve hostname" in low or "name or service not known" in low or \
            "temporary failure in name resolution" in low:
        return Diagnosis("dns", f"The name {host} doesn't resolve from this machine.",
                         "Check the spelling, or use the target's IP / tailnet address.", retry=False)
    if "connection refused" in low:
        return Diagnosis(
            "refused", f"{host} refused the SSH connection.",
            "Either sshd isn't running / isn't on port 22 (for another port, add a Host entry with that Port to "
            "~/.ssh/config here), or the target's fail2ban has BANNED this machine after earlier failed logins -- "
            "a ban looks exactly like this. From another way in, check the ban list on the target; unban with "
            "`sudo fail2ban-client set sshd unbanip <this machine's IP>` and add it to ignoreip.",
            "sudo fail2ban-client status sshd", ON_TARGET)
    if "no route to host" in low or "network is unreachable" in low:
        return Diagnosis("no_route", f"There's no network path from this machine to {host}.",
                         "Check the address, that the box is powered on, and -- for a tailnet address -- that "
                         "Tailscale is up on both ends.", "tailscale status", ON_THIS_MACHINE)
    if "timed out" in low:
        return Diagnosis("timeout", f"{host} didn't answer (connection timed out).",
                         "The box may be off, a firewall may drop SSH, or the address is wrong. For a tailnet "
                         "address, check Tailscale on both ends.", "tailscale status", ON_THIS_MACHINE)
    if "connection closed by" in low or "connection reset by peer" in low or "kex_exchange_identification" in low:
        return Diagnosis(
            "dropped", f"{host} accepted the connection and then closed it.",
            "Usually sshd rejected this machine (hosts.deny / AllowUsers / too many parallel logins -- "
            "MaxStartups). Check the target's sshd log from another way in.",
            "sudo journalctl -u ssh -u sshd -n 50 --no-pager", ON_TARGET)
    if "a password is required" in low or "a terminal is required" in low:
        return Diagnosis("sudo_prompt", f"sudo on {host} wanted a password.",
                         "The installer falls back to a user service without sudo; if this still appears, run the "
                         "installer yourself in a terminal on the target.", retry=False)
    if "ssh: not found" in low or "no such file or directory: 'ssh'" in low or "no such file or directory: 'scp'" in low:
        return Diagnosis("no_ssh_client", "This machine has no ssh/scp client installed.",
                         "Install OpenSSH's client here, then retry.", "sudo apt-get install -y openssh-client",
                         ON_THIS_MACHINE)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "no error output")
    return Diagnosis("unknown", f"The deploy failed: {first[:200]}",
                     "Run the scp/ssh commands yourself to see the full error (press c for them).")


def _install_error(code: str, message: str) -> Diagnosis:
    if code == "no_python":
        return Diagnosis("no_python", "The target has no python3 (the agent needs it).",
                         "Install Python 3 on the target, then retry.", install_python_command(), ON_TARGET)
    if code == "python_too_old":
        return Diagnosis("python_too_old", message, "Install Python 3.8 or newer on the target, then retry.",
                         install_python_command(), ON_TARGET)
    if code == "no_base64":
        return Diagnosis("no_base64", "The target has no base64 tool (coreutils).",
                         "Install coreutils on the target, then retry.")
    if code == "start_failed":
        return Diagnosis("start_failed", f"The agent was installed but didn't stay running: {message}",
                         "Its own log (above) says why; fix that on the target, then deploy again.")
    if code == "not_paired":
        return Diagnosis("not_paired", "That box has no pairing to upgrade.",
                         "Use a pairing installer (add the server) instead of an upgrade.", retry=False)
    if code == "write_failed":
        return Diagnosis("write_failed", message, "Check free space and that the filesystem is writable.",
                         "df -h", ON_TARGET)
    return Diagnosis(f"install_{code}", message, "See the message above, fix it on the target, then retry.")


def install_warning(stdout: str) -> Diagnosis | None:
    """After a SUCCESSFUL install: a Diagnosis when the agent won't survive
    something the operator would expect it to (logout, reboot), else None."""
    m = _INSTALL_OK_RE.search(stdout or "")
    if not m:
        return None
    fields = dict(kv.split("=", 1) for kv in m.group(1).split() if "=" in kv)
    if fields.get("service") == "none" and fields.get("boot") != "yes":
        start = fields.get("start")
        return Diagnosis(
            "no_service", "The agent is running in the background (no systemd on that box), but it will NOT start "
            "again after a reboot.",
            "After a reboot, start it again with this ON the target -- or add it to the box's own startup "
            "(cron @reboot, rc.local).", f"sh {start}" if start else None, ON_TARGET if start else None,
            retry=False)
    if fields.get("mode") == "user" and fields.get("linger") == "no":
        user = fields.get("user", "")
        if not re.fullmatch(r"[A-Za-z0-9._][A-Za-z0-9._-]*\$?", user):
            user = ""
        return Diagnosis(
            "user_no_linger", f"The agent runs as {user or 'a'} user service that stops when that user logs out "
            "(it has no sudo, so the installer couldn't make it a system service).",
            "Run this ON the target as any user with sudo, so it keeps running after logout and across reboots.",
            f"sudo loginctl enable-linger {user}" if user else 'sudo loginctl enable-linger "$(id -un)"',
            ON_TARGET, retry=False)
    return None
