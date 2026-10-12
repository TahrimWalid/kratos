"""
Target onboarding: setup checklist generation for a real, independent
production target.

A local dev/test target (a container on the same host as Kratos) tends to
have SSH access, sudo, and the target binaries Kratos needs already
provisioned as part of building the lab image -- none of that happens
automatically for a real, independent target, and nothing else in Kratos
tells an operator what to set up or verifies any of it worked; `/target`
and the first-run wizard only ever validated that the input was non-empty.

generate_target_setup_checklist() produces copy-pasteable shell commands for
a HUMAN to run ON the target -- Kratos never runs them itself, per the
project's permanent boundary (see docs/DESIGN.md's "Execution boundary"
section) on never executing or changing state on a monitored target. The
read-only counterpart that confirms what
those commands actually accomplished, run_target_probe_checks(), lives in
adapters/ssh_remote.py alongside its sibling run_config_audit_checks (same
trust class: status-only commands over an existing SSH connection, not
target-side setup this module's own job).

journalctl access: the checklist recommends systemd-journal GROUP
membership over passwordless sudo -- smaller blast radius if the SSH key
ever leaks, since group membership can only ever grant journal-READ access,
never a path to root, whereas even a narrowly-scoped sudo rule is still a
privilege-escalation surface. Sudo remains fully supported (see
kratos_config.py::JOURNALCTL_USE_SUDO) -- this is a preference the checklist
defaults to, not a deprecation of the sudo path.
"""
from __future__ import annotations

import socket

from kratos import kratos_config as _kconfig
from kratos.kratos_config import SSH_TARGET_KEY_PATH


# What each setup-probe row checks, in words (the probe itself reports short ids).
CHECK_LABELS: dict[str, str] = {
    "ssh_reachable": "Log in over SSH",
    "subagent_reachable": "Reach it through its sub-agent",
    "agent_privilege": "Sub-agent's access level",
    "journalctl_access": "Read the system logs",
    "sudo_sshd_config": "Read the SSH server settings",
    "sshd_config": "Read the SSH server settings",
    "sudo_firewall_status": "Read the firewall status",
    "firewall_status": "Read the firewall status",
    "sudo_fail2ban": "Read fail2ban's status",
    "fail2ban_status": "Read fail2ban's status",
    "yara_installed": "YARA installed (malware scans)",
    "lsof_installed": "lsof installed (open files)",
    "yara_rules": "YARA rules on the box",
    "target_timezone": "Clock and timezone",
    "log_source_auditd": "Read auditd's log (programs run)",
    "log_source_sudo": "Read sudo's log",
    "log_source_cron": "Read cron's log",
    "log_source_systemd": "Read service activity (systemd)",
    "log_source_firewall": "Read firewall log lines",
    "log_source_packages": "Read the package install history",
    "log_source_web": "Read web server logs",
    "audit_status": "Read auditd's status",
    "journal_persistent": "Journal kept on disk",
    "sealing": "Journal sealing",
}


def check_label(check_id: str) -> str:
    """A setup check's plain name; unknown ids are shown readably, not hidden."""
    return CHECK_LABELS.get(check_id, str(check_id).replace("_", " ").capitalize())


def _detect_local_ip(target_host: str) -> str | None:
    """Best-effort: which local IP would the OS route through to reach
    target_host? A UDP socket's connect() never actually sends a packet (UDP
    has no handshake) -- this is purely a routing-table lookup, the standard
    no-network-traffic trick for "what's my outbound IP for this
    destination." Returns None (never a guessed/wrong value) if it fails,
    e.g. target_host doesn't resolve or no route exists -- the checklist
    falls back to an explicit placeholder + instruction rather than silently
    printing a wrong IP into a firewall rule or fail2ban ignoreip line."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target_host, 1))
            return sock.getsockname()[0]
    except OSError:
        return None


def seal_setup_commands(target_host: str) -> str:
    """Checklist step 7 -- journal sealing (FSS), also shown on its own by the
    onboarding seal step and /target seal. Verified on systemd 249 and 252:
    --setup-keys refuses if keys exist (--force regenerates); journald seals only
    files it opens after the keys exist, hence the rotate."""
    return f"""\
# 7. (Recommended) Seal this machine's journal so edits can be detected.
#    Needs persistent journal storage (the first two lines make sure of it).
sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
sudo journalctl --setup-keys
#    It prints a "secret verification key" -- one line like
#    a1b2c3-d4e5f6-a7b8c9-d0e1f2/1a2b3c-35a4e900. Paste it into Kratos
#    (/target seal, or: kratos seal set-key {target_host}).
#    Keep it OFF this machine: anyone who can read it here could forge seals.
#    If it says keys already exist and you no longer have that key:
#    sudo journalctl --setup-keys --force   (then give Kratos the new key)
sudo journalctl --rotate     # start sealing new log files right away
"""


def generate_target_setup_checklist(target_host: str) -> str:
    pubkey_path = SSH_TARGET_KEY_PATH.with_name(SSH_TARGET_KEY_PATH.name + ".pub")
    try:
        pubkey = pubkey_path.read_text(encoding="utf-8").strip()
    except OSError:
        pubkey = ""
    from kratos.utils.ssh_keys import authorize_key_command

    # Idempotent and safe on a file with no trailing newline (see ssh_keys).
    authorize = authorize_key_command(pubkey) if pubkey else (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh\n"
        f"echo '<could not read {pubkey_path} -- paste your real public key here>' >> ~/.ssh/authorized_keys\n"
        "chmod 600 ~/.ssh/authorized_keys")

    login = _kconfig.ssh_user_for(target_host)
    kratos_ip = _detect_local_ip(target_host)
    kratos_ip_display = kratos_ip or "<KRATOS_HOST_IP -- could not auto-detect, fill in manually>"

    return f"""\
# Kratos target setup -- run these ON THE TARGET ({target_host}), never on
# the Kratos host, and never something Kratos runs for you. Requires an
# existing account ("{login}" is who Kratos logs in as on this machine -- change
# it with `/target <user>@{target_host}`) reachable by some other means first
# (console access, your cloud provider's own SSH, etc.) -- Kratos never
# provisions its own initial access, by design.

# 1. SSH key access (as {login})
{authorize}

# 2. Read access to logs -- group membership, no sudo needed. systemd-journal
#    reads the journal; adm reads the files under /var/log (auth.log, syslog,
#    ufw.log, web server logs, sudo's own log). Takes effect on Kratos's NEXT
#    ssh connection (it opens a fresh one per command already, so nothing else
#    to do -- no reboot/relogin required for Kratos itself, though your own
#    shell session won't see it until you reconnect too). On Rocky/RHEL the
#    /var/log files are root-only by default; the journal covers most of them.
sudo usermod -aG systemd-journal,adm {login}
#    If auditd is installed, let adm read its log too (auditd's own setting):
if [ -f /etc/audit/auditd.conf ]; then
  sudo sed -i 's/^log_group *=.*/log_group = adm/' /etc/audit/auditd.conf
  sudo chgrp adm /var/log/audit && sudo chmod 0750 /var/log/audit
  sudo systemctl restart auditd || sudo service auditd restart
fi

# 3. Passwordless sudo for read-only status checks (run_config_audit, and
#    auditd's status for the log-tampering check). Adjust binary paths below if
#    `which sshd` / `which ufw` / `which auditctl` differ on your distro. All are
#    status/read-only commands, never state-changing.
sudo tee /etc/sudoers.d/kratos > /dev/null << 'EOF'
{login} ALL=(ALL) NOPASSWD: /usr/sbin/sshd -T
{login} ALL=(ALL) NOPASSWD: /usr/sbin/ufw status
{login} ALL=(ALL) NOPASSWD: /usr/sbin/nft list ruleset
{login} ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L -n
{login} ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client status
{login} ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client get * maxretry
{login} ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client get * bantime
{login} ALL=(ALL) NOPASSWD: /usr/sbin/auditctl -s
{login} ALL=(ALL) NOPASSWD: /usr/sbin/auditctl -l
EOF
sudo chmod 440 /etc/sudoers.d/kratos

# 4. Target-side binaries Kratos's tools shell out to.
sudo apt-get install -y yara lsof

# 5. Allow the Kratos host through the firewall (ufw example below -- adjust
#    for nft/iptables if that's what this target actually uses).
sudo ufw allow from {kratos_ip_display} to any port 22 proto tcp

# 6. IMPORTANT if fail2ban is installed: add the Kratos host to its
#    ignoreip list. Skipping this is a real failure mode that has actually
#    happened -- Kratos's own investigative SSH traffic can trip the SSH
#    jail and get itself banned mid-investigation. Edit
#    /etc/fail2ban/jail.local (create it if it doesn't exist) and add/extend
#    under [DEFAULT]:
#      ignoreip = 127.0.0.1/8 ::1 {kratos_ip_display}
#    then: sudo systemctl restart fail2ban

{seal_setup_commands(target_host)}
# When done, verify from Kratos with: /target {target_host}
# (or /target verify, if this target is already active)
"""
