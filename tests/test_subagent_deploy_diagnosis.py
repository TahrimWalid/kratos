"""Deploy/SSH failure classifier (connection-UX WS3). Every stderr sample below is REAL
output captured from real failures in the lab (OpenSSH 8.9 client against Ubuntu, RHEL and
Alpine targets, plus a real fail2ban ban), not hand-written approximations."""
from __future__ import annotations

import pytest

from kratos.subagent import deploy_diagnosis as D

AUTH = "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA test' >> ~/.ssh/authorized_keys"

REAL = {
    "key_not_authorized": "root@10.136.28.45: Permission denied (publickey,password,keyboard-interactive).",
    "host_key_unknown": ("No ED25519 host key is known for 10.136.28.168 and you have requested strict checking.\n"
                         "Host key verification failed."),
    "host_key_changed": """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:JQQSJdvbOIwPzLC0ULhS1FnNPi2G73lYhoDkI9zTUbM.
Please contact your system administrator.
Add correct host key in /tmp/tmp.WeOZzjQKbU/kh to get rid of this message.
Offending ED25519 key in /tmp/tmp.WeOZzjQKbU/kh:1
  remove with:
  ssh-keygen -f '/tmp/tmp.WeOZzjQKbU/kh' -R '10.136.28.168'
Host key for 10.136.28.168 has changed and you have requested strict checking.
Host key verification failed.""",
    "timeout": "ssh: connect to host 10.136.28.168 port 2: Connection timed out",
    "no_route": "ssh: connect to host 10.136.28.250 port 22: No route to host",
    "dns": "ssh: Could not resolve hostname nonexistent-host.invalid: Name or service not known",
    "refused": "ssh: connect to host 127.0.0.1 port 2: Connection refused",
    "too_many_keys": ("Received disconnect from 10.136.28.168 port 22:2: Too many authentication failures\n"
                      "Disconnected from 10.136.28.168 port 22"),
    "no_python": ("KRATOS_INSTALL_ERROR: no_python: python3 is required on the target but was not found\n"
                  "error: python3 is required on the target but was not found"),
}
FAIL2BAN_BAN = "ssh: connect to host 10.136.28.168 port 22: Connection refused"


@pytest.mark.parametrize("kind", sorted(REAL))
def test_real_samples_classify(kind):
    d = D.diagnose(REAL[kind], ssh_addr="ubuntu@10.136.28.168", authorize_command=AUTH)
    assert d.kind == kind
    assert d.summary and d.next_step


def test_publickey_hands_over_the_authorize_command_to_run_on_the_target():
    d = D.diagnose(REAL["key_not_authorized"], ssh_addr="root@10.136.28.45", authorize_command=AUTH)
    assert d.command == AUTH and d.run_on == D.ON_TARGET
    assert "as root" in d.next_step and "never uses them" in d.next_step  # the box also takes passwords


def test_publickey_without_a_local_key_asks_to_create_one():
    d = D.diagnose(REAL["key_not_authorized"], ssh_addr="root@h", authorize_command=None)
    assert d.kind == "no_local_key" and d.command is None


def test_password_only_never_asks_for_the_password():
    d = D.diagnose("ubuntu@h: Permission denied (password).", ssh_addr="ubuntu@h", authorize_command=AUTH)
    assert d.kind == "password_only" and d.command == AUTH and d.run_on == D.ON_TARGET
    assert "PubkeyAuthentication" in d.next_step


def test_changed_host_key_is_cleared_on_this_machine_with_a_mitm_warning():
    d = D.diagnose(REAL["host_key_changed"], ssh_addr="ubuntu@10.136.28.168")
    assert d.command == "ssh-keygen -R 10.136.28.168" and d.run_on == D.ON_THIS_MACHINE
    assert "man-in-the-middle" in d.next_step


def test_a_fail2ban_ban_is_named_as_a_possible_cause_of_refused():
    d = D.diagnose(FAIL2BAN_BAN, ssh_addr="ubuntu@10.136.28.168")
    assert d.kind == "refused" and "fail2ban" in d.next_step


def test_dns_is_not_worth_blind_retry():
    assert D.diagnose(REAL["dns"], ssh_addr="u@x").retry is False


def test_installer_error_codes():
    no_py = D.diagnose(REAL["no_python"], ssh_addr="u@h")
    assert no_py.run_on == D.ON_TARGET and "apk add python3" in no_py.command and "dnf install" in no_py.command
    old = D.diagnose("KRATOS_INSTALL_ERROR: python_too_old: python3 is too old (Python 3.6.8)", ssh_addr="u@h")
    assert old.kind == "python_too_old" and "3.6.8" in old.summary
    full = D.diagnose("KRATOS_INSTALL_ERROR: write_failed: could not write /opt/x (disk full or read-only?)",
                      ssh_addr="u@h")
    assert full.kind == "write_failed" and full.command == "df -h"
    assert D.diagnose("KRATOS_INSTALL_ERROR: not_paired: no", ssh_addr="u@h").retry is False
    crash = D.diagnose("KRATOS_INSTALL_ERROR: start_failed: the agent exited right after starting: Traceback",
                       ssh_addr="u@h")
    assert crash.kind == "start_failed" and "Traceback" in crash.summary
    assert D.diagnose("KRATOS_INSTALL_ERROR: brand_new: x", ssh_addr="u@h").kind == "install_brand_new"


def test_missing_local_ssh_client():
    d = D.diagnose("[Errno 2] No such file or directory: 'scp'", ssh_addr="u@h")
    assert d.kind == "no_ssh_client" and d.run_on == D.ON_THIS_MACHINE


def test_unknown_keeps_the_first_line_of_real_output():
    d = D.diagnose("\n\nsomething odd happened\nmore", ssh_addr="u@h")
    assert d.kind == "unknown" and "something odd happened" in d.summary
    assert D.diagnose("", ssh_addr="u@h").kind == "unknown"


def test_install_warning_user_service_without_linger():
    w = D.install_warning("...\nKRATOS_INSTALL_OK mode=user service=kratos-subagent dir=/home/u/.kratos-subagent "
                          "linger=no\n")
    assert w.kind == "user_no_linger" and "enable-linger" in w.command
    named = D.install_warning("KRATOS_INSTALL_OK mode=user service=s dir=/d linger=no user=kuser")
    assert named.command == "sudo loginctl enable-linger kuser"
    evil = D.install_warning("KRATOS_INSTALL_OK mode=user service=s dir=/d linger=no user=a;rm")
    assert ";rm" not in evil.command
    assert D.install_warning("KRATOS_INSTALL_OK mode=user service=s dir=/d linger=yes") is None
    assert D.install_warning("KRATOS_INSTALL_OK mode=system service=s dir=/opt/k") is None
    plain = D.install_warning("KRATOS_INSTALL_OK mode=user service=none dir=/h/.k boot=no start=/h/.k/start.sh")
    assert plain.kind == "no_service" and plain.command == "sh /h/.k/start.sh"
    assert D.install_warning("KRATOS_INSTALL_OK mode=system service=none dir=/opt/k boot=yes start=/opt/k/s") is None
    assert D.install_warning("no marker at all") is None
