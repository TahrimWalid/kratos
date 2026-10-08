"""
Review v2 F-9: what a read sends back is narrowed where it can be without
losing a finding.

- privileged_accounts sends only sudoers GRANT lines (not Defaults, which can
  carry mail addresses and paths, nor includes or alias definitions), joins
  continuation lines, and reads the sudoers.d files sudo itself loads.
- More secret file names are never YARA-scanned and can't appear in an
  execution action.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from kratos.adapters import privileged_accounts as PA
from kratos.subagent import whitelist as W
from kratos.subagent.reads import is_credential_path

SUDOERS = """\
# a comment
Defaults\tenv_reset
Defaults\tmailto="admin@example.com"
Defaults env_keep += "HTTP_PROXY \\
    NO_PROXY"
User_Alias ADMINS = alice, bob
Cmnd_Alias PKG = /usr/bin/apt
@includedir /etc/sudoers.d
root\tALL=(ALL:ALL) ALL
%sudo\tALL=(ALL:ALL) ALL
carol ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, \\
      /usr/bin/journalctl
"""


def _sudoers_block(script: str) -> str:
    start = script.index("if $SUDO true")
    end = script.index("\nfi\n", start) + 4
    return script[start:end]


@pytest.mark.skipif(not (shutil.which("sh") and shutil.which("awk") and shutil.which("find")),
                    reason="needs sh, awk, find")
def test_only_grant_lines_leave_the_box(tmp_path):
    etc = tmp_path / "etc"
    (etc / "sudoers.d").mkdir(parents=True)
    (etc / "sudoers").write_text(SUDOERS)
    (etc / "sudoers.d" / "90-ops").write_text("dave ALL=(ALL) ALL\nDefaults:dave !lecture\n")
    (etc / "sudoers.d" / "old.bak").write_text("mallory ALL=(ALL) ALL\n")   # sudo skips names with '.'
    (etc / "sudoers.d" / "90-ops~").write_text("eve ALL=(ALL) ALL\n")      # ... and editor backups
    block = _sudoers_block(PA.build_script(0, "journalctl", sudo=""))
    block = block.replace("/etc/sudoers", str(etc / "sudoers"))
    out = subprocess.run(["sh", "-c", "SUDO=\n" + block], capture_output=True, text=True, timeout=20).stdout
    sent = [line for line in out.splitlines() if line.startswith("SUDOERS\t")]
    text = "\n".join(sent)
    assert "Defaults" not in text and "mailto" not in text and "NO_PROXY" not in text
    assert "_Alias" not in text and "@include" not in text and "comment" not in text
    assert "mallory" not in text and "eve" not in text
    inv = PA.parse_output(out)
    assert inv.sudoers_visible
    subjects = [g["subject"] for g in inv.sudoers_grants]
    assert subjects == ["root", "%sudo", "carol", "dave"]
    carol = next(g for g in inv.sudoers_grants if g["subject"] == "carol")
    assert "/usr/bin/journalctl" in carol["line"]  # continuation joined into one grant


@pytest.mark.parametrize("path", [
    "/home/a/.ssh/authorized_keys2", "/var/www/html/wp-config.php", "/home/a/.npmrc", "/home/a/.pypirc",
    "/opt/app/secrets.yaml", "/opt/app/config/credentials.json", "/opt/app/.env.production",
    "/etc/openvpn/client.ovpn", "/home/a/.config/gh/hosts.yml", "/run/secrets/db_password",
    "/opt/infra/terraform.tfstate", "/opt/infra/prod.tfvars", "/home/a/key.ppk", "/etc/krb5.keytab",
    "/var/www/.htpasswd", "/home/a/.gem/credentials",
])
def test_more_secret_files_are_never_scanned(path):
    assert is_credential_path(path)


@pytest.mark.parametrize("path", [
    "/var/www/html/index.php", "/tmp/dropper.sh", "/opt/app/config/settings.py", "/home/a/.environment",
    "/srv/ansible/hosts.yml", "/opt/app/local.xml", "/home/a/notes/secret-plan.txt",
])
def test_ordinary_files_are_still_scanned(path):
    assert not is_credential_path(path)


@pytest.mark.parametrize("target", ["/home/a/.npmrc", "/opt/app/secrets.yaml", "/srv/credentials.json",
                                    "/var/www/wp-config.php", "/etc/openvpn/c.ovpn", "/root/.aws/config"])
def test_an_action_can_not_name_them(target):
    spec = W.ActionSpec(id="x.read", layer="user", argv_template=("sha256sum", target), effect="e",
                        reversibility="r", blast_radius="b", source_recommendation=("T",))
    with pytest.raises(W.HardExclusionError, match="credential/secret"):
        W.validate_spec(spec)
