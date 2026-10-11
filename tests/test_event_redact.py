"""Credential masking and byte caps for event text (spec §5.6)."""
from __future__ import annotations

import pytest

from kratos.events.redact import MASK, cap, clean, mask


@pytest.mark.parametrize("raw, secret", [
    ("mysql -u root -pS3cret! shop", "S3cret!"),
    ("/usr/bin/mariadb -uadmin -phunter22 -h db", "hunter22"),
    ("mysqldump -pdumppw --all-databases", "dumppw"),
    ("sshpass -p 'my pass' ssh -p 22 host", "'my pass'"),
    ("sshpass -ptopsecret ssh host", "topsecret"),
    ("tool --password=abc123 --verbose", "abc123"),
    ("tool --password abc123", "abc123"),
    ("tool --passwd xyz789", "xyz789"),
    ("curl --token ghp_ABCDEF123", "ghp_ABCDEF123"),
    ("app --secret=s3", "s3"),
    ("app --api-key=k-123456", "k-123456"),
    ("PASSWORD=pw1 ./run", "pw1"),
    ("env DB_PASSWORD=\"two words\" app", "\"two words\""),
    ("export GITHUB_TOKEN=ghp_xyz", "ghp_xyz"),
    ("SECRET=abc make", "abc"),
    ("api_key=lower-case-too", "lower-case-too"),
    ("API_KEY=K1", "K1"),
    ("git clone https://bob:pa55word@git.example.com/r.git", "pa55word"),
    ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
    ("authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
])
def test_each_mask_pattern(raw, secret):
    out, changed = mask(raw)
    assert changed and secret not in out and MASK in out


def test_sshpass_masks_only_its_own_p_not_the_ssh_port():
    out, _ = mask("sshpass -p secretpw ssh -p 2222 host")
    assert "secretpw" not in out and "-p 2222" in out


def test_mysql_p_with_a_space_is_a_database_not_a_password():
    out, changed = mask("mysql -u root -p shopdb")
    assert out == "mysql -u root -p shopdb" and not changed


@pytest.mark.parametrize("raw", [
    "Invalid user password from 10.136.28.52 port 22",          # a username "password"
    "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2",
    "cat /etc/passwd",                                           # a path
    "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/vi /etc/passwd",
    "ssh -p 22 ubuntu@10.0.0.5",                                 # ssh's port
    "nc -p 4444 10.0.0.5",
    "pam_unix(sudo:auth): authentication failure; logname=ubuntu uid=1000 user=password",
    "passwd: password changed for bob",
    "https://example.com/path?q=1",                              # no userinfo
    "token refresh scheduled",
])
def test_false_positives_left_alone(raw):
    out, changed = mask(raw)
    assert out == raw and not changed


def test_known_api_key_value_masked(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "abcd1234efgh5678")
    out, changed = mask("curl -H X-OTX-API-KEY:abcd1234efgh5678 https://otx")
    assert changed and "abcd1234efgh5678" not in out


def test_cap_cuts_on_a_utf8_boundary():
    text = "é" * 10  # 2 bytes each
    out, cut = cap(text, 5)
    assert cut and out == "éé" and len(out.encode()) <= 5
    assert cap("short", 100) == ("short", False)


def test_clean_masks_before_capping():
    # The secret sits across the cap boundary: it must be masked, not half-kept.
    text = "x" * 20 + " --password=abcdefghijkl"
    out, redacted, truncated = clean(text, 34)
    assert redacted and truncated and "abcdef" not in out
    assert clean(None, 10) == (None, False, False)
