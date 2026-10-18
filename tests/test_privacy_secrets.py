"""B.2: secrets never reach the model and are never put back.

Every secret-shaped value is built at test time from parts, so no file in the repo
holds one whole.
"""
from __future__ import annotations

import pytest

from kratos.privacy.mask import Masker
from kratos.privacy.secrets import REDACTED, redact
from kratos.privacy.values import KnownValues


def _key_block() -> str:
    head, tail = "-----BEGIN " + "OPENSSH " + "PRIVATE " + "KEY-----", "-----END " + "OPENSSH " + "PRIVATE " + "KEY-----"
    return f"{head}\n{'Q' * 40}\n{'R' * 40}\n{tail}"


def _shapes() -> list[tuple[str, str]]:
    """(name, text holding one secret) -- the secret part is what must disappear."""
    return [
        ("aws", "key id " + "AKIA" + "X" * 16 + " here"),
        ("google", "key " + "AIza" + "Y" * 35),
        ("github", "token " + "ghp_" + "Z" * 36),
        ("github_pat", "token " + "github_pat_" + "W" * 30),
        ("slack", "hook " + "xox" + "b-" + "1" * 12 + "-abc"),
        ("jwt", "auth " + "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12),
        ("bearer", "Authorization: Bearer " + "t" * 24),
        ("json_password", '{"password": "' + "p" * 10 + '"}'),
        ("yaml_token", "token: " + "q" * 16),
        ("assignment", "DB_PASSWORD=" + "s" * 10),
        ("url", "https://bob:" + "u" * 10 + "@example.com/x"),
        ("key_block", _key_block()),
    ]


@pytest.mark.parametrize("name,text", _shapes(), ids=[n for n, _ in _shapes()])
def test_each_secret_shape_becomes_redacted(name, text):
    out, n = redact(text)
    assert REDACTED in out and n >= 1
    for run in ("X" * 16, "Y" * 35, "Z" * 36, "W" * 30, "1" * 12, "a" * 12, "t" * 24, "p" * 10, "q" * 16,
                "s" * 10, "u" * 10, "Q" * 40):
        assert run not in out


@pytest.mark.parametrize("text", [
    '{"prompt_tokens": 120, "token": 5}', "PasswordAuthentication no", "Failed password for alice from 192.0.2.4",
    "the token count was low", "/etc/passwd changed",
])
def test_ordinary_text_is_not_a_secret(text):
    assert redact(text) == (text, 0)


def test_secrets_are_removed_before_anything_gets_a_placeholder():
    secret = "AKIA" + "X" * 16
    m = Masker(mode="standard", scope=None, data_dir=None, machine="192.0.2.10", values=KnownValues())
    masked = m.mask(f"alice@example.com used {secret}")
    assert secret not in masked and REDACTED in masked
    # the reply naming [REDACTED] stays [REDACTED]: no value was kept to put back
    assert m.restore(f"the key {REDACTED} was exposed") == f"the key {REDACTED} was exposed"


def test_mode_off_leaves_secrets_as_written():
    secret = "AKIA" + "X" * 16
    m = Masker(mode="off", scope=None, data_dir=None, machine="")
    assert m.mask_request("s", f"x {secret}") == ("s", f"x {secret}")
