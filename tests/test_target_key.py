"""target_key: the one comparable form every table stores a machine in."""
from __future__ import annotations

import pytest

from kratos.adapters import findings_engine
from kratos.target_key import LOOPBACK_KEY, target_key


@pytest.mark.parametrize("raw, expected", [
    ("10.136.28.168", "10.136.28.168"),
    ("ubuntu@10.136.28.168", "10.136.28.168"),
    ("  Web-01.Example.COM ", "web-01.example.com"),
    ("root@[fe80::1]", "fe80::1"),
    ("[2001:db8::5]", "2001:db8::5"),
    ("", ""),
    (None, ""),
])
def test_normalisation(raw, expected):
    assert target_key(raw) == expected


@pytest.mark.parametrize("raw", ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "ubuntu@127.0.0.1"])
def test_loopback_names_unify(raw):
    assert target_key(raw) == LOOPBACK_KEY == "loopback"


def test_findings_engine_uses_the_shared_helper():
    # Same function, not a copy: a change in one place reaches both.
    assert findings_engine._host_key is target_key
