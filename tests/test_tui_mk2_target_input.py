"""
Target-input validation (tui_mk2/target_input.py).

Guards the Sprint-4 gap: a pasted command line or quoted goal typed into a
target field used to become the active target verbatim. The validator accepts
any plausible IP/hostname and rejects obvious garbage, returning a message the
caller re-prompts with (never silently coercing).
"""
from __future__ import annotations

import pytest

from kratos.tui_mk2.target_input import validate_targets


@pytest.mark.parametrize("raw", [
    ["10.0.0.5"],
    ["10.136.28.168"],
    ["127.0.0.1"],
    ["host.local"],
    ["kratos-target"],
    ["a.b.c.example.com"],
    ["::1"],
    ["fe80::1"],
    ["10.0.0.5", "10.0.0.6", "host.local"],  # multi-target
])
def test_valid_targets_pass_unchanged(raw):
    cleaned, err = validate_targets(raw)
    assert err is None
    assert cleaned == raw


def test_strips_whitespace_and_drops_blanks():
    cleaned, err = validate_targets(["  10.0.0.5 ", "", "  "])
    assert err is None and cleaned == ["10.0.0.5"]


def test_rejects_pasted_command_line():
    # The exact reported case: `kratos investigate "look for X"` split into
    # tokens. The quoted fragments fail, so the whole input is rejected.
    tokens = 'kratos investigate "look for X"'.split()
    cleaned, err = validate_targets(tokens)
    assert cleaned == [] and err is not None
    assert "hostname" in err.lower()


@pytest.mark.parametrize("bad", [
    ['"look'],            # leading quote
    ['X"'],               # trailing quote
    ["a b"],              # embedded space (already-split junk would look like this)
    ["-startdash"],       # leading punctuation
    ["enddash-"],         # trailing punctuation
    ["path/to/thing"],    # slash
    ["user@host"],        # @ (not a bare host)
    ["host_name"],        # underscore isn't valid in a hostname
    ["a" * 300],          # over the length ceiling
])
def test_rejects_obvious_garbage(bad):
    cleaned, err = validate_targets(bad)
    assert cleaned == [] and err is not None


@pytest.mark.parametrize("bad_ip", [
    "10.0.0.999",   # octet > 255
    "1.2.3.4.5",    # too many octets
    "999.1.1.1",    # octet > 255
    "10.0.0",       # too few octets
    "123",          # bare integer is not a host identifier
])
def test_rejects_malformed_ip(bad_ip):
    # Proper ipaddress-based validation, not a loose digits-and-dots regex.
    cleaned, err = validate_targets([bad_ip])
    assert cleaned == [] and err is not None


def test_empty_input_rejected():
    cleaned, err = validate_targets([])
    assert cleaned == [] and err is not None


def test_kratos_host_aliases_expand_to_loopback():
    from kratos.tui_mk2.target_input import KRATOS_HOST_VALUE, expand_host_aliases

    for alias in ["kratos-host", "KRATOS-HOST", "self", "localhost", "this-host"]:
        assert expand_host_aliases([alias]) == [KRATOS_HOST_VALUE]
    # Non-aliases are untouched; mixed lists only rewrite the alias.
    assert expand_host_aliases(["10.0.0.5"]) == ["10.0.0.5"]
    assert expand_host_aliases(["self", "10.0.0.5"]) == [KRATOS_HOST_VALUE, "10.0.0.5"]


def test_kratos_host_option_shape():
    from kratos.tui_mk2.target_input import KRATOS_HOST_SENTINEL, kratos_host_option

    opt = kratos_host_option()
    assert opt["value"] == KRATOS_HOST_SENTINEL and "Kratos-Host" in opt["label"]
