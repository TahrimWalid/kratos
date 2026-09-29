"""
Tests for the sub-agent one-command installer generator + hub-address detection.

The generator is pure text -- no target, no network, nothing executed -- so this
verifies (a) the embedded bundle blobs base64-round-trip to the real files
byte-for-byte, (b) core address/port/code are substituted, (c) the script is
valid POSIX sh (``sh -n``), and (d) it never enables capability 2.
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess

import pytest

from kratos.subagent import hub_address, installer


def _extract_blobs(script: str) -> dict[str, str]:
    """Pull each ``write_file subagent/<name> <<'EOF' ... EOF`` blob back out."""
    pattern = re.compile(
        r"write_file subagent/(?P<name>\S+) <<'"
        + re.escape(installer._EOF)
        + r"'\n(?P<body>.*?)\n"
        + re.escape(installer._EOF),
        re.DOTALL,
    )
    return {m.group("name"): m.group("body") for m in pattern.finditer(script)}


def test_generate_installer_embeds_all_bundle_files_roundtrip():
    script = installer.generate_installer("100.64.0.10", "CODE-1234", core_port=8765)
    blobs = _extract_blobs(script)

    # __init__.py plus the five real bundle files.
    assert set(blobs) == {"__init__.py", *installer.BUNDLE_FILES}

    real = installer.read_bundle_files()
    for name, real_text in real.items():
        decoded = base64.b64decode(blobs[name].encode("ascii")).decode("utf-8")
        assert decoded == real_text, f"{name} did not round-trip"

    # The generated __init__ is the minimal bundle one, not the repo's docstring.
    init_decoded = base64.b64decode(blobs["__init__.py"].encode("ascii")).decode("utf-8")
    assert "stdlib-only" in init_decoded
    assert "core_server" not in init_decoded  # i.e. not the repo's narrative __init__


def test_generate_installer_substitutes_address_port_code():
    script = installer.generate_installer("host.example", "CODE-ABCD", core_port=9999)
    assert "CORE_HOST='host.example'" in script
    assert "CORE_PORT=9999" in script
    assert "PAIR_CODE='CODE-ABCD'" in script
    assert "--core-host $CORE_HOST --core-port $CORE_PORT --state-file $STATE_FILE" in script
    assert 'EXEC_CMD="$EXEC_CMD --pair $PAIR_CODE"' in script  # only added when a code is given


def test_generate_installer_never_enables_execution():
    script = installer.generate_installer("10.0.0.1", "CODE-1")
    # Capability 2 must never be turned on by the onboarding installer.
    assert "--enable-execution" not in script
    assert "execution_enabled" not in script


def test_generate_installer_has_systemd_unit_and_fallbacks():
    script = installer.generate_installer("10.0.0.1", "CODE-1")
    assert "[Unit]" in script and "[Service]" in script and "[Install]" in script
    assert "Restart=always" in script
    assert "systemctl --user" in script  # user fallback
    assert "start_plain" in script  # no-systemd fallback


def test_single_quote_escaping_is_injection_safe():
    # A pairing code / host can never break out of the sh single-quote.
    script = installer.generate_installer("h'; rm -rf /; '", "c'code", core_port=8765)
    assert "rm -rf /" in script  # present only as inert quoted data...
    # ...and the quoting is the escaped form, not a live command break-out.
    assert installer._sh_squote("h'; rm -rf /; '") in script


@pytest.mark.parametrize("bad", [("", "code"), ("host", ""), ("host", "  ")])
def test_generate_installer_rejects_empty(bad):
    host, code = bad
    with pytest.raises(installer.InstallerError):
        installer.generate_installer(host, code)


def test_generate_installer_rejects_bad_port():
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("host", "code", core_port=0)
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("host", "code", core_port=70000)


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")
def test_generated_script_is_valid_posix_sh(tmp_path):
    script = installer.generate_installer("100.64.0.10", "CODE-9", core_port=8765)
    path = tmp_path / "install.sh"
    path.write_text(script, encoding="utf-8")
    # `sh -n` parses without executing -- catches quoting/heredoc/syntax errors.
    proc = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, f"sh -n failed:\n{proc.stderr}"


# --- hub_address ---------------------------------------------------------


def test_candidate_hub_addresses_always_offers_manual_last():
    cands = hub_address.candidate_hub_addresses()
    assert cands, "should always return at least the manual option"
    assert cands[-1].kind == "manual"
    assert cands[-1].address == ""


def test_candidate_hub_addresses_dedups_and_shapes(monkeypatch):
    monkeypatch.setattr(hub_address, "detect_tailscale_ip", lambda: "100.1.2.3")
    monkeypatch.setattr(hub_address, "detect_lan_ip", lambda *a, **k: "100.1.2.3")
    cands = hub_address.candidate_hub_addresses()
    addrs = [c.address for c in cands if c.address]
    assert addrs == ["100.1.2.3"], "duplicate address should appear once"
    # tailscale is preferred first when present
    assert cands[0].kind == "tailscale"


def test_detect_lan_ip_returns_ip_or_none():
    ip = hub_address.detect_lan_ip()
    assert ip is None or ip.count(".") == 3
