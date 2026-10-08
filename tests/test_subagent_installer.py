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
    script = installer.generate_installer("100.64.0.10", "1A2B-3C4D", core_port=8765)
    blobs = _extract_blobs(script)

    # __init__.py, the agent's own files, the shared measurement builder and
    # the starter YARA rules (scanned with rules from the box only -- D4).
    assert set(blobs) == {"__init__.py", *installer.read_bundle_files()}
    assert {*installer.BUNDLE_FILES, "measure.py", "privileged_accounts.py", "yara_rules/MALW_Eicar.yar",
            "yara_rules/README.md", "yara_rules/LICENSE"} <= set(blobs)

    real = installer.read_bundle_files()
    for name, real_text in real.items():
        decoded = base64.b64decode(blobs[name].encode("ascii")).decode("utf-8")
        assert decoded == real_text, f"{name} did not round-trip"

    # The generated __init__ is the minimal bundle one, not the repo's docstring.
    init_decoded = base64.b64decode(blobs["__init__.py"].encode("ascii")).decode("utf-8")
    assert "stdlib-only" in init_decoded
    assert "core_server" not in init_decoded  # i.e. not the repo's narrative __init__


def test_generate_installer_substitutes_address_port_code():
    script = installer.generate_installer("host.example", "ABCD-ABCD", core_port=9999)
    assert "CORE_HOST='host.example'" in script
    assert "CORE_PORT=9999" in script
    assert "PAIR_CODE='ABCD-ABCD'" in script
    assert "--core-host $CORE_HOST --core-port $CORE_PORT --state-file $STATE_FILE" in script
    assert 'EXEC_CMD="$EXEC_CMD --pair $PAIR_CODE"' in script  # only added when a code is given


def test_generate_installer_never_enables_execution():
    script = installer.generate_installer("10.0.0.1", "0000-0001")
    # Capability 2 must never be turned on by the onboarding installer.
    assert "--enable-execution" not in script
    assert "execution_enabled" not in script


def test_generate_installer_has_systemd_unit_and_fallbacks():
    script = installer.generate_installer("10.0.0.1", "0000-0001")
    assert "[Unit]" in script and "[Service]" in script and "[Install]" in script
    assert "Restart=always" in script
    assert "systemctl --user" in script  # user fallback
    assert "start_plain" in script  # no-systemd fallback


def test_single_quote_helper_never_lets_a_value_break_out():
    # Defence in depth behind the validation below: the quoting used for every
    # assignment keeps even a hostile value as inert data.
    hostile = "h'; touch /tmp/kratos_pwn; '"
    proc = subprocess.run(["sh", "-c", f"printf %s {installer._sh_squote(hostile)}"],
                          capture_output=True, text=True, timeout=10)
    assert proc.stdout == hostile


@pytest.mark.parametrize("host", [
    "1.2.3.4 --enable-execution",   # review v2 F-2: would have switched execution on
    "1.2.3.4;id", "$(id)", "`id`", "h'; rm -rf /; '", "-x", "a b", "10.0.0.999", "a\nb",
])
def test_an_address_that_is_not_an_ip_or_hostname_is_refused(host):
    with pytest.raises(installer.InstallerError):
        installer.generate_installer(host, "1A2B-3C4D")


@pytest.mark.parametrize("code", ["c'code", "1A2B-3C4D --enable-execution", "1A2B3C4D", "ZZZZ-ZZZZ"])
def test_a_code_not_in_kratoss_format_is_refused(code):
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("10.0.0.5", code)


@pytest.mark.parametrize("name", ["kratos; touch /tmp/x; echo x", "Kratos", "-x", "a/b", "a b", "", "x" * 65])
def test_a_service_name_that_is_not_plain_is_refused(name):
    # Review v2 F-2: the name used to reach `sudo sh -c "cat > $UNIT"`.
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("10.0.0.5", "1A2B-3C4D", service_name=name)
    with pytest.raises(installer.InstallerError):
        installer.uninstall_command(name)


def test_good_values_are_accepted_and_the_unit_is_not_written_through_sh_c():
    script = installer.generate_installer(
        "fd7a:115c:a1e0::5", " 1a2b-3c4d ", service_name="kratos-agent.v2")
    assert "CORE_HOST='fd7a:115c:a1e0::5'" in script
    assert "PAIR_CODE='1a2b-3c4d'" in script
    assert "--enable-execution" not in script
    assert 'sh -c "cat > $UNIT"' not in script
    assert '$SUDO tee "$UNIT"' in script


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")
@pytest.mark.parametrize("line, edited", [
    ("CORE_HOST='10.0.0.5'", "CORE_HOST='10.0.0.5 --enable-execution'"),
    ("PAIR_CODE='1A2B-3C4D'", "PAIR_CODE='1A2B-3C4D;id'"),
    ("SERVICE_NAME='kratos-subagent'", "SERVICE_NAME='x; id'"),
])
def test_the_script_itself_refuses_a_value_edited_after_generation(tmp_path, line, edited):
    """The generated script re-checks its values, so an installer edited after
    Kratos produced it still refuses to build a bad command or unit."""
    script = installer.generate_installer("10.0.0.5", "1A2B-3C4D")
    assert line in script
    # Only the preamble (checks) -- never let the test reach the install steps.
    preamble = script.replace(line, edited, 1).split("# Decide where to install")[0]
    path = tmp_path / "pre.sh"
    path.write_text(preamble, encoding="utf-8")
    proc = subprocess.run(["sh", str(path)], capture_output=True, text=True, timeout=20, cwd=tmp_path)
    assert proc.returncode != 0
    assert "KRATOS_INSTALL_ERROR: bad_input" in proc.stderr
    # The unedited preamble passes its own checks.
    clean = tmp_path / "clean.sh"
    clean.write_text(script.split("# Decide where to install")[0], encoding="utf-8")
    assert subprocess.run(["sh", str(clean)], capture_output=True, timeout=20, cwd=tmp_path).returncode == 0


@pytest.mark.parametrize("bad", [("", "code"), ("host", ""), ("host", "  ")])
def test_generate_installer_rejects_empty(bad):
    host, code = bad
    with pytest.raises(installer.InstallerError):
        installer.generate_installer(host, code)


def test_generate_installer_rejects_bad_port():
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("host", "1A2B-3C4D", core_port=0)
    with pytest.raises(installer.InstallerError):
        installer.generate_installer("host", "1A2B-3C4D", core_port=70000)


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")
def test_generated_script_is_valid_posix_sh(tmp_path):
    script = installer.generate_installer("100.64.0.10", "0000-0009", core_port=8765)
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


def test_bundle_runs_standalone_and_serves_reads(tmp_path):
    """The extracted bundle imports and runs every read probe with only the
    system python3 -- no kratos package on the path."""
    import subprocess

    script = installer.generate_installer("100.64.0.10", "1A2B-3C4D", core_port=8765)
    pkg = tmp_path / "subagent"
    (pkg / "yara_rules").mkdir(parents=True)
    for name, body in _extract_blobs(script).items():
        (pkg / name).write_bytes(base64.b64decode(body.encode("ascii")))
    code = (
        "import json, sys; sys.path.insert(0, '.'); from subagent import reads, agent; "
        "assert agent.AGENT_VERSION >= '0.3.0'; "
        "print(json.dumps({p: reads.run_probe(p, {'lines': 2} if p == 'journal_fetch' else "
        "{'start': 1790000000, 'granularity': 60} if p == 'measure_auth' else {})['status'] "
        "for p in ('clock', 'file_hashes', 'processes', 'journal_fetch', 'config_audit', 'measure_auth')})); "
        "import time; assert reads.run_probe('privileged_accounts', {'since': time.time() - 86400})['status'] == 'ok'; "
        "print(reads.yara_rule_files('bundled')[0])"
    )
    out = subprocess.run(["/usr/bin/python3", "-I", "-c", code], cwd=tmp_path, capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr
    statuses, rules = out.stdout.splitlines()[:2]
    import json

    assert set(json.loads(statuses).values()) == {"ok"}
    assert "MALW_Eicar.yar" in rules


def test_installer_can_allow_an_untrusted_transport_for_reads_only():
    plain = installer.generate_installer("192.168.1.20", "1A2B-3C4D")
    lan = installer.generate_installer("192.168.1.20", "1A2B-3C4D", allow_untrusted_transport=True)
    assert "--allow-untrusted-transport" not in plain
    assert "--state-file $STATE_FILE --allow-untrusted-transport\"" in lan
    assert "--enable-execution" not in lan
