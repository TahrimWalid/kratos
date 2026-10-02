"""The sub-agent's closed read set (kratos.subagent.reads): closed validators,
refusals, scope limits, and parity with the SSH path's commands/output."""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

from kratos.subagent import reads as R


# ---------------------------------------------------------------------------
# Validators -- closed, type-strict, never coerce
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("probe,params", [
    ("journal_fetch", {"lines": 10}),
    ("journal_fetch", {"lines": 5000, "unit": "sshd.service", "since": 1790000000, "until": 1790003600.5}),
    ("journal_auth", {"identifier": "sudo", "lines": 1}),
    ("open_files", {}),
    ("open_files", {"pid": 4194304}),
    ("measure_auth", {"start": 1790000000, "granularity": 3600, "exclude_user": "ubuntu"}),
    ("yara_scan", {"path": "/tmp"}),
])
def test_valid_params_pass(probe, params):
    R.validate_params(probe, params)


@pytest.mark.parametrize("probe,params,why", [
    ("journal_fetch", {}, "required"),
    ("journal_fetch", {"lines": "10"}, "whole number"),
    ("journal_fetch", {"lines": True}, "whole number"),
    ("journal_fetch", {"lines": 5001}, "whole number"),
    ("journal_fetch", {"lines": 10, "unit": "-o"}, "systemd unit"),           # argv injection
    ("journal_fetch", {"lines": 10, "unit": "a b"}, "systemd unit"),
    ("journal_fetch", {"lines": 10, "unit": "x;rm"}, "systemd unit"),
    ("journal_fetch", {"lines": 10, "since": "yesterday"}, "Unix time"),
    ("journal_fetch", {"lines": 10, "since": float("nan")}, "Unix time"),
    ("journal_fetch", {"lines": 10, "since": 1790003600, "until": 1790000000}, "ends before"),
    ("journal_fetch", {"lines": 10, "command": "id"}, "unknown parameter"),
    ("journal_auth", {"identifier": "cron", "lines": 1}, "one of"),
    ("open_files", {"pid": 0}, "whole number"),
    ("open_files", {"pid": "1; id"}, "whole number"),
    ("measure_auth", {"start": 1790000000, "granularity": 61}, "one of"),
    ("measure_auth", {"start": 1790000000, "granularity": 60, "exclude_user": "$(id)"}, "user name"),
    ("yara_scan", {"path": "relative"}, "absolute"),
    ("yara_scan", {"path": "/tmp/../etc"}, ".."),
    ("yara_scan", {"path": "/tmp", "rules": "rule x {condition: true}"}, "unknown parameter"),
    ("processes", "not a dict", "object"),
    ("nope", {}, "unknown probe"),
])
def test_invalid_params_refused(probe, params, why):
    with pytest.raises(R.ReadParamError, match=why):
        R.validate_params(probe, params)


def test_run_probe_never_raises_and_says_why():
    assert R.run_probe("nope", {})["status"] == "unsupported"
    assert "available" in R.run_probe("nope", {})
    bad = R.run_probe("journal_fetch", {"lines": 10, "unit": "--output=export"})
    assert bad["status"] == "refused" and "unit" in bad["reason"]


def test_no_probe_accepts_command_or_script_text():
    for probe, spec in R.PARAM_SPECS.items():
        assert not ({"command", "cmd", "script", "argv", "rules", "args", "paths"} & set(spec)), probe


# ---------------------------------------------------------------------------
# YARA scope (D4): closed roots, credential paths never scanned
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [
    "/home/u/.ssh/id_ed25519", "/root/.ssh/authorized_keys", "/home/u/.aws/credentials",
    "/etc/shadow", "/srv/app/.env", "/opt/x/server.key", "/home/u/.gnupg/pubring.kbx",
    "/home/u/id_rsa.bak", "/var/www/cert.pem",
])
def test_credential_paths_are_recognised(path):
    assert R.is_credential_path(path)


@pytest.mark.parametrize("path", ["/var/www/html/shell.php", "/tmp/x", "/home/u/notes.txt"])
def test_ordinary_paths_are_not_credentials(path):
    assert not R.is_credential_path(path)


def test_scan_path_outside_roots_refused_even_without_yara():
    out = R.run_probe("yara_scan", {"path": "/etc"})
    assert out["status"] == "refused" and "scan roots" in out["reason"]


def test_symlink_out_of_a_root_is_refused(tmp_path, monkeypatch):
    link = Path("/tmp") / f"kratos-test-link-{tmp_path.name}"
    link.symlink_to("/etc")
    try:
        with pytest.raises(R.ReadParamError, match="scan roots"):
            R._resolve_scan_path(str(link))
    finally:
        link.unlink()


def test_walk_skips_credential_dirs_and_files(tmp_path, monkeypatch):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("k")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "index.php").write_text("<?php")
    (tmp_path / "web" / "server.key").write_text("k")
    files, counts, capped = R._walk_scan_files(str(tmp_path))
    assert files == [str(tmp_path / "web" / "index.php")]
    assert counts["skipped_credential"] == 2 and not capped


def test_local_rules_must_be_root_owned(tmp_path, monkeypatch):
    rules = tmp_path / "yara"
    rules.mkdir(mode=0o755)
    rules.chmod(0o755)
    (rules / "mine.yar").write_text("rule a { condition: true }")
    (rules / "mine.yar").chmod(0o644)
    monkeypatch.setattr(R, "LOCAL_YARA_DIR", str(rules))
    monkeypatch.setattr(R, "bundled_rules_dir", lambda: str(tmp_path / "none"))
    files, problems = R.yara_rule_files("local")
    # owned by the test user (== the agent's own user here), not writable by others: trusted
    assert files == [str(rules / "mine.yar")] and problems == []
    (rules / "mine.yar").chmod(0o666)
    files, problems = R.yara_rule_files("local")
    assert files == [] and "group/world-writable" in problems[0]


def test_yara_output_parsed_without_matched_text():
    out = "EICAR /tmp/e.txt\n0x0:$a: X5O!P%@AP\n0x10:$b: secret:with:colons\nOther /tmp/f\n"
    with_content = R.parse_yara_output(out)
    without = R.parse_yara_output(out, include_content=False)
    assert with_content[0]["strings"][1]["matched"] == "secret:with:colons"
    assert without == [{"rule": "EICAR", "file": "/tmp/e.txt",
                        "strings": [{"offset": "0x0", "identifier": "$a"}, {"offset": "0x10", "identifier": "$b"}]},
                       {"rule": "Other", "file": "/tmp/f", "strings": []}]


# ---------------------------------------------------------------------------
# Parity with the SSH path: same commands, same output format
# ---------------------------------------------------------------------------
def test_journal_commands_match_the_ssh_strings_they_replace():
    argv = R.journal_fetch_argv("sshd.service", 1790000000, None, 500, prefix=["sudo", "-n"])
    assert shlex.join(argv) == ("sudo -n journalctl --no-pager -o json _SYSTEMD_UNIT=sshd.service + _COMM=sshd "
                                "--since @1790000000 --reverse -n 501")
    auth = R.journal_auth_argv("sshd", 1790000000, 1790003600, 500, prefix=["sudo", "-n"])
    assert shlex.join(auth) == ("sudo -n journalctl --no-pager -o json _COMM=sshd _COMM=sshd-session "
                                "--since @1790000000 --until @1790003600 --reverse -n 501")
    assert R.lsof_argv(42) == ["lsof", "-n", "-P", "-p", "42"]


def test_agent_hashing_matches_the_ssh_script_line_for_line(tmp_path):
    present = tmp_path / "a"
    present.write_text("hello\n")
    unreadable = tmp_path / "b"
    unreadable.write_text("x")
    unreadable.chmod(0o000)
    paths = (str(present), str(unreadable), str(tmp_path / "missing"))
    try:
        sh = subprocess.run(["sh", "-c", R.file_hash_script(paths)], capture_output=True, text=True).stdout
        agent = "\n".join(R.hash_file(p) for p in paths) + "\n"
    finally:
        unreadable.chmod(0o600)
    import os
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    assert agent == sh
    assert R.parse_hash_lines(agent, "U") == {paths[0]: R.hash_file(paths[0]).split("\t")[2], paths[1]: "U", paths[2]: None}


def test_config_audit_script_privilege_prefix():
    ssh = R.config_audit_script("sudo -n")
    root = R.config_audit_script("")
    assert ssh.startswith("SUDO='sudo -n'\nSSHD_T='sudo -n sshd -T'\n")
    assert root.startswith("SUDO=''\nSSHD_T='sshd -T'\n")
    assert "sudo -n" not in R._CONFIG_AUDIT_BODY  # privilege comes only from $SUDO


def test_config_audit_body_is_the_same_on_both_transports():
    from kratos.adapters import ssh_remote

    assert ssh_remote._CONFIG_AUDIT_SCRIPT == R.config_audit_script("sudo -n")
    assert R._CONFIG_AUDIT_BODY in R.config_audit_script("")


def test_measure_script_is_the_same_builder():
    from kratos.timewin import measure

    assert R.measure is measure


# ---------------------------------------------------------------------------
# The capped runner
# ---------------------------------------------------------------------------
def test_run_capped_truncates_at_a_line_boundary():
    out = R.run_capped(["seq", "1", "100000"], timeout=10, cap=1000)
    assert out["truncated"] and out["stdout"].endswith("\n")
    assert len(out["stdout"]) <= 1000 and out["stdout"].splitlines()[-1].isdigit()


def test_run_capped_times_out():
    with pytest.raises(R.ProbeTimeout):
        R.run_capped(["sleep", "5"], timeout=0.5, cap=100)


def test_run_capped_never_uses_path(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert R.run_capped(["echo", "hi"], timeout=5, cap=100)["stdout"] == "hi\n"
    with pytest.raises(R.ProbeMissing):
        R.run_capped(["definitely-not-a-binary-xyz"], timeout=5, cap=100)


def test_journal_output_is_trimmed_to_parsed_fields():
    raw = '{"__REALTIME_TIMESTAMP":"1","MESSAGE":"m","_HOSTNAME":"h","_CMDLINE":"secret --token x","_PID":"9"}\n'
    assert R._trim_journal(raw) == '{"__REALTIME_TIMESTAMP":"1","MESSAGE":"m"}\n'
