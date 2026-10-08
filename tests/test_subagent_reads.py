"""The sub-agent's closed read set (kratos.subagent.reads): closed validators,
refusals, scope limits, and parity with the SSH path's commands/output."""
from __future__ import annotations

import os
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


def test_walk_skips_credential_dirs_and_files(yara_box):
    root, outside, scan = yara_box
    (root / ".ssh").mkdir()
    (root / ".ssh" / "id_ed25519").write_text("evil")
    (root / "web").mkdir()
    (root / "web" / "index.php").write_text("<?php evil")
    (root / "web" / "server.key").write_text("evil")
    out = scan(str(root))
    assert [m["file"] for m in out["matches"]] == [str(root / "web" / "index.php")]
    assert out["skipped_credential"] == 2 and out["files_scanned"] == 1 and not out["truncated"]


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


def test_a_root_agent_skips_rules_that_load_yara_modules(tmp_path, monkeypatch):
    """Security review 2026-10-05, finding 2: as root, YARA scans files any local
    user can write; module parsers (pe, elf, ...) are where YARA's past security
    bugs were, so a root agent uses only module-free rules and names the rest."""
    d = tmp_path / "yara"
    d.mkdir(mode=0o755)
    (d / "plain.yar").write_text('rule a { strings: $x = "evil" condition: $x }\n')
    (d / "mod.yar").write_text('import "pe"\nrule b { condition: pe.number_of_sections > 0 }\n')
    for f in d.iterdir():
        f.chmod(0o644)
    monkeypatch.setattr(R, "LOCAL_YARA_DIR", str(d))
    monkeypatch.setattr(R.os, "geteuid", lambda: 0)
    monkeypatch.setattr(R, "_rule_files_in", lambda directory, trusted_only: (
        sorted(str(p) for p in d.glob("*.yar")), []) if directory == str(d) else ([], []))
    files, problems = R.yara_rule_files("local")
    assert [f.rsplit("/", 1)[1] for f in files] == ["plain.yar"]
    assert any("mod.yar" in p and "module" in p for p in problems)
    monkeypatch.setattr(R.os, "geteuid", lambda: 1000)        # not root: both used
    assert len(R.yara_rule_files("local")[0]) == 2


def test_the_shipped_rules_load_no_yara_modules():
    from pathlib import Path

    import kratos

    shipped = Path(kratos.__file__).parent / "yara_rules"      # what the installer bundles
    files, _ = R._rule_files_in(str(shipped), trusted_only=False)
    assert files and not any(R._uses_yara_modules(f) for f in files)



# ---------------------------------------------------------------------------
# Review v2 F-1: the scan can't be redirected outside the scan roots
# ---------------------------------------------------------------------------
_FAKE_YARA = """#!/usr/bin/env python3
# Stand-in for yara: reads its --scan-list, really opens each path, and reports
# a match for files containing "evil" -- so tests see exactly what yara would open.
import sys
log = open(sys.argv[0] + ".calls", "a")
paths = [l for l in sys.stdin.read().split("\\n") if l]
log.write("%d\\n" % len(paths)); log.close()
open(sys.argv[0] + ".paths", "a").write("".join(p + "\\n" for p in paths))
for path in paths:
    try:
        data = open(path, "rb").read()
    except OSError:
        continue
    if b"evil" in data:
        print("Evil " + path)
        print("0x%x:$a: evil" % data.index(b"evil"))
"""


@pytest.fixture
def yara_box(tmp_path, monkeypatch):
    """A scan root, a directory OUTSIDE every root holding a secret, and a scan()
    that runs the real yara_scan probe with the stand-in scanner."""
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("evil secret")
    fake = tmp_path / "yara"
    fake.write_text(_FAKE_YARA)
    fake.chmod(0o755)
    rules = tmp_path / "rules.yar"
    rules.write_text('rule Evil { strings: $a = "evil" condition: $a }\n')
    real_resolve = R.resolve_binary
    monkeypatch.setattr(R, "resolve_binary", lambda name: str(fake) if name == "yara" else real_resolve(name))
    monkeypatch.setattr(R, "SCAN_ROOTS", (str(root),))
    monkeypatch.setattr(R, "yara_rule_files", lambda ruleset: ([str(rules)], []))

    def scan(path):
        out = R.run_probe("yara_scan", {"path": path})
        assert out["status"] in ("ok", "refused"), out
        return out["data"] if out["status"] == "ok" else out

    scan.calls = fake.with_name("yara.calls")
    scan.paths = fake.with_name("yara.paths")
    return root, outside, scan


def _outside(out, outside):
    return [m["file"] for m in out.get("matches", []) if "outside" in m["file"] or "secret" in m["file"]]


def test_a_directory_swapped_for_a_symlink_after_the_check_is_not_scanned(yara_box, monkeypatch):
    """The reviewer's PoC: the path passes the scan-root check, then a local user
    replaces it with a symlink to a directory outside every root."""
    root, outside, scan = yara_box
    sus = root / "suspicious"
    sus.mkdir()
    real_resolve = R._resolve_scan_path

    def resolve_then_swap(path):
        canonical = real_resolve(path)
        sus.rmdir()
        sus.symlink_to(outside)
        return canonical

    monkeypatch.setattr(R, "_resolve_scan_path", resolve_then_swap)
    out = scan(str(sus))
    assert out.get("status") == "refused" and "changed while it was being checked" in out["reason"]


def test_symlinked_files_and_directories_inside_a_root_are_never_followed(yara_box):
    root, outside, scan = yara_box
    (root / "link_dir").symlink_to(outside)
    (root / "link_file").symlink_to(outside / "secret.txt")
    (root / "plain.txt").write_text("evil")
    out = scan(str(root))
    assert _outside(out, outside) == [] and [m["file"] for m in out["matches"]] == [str(root / "plain.txt")]


def test_a_file_name_cannot_inject_a_path_into_the_scan_list(yara_box):
    """yara's --scan-list is newline-separated; a name containing a newline used to
    add any path to it. yara now only ever sees /proc/self/fd/N."""
    root, outside, scan = yara_box
    (root / "a\netc").write_text("harmless")       # used to add 'etc' (= /etc, yara runs in /) to the list
    out = scan(str(root))
    listed = scan.paths.read_text().splitlines()
    assert out["files_scanned"] == 1 and len(listed) == 1 and listed[0].startswith("/proc/self/fd/")


def test_large_trees_are_scanned_in_batches_and_matches_map_back(yara_box):
    root, outside, scan = yara_box
    for i in range(R.YARA_BATCH_FILES * 2 + 50):
        (root / f"f{i:04d}.txt").write_text("evil" if i % 200 == 7 else "ok")
    out = scan(str(root))
    assert out["files_scanned"] == R.YARA_BATCH_FILES * 2 + 50
    assert sorted(m["file"] for m in out["matches"]) == [str(root / f"f{i:04d}.txt") for i in (7, 207, 407)]
    assert [int(x) for x in scan.calls.read_text().split()] == [200, 200, 50]


def test_a_single_file_can_be_scanned(yara_box):
    root, outside, scan = yara_box
    (root / "drop.php").write_text("evil")
    out = scan(str(root / "drop.php"))
    assert [m["file"] for m in out["matches"]] == [str(root / "drop.php")] and out["files_scanned"] == 1


def test_open_nofollow_refuses_a_symlinked_component(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    fd = R._open_nofollow(str(tmp_path / "real"))
    os.close(fd)
    with pytest.raises(OSError):
        R._open_nofollow(str(tmp_path / "link"))
