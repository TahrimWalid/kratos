"""0.3 reads on both transports: the sub-agent's probes (kratos.subagent.reads)
give the same results as the SSH scripts on the same files, refuse symlinks,
hard links and credential paths, accept only closed parameters, and an older
agent gets a clear "update the agent" answer with nothing sent to it."""
from __future__ import annotations

import base64
import os
import sys
import time
from datetime import datetime, timezone

import pytest

from kratos.logsources import catalog, hostfiles, logread
from kratos.subagent import protocol as proto, reads
from tests._logsources_util import awks, bindir, make_root, run_sh
from tests.test_subagent_read_channel import Harness, run

NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc).timestamp()
SINCE = datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
needs_awk = pytest.mark.skipif(not awks(), reason="no awk")


def _both(tmp_path, source, family, files, *, tz="Etc/UTC"):
    root = make_root(tmp_path, family, files, tz=tz)
    ssh = run_sh(logread.build_script(source, SINCE, NOW, journal_prefix="", root=str(root)),
                 bindir(tmp_path, "mawk" if "mawk" in awks() else awks()[0]), now=NOW)
    assert ssh.returncode == 0, ssh.stderr
    agent = reads.log_read_output(source, SINCE, NOW, logread.DEFAULT_MAX_LINES, root=str(root), now=NOW)
    return (logread.parse_output(source, ssh.stdout, SINCE, NOW), logread.parse_output(source, agent["stdout"], SINCE, NOW),
            root, ssh.stdout, agent["stdout"])


def _key(read):
    return ([(round(r.ts, 3), r.text) for r in read.records],
            [(f.slot, f.path, f.status) for f in read.files], read.skipped, read.gaps, read.family)


@needs_awk
@pytest.mark.parametrize("source, family, files", [
    ("web", "debian", {"/var/log/nginx/access.log": "@nginx_access.log", "/var/log/nginx/error.log": "@nginx_error.log",
                       "/var/log/nginx/access.log.1": "@nginx_access.log", "/var/log/nginx/access.log.2.gz": b"x"}),
    ("cron", "rhel", {"/var/log/cron": "@rhel_cron.log", "/var/log/cron-20261004": "@rhel_cron.log"}),
    ("auditd", "debian", {"/var/log/audit/audit.log": "@audit.log.sample"}),
    ("packages", "debian", {"/var/log/dpkg.log": "@dpkg.log", "/var/log/apt/history.log": "@apt_history.log"}),
    ("sudo", "debian", {"/var/log/sudo.log": "@sudo.log"}),
    ("firewall", "alpine", {"/var/log/messages": "@ufw.log", "/var/log/messages.0": "@ufw.log"}),
    ("packages", "alpine", {}),
])
def test_agent_and_ssh_read_the_same(tmp_path, source, family, files):
    ssh, agent, *_ = _both(tmp_path, source, family, files)
    assert _key(ssh) == _key(agent)
    assert ssh.records or source == "packages"


@needs_awk
def test_agent_refuses_symlink_hardlink_and_symlinked_directory_to_shadow(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$PLANTED:19000:0:99999:7:::\n")
    root = make_root(tmp_path, "debian", {"/var/log/nginx/access.log": "@nginx_access.log"})
    (root / "var/log/nginx/error.log").symlink_to(shadow)
    (root / "var/log/apache2").mkdir(parents=True)
    os.link(shadow, root / "var/log/apache2/access.log")
    out = reads.log_read_output("web", SINCE, NOW, 5000, root=str(root), now=NOW)["stdout"]
    read = logread.parse_output("web", out, SINCE, NOW)
    status = {f.path.split("/var/log/", 1)[1]: f.status for f in read.files}
    assert status["nginx/error.log"] == "symlink" and status["apache2/access.log"] == "hardlink"
    assert "PLANTED" not in out
    # a symlinked DIRECTORY on the way to the file is refused too
    (root / "var/log/audit").symlink_to(shadow.parent)
    (shadow.parent / "audit.log").write_text("type=X msg=audit(1791700000.0:1): PLANTED\n")
    out2 = reads.log_read_output("auditd", SINCE, NOW, 5000, root=str(root), now=NOW)["stdout"]
    assert "PLANTED" not in out2 and "\tsymlink\t" in out2
    # file state (head hash) and login records refuse the same way
    (root / "var/log/auth.log").symlink_to(shadow)
    os.link(shadow, root / "var/log/syslog")
    states = hostfiles.parse_file_states("\n".join(hostfiles.file_state_lines("debian", root=str(root))))["files"]
    assert states[f"{root}/var/log/auth.log"]["status"] == "symlink"
    assert states[f"{root}/var/log/syslog"]["status"] == "hardlink"
    assert states[f"{root}/var/log/syslog"]["head_hash"] is None
    (root / "var/log/wtmp").symlink_to(shadow)
    assert hostfiles.parse_utmp_line(hostfiles.utmp_line("wtmp", 4096, root=str(root)))["status"] == "symlink"


def test_hardened_opener_rechecks_and_refuses_non_regular(tmp_path):
    f = tmp_path / "log"
    f.write_text("x")
    fd, st = hostfiles.open_log_file(str(f))
    os.close(fd)
    assert st.st_nlink == 1
    with pytest.raises(hostfiles.FileRefused) as e:
        hostfiles.open_log_file(str(tmp_path))
    assert e.value.status == "not_regular"
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(hostfiles.FileRefused) as e:
        hostfiles.open_log_file(str(fifo))
    assert e.value.status == "not_regular"
    with pytest.raises(hostfiles.FileRefused) as e:
        hostfiles.open_log_file(str(tmp_path / "nope"))
    assert e.value.status == "missing"
    with pytest.raises(hostfiles.FileRefused):
        hostfiles.open_log_file("relative/path")


def test_ssh_side_refuses_links_too(tmp_path):
    """The SSH stat script reports links and never hashes their target."""
    shadow = tmp_path / "shadow"
    shadow.write_text("secret")
    root = make_root(tmp_path, "debian")
    (root / "var/log").mkdir(parents=True)
    (root / "var/log/auth.log").symlink_to(shadow)
    os.link(shadow, root / "var/log/syslog")
    r = run_sh(hostfiles.stat_script(root=str(root)), bindir(tmp_path, awks()[0] if awks() else "mawk"), now=NOW)
    states = hostfiles.parse_file_states(r.stdout)["files"]
    assert states[f"{root}/var/log/auth.log"]["status"] == "symlink"
    assert states[f"{root}/var/log/syslog"]["status"] == "hardlink" and states[f"{root}/var/log/syslog"]["head_hash"] is None


def test_no_catalog_path_is_a_credential_location_and_credential_paths_are_refused():
    assert not [p for p in catalog.ALL_PATHS if reads.is_credential_path(p)]
    with pytest.raises(hostfiles.FileRefused) as e:
        reads._open_for_read("/etc/shadow")
    assert e.value.status == "refused"


@pytest.mark.parametrize("probe, params", [
    ("log_read", {"source": "/etc/shadow"}),
    ("log_read", {"source": "cron", "path": "/etc/shadow"}),
    ("log_read", {"source": "cron", "since": 2000000000, "until": 1900000000}),
    ("journal_file_hash", {"name": "../../etc/shadow"}),
    ("journal_file_hash", {"name": "system.journal; rm -rf /"}),
    ("journal_file_chunk", {"name": "system.journal", "offset": 0, "length": 64 * 1024 * 1024}),
    ("utmp_read", {"file": "/etc/shadow"}),
    ("utmp_read", {"file": "lastlog"}),
    ("audit_status", {"rules": "-D"}),
])
def test_closed_parameters_refuse_everything_else(probe, params):
    assert reads.run_probe(probe, params)["status"] == "refused"


def test_journal_file_names_must_be_in_the_live_listing(tmp_path):
    jd = tmp_path / "var/log/journal" / ("a" * 32)
    jd.mkdir(parents=True)
    (jd / "system.journal").write_bytes(b"LPKSHHRH" + b"\0" * 100)
    other = tmp_path / "elsewhere.journal"
    other.write_bytes(b"x")
    (jd / "user-1000.journal").symlink_to(other)
    assert hostfiles.journal_file_hash("system.journal", root=str(tmp_path))["size"] == 108
    with pytest.raises(hostfiles.FileRefused):
        hostfiles.journal_file_hash("user-1000.journal", root=str(tmp_path))   # a symlink
    with pytest.raises(hostfiles.FileRefused):
        hostfiles.journal_file_hash("system@" + "b" * 32 + "-" + "0" * 16 + "-" + "1" * 16 + ".journal",
                                    root=str(tmp_path))                     # not in the listing
    chunk = hostfiles.journal_file_chunk("system.journal", 4, 4, root=str(tmp_path))
    assert base64.b64decode(chunk["data"]) == b"HHRH" and not chunk["eof"]


def test_journal_name_pattern_matches_real_systemd_names():
    for name in ("system.journal", "user-1000.journal", "system@00065d932c48dec6-c540336929c36b02.journal~",
                 "system@ca9088152cec48338fa9d18a97054e37-0000000000000001-0005c837dd159f6a.journal",
                 "user-1000@5e829b0a03ca4d8a884f7ae525f2c41a-00000000000004d4-00065c837dd159f6.journal"):
        assert hostfiles.JOURNAL_NAME_RE.fullmatch(name), name
    for name in ("system.journal.bak", "../system.journal", "system@x.journal", "foo.journal", "system.journal~~"):
        assert not hostfiles.JOURNAL_NAME_RE.fullmatch(name), name


def test_real_probes_run_on_this_host():
    for probe, params in (("log_read", {"source": "systemd", "since": time.time() - 600}),
                          ("log_file_stat", {}), ("journal_headers", {}), ("audit_status", {}),
                          ("boot_history", {}), ("utmp_read", {"file": "wtmp", "max_bytes": 3840})):
        out = reads.run_probe(probe, params)
        assert out["status"] == "ok", (probe, out)


def test_new_reads_to_an_older_agent_get_an_update_message_and_nothing_is_sent(tmp_path, monkeypatch):
    real = proto.build_hello
    old_probes = [p for p in reads.READ_PROBES if p not in reads.PARAM_SPECS or p in (
        "clock", "journal_fetch", "journal_auth", "open_files", "processes", "file_hashes", "config_audit",
        "capabilities", "yara_scan", "measure_auth", "privileged_accounts")]

    def old_hello(*a, **k):
        k["read_probes"] = old_probes
        msg = real(*a, **k)
        msg["agent_version"] = "0.3.5"
        return msg

    monkeypatch.setattr(proto, "build_hello", old_hello)
    seen: list[str] = []
    real_run = reads.run_probe
    monkeypatch.setattr(reads, "run_probe", lambda probe, params: seen.append(probe) or real_run(probe, params))

    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            for probe, params in (("log_read", {"source": "cron"}), ("journal_headers", {}),
                                  ("utmp_read", {"file": "wtmp"}), ("audit_status", {})):
                out = await h.read(tid, probe, params)
                assert out["status"] == "old_agent", out
                assert "0.4.0" in out["reason"] and "`g` in /subagent" in out["reason"]
            assert (await h.read(tid, "clock"))["status"] == "ok"   # old reads still work
        finally:
            await h.stop()
    run(go())
    assert seen == ["clock"]


def test_a_current_agent_serves_the_new_reads_over_the_real_channel(tmp_path):
    async def go():
        h = Harness(tmp_path)
        tid = await h.start()
        try:
            out = await h.read(tid, "log_read", {"source": "systemd", "since": time.time() - 3600})
            assert out["status"] == "ok" and "M\tfamily\t" in out["data"]["stdout"]
            st = await h.read(tid, "log_file_stat")
            assert st["status"] == "ok" and "M\tfamily\t" in st["data"]["stdout"]
        finally:
            await h.stop()
    run(go())


def test_agent_version_and_bundle_files():
    from kratos.subagent import agent, installer

    assert agent.AGENT_VERSION == "0.9.1"       # Phase C audit: account-change lines in the auth match + classifier
    files = installer.read_bundle_files()
    names = ("catalog.py", "logread.py", "hostfiles.py", "persistence.py", "live_response.py", "packages.py",
             "detect.py")
    assert set(names) <= set(files)
    for name in names:
        assert "import kratos" not in files[name].replace("from kratos.logsources import", "")


def test_new_bundle_files_import_and_run_standalone(tmp_path):
    """The bundle layout (sibling modules, system python3, no kratos package)."""
    import subprocess

    from kratos.subagent import installer

    pkg = tmp_path / "subagent"
    (pkg / "yara_rules").mkdir(parents=True)
    for name, text in installer.read_bundle_files().items():
        (pkg / name).write_text(text)
    (pkg / "__init__.py").write_text("")
    code = ("import sys, time; sys.path.insert(0, '.'); from subagent import reads; "
            "print(reads.run_probe('log_read', {'source': 'cron', 'since': time.time() - 600})['status'], "
            "reads.run_probe('log_file_stat', {})['status'], reads.run_probe('utmp_read', {'file': 'wtmp'})['status'])")
    out = subprocess.run([sys.executable, "-I", "-S", "-c", code], cwd=tmp_path, capture_output=True, text=True,
                         timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["ok", "ok", "ok"]
