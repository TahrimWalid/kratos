"""E.4 `file_facts`: the SSH script (gawk, mawk, BusyBox awk) and the agent's read print the
same records for the same files; the read is safe (snapshot paths only, stdin-only paths,
no link followed, hard links and non-regular files refused, never the file's bytes)."""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import file_facts as F
from kratos.hashdb import facts as FX

from tests._logsources_util import awks  # noqa: E402

AWKS = awks()          # CI's awk job sets KRATOS_TEST_REQUIRE_AWKS: a missing awk is an error, never a skip
TOOLS = ("sh", "sed", "tr", "cat", "readlink", "head", "stat", "grep", "sha256sum", "sha1sum", "md5sum", "cut",
         "sort", "wc", "printf", "id", "date", "od", "base64", "rpm")


def _busybox() -> str:
    return (os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
            or str(Path("~/.local/bin/busybox").expanduser()))


def _bindir(base: Path, awk: str, extra: dict[str, str] | None = None) -> Path:
    b = base / f"bin_{awk}"
    b.mkdir(parents=True, exist_ok=True)
    for t in TOOLS:
        src = shutil.which(t)
        if src and not (b / t).exists():
            os.symlink(src, b / t)
    if not (b / "awk").exists():
        os.symlink(_busybox() if awk == "busybox" else shutil.which(awk), b / "awk")
    for name, body in (extra or {}).items():
        (b / name).unlink(missing_ok=True)
        (b / name).write_text(body)
        (b / name).chmod(0o755)
    return b


def _awk_has_math(b: Path) -> bool:
    r = subprocess.run([str(b / "awk"), "BEGIN { print log(2) }"], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip().startswith("0.69")


def _w(root: Path, rel: str, data: bytes, mode: int = 0o644) -> Path:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    p.chmod(mode)
    return p


def make_tree(base: Path, family: str = "debian") -> tuple[Path, list[bytes]]:
    r = base / "root"
    os_release = {"debian": "ID=ubuntu\nID_LIKE=debian\n", "alpine": "ID=alpine\n",
                  "rhel": "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n"}[family]
    _w(r, "/etc/os-release", os_release.encode())
    su = _w(r, "/usr/bin/su", b"\x7fELF\x02" + b"A" * 5000, 0o4755)
    _w(r, "/usr/bin/edited", b"\x7fELF\x02" + b"B" * 100, 0o755)
    _w(r, "/tmp/.x", b"\x7fELF\x02" + bytes(range(256)) * 900, 0o755)
    _w(r, "/dev/shm/upx", b"\x7fELF\x01" + b"\0" * 300 + b"UPX!" + bytes(range(256)) * 3, 0o755)
    _w(r, "/tmp/notes.txt", b"hello", 0o644)
    _w(r, "/tmp/sc.sh", b"#!/bin/sh\necho\n", 0o755)
    _w(r, "/tmp/gz.bin", b"\x1f\x8b\x08" + bytes(range(256)) * 900, 0o755)
    _w(r, "/usr/lib/libx.so.1", b"\x7fELF\x02lib", 0o644)
    _w(r, "/tmp/sucopy", su.read_bytes(), 0o4755)                     # a packaged program copied elsewhere
    _w(r, "/etc/init.d/svc", b"#!/bin/sh\necho svc\n", 0o755)        # a dpkg configuration file
    (r / "tmp/sulink").symlink_to(su)
    os.link(r / "tmp/.x", r / "tmp/.xlink")
    os.mkfifo(r / "tmp/fifo")
    if family == "debian":
        info = r / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (info / "login:amd64.list").write_text("/usr/bin/su\n/usr/bin/edited\n")
        md5 = hashlib.md5(su.read_bytes()).hexdigest()
        (info / "login:amd64.md5sums").write_text(f"{md5}  usr/bin/su\n{'0' * 32}  usr/bin/edited\n")
        (info / "svc.list").write_text("/etc/init.d/svc\n")
        conf = hashlib.md5((r / "etc/init.d/svc").read_bytes()).hexdigest()
        (r / "var/lib/dpkg/status").write_text(
            f"Package: svc\nStatus: install ok installed\nConffiles:\n /etc/init.d/svc {conf}\n /etc/other x\n"
            "Description: d\n\nPackage: login\nStatus: install ok installed\n\n")
    elif family == "alpine":
        q1 = "Q1" + base64.b64encode(hashlib.sha1(su.read_bytes()).digest()).decode()
        db = r / "lib/apk/db/installed"
        db.parent.mkdir(parents=True)
        db.write_text(f"P:login\nV:1\nF:usr/bin\nR:su\nZ:{q1}\nR:edited\nZ:Q1{'A' * 26}A=\n\n")
    rels = ["/usr/bin/su", "/usr/bin/edited", "/tmp/.x", "/dev/shm/upx", "/tmp/notes.txt", "/tmp/sc.sh", "/tmp/gone",
            "/tmp/sulink", "/tmp/.xlink", "/tmp/fifo", "/tmp/gz.bin", "/usr/lib/libx.so.1", "/tmp/sucopy",
            "/etc/init.d/svc"]
    return r, [str(r).encode() + p.encode() for p in rels]


def run_ssh(base: Path, root: Path, paths: list[bytes], awk: str = "gawk", extra: dict[str, str] | None = None,
            **kw) -> dict:
    b = _bindir(base, awk, extra)
    script = F.build_script(paths, root=str(root), **kw)
    r = subprocess.run([str(b / "sh"), "-s"], input=script, capture_output=True, text=True,
                       env={"PATH": str(b), "LC_ALL": "C"}, timeout=120)
    assert r.returncode == 0, r.stderr
    return F.parse_output(r.stdout, len(paths))


def run_agent(root: Path, paths: list[bytes], run=None, **kw) -> dict:
    return F.parse_output(F.facts_output(paths, root=str(root), run=run, **kw)["stdout"], len(paths))


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("family", ["debian", "alpine"])
def test_ssh_and_agent_print_the_same_records(tmp_path, awk, family):
    base = tmp_path / f"{family}_{awk}"
    root, paths = make_tree(base, family)
    ssh, agent = run_ssh(base, root, paths, awk), run_agent(root, paths)
    math = _awk_has_math(base / f"bin_{awk}")
    for i in range(len(paths)):
        a, s = dict(agent["files"][i]), dict(ssh["files"][i])
        if not math:              # an awk built without log() leaves the entropy unread ("-"), nothing else
            assert s["entropy"] is None
            a.pop("entropy"), s.pop("entropy")
        assert a == s, i
    assert ssh["complete"] and agent["complete"] and ssh["ownership"] == agent["ownership"]


def test_statuses_types_packers_and_package_checksums(tmp_path):
    root, paths = make_tree(tmp_path)
    f = run_agent(root, paths)["files"]
    st = {i: f[i]["status"] for i in f}
    assert st == {0: "ok", 1: "ok", 2: "hardlink", 3: "ok", 4: "not_program", 5: "ok", 6: "missing", 7: "link",
                  8: "hardlink", 9: "not_regular", 10: "ok", 11: "ok", 12: "ok", 13: "ok"}
    assert f[0]["package"] == "login:amd64" and f[0]["pkg_digests"][0]["algo"] == "md5"
    assert f[0]["md5"] == f[0]["pkg_digests"][0]["digest"]          # the md5sums line for su matches
    assert f[1]["md5"] != f[1]["pkg_digests"][0]["digest"]          # `edited` doesn't
    assert f[0]["type"] is None and f[0]["entropy"] is None          # owned files: no content facts
    assert (f[3]["type"], f[3]["packers"]) == ("elf32", ["upx"])
    assert f[5]["type"] == "script" and f[10]["type"] == "other"
    assert f[3]["sha256"] == hashlib.sha256((root / "dev/shm/upx").read_bytes()).hexdigest()
    assert f[3]["sha1"] == hashlib.sha1((root / "dev/shm/upx").read_bytes()).hexdigest()
    assert f[3]["md5"] == hashlib.md5((root / "dev/shm/upx").read_bytes()).hexdigest()   # Debian records MD5s
    assert f[11]["status"] == "ok"                                   # a library name without an execute bit
    assert f[10]["entropy"] > 7.5 and f[5]["entropy"] < 5


def test_rpm_digest_algorithms(tmp_path):
    base = tmp_path
    root, paths = make_tree(base, "rhel")
    su = (root / "usr/bin/su").read_bytes()
    fake_rpm = ("#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *-qa*) printf 'R\\t/usr/bin/su\\tutil-linux\\nR\\t/usr/bin/edited\\tcoreutils\\n' ;;\n"
                "  *FILEDIGESTALGO*util-linux*) echo 8 ;;\n"
                "  *FILEDIGESTALGO*coreutils*) echo ;;\n"
                f"  *FILEDIGESTS*util-linux*) printf '{hashlib.sha256(su).hexdigest().upper()}\\t/usr/bin/su\\n' ;;\n"
                f"  *FILEDIGESTS*coreutils*) printf '{'0' * 32}\\t/usr/bin/edited\\n' ;;\n"
                "esac\n")
    b = _bindir(base, "gawk", {"rpm": fake_rpm})

    def run(argv, timeout, cap):
        r = subprocess.run([str(b / "rpm"), *argv[1:]], capture_output=True, text=True)
        return {"stdout": r.stdout}

    agent = run_agent(root, paths[:2], run=run)
    ssh = run_ssh(base, root, paths[:2], "gawk", {"rpm": fake_rpm})
    assert agent["files"] == ssh["files"]
    assert agent["files"][0]["pkg_digests"] == [{"algo": "sha256", "digest": hashlib.sha256(su).hexdigest()}]
    assert agent["files"][1]["pkg_digests"][0]["algo"] == "md5"     # no algorithm tag: rpm's MD5 default


def test_apk_q1_checksum(tmp_path):
    root, paths = make_tree(tmp_path, "alpine")
    f = run_agent(root, paths[:2])["files"]
    assert F.apk_q1_to_hex(f[0]["pkg_digests"][0]["digest"]) == f[0]["sha1"]


def test_size_caps_and_time_budget(tmp_path):
    root, paths = make_tree(tmp_path)
    big = _w(root, "/tmp/big", b"\x7fELF\x02" + b"z" * (2 * 1024 * 1024), 0o755)
    p = [str(big).encode(), paths[5]]
    f = run_agent(root, p, max_file_bytes=1024 * 1024, run_bytes=1024 * 1024)["files"]
    assert f[0]["status"] == "too_large" and f[0]["size"] == big.stat().st_size and f[1]["status"] == "ok"
    s = run_ssh(tmp_path, root, p, max_file_bytes=1024 * 1024, run_bytes=1024 * 1024)["files"]
    assert s[0]["status"] == "too_large" and s[1]["status"] == "ok"
    # a big file is hashed while the run budget allows
    assert run_agent(root, p, max_file_bytes=1024 * 1024, run_bytes=8 * 1024 * 1024)["files"][0]["status"] == "ok"
    assert all(v["status"] == "time" for v in run_agent(root, p, seconds=0)["files"].values())


def test_paths_must_come_from_snapshots_agent(tmp_path):
    root, paths = make_tree(tmp_path)
    listed = {paths[0]}
    f = run_agent(root, paths[:2], listed=lambda p: p in listed)["files"]
    assert f[0]["status"] == "ok" and f[1]["status"] == "not_listed" and f[1]["sha256"] is None


def test_agent_memory_lists_only_what_its_own_reads_listed(tmp_path):
    from kratos.subagent import reads as RD

    RD._LISTED.clear()
    RD._note_listed("live_inventory", {"stdout": "P\t42\t100\nE\t42\t/opt/x/run (deleted)\n"})
    RD._remember(["/usr/bin/su"], now=1000.0)
    assert RD._listed(b"/usr/bin/su", now=1000.0 + 3600)
    assert not RD._listed(b"/usr/bin/su", now=1000.0 + 25 * 3600)      # a day at most
    assert not RD._listed(b"/etc/passwd")
    out = RD.run_probe("file_facts", {"paths": [base64.b64encode(b"/etc/hostname").decode()]})
    assert out["status"] == "ok" and "\tnot_listed\t" in out["data"]["stdout"]


def test_paths_must_come_from_snapshots_core():
    chosen = [{"path": "/usr/bin/su"}, {"path": "/etc/shadow"}]
    with pytest.raises(FX.NotFromSnapshot):
        FX.build_request(chosen, frozenset({"/usr/bin/su"}))
    sent = []
    facts, skipped, info = FX.read([{"path": "/usr/bin/su"}], frozenset({"/usr/bin/su"}), limits={},
                                   fetch=lambda p, **k: sent.append(p) or {"files": {}, "complete": True})
    assert sent == [[b"/usr/bin/su"]]


def test_agent_probe_validates_its_parameters():
    from kratos.subagent import reads as RD

    for bad in ([], ["not base64!!"], [base64.b64encode(b"relative").decode()],
                [base64.b64encode(b"/a\nb").decode()], [base64.b64encode(b"/a/../etc/shadow").decode()],
                [base64.b64encode(b"/x").decode()] * (F.MAX_PATHS + 1), "/etc/passwd"):
        assert RD.run_probe("file_facts", {"paths": bad})["status"] == "refused"


def test_credential_paths_are_never_read_by_the_agent(tmp_path):
    p = _w(tmp_path, "/home/u/.ssh/id_ed25519", b"secret", 0o755)
    from kratos.subagent.reads import is_credential_path

    out = F.facts_output([str(p).encode()], is_credential=is_credential_path)["stdout"]
    assert "\trefused\t" in out and hashlib.sha256(b"secret").hexdigest() not in out


def test_paths_reach_the_ssh_script_only_on_stdin(tmp_path):
    hostile = b"/tmp/$(touch pwned)`id`;x'\"\x1b[31m"
    script = F.build_script([hostile])
    assert hostile not in script.encode() and b"pwned" not in script.encode()
    assert base64.b64encode(hostile).decode() in script            # base64 inside the script text
    # and fetch_file_facts runs it as `sh -s`, the script on standard input
    import inspect

    from kratos.adapters import ssh_remote
    src = inspect.getsource(ssh_remote.fetch_file_facts)
    assert 'run_remote_script(script, shell="sh"' in src


def test_hostile_path_names(tmp_path):
    root = tmp_path / "r"
    name = "/tmp/‮evil\x1b[2J$(id)'.sh"
    p = _w(root, name, b"#!/bin/sh\n", 0o755)
    raw = str(p).encode()
    for f in (run_agent(root, [raw])["files"][0], run_ssh(tmp_path, root, [raw])["files"][0]):
        assert f["status"] == "ok" and f["type"] == "script"
    with pytest.raises(F.RequestError):
        F.check_path(b"/tmp/a\nb")
    with pytest.raises(F.RequestError):
        F.check_path(b"/tmp/a\x00b")


def test_non_utf8_paths(tmp_path):
    root = tmp_path / "r"
    raw = str(root).encode() + b"/tmp/caf\xe9"
    os.makedirs(os.fsdecode(raw).rsplit("/", 1)[0], exist_ok=True)
    with open(raw, "wb") as fh:
        fh.write(b"\x7fELF\x02x")
    os.chmod(raw, 0o755)
    assert run_agent(root, [raw])["files"][0]["status"] == "ok"
    assert run_ssh(tmp_path, root, [raw])["files"][0]["status"] == "ok"
    # a name that came back from an SSH read with replacement characters is never guessed at
    assert FX.to_bytes(os.fsdecode(raw)) == raw
    assert FX.to_bytes("/tmp/caf�") is None


def test_the_read_never_sends_file_bytes(tmp_path):
    root, paths = make_tree(tmp_path)
    secret = b"KRATOS-CANARY-" + os.urandom(8).hex().encode()
    p = _w(root, "/tmp/canary", b"#!/bin/sh\n" + secret + b"\n", 0o755)
    for out in (F.facts_output([str(p).encode()], root=str(root))["stdout"],
                subprocess.run([str(_bindir(tmp_path, "gawk") / "sh"), "-s"],
                               input=F.build_script([str(p).encode()], root=str(root)), capture_output=True,
                               text=True, env={"PATH": str(tmp_path / "bin_gawk"), "LC_ALL": "C"}).stdout):
        assert secret.decode() not in out and "#!/bin/sh" not in out


def test_proc_exe_of_a_deleted_running_program(tmp_path):
    src = _w(tmp_path, "/bin/sleeper", Path(shutil.which("sleep")).read_bytes(), 0o755)
    proc = subprocess.Popen([str(src), "30"])
    try:
        want = hashlib.sha256(src.read_bytes()).hexdigest()
        src.unlink()
        raw = f"/proc/{proc.pid}/exe".encode()
        f = run_agent(tmp_path, [raw])["files"][0]
        assert f["status"] == "ok" and f["sha256"] == want
        s = run_ssh(tmp_path, tmp_path / "nonexistent-root", [raw])["files"][0]    # our own process: readable
        assert s["status"] == "ok" and s["sha256"] == want
    finally:
        proc.kill()
        proc.wait()


def test_usrmerge_paths_are_read_through_usr(tmp_path):
    root = tmp_path / "r"
    _w(root, "/usr/bin/tool", b"\x7fELF\x02t", 0o755)
    (root / "bin").symlink_to("usr/bin")
    raw = str(root).encode() + b"/bin/tool"
    assert run_agent(root, [raw])["files"][0]["status"] == "ok"
    assert run_ssh(tmp_path, root, [raw])["files"][0]["status"] == "ok"
    # any other link in the path is refused
    (root / "opt").mkdir()
    (root / "opt/lnk").symlink_to(root / "usr/bin")
    raw2 = str(root).encode() + b"/opt/lnk/tool"
    assert run_agent(root, [raw2])["files"][0]["status"] == "link"
    assert run_ssh(tmp_path, root, [raw2])["files"][0]["status"] == "link"



@pytest.mark.parametrize("family", ["debian", "alpine"])
def test_a_copy_of_a_packaged_program_is_found_through_the_package_database(tmp_path, family):
    root, paths = make_tree(tmp_path / family, family)
    for f in (run_agent(root, paths)["files"], run_ssh(tmp_path / family, root, paths)["files"]):
        assert f[12]["package_copy"] == [{"package": "login:amd64" if family == "debian" else "login",
                                          "path": "/usr/bin/su"}]
        assert "package_copy" not in f[0]          # the packaged file itself is owned, not a copy
        assert "package_copy" not in f[2]


def test_rpm_package_copy(tmp_path):
    root, paths = make_tree(tmp_path, "rhel")
    su = (root / "usr/bin/su").read_bytes()
    fake = ("#!/bin/sh\ncase \"$*\" in\n"
            f"  *FILEDIGESTS*NAME*) printf '{hashlib.sha256(su).hexdigest()}\\t/usr/bin/su\\tutil-linux\\n' ;;\n"
            "  *-qa*) : ;;\nesac\n")
    b = _bindir(tmp_path, "gawk", {"rpm": fake})

    def run(argv, timeout, cap):
        return {"stdout": subprocess.run([str(b / "rpm"), *argv[1:]], capture_output=True, text=True).stdout}

    want = [{"package": "util-linux", "path": "/usr/bin/su"}]
    assert run_agent(root, [paths[12]], run=run)["files"][0]["package_copy"] == want
    assert run_ssh(tmp_path, root, [paths[12]], "gawk", {"rpm": fake})["files"][0]["package_copy"] == want


def test_dpkg_configuration_file_checksum(tmp_path):
    root, paths = make_tree(tmp_path)
    for f in (run_agent(root, paths)["files"], run_ssh(tmp_path, root, paths)["files"]):
        assert f[13]["package"] == "svc"
        assert f[13]["pkg_digests"] == [{"algo": "md5c", "digest": f[13]["md5"]}]
