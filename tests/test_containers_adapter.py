"""The container read (D.5, adapters/containers.py): the closed GET-only API client, the
/proc collector on both transports, the per-image package reads and the log chunks."""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import containers as C
from kratos.adapters import packages as P

CID = "a" * 64
CID2 = "b" * 64
IMG = "sha256:" + "c" * 64


# --------------------------------------------------------------------------- the API client
class FakeConn:
    calls: list[tuple[str, str]] = []
    body = b"{}"
    status = 200

    def __init__(self, path, timeout):
        self.path = path

    def request(self, method, path, headers=None):
        FakeConn.calls.append((method, path))

    def getresponse(self):
        outer = self

        class R:
            status = FakeConn.status

            def read(self, n):
                return FakeConn.body[:n]
        return R()

    def close(self):
        pass


@pytest.fixture
def fake_conn(monkeypatch):
    FakeConn.calls, FakeConn.body, FakeConn.status = [], b"{}", 200
    monkeypatch.setattr(C.ApiClient, "connection_class", FakeConn)
    return FakeConn


@pytest.mark.parametrize("path", ["/version", "/info", "/containers/json?all=1", "/networks",
                                  f"/containers/{CID}/json"])
def test_the_closed_path_list_is_allowed(path):
    assert C.allowed_api_path(path)


@pytest.mark.parametrize("path", ["/containers/web/json", f"/containers/{CID[:12]}/json", f"/containers/{CID}/logs",
                                  f"/containers/{CID}/exec", "/images/json", "/containers/json",
                                  "/version?x=1", "/v1.45/version", f"/containers/{CID}/json/../exec", "", None])
def test_anything_else_is_refused_before_connecting(fake_conn, path):
    with pytest.raises(C.ApiError) as e:
        C.ApiClient("/run/x.sock").get(path)
    assert e.value.kind == "refused"
    assert fake_conn.calls == []


def test_only_get_is_ever_sent(fake_conn):
    client = C.ApiClient("/run/x.sock")
    for p in C.FIXED_API_PATHS:
        client.get(p)
    client.get(f"/containers/{CID}/json")
    assert {m for m, _p in fake_conn.calls} == {"GET"}
    # and the source has no other method at all
    src = Path(C.__file__).read_text()
    assert "conn.request(\"GET\"" in src
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        assert f'"{verb}"' not in src


def test_an_oversized_answer_stops_at_the_cap(fake_conn):
    fake_conn.body = b"[" + b"1," * (C.MAX_RESPONSE_BYTES // 2) + b"1]"
    with pytest.raises(C.ApiError) as e:
        C.ApiClient("/run/x.sock").get("/info")
    assert e.value.kind == "too_big"


def test_a_deeply_nested_answer_is_refused(fake_conn):
    fake_conn.body = b"[" * (C.MAX_JSON_DEPTH + 5) + b"]" * (C.MAX_JSON_DEPTH + 5)
    with pytest.raises(C.ApiError) as e:
        C.ApiClient("/run/x.sock").get("/info")
    assert e.value.kind == "too_deep"


def test_the_shared_total_cap_stops_later_calls(fake_conn):
    fake_conn.body = b'{"a": "' + b"x" * 1000 + b'"}'
    budget = [1500]
    client = C.ApiClient("/run/x.sock", budget)
    client.get("/info")                       # 1009 bytes of 1500
    with pytest.raises(C.ApiError) as e:      # only 491 left
        client.get("/info")
    assert e.value.kind == "too_big"
    with pytest.raises(C.ApiError):
        client.get("/info")                   # spent: refused before connecting


# --------------------------------------------------------------------------- engine sockets
def _sock(path: Path) -> socket.socket:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(path))
    return s


def test_a_socket_inside_run_is_accepted(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    s = _sock(run / "docker.sock")
    try:
        real, why = C.socket_path_ok(str(run / "docker.sock"), str(run))
        assert why is None and real == str(run / "docker.sock")
    finally:
        s.close()


def test_a_socket_that_is_a_symlink_out_of_run_is_refused(tmp_path):
    run, elsewhere = tmp_path / "run", tmp_path / "elsewhere"
    run.mkdir()
    elsewhere.mkdir()
    s = _sock(elsewhere / "evil.sock")
    try:
        (run / "docker.sock").symlink_to(elsewhere / "evil.sock")
        real, why = C.socket_path_ok(str(run / "docker.sock"), str(run))
        assert real is None and "symbolic link" in why
        (run / "podman").mkdir()
        os.symlink(str(elsewhere), str(run / "podman" / "linked"))
        real, why = C.socket_path_ok(str(run / "podman" / "linked" / "evil.sock"), str(run))
        assert real is None and "outside" in why
    finally:
        s.close()


def test_a_regular_file_is_not_a_socket_and_absent_is_absent(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "docker.sock").write_text("x")
    assert C.socket_path_ok(str(run / "docker.sock"), str(run))[1].startswith("refused")
    assert C.socket_path_ok(str(run / "podman.sock"), str(run))[1] == "absent"


def test_rootless_sockets_must_belong_to_their_user(tmp_path):
    run = tmp_path / "run"
    (run / "user" / str(os.getuid()) / "podman").mkdir(parents=True)
    s = _sock(run / "user" / str(os.getuid()) / "podman" / "podman.sock")
    try:
        found = C.engine_sockets(str(run))
        assert [(e, real is not None) for e, _c, real, _w in found] == [(f"podman-rootless:{os.getuid()}", True)]
    finally:
        s.close()


# --------------------------------------------------------------------------- distilling
def _inspect(**over):
    raw = {
        "Id": CID, "Name": "/web", "Image": IMG,
        "ImageManifestDescriptor": {"digest": "sha256:" + "d" * 64},
        "State": {"Status": "running", "Running": True, "Pid": 4242, "StartedAt": "2026-11-01T00:00:00Z"},
        "Config": {"Image": "nginx:1.27", "User": "", "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2-not-sent"],
                   "Labels": {"com.docker.compose.project": "demo", "secret.token": "abc-not-sent"}},
        "HostConfig": {"Privileged": False, "CapAdd": None, "NetworkMode": "bridge", "LogConfig": {"Type": "json-file"},
                       "PortBindings": {}},
        "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}], "443/tcp": None},
                            "Networks": {"bridge": {"NetworkID": "e" * 64, "IPAddress": "172.17.0.2"}}},
        "Mounts": [{"Type": "bind", "Source": "/etc", "Destination": "/host-etc", "RW": True}],
    }
    raw.update(over)
    return raw


def test_environment_values_never_leave_the_machine():
    d = C.distill_container(_inspect(), "docker")
    text = json.dumps(d)
    assert d["env_keys"] == ["PATH", "DB_PASSWORD"]
    assert "hunter2" not in text and "/usr/bin" not in text
    assert d["labels"] == {"com.docker.compose.project": "demo", "secret.token": ""}
    assert "abc-not-sent" not in text
    assert d["ports"] == [{"proto": "tcp", "container_port": 80, "host_ip": "0.0.0.0", "host_port": 8080}]
    assert d["mounts"] == [{"type": "bind", "source": "/etc", "destination": "/host-etc", "rw": True}]


def test_a_bad_id_or_shape_is_dropped_and_machine_text_is_one_line():
    assert C.distill_container(_inspect(Id="web"), "docker") is None
    assert C.distill_container("nope", "docker") is None
    d = C.distill_container(_inspect(Name="/we\tb\nx\x1b[31m"), "docker")
    assert "\t" not in d["name"] and "\n" not in d["name"] and "\x1b" not in d["name"]


def test_container_records_round_trip_through_the_parser():
    rec = C._json_record("C", "docker", C.distill_container(_inspect(), "docker"))
    out = C.parse_output("CONTINV\t1\n" + rec + "\nEND\n")
    assert out["complete"] and CID in out["containers"] and out["containers"][CID]["engine"] == "docker"


# --------------------------------------------------------------------------- /proc on both transports
def _fake_proc(root: Path) -> None:
    def proc(pid, cgroup, uid, cap, comm, tcp=None):
        d = root / "proc" / str(pid)
        (d / "net").mkdir(parents=True)
        (d / "cgroup").write_text(cgroup + "\n")
        (d / "status").write_text(f"Name:\t{comm}\nPPid:\t1\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapEff:\t{cap}\n")
        (d / "comm").write_text(comm + "\n")
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        (d / "net" / "tcp").write_text(header + (tcp or ""))
        (d / "net" / "tcp6").write_text(header)
        (d / "net" / "udp").write_text(header)
        (d / "net" / "udp6").write_text(header)
    listen = "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n"
    proc(100, f"0::/system.slice/docker-{CID}.scope", 0, "00000000a80425fb", "nginx", listen)
    proc(101, f"0::/system.slice/docker-{CID}.scope", 101, "0000000000000000", "nginx")
    proc(200, f"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{CID2}.scope/container",
         1000, "000001ffffffffff", "sleep")
    proc(300, "0::/user.slice/user-1000.slice/session-3.scope", 1000, "0", "bash")
    (root / "proc" / "net").mkdir(parents=True)
    (root / "proc" / "net" / "route").write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
    (root / "proc" / "net" / "ipv6_route").write_text("")
    (root / "proc" / "self").mkdir(parents=True)
    (root / "proc" / "self" / "mountinfo").write_text("22 1 0:5 / /proc rw - proc proc rw\n")


def test_the_python_and_shell_collectors_print_the_same_records(tmp_path):
    _fake_proc(tmp_path)
    py = C.parse_output("CONTINV\t1\n" + "\n".join(C.proc_records(str(tmp_path)) + C.route_records(str(tmp_path)))
                        + "\nEND\n")
    script = C.build_script(root=str(tmp_path), firewall=False)
    r = subprocess.run(["sh", "-s"], input=script, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    sh = C.parse_output(r.stdout)
    assert py["procs"] == sh["procs"]
    assert py["listeners"] == sh["listeners"]
    assert py["routes"] == sh["routes"] == {"4": ["eth0"], "6": []}
    assert set(py["procs"]) == {100, 101, 200}                      # the plain shell is no container
    assert py["procs"][200]["engine"] == "podman" and py["procs"][200]["rootless_owner"] == 1000
    assert py["listeners"] == [{"container": CID, "proto": "tcp", "local": "00000000:0050"}]


def test_a_field_the_ssh_login_cannot_read_is_a_gap_not_an_empty_value(tmp_path):
    _fake_proc(tmp_path)
    os.chmod(tmp_path / "proc" / "101" / "status", 0)
    try:
        if os.access(tmp_path / "proc" / "101" / "status", os.R_OK):
            pytest.skip("running as root: permissions don't apply")
        script = C.build_script(root=str(tmp_path), firewall=False)
        out = C.parse_output(subprocess.run(["sh", "-s"], input=script, capture_output=True, text=True).stdout)
        py = C.parse_output("\n".join(C.proc_records(str(tmp_path))))
        assert 101 not in out["procs"] and (101, CID, "status") in out["proc_gaps"]
        assert out["proc_gaps"] == py["proc_gaps"]
    finally:
        os.chmod(tmp_path / "proc" / "101" / "status", 0o644)


def test_the_ssh_script_never_reads_the_engine_api_and_writes_nothing():
    script = C.build_script()
    for word in ("curl", "--unix-socket", "docker ps", "docker inspect", "docker info", "podman ps", "nc -U", "socat"):
        assert word not in script, word
    import re
    redirects = re.findall(r">{1,2}\s*[\"/$~A-Za-z]", script.replace("2>/dev/null", ""))
    assert redirects == []                    # no file is written on the machine (awk's "NR > 1" is no redirect)
    assert "sudo -n" in script and "kr_fw iptables iptables-save" in script


def test_firewall_records_carry_the_listing_and_a_missing_binary_is_stated():
    class ProbeMissing(Exception):
        pass

    def run(argv, timeout, cap):
        if argv[0] == "nft":
            raise ProbeMissing("nft")
        return {"returncode": 0, "stdout": "*filter\n:INPUT DROP [0:0]\nCOMMIT\n", "truncated": False}
    out = C.parse_output("\n".join(C.firewall_records(run)))
    assert out["firewall"]["iptables"]["status"] == "ok" and ":INPUT DROP" in out["firewall"]["iptables"]["text"]
    assert out["firewall"]["nft"]["status"] == "missing"


# --------------------------------------------------------------------------- packages inside images
def _rpm_blob(name: str, version: str, release: str, arch: str, srpm: str) -> bytes:
    entries, store = [], b""
    for tag, val in ((1000, name), (1001, version), (1002, release), (1022, arch), (1044, srpm)):
        entries.append((tag, 6, len(store), 1))
        store += val.encode() + b"\x00"
    head = len(entries).to_bytes(4, "big") + len(store).to_bytes(4, "big")
    for tag, typ, off, cnt in entries:
        head += tag.to_bytes(4, "big") + typ.to_bytes(4, "big") + off.to_bytes(4, "big") + cnt.to_bytes(4, "big")
    return head + store


def _image_root(root: Path, kind: str) -> None:
    (root / "etc").mkdir(parents=True)
    if kind == "deb":
        (root / "etc" / "os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian 12"\n')
        (root / "var/lib/dpkg").mkdir(parents=True)
        (root / "var/lib/dpkg/status").write_text(
            "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl (3.0.11-1)\n"
            "Version: 3.0.11-1\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n")
    elif kind == "distroless_debs":
        (root / "etc" / "os-release").write_text('ID=debian\nVERSION_ID="12"\n')
        (root / "var/lib/dpkg/status.d").mkdir(parents=True)
        (root / "var/lib/dpkg/status.d/base").write_text("Package: base-files\nVersion: 12.4\nArchitecture: amd64\n")
    elif kind == "apk":
        (root / "etc" / "os-release").write_text("ID=alpine\nVERSION_ID=3.20.3\n")
        (root / "lib/apk/db").mkdir(parents=True)
        (root / "lib/apk/db/installed").write_text("P:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\nP:busybox\nV:1.36\nA:x86_64\n\n")
    elif kind == "rpm":
        (root / "etc" / "os-release").write_text('ID="rocky"\nVERSION_ID="9.4"\n')
        (root / "var/lib/rpm").mkdir(parents=True)
        db = sqlite3.connect(root / "var/lib/rpm/rpmdb.sqlite")
        db.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)")
        db.execute("INSERT INTO Packages (blob) VALUES (?)", (_rpm_blob("openssl", "3.0.7", "27.el9", "x86_64",
                                                                         "openssl-3.0.7-27.el9.src.rpm"),))
        db.commit()
        db.close()


@pytest.mark.parametrize("kind,manager,names", [
    ("deb", "dpkg", ["libssl3"]), ("distroless_debs", "dpkg", ["base-files"]),
    ("apk", "apk", ["musl", "busybox"]), ("rpm", "rpm", ["openssl"])])
def test_each_package_database_inside_an_image_reads_like_the_host_read(tmp_path, kind, manager, names):
    _image_root(tmp_path / "r", kind)
    fd = os.open(tmp_path / "r", os.O_RDONLY)
    try:
        lines, status = C.image_package_lines(fd)
    finally:
        os.close(fd)
    inv = P.parse_output("\n".join(lines))
    assert status == "ok" and inv["complete"] and inv["managers"] == {manager: "ok"}
    assert [p["name"] for p in inv["packages"]] == names
    if kind == "deb":
        assert inv["packages"][0]["source"] == "openssl" and inv["packages"][0]["source_version"] == "3.0.11-1"
    if kind == "rpm":
        assert inv["packages"][0]["version"] == "0:3.0.7-27.el9" and inv["packages"][0]["source"] == "openssl"


def test_a_link_escaping_the_container_root_is_refused(tmp_path):
    outside = tmp_path / "host"
    (outside / "var/lib/dpkg").mkdir(parents=True)
    (outside / "var/lib/dpkg/status").write_text("Package: host-secret\nVersion: 1\nStatus: install ok installed\n")
    root = tmp_path / "r"
    (root / "var/lib").mkdir(parents=True)
    (root / "var/lib/dpkg").symlink_to(outside / "var/lib/dpkg")
    (root / "etc").mkdir()
    (root / "etc" / "os-release").symlink_to("/etc/os-release")
    fd = os.open(root, os.O_RDONLY)
    try:
        with pytest.raises(C.RootRefused) as e:
            C.read_in_root(fd, "var/lib/dpkg/status")
        assert e.value.status == "symlink"
        lines, status = C.image_package_lines(fd)
    finally:
        os.close(fd)
    assert status == "no_db" and "host-secret" not in "\n".join(lines)
    assert not any(ln.startswith("OS\t") for ln in lines)       # the linked os-release was not followed either


def test_a_static_image_has_no_package_database(tmp_path):
    (tmp_path / "r").mkdir()
    fd = os.open(tmp_path / "r", os.O_RDONLY)
    try:
        assert C.image_package_lines(fd)[1] == "no_db"
    finally:
        os.close(fd)


class FakeClient:
    def __init__(self, listing, inspects):
        self.listing, self.inspects = listing, inspects

    def get(self, path):
        assert C.allowed_api_path(path)
        if path == "/containers/json?all=1":
            return self.listing
        if path == "/info":
            return {"DockerRootDir": "/var/lib/docker"}
        cid = path.split("/")[2]
        return self.inspects[cid]


def test_one_image_is_read_once_however_many_containers_run_it(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    s = _sock(run / "docker.sock")
    proc = tmp_path / "proc"
    _image_root(tmp_path / "img", "apk")
    for pid in (11, 12):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "root").symlink_to(tmp_path / "img")
    listing = [{"Id": CID, "State": "running", "ImageID": IMG}, {"Id": CID2, "State": "running", "ImageID": IMG},
               {"Id": "f" * 64, "State": "exited", "ImageID": "sha256:" + "9" * 64}]
    inspects = {CID: _inspect(State={"Running": True, "Pid": 11}), CID2: _inspect(Id=CID2, State={"Running": True, "Pid": 12})}
    opened = []
    real_open_root = C.open_root

    def counting_open_root(pid, proc_dir="/proc"):
        opened.append(pid)
        return real_open_root(pid, proc_dir)
    monkeypatch.setattr(C, "open_root", counting_open_root)
    try:
        out = C.packages_output(deadline=1e18, run_root=str(run), proc=str(proc),
                                client_factory=lambda p, b: FakeClient(listing, inspects))
    finally:
        s.close()
    parsed = C.parse_packages_output(out["stdout"])
    assert list(parsed["images"]) == [IMG] and len(opened) == 1 and parsed["complete"]
    assert [p["name"] for p in parsed["images"][IMG]["inventory"]["packages"]] == ["musl", "busybox"]


# --------------------------------------------------------------------------- container log chunks
def _log_setup(tmp_path, driver="json-file"):
    root = tmp_path / "docker"
    d = root / "containers" / CID
    d.mkdir(parents=True)
    path = d / f"{CID}-json.log"
    insp = _inspect(LogPath=str(path), HostConfig={"LogConfig": {"Type": driver}})
    client = FakeClient([], {CID: insp})
    client.get = (lambda p, _c=client: {"DockerRootDir": str(root)} if p == "/info" else _c.inspects[CID])
    run = tmp_path / "run"
    run.mkdir()
    s = _sock(run / "docker.sock")
    return path, client, run, s


def _opener(path):
    fd = os.open(path, os.O_RDONLY)
    return fd, os.fstat(fd)


def test_a_log_chunk_reads_whole_lines_from_a_position(tmp_path):
    path, client, run, s = _log_setup(tmp_path)
    try:
        lines = [json.dumps({"log": f"line {i}\n", "stream": "stdout", "time": "2026-11-02T00:00:0%dZ" % i}) for i in range(3)]
        path.write_text("\n".join(lines) + "\n" + '{"log":"partial')
        out = C.parse_log_output(C.container_log_output(CID, None, 0, run_root=str(run), opener=_opener,
                                                        client_factory=lambda p, b: client)["stdout"])
        f0 = out["files"][0]
        assert f0["status"] == "read" and f0["start"] == 0 and len(out["lines"]) == 3
        assert f0["consumed"] == len("\n".join(lines)) + 1            # the partial line is left for next time
        again = C.parse_log_output(C.container_log_output(CID, f0["inode"], f0["consumed"], run_root=str(run),
                                                          opener=_opener, client_factory=lambda p, b: client)["stdout"])
        assert again["lines"] == [] and again["files"][0]["consumed"] == 0
    finally:
        s.close()


def test_a_rotated_log_is_finished_from_its_dot_one_file(tmp_path):
    path, client, run, s = _log_setup(tmp_path)
    try:
        path.write_text('{"log":"old 1\\n","stream":"stdout","time":"2026-11-02T00:00:01Z"}\n')
        first = C.parse_log_output(C.container_log_output(CID, None, 0, run_root=str(run), opener=_opener,
                                                          client_factory=lambda p, b: client)["stdout"])
        inode, off = first["files"][0]["inode"], first["files"][0]["consumed"]
        with path.open("a") as fh:
            fh.write('{"log":"old 2\\n","stream":"stdout","time":"2026-11-02T00:00:02Z"}\n')
        os.rename(path, str(path) + ".1")
        path.write_text('{"log":"new 1\\n","stream":"stdout","time":"2026-11-02T00:00:03Z"}\n')
        out = C.parse_log_output(C.container_log_output(CID, inode, off, run_root=str(run), opener=_opener,
                                                        client_factory=lambda p, b: client)["stdout"])
        assert [f["slot"] for f in out["files"]] == [1, 0] and out["files"][1]["status"] == "current"
        assert ["old 2" in raw for _f, raw in out["lines"]] == [True]
    finally:
        s.close()


def test_an_unexpected_log_path_or_driver_is_not_read(tmp_path):
    path, client, run, s = _log_setup(tmp_path)
    try:
        client.inspects[CID]["LogPath"] = "/etc/shadow"
        out = C.parse_log_output(C.container_log_output(CID, None, 0, run_root=str(run), opener=_opener,
                                                        client_factory=lambda p, b: client)["stdout"])
        assert out["files"][0]["status"] == "unsupported" and out["lines"] == []
        client.inspects[CID]["HostConfig"] = {"LogConfig": {"Type": "local"}}
        out = C.parse_log_output(C.container_log_output(CID, None, 0, run_root=str(run), opener=_opener,
                                                        client_factory=lambda p, b: client)["stdout"])
        assert "binary format" in out["files"][0]["note"]
    finally:
        s.close()


def test_a_removed_container_is_gone_and_a_bad_id_is_refused(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    assert C.parse_log_output(C.container_log_output(CID, None, 0, run_root=str(run))["stdout"])["files"][0]["status"] == "gone"
    assert C.parse_log_output(C.container_log_output("web", None, 0)["stdout"])["files"][0]["status"] == "refused"


# --------------------------------------------------------------------------- security review
def test_a_fifo_or_device_under_a_package_database_name_is_never_opened(tmp_path, monkeypatch):
    root = tmp_path / "r"
    (root / "var/lib/dpkg").mkdir(parents=True)
    os.mkfifo(root / "var/lib/dpkg/status")           # opening a FIFO for reading would block / could signal
    opened = []
    real_open = os.open

    def spy(path, flags, *a, **k):
        opened.append(str(path))
        return real_open(path, flags, *a, **k)
    fd = real_open(root, os.O_RDONLY)
    monkeypatch.setattr(os, "open", spy)
    try:
        with pytest.raises(C.RootRefused) as e:
            C.read_in_root(fd, "var/lib/dpkg/status")
    finally:
        monkeypatch.setattr(os, "open", real_open)
        os.close(fd)
    assert e.value.status == "not_regular" and "status" not in opened     # refused before any open()


def test_tabs_in_a_containers_package_files_cannot_shift_record_fields():
    recs = C.dpkg_records("Package: evil\tD\tinjected\nStatus: install ok installed\nVersion: 1\tx\n")
    assert len(recs) == 1 and recs[0].count("\t") == 6
    assert C.apk_records("P:musl\tA\tfake\nV:1\n\n")[0].count("\t") == 4
