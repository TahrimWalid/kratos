"""The live-response check (A.5): the /proc read two ways (a POSIX sh+awk script
over SSH as the SSH user, a stdlib walk as root through the sub-agent) that print
the SAME records; one parser; judging on Kratos; LIVE-* findings with
process-identity entities and ATT&CK v19 labels. Reads use fake /proc trees under
tmp_path -- no real SSH -- and run the real generated script under every awk
available (mawk/gawk/BusyBox)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import live_response as L
from kratos.live import record
from kratos.live.judge import judge
from tests._logsources_util import awks

AWKS = awks()
pytestmark = pytest.mark.skipif(not AWKS, reason="no awk available")

_OSREL = {"debian": "ID=ubuntu\nID_LIKE=debian\n", "rhel": "ID=rocky\nID_LIKE=\"rhel fedora\"\n", "alpine": "ID=alpine\n"}


# ---------------------------------------------------------------- fake /proc trees
def _w(path: Path, data, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def _link(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        path.unlink()
    path.symlink_to(target)


def mkproc(root: Path, pid: int, comm: str, exe: str, cmdline: bytes, *, ppid: int = 1,
           start: int = 100, environ: bytes = b"PATH=/usr/bin\x00", cwd: str = "/root",
           cgroup: str = "0::/system.slice/x.service", sockets: dict[str, int] | None = None) -> None:
    d = root / "proc" / str(pid)
    fields = [str(pid), f"({comm})", "S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 20
    _w(d / "stat", " ".join(fields))
    _link(d / "exe", exe)
    _w(d / "comm", comm + "\n")
    _w(d / "cmdline", cmdline)
    _w(d / "environ", environ)
    _link(d / "cwd", cwd)
    _w(d / "cgroup", cgroup + "\n")
    (d / "fd").mkdir(parents=True, exist_ok=True)
    for fd, inode in (sockets or {}).items():
        _link(d / "fd" / fd, f"socket:[{inode}]")


def make_machine(tmp_path: Path, family: str = "debian", *, name: str = "root",
                 owned: dict[str, str] | None = None) -> Path:
    r = tmp_path / name
    _w(r / "etc/os-release", _OSREL[family])
    (r / "proc").mkdir(parents=True, exist_ok=True)
    owned = owned or {}
    if family == "debian":
        lists: dict[str, list[str]] = {}
        for path, pkg in owned.items():
            lists.setdefault(pkg, []).append(path)
        for pkg, paths in lists.items():
            _w(r / f"var/lib/dpkg/info/{pkg}.list", "\n".join(paths) + "\n")
        (r / "var/lib/dpkg/info").mkdir(parents=True, exist_ok=True)
    return r


def net_table(entries: list[tuple[str, int, str]]) -> str:
    """entries: (local_addr_hex, port, state_hex) -> a /proc/net/tcp body (header + rows)."""
    head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    rows = []
    for i, (addr, port, st) in enumerate(entries):
        inode = 50 + i
        rows.append(f"   {i}: {addr}:{port:04X} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000 0 0 {inode} 1 x")
    return head + "\n".join(rows) + "\n"


def _bindir(tmp_path: Path, awk: str) -> Path:
    b = tmp_path / f"bin_{awk}"
    if b.exists():
        return b
    b.mkdir()
    tools = ("sh", "sed", "tr", "cat", "readlink", "head", "stat", "grep", "sha256sum", "cut", "sort", "wc",
             "echo", "printf", "mkdir", "find", "id", "uname", "xargs", "date", "env", "timeout", "dd", "od", "true")
    for tool in tools:
        src = shutil.which(tool)
        if src:
            os.symlink(src, b / tool)
    bb = os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
    os.symlink(bb if awk == "busybox" else shutil.which(awk), b / "awk")
    return b


def run_ssh(tmp_path: Path, root: Path, awk: str = "gawk") -> dict:
    b = _bindir(tmp_path, awk)
    script = L.build_script(root=str(root))
    r = subprocess.run([str(b / "sh"), "-s"], input=script, capture_output=True, text=True,
                       env={"PATH": str(b), "LC_ALL": "C"}, timeout=90)
    assert r.returncode == 0, r.stderr
    return L.parse_output(r.stdout, root=str(root))


def run_agent(root: Path) -> dict:
    def run(argv, timeout, cap):
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"stdout": res.stdout}
    out = L.inventory_output(root=str(root), run=run)
    return L.parse_output(out["stdout"], root=str(root))


def _planted(tmp_path: Path, family: str = "debian", name: str = "root") -> Path:
    r = make_machine(tmp_path, family, name=name, owned={"/usr/bin/sleep": "coreutils", "/bin/sleep": "coreutils"})
    _w(r / "usr/bin/sleep", b"\x7fELFxxxx", 0o755)
    mkproc(r, 1000, "sleep", str(r) + "/usr/bin/sleep", b"sleep\x00600\x00", start=100)        # clean
    mkproc(r, 2000, "svc", str(r) + "/opt/app/svc (deleted)", b"/opt/app/svc\x00", start=200,  # LIVE-001+003+005
           environ=b"LD_PRELOAD=/opt/evil.so\x00PATH=/bin\x00", sockets={"3": 50})
    mkproc(r, 3000, "py", "/memfd:stage (deleted)", b"python3\x00", start=300)                 # LIVE-002
    mkproc(r, 4000, "sleep", str(r) + "/usr/bin/sleep (deleted)", b"sleep\x00", start=400)      # restart hint
    _w(r / "proc/net/tcp", net_table([("00000000", 0x1F90, "0A")]))        # inode 50 listening
    _w(r / "tmp/.x", b"\x7fELFdrop", 0o755)                                # LIVE-004 present
    _w(r / "dev/shm/run.sh", b"#!/bin/sh\necho hi\n", 0o755)               # LIVE-004 present
    return r


# ---------------------------------------------------------------- read + parity
@pytest.mark.parametrize("awk", AWKS)
def test_ssh_and_agent_print_the_same_records(tmp_path, awk):
    r = _planted(tmp_path / awk)
    ssh = run_ssh(tmp_path / awk, r, awk)
    agent = run_agent(r)
    for key in ("procs", "sockets", "temp_files", "ownership", "exists_again", "proc_gaps"):
        assert ssh[key] == agent[key], key
    assert ssh["complete"] and agent["complete"]


@pytest.mark.parametrize("awk", AWKS)
def test_ssh_reads_every_marker(tmp_path, awk):
    r = _planted(tmp_path / awk)
    inv = run_ssh(tmp_path / awk, r, awk)
    assert inv["procs"][2000]["exe"] == "/opt/app/svc (deleted)"
    assert inv["procs"][3000]["exe"] == "/memfd:stage (deleted)"
    assert inv["procs"][2000]["ld"] == {"LD_PRELOAD": "/opt/evil.so"}
    assert inv["procs"][1000]["exe_package"] == "coreutils"
    assert inv["procs"][4000]["exe_exists"] and inv["procs"][4000]["exe_package"] == "coreutils"
    assert any(s["inode"] == 50 and s["pid"] == 2000 for s in inv["sockets"])
    assert set(inv["temp_files"]) == {"/tmp/.x", "/dev/shm/run.sh"}
    assert inv["temp_files"]["/tmp/.x"]["header"] == "elf"
    assert inv["temp_files"]["/dev/shm/run.sh"]["header"] == "script"


# ---------------------------------------------------------------- awk programs under three awks
@pytest.mark.parametrize("awk", AWKS)
def test_awk_stat_under_three_awks(tmp_path, awk):
    b = _bindir(tmp_path, awk)
    # pid (comm with (parens)) state ppid ...; starttime is overall field 22 (777 here).
    stat_line = "4242 (a program (with) parens) S 99" + " 0" * 17 + " 777 0 0\n"
    out = subprocess.run([str(b / "awk"), L.AWK_STAT], input=stat_line, capture_output=True, text=True,
                         env={"PATH": str(b), "LC_ALL": "C"}).stdout
    assert out.strip() == "PP\t4242\t99\t777"


@pytest.mark.parametrize("awk", AWKS)
def test_awk_net_under_three_awks(tmp_path, awk):
    b = _bindir(tmp_path, awk)
    body = net_table([("0100007F", 8080, "0A")])
    out = subprocess.run([str(b / "awk"), "-v", "proto=tcp", L.AWK_NET], input=body, capture_output=True, text=True,
                         env={"PATH": str(b), "LC_ALL": "C"}).stdout
    assert out.strip() == "NET\ttcp\t0100007F:1F90\t00000000:0000\t0A\t50"


# ---------------------------------------------------------------- caps
def test_cmdline_is_capped_and_cleaned(tmp_path):
    r = make_machine(tmp_path)
    mkproc(r, 7, "x", "/bin/x", (b"A" * 1000 + b"\x00" + b"B" * 10), start=5)
    inv = run_agent(r)
    assert len(inv["procs"][7]["cmdline"]) <= L.MAX_CMDLINE_CHARS
    assert "\t" not in inv["procs"][7]["cmdline"] and "\n" not in inv["procs"][7]["cmdline"]


# ---------------------------------------------------------------- the rules
def _inv(procs=None, sockets=None, temp=None, ownership=None, complete=True, **extra):
    base = {"family": "debian", "now": 1, "reader_uid": 0, "procs": {}, "sockets": [], "temp_files": {},
            "ownership": ownership or {"source": "dpkg", "error": None}, "exists_again": [],
            "proc_gaps": {}, "temp_timeouts": [], "truncated": [], "complete": complete}
    base.update(extra)
    if procs:
        base["procs"] = {p["pid"]: p for p in procs}
    base["sockets"] = sockets or []
    base["temp_files"] = temp or {}
    return base


def _rules(j) -> set[str]:
    return {s.rule for s in j.signals}


def test_live001_deleted_binary(tmp_path):
    j = judge(_inv(procs=[{"pid": 9, "exe": "/opt/x (deleted)", "exe_exists": False, "exe_package": None,
                           "comm": "x", "starttime": 10}]))
    s = [x for x in j.signals if x.rule == "LIVE-001"][0]
    assert s.severity == "high" and s.entities == ["/opt/x (deleted)|9|10"]
    assert s.attack[0]["technique_id"] == "T1070.004"


def test_upgrade_deleted_binary_is_a_restart_hint_not_live001(tmp_path):
    j = judge(_inv(procs=[{"pid": 9, "exe": "/usr/bin/sleep (deleted)", "exe_exists": True,
                           "exe_package": "coreutils", "comm": "sleep", "starttime": 10}]))
    assert "LIVE-001" not in _rules(j)
    note = [x for x in j.signals if x.rule == "LIVE-007"][0]
    assert any("package update replaced" in ln for ln in note.evidence)


def test_live002_memfd(tmp_path):
    j = judge(_inv(procs=[{"pid": 5, "exe": "/memfd:x (deleted)", "comm": "m", "starttime": 2}]))
    s = [x for x in j.signals if x.rule == "LIVE-002"][0]
    assert s.severity == "high" and s.attack[0]["technique_id"] == "T1620"


def test_live002_deleted_in_tmp(tmp_path):
    j = judge(_inv(procs=[{"pid": 6, "exe": "/dev/shm/p (deleted)", "exe_exists": False, "exe_package": None,
                           "comm": "p", "starttime": 3}]))
    assert "LIVE-002" in _rules(j) and "LIVE-001" not in _rules(j)


def test_live003_preload_unowned_high_owned_low(tmp_path):
    hi = judge(_inv(procs=[{"pid": 1, "exe": "/bin/a", "ld": {"LD_PRELOAD": "/opt/e.so"},
                            "preload_packages": {"/opt/e.so": None}, "comm": "a", "starttime": 1}]))
    s = [x for x in hi.signals if x.rule == "LIVE-003"][0]
    assert s.severity == "high" and s.attack[0]["technique_id"] == "T1574.006"
    lo = judge(_inv(procs=[{"pid": 2, "exe": "/bin/b", "ld": {"LD_AUDIT": "/usr/lib/x.so"},
                            "preload_packages": {"/usr/lib/x.so": "libx"}, "comm": "b", "starttime": 1}]))
    assert [x for x in lo.signals if x.rule == "LIVE-003"][0].severity == "low"


def test_live004_running_high_present_medium(tmp_path):
    running = judge(_inv(procs=[{"pid": 1, "exe": "/tmp/.x", "comm": "x", "starttime": 1}],
                         temp={"/tmp/.x": {"path": "/tmp/.x", "header": "elf", "perm": "755", "owner": "ubuntu",
                                           "sha256": "a" * 64}}))
    assert [x for x in running.signals if x.rule == "LIVE-004"][0].severity == "high"
    present = judge(_inv(temp={"/var/tmp/y": {"path": "/var/tmp/y", "header": "script", "perm": "755",
                                              "owner": "root", "sha256": "b" * 64}}))
    s = [x for x in present.signals if x.rule == "LIVE-004"][0]
    assert s.severity == "medium" and s.entities == ["/var/tmp/y#bbbbbbbbbbbb"]
    assert s.attack == []


def test_live005_listener_from_suspicious_process(tmp_path):
    j = judge(_inv(procs=[{"pid": 2, "exe": "/tmp/bd", "exe_package": None, "comm": "bd", "starttime": 9}],
                   sockets=[{"proto": "tcp", "state": "0A", "inode": 1, "pid": 2, "local_addr": "00000000",
                             "local_port": 4444}]))
    s = [x for x in j.signals if x.rule == "LIVE-005"][0]
    assert s.severity == "high" and s.entities == ["/tmp/bd|2|9"]


def test_live005_ignores_a_normal_listener(tmp_path):
    j = judge(_inv(procs=[{"pid": 2, "exe": "/usr/sbin/sshd", "exe_package": "openssh-server", "comm": "sshd",
                           "starttime": 9}],
                   sockets=[{"proto": "tcp", "state": "0A", "inode": 1, "pid": 2, "local_addr": "00000000",
                             "local_port": 22}]))
    assert "LIVE-005" not in _rules(j)


def test_live006_shell_under_web_server(tmp_path):
    j = judge(_inv(procs=[
        {"pid": 10, "exe": "/usr/sbin/nginx", "comm": "nginx", "starttime": 1, "ppid": 1},
        {"pid": 11, "exe": "/bin/bash", "comm": "bash", "starttime": 2, "ppid": 10, "cmdline": "bash -i"}]))
    s = [x for x in j.signals if x.rule == "LIVE-006"][0]
    assert s.severity == "medium"
    ids = {a["technique_id"] for a in s.attack}
    assert ids == {"T1059.004", "T1505.003"}


def test_live006_ignores_a_shell_under_a_normal_parent(tmp_path):
    j = judge(_inv(procs=[
        {"pid": 10, "exe": "/lib/systemd/systemd", "comm": "systemd", "starttime": 1, "ppid": 1},
        {"pid": 11, "exe": "/bin/bash", "comm": "bash", "starttime": 2, "ppid": 10}]))
    assert "LIVE-006" not in _rules(j)


# ---------------------------------------------------------------- identity
def test_reused_pid_with_a_new_start_time_is_a_new_entity(tmp_path):
    a = judge(_inv(procs=[{"pid": 9, "exe": "/opt/x (deleted)", "exe_exists": False, "comm": "x", "starttime": 10}]))
    b = judge(_inv(procs=[{"pid": 9, "exe": "/opt/x (deleted)", "exe_exists": False, "comm": "x", "starttime": 77}]))
    ea = [s for s in a.signals if s.rule == "LIVE-001"][0].entities
    eb = [s for s in b.signals if s.rule == "LIVE-001"][0].entities
    assert ea == ["/opt/x (deleted)|9|10"] and eb == ["/opt/x (deleted)|9|77"] and ea != eb


def test_same_process_across_runs_is_the_same_entity(tmp_path):
    p = {"pid": 9, "exe": "/opt/x (deleted)", "exe_exists": False, "comm": "x", "starttime": 10}
    a = judge(_inv(procs=[dict(p)]))
    b = judge(_inv(procs=[dict(p)]))
    assert [s for s in a.signals if s.rule == "LIVE-001"][0].entities == \
           [s for s in b.signals if s.rule == "LIVE-001"][0].entities


# ---------------------------------------------------------------- gaps + safety
def test_non_root_ssh_user_reports_a_coverage_gap_with_the_agent_fix(tmp_path):
    j = judge(_inv(reader_uid=1000, proc_gaps={"exe": 3, "environ": 3}))
    note = [s for s in j.signals if s.rule == "LIVE-007"][0]
    text = " ".join(note.evidence)
    assert "could not read" in text and "sub-agent" in text and "uid 1000" in text


def test_only_preload_values_leave_the_machine(tmp_path):
    """The read sends LD_PRELOAD/LD_AUDIT values and LD_LIBRARY_PATH presence only --
    no other environment variable's value."""
    r = make_machine(tmp_path)
    mkproc(r, 8, "x", str(r) + "/bin/x", b"x\x00", start=1,
           environ=b"SECRET=topsecret\x00LD_PRELOAD=/e.so\x00LD_LIBRARY_PATH=/opt/lib\x00AWS_KEY=zzz\x00")
    out = L.inventory_output(root=str(r), run=lambda a, t, c: {"stdout": subprocess.run(a, capture_output=True, text=True, timeout=t).stdout})
    assert "topsecret" not in out["stdout"] and "AWS_KEY" not in out["stdout"] and "zzz" not in out["stdout"]
    inv = L.parse_output(out["stdout"], root=str(r))
    assert inv["procs"][8]["ld"] == {"LD_PRELOAD": "/e.so", "LD_LIBRARY_PATH": "(set)"}


def test_a4_corpus_cmdlines_render_and_frame_safely(tmp_path):
    from kratos import untrusted
    corpus = json.loads((Path(__file__).parent / "fixtures" / "untrusted" / "corpus.json").read_text())
    procs = []
    for i, (name, payload) in enumerate(corpus.items(), start=100):
        procs.append({"pid": i, "exe": f"/tmp/{name}", "comm": name, "starttime": i,
                      "cmdline": payload, "exe_package": None})
    j = judge(_inv(procs=procs))
    for s in j.signals:
        for line in s.evidence:
            safe = untrusted.for_display(line)
            assert "\x1b" not in safe and "\x9b" not in safe and "\x08" not in safe


# ---------------------------------------------------------------- findings engine + loader
def test_live_response_findings_from_a_snapshot(tmp_path):
    from kratos.adapters import findings_engine as FE
    doc = {"target": "10.0.0.5", "checked_at": "2026-10-14T00:00:00Z", "via": "ssh", "reader_uid": 0,
           "coverage_gaps": ["3 could not read exe. Read this machine through its sub-agent"],
           "signals": [{"rule": "LIVE-002", "severity": "high", "title": "a memfd process",
                        "evidence": ["pid 5"], "recommendation": ["look"], "entities": ["/memfd:x|5|2"],
                        "attack": [{"technique_id": "T1620"}]}]}
    out = FE._live_response_findings(doc)
    assert [f.id for f in out] == ["LIVE-002"]
    assert out[0].severity == "high" and out[0].entities == ["/memfd:x|5|2"]
    assert any("sub-agent" in e or "LIVE-007" in e for e in out[0].evidence)


def test_loader_drops_a_stale_live_snapshot(tmp_path):
    from kratos.adapters import findings_engine as FE
    fresh = tmp_path / "fresh.json"
    old = tmp_path / "old.json"
    fresh.write_text(json.dumps({"target": "t", "checked_at": "2026-10-14T00:00:00Z", "signals": [],
                                 "checked_at_epoch": __import__("time").time()}))
    old.write_text(json.dumps({"target": "t", "checked_at": "2000-01-01T00:00:00Z", "signals": [],
                               "checked_at_epoch": 946684800.0}))
    assert FE._load_recent_live(fresh) is not None
    assert FE._load_recent_live(old) is None


# ---------------------------------------------------------------- record + check
def test_record_saves_a_snapshot_and_a_failed_read_saves_nothing(tmp_path):
    r = _planted(tmp_path)
    inv = L.parse_output(L.inventory_output(root=str(r), run=lambda a, t, c: {"stdout": subprocess.run(a, capture_output=True, text=True, timeout=t).stdout})["stdout"], root=str(r))
    doc = record.run(tmp_path, "10.0.0.9", reader=lambda: inv)
    assert doc["status"] == "ok" and Path(doc["file"]).exists()
    assert {"LIVE-001", "LIVE-002", "LIVE-003", "LIVE-005", "LIVE-004"} <= {s["rule"] for s in doc["signals"]}

    from kratos.adapters.ssh_remote import SSHResult
    fail = record.run(tmp_path, "10.0.0.9", reader=lambda: SSHResult(ok=False, returncode=1, stdout="", stderr="nope"))
    assert fail["status"] == "error" and "nope" in fail["observation"]


def test_the_check_is_registered_quick_and_runs(tmp_path):
    import kratos.collect.checks  # noqa: F401 -- registers checks
    from kratos.collect.registry import get, CheckContext

    chk = get("live_response")
    assert chk is not None and chk.cost == "quick" and chk.inputs == ("live_response",)
    r = _planted(tmp_path)
    inv = L.parse_output(L.inventory_output(root=str(r), run=lambda a, t, c: {"stdout": subprocess.run(a, capture_output=True, text=True, timeout=t).stdout})["stdout"], root=str(r))
    import kratos.live.record as rec
    orig = rec._default_reader
    rec._default_reader = lambda: inv
    try:
        ctx = CheckContext(target="10.0.0.9", target_key="10.0.0.9", data_dir=tmp_path, transport="ssh",
                           dispatch=lambda *a, **k: {}, deadline=0.0, now=0.0)
        res = chk.run(ctx)
    finally:
        rec._default_reader = orig
    assert res.status in ("ok", "partial") and "running process" in res.summary


# ---------------------------------------------------------------- no writes on the target
def test_the_ssh_script_writes_nothing_on_the_target():
    s = L.build_script()
    for forbidden in (">>", "tee ", "mktemp", "touch ", " dd ", "> /", "of=", "--cursor-file"):
        assert forbidden not in s, forbidden


# ---------------------------------------------------------------- guard 3 still fires
def test_guard3_rejects_a_clean_verdict_over_a_high_live_finding(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos import kratos_config
    from tests.test_agent_loop_guards import ScriptedChat, _final_json, _tool_json

    finding = {"id": "LIVE-002", "title": "a process is running from memory", "severity": "high",
               "evidence": ["pid 5"], "recommendation": ["look"], "entities": ["/memfd:x|5|2"]}

    def correlate(**kwargs):
        return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
                "input_errors": {}, "staleness_warning": None, "findings": [finding], "count": 1}
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", correlate)
    kratos_config.set_active_target("10.136.28.168")
    answer = "Nothing is running that looks suspicious -- the system looks clean."
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(answer), _final_json(answer), _final_json(answer)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("is anything malicious running on this box?", tmp_path, max_iters=10)
    assert any("dismissive_verdict_contradiction" in s.get("violations", [])
               for s in result["transcript"] if s.get("status") == "final_answer_rejected")
