"""D.3: the loaded-libraries read of listening processes and the machine's own
addresses -- printed the same by the SSH script (every awk) and the agent's walk,
read by one parser; older agents say they didn't look (no `maps` marker)."""
from __future__ import annotations

import pytest

from kratos.adapters import live_response as L
from kratos.live import record
from tests.test_live_response import AWKS, _w, make_machine, mkproc, net_table, run_agent, run_ssh

pytestmark = pytest.mark.skipif(not AWKS, reason="no awk available")

LIBSSL = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     |-- 203.0.113.7
        /32 host LOCAL
Local:
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.1
        /32 host LOCAL
     |-- 203.0.113.7
        /32 host LOCAL
"""
IF_INET6 = ("00000000000000000000000000000001 01 80 10 80       lo\n"
            "fe800000000000000216eafffe123456 02 40 20 80     eth0\n")


def _maps(paths: list[str]) -> str:
    lines = [f"7f00000{i}000-7f00000{i}fff r-xp 00000000 08:01 {1000 + i}                     {p}"
             for i, p in enumerate(paths)]
    lines += ["7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]",
              "55d000000000-55d000001000 r--p 00000000 08:01 42   /usr/sbin/nginx"]
    return "\n".join(lines) + "\n"


def _web(tmp_path, name="root", *, maps_mode=0o644):
    r = make_machine(tmp_path, name=name, owned={"/usr/sbin/nginx": "nginx-core", LIBSSL: "libssl3:amd64",
                                                 LIBC: "libc6:amd64", "/usr/bin/sleep": "coreutils"})
    _w(r / "usr/sbin/nginx", b"\x7fELF", 0o755)
    _w(r / "usr/bin/sleep", b"\x7fELF", 0o755)
    mkproc(r, 100, "nginx", str(r) + "/usr/sbin/nginx", b"nginx\x00", sockets={"6": 50})
    _w(r / "proc/100/maps", _maps([LIBSSL, LIBC, LIBSSL + " (deleted)", "/usr/lib/locale/locale-archive"]), maps_mode)
    mkproc(r, 200, "sleep", str(r) + "/usr/bin/sleep", b"sleep\x00600\x00")          # not listening: maps not read
    _w(r / "proc/200/maps", _maps(["/opt/never-read.so"]))
    _w(r / "proc/net/tcp", net_table([("00000000", 443, "0A")]))
    _w(r / "proc/net/fib_trie", FIB_TRIE)
    _w(r / "proc/net/if_inet6", IF_INET6)
    return r


@pytest.mark.parametrize("awk", AWKS)
def test_listening_libraries_and_addresses_read_the_same_both_ways(tmp_path, awk):
    r = _web(tmp_path / awk)
    ssh, agent = run_ssh(tmp_path / awk, r, awk), run_agent(r)
    for inv in (ssh, agent):
        assert inv["maps_read"] and not inv["maps_gaps"]
        assert inv["procs"][100]["libs"] == sorted([LIBSSL, LIBC])          # deduplicated, (deleted) folded, .so only
        assert inv["procs"][100]["lib_packages"] == ["libc6:amd64", "libssl3:amd64"]
        assert "libs" not in inv["procs"][200]                               # only listening processes
        assert inv["local_addresses"] == ["203.0.113.7", "127.0.0.1", "::1", "fe80::216:eaff:fe12:3456"] or \
            sorted(inv["local_addresses"]) == sorted(["203.0.113.7", "127.0.0.1", "::1", "fe80::216:eaff:fe12:3456"])
    for key in ("procs", "maps_read", "maps_gaps"):
        assert ssh[key] == agent[key], key
    assert sorted(ssh["local_addresses"]) == sorted(agent["local_addresses"])


@pytest.mark.parametrize("awk", AWKS)
def test_unreadable_maps_is_a_gap_not_no_libraries(tmp_path, awk):
    r = _web(tmp_path / awk, maps_mode=0o000)
    for inv in (run_ssh(tmp_path / awk, r, awk), run_agent(r)):
        assert inv["maps_read"] and inv["maps_gaps"] == [100] and "libs" not in inv["procs"][100]


def test_libraries_are_capped_per_process():
    out = "\n".join(["M\tmaps\t1"] + [f"LIB\t9\t/lib/l{i}.so" for i in range(L.MAX_LIBS_PER_PROC + 50)]) + "\nEND\n"
    inv = L.parse_output(out)
    assert len(inv["procs"][9]["libs"]) == L.MAX_LIBS_PER_PROC


def test_an_older_agent_says_it_did_not_look():
    inv = L.parse_output("M\tfamily\tdebian\nEND\n")
    assert inv["maps_read"] is False and inv["local_addresses"] == []


def test_the_snapshot_keeps_listener_libraries_running_packages_and_addresses(tmp_path):
    r = _web(tmp_path)
    inv = run_agent(r)
    doc = record.run(tmp_path / "data", "10.0.0.5", reader=lambda: {**inv, "via": "agent"})
    (web,) = [x for x in doc["listeners"] if x["port"] == 443]
    assert web["package"] == "nginx-core" and web["lib_packages"] == ["libc6:amd64", "libssl3:amd64"]
    assert web["maps"] == "read"
    assert {"nginx-core", "coreutils"} <= set(doc["running_packages"])
    assert doc["maps_read"] and "203.0.113.7" in doc["local_addresses"]


def test_a_snapshot_marks_a_listener_whose_maps_could_not_be_read(tmp_path):
    r = _web(tmp_path, maps_mode=0o000)
    doc = record.run(tmp_path / "data", "10.0.0.5", reader=lambda: run_agent(r))
    assert [x["maps"] for x in doc["listeners"]] == ["unreadable"]
