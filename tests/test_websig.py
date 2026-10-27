"""Web-server signals (PHP2Shell follow-up): bursts of crashing PHP / web-server workers
(WEB-001, from the kernel's and Apache's crash lines log sync already stores) and PHP
served to the network that the package check can't cover (WEB-002)."""
from __future__ import annotations

from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest

from kratos.events import converters as C
from kratos.events.store import EventStore
from kratos.logsources import parsers as LP
from kratos.logsources.parsers import firewall, web
from kratos.websig import judge as J
from kratos.websig import record as R

HOST = "10.0.0.7"
T0 = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc).timestamp()

KERNEL_LINES = [
    "php-fpm8.1[2345]: segfault at 0 ip 00007f3a2b1c4d5e sp 00007ffd1234abcd error 4 in libphp8.1.so"
    "[7f3a2b000000+300000] likely on CPU 2 (core 2, socket 0)",
    "traps: php-fpm8.3[777] general protection fault ip:7f00aa sp:7ffdbb error:0 in libc.so.6[7f00+180000]",
    "traps: httpd[1000] trap invalid opcode ip:55d sp:7ff error:0 in httpd[55d+1000]",
    "php-fpm[123]: unhandled level 3 translation fault (11) at 0x00000000, esr 0x92000007, in libphp.so[ffff+1000]",
    "php-fpm8.2[44]: potentially unexpected fatal signal 11.",
]


def _rec(text: str, ts: float = T0, kind: str = "journal"):
    return SimpleNamespace(ts=ts, kind=kind, text=text, path=None if kind == "journal" else "/var/log/x",
                           zone_assumed=False, entry={"MESSAGE": text, "_TRANSPORT": "kernel", "__CURSOR": f"c{ts}"}
                           if kind == "journal" else None)


# ---------------------------------------------------------------- the crash lines
@pytest.mark.parametrize("line,name,pid", [(KERNEL_LINES[0], "php-fpm8.1", 2345), (KERNEL_LINES[1], "php-fpm8.3", 777),
                                           (KERNEL_LINES[2], "httpd", 1000), (KERNEL_LINES[3], "php-fpm", 123),
                                           (KERNEL_LINES[4], "php-fpm8.2", 44)])
def test_kernel_crash_lines_become_crash_events(line, name, pid):
    p = firewall.to_parsed(_rec(line))
    assert p is not None and p.action == "process_crashed" and p.provider == "kernel"
    assert p.fields == {"process_name": name, "process_pid": pid}
    assert p.dataset == "kratos.journal"            # a journal entry, not a firewall event
    e = C.from_parsed(p, ctx=C.ReadContext(target=HOST, transport="ssh", read="sync_firewall"), dataset="kratos.firewall")
    assert e.dataset == "kratos.journal" and e.action == "process_crashed" and e.outcome == "failure"


def test_firewall_lines_are_unchanged_and_other_kernel_lines_skipped():
    fw = firewall.to_parsed(_rec("[UFW BLOCK] IN=eth0 OUT= MAC=00 SRC=192.0.2.9 DST=10.0.0.7 LEN=60 PROTO=TCP "
                                 "SPT=4000 DPT=23"))
    assert fw.action == "blocked" and fw.dataset is None
    assert firewall.to_parsed(_rec("EXT4-fs (sda1): mounted filesystem")) is None
    assert firewall.to_parsed(_rec("audit: type=1400 apparmor=\"DENIED\" name=\"[x]: segfault at 0\"")) is None


def test_apaches_own_crash_line_is_a_crash_event():
    line = ("[Tue Oct 27 10:02:03.123456 2026] [core:notice] [pid 1001:tid 1001] AH00052: child pid 2345 exit "
            "signal Segmentation fault (11)")
    p = web.to_parsed(_rec(line, kind="file"))
    assert p.action == "process_crashed" and p.provider == "apache" and p.fields == {"process_pid": 2345}
    other = web.to_parsed(_rec("[Tue Oct 27 10:02:03 2026] [core:error] [pid 1] AH00126: Invalid URI", kind="file"))
    assert other.action == "web_error"


def test_every_parser_action_has_an_event_kind():
    from kratos.events.assemble import LOG_ACTIONS

    assert "process_crashed" in LOG_ACTIONS


# ---------------------------------------------------------------- bursts
def _crash(i: int, name: str = "php-fpm8.1", gap: float = 30.0, pid0: int = 100) -> J.Crash:
    return J.Crash(ts=T0 + i * gap, name=name, pid=pid0 + i, provider="kernel", message="segfault at 0")


def test_a_lone_crash_is_not_a_burst_but_three_close_together_are():
    assert J.bursts([_crash(0), _crash(1)]) == {}
    assert J.bursts([_crash(0), _crash(1, gap=700), _crash(2, gap=700)]) == {}       # too far apart
    found = J.bursts([_crash(i) for i in range(4)] + [_crash(0, name="bash")])
    assert list(found) == ["php"] and len(found["php"][0]) == 4


def test_the_same_crash_seen_twice_counts_once():
    a = J.Crash(T0, "apache2", 2345, "kernel")
    b = J.Crash(T0 + 1, "", 2345, "apache")                  # Apache's own line for the same child
    c = J.Crash(T0 + 2, "apache2", 2346, "kernel")
    assert J.bursts([a, b, c]) == {}


def test_burst_signals_name_the_bursts_and_scale_severity():
    many = J.bursts([_crash(i, gap=10) for i in range(12)] + [_crash(i, gap=10, pid0=900) for i in range(200, 203)])
    [s] = J.burst_signals(many, target=HOST, source_note="note")
    assert s["rule"] == "WEB-001" and s["severity"] == "high" and s["subject"] == "php"
    assert len(s["entities"]) == 2 and s["entities"][0].startswith("php@2026-10-27T10:0")
    assert "12 crashes between 2026-10-27 10:00 UTC" in " ".join(s["evidence"])
    [few] = J.burst_signals(J.bursts([_crash(i) for i in range(3)]), target=HOST, source_note="note")
    assert few["severity"] == "medium"


# ---------------------------------------------------------------- PHP exposure
LISTEN = [{"port": 80, "proto": "tcp", "seen": True, "exe": "/usr/sbin/apache2", "address": "0.0.0.0"},
          {"port": 9000, "proto": "tcp", "seen": True, "exe": "/usr/sbin/php-fpm8.3", "address": "127.0.0.1"},
          {"port": 22, "proto": "tcp", "seen": True, "exe": "/usr/sbin/sshd", "address": "0.0.0.0"}]
PHP = [{"name": "php8.3-fpm", "version": "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"},
       {"name": "libapache2-mod-php8.3", "version": "8.3.12-1+ubuntu22.04.1+deb.sury.org+1"},
       {"name": "curl", "version": "7.81.0"}]
OUTSIDE = {"php8.3-fpm": {"origin": "LP-PPA-ondrej-php", "kind": "third_party"},
           "libapache2-mod-php8.3": {"origin": "LP-PPA-ondrej-php", "kind": "third_party"}}


def _expose(listeners=LISTEN, packages=PHP, outside=OUTSIDE, today=date(2026, 10, 27)):
    return J.exposure_signal(target=HOST, listeners=listeners, packages=packages, outside=outside,
                             origins_checked=True, distro="Ubuntu", today=today)


def test_ppa_php_served_to_the_network_is_named_as_not_checked():
    sig, line = _expose()
    assert sig["rule"] == "WEB-002" and sig["severity"] == "low" and sig["ports"] == [80]
    assert "LP-PPA-ondrej-php" in " ".join(sig["evidence"]) and "apache2 on port(s) 80" in sig["evidence"][0]
    assert sig["entities"] == ["php8.3"] and "not checked" in line


def test_an_unsupported_php_branch_is_medium():
    old = [{"name": "php8.1-fpm", "version": "8.1.30-1+deb.sury.org+1"}]
    sig, _ = _expose(packages=old, outside={"php8.1-fpm": {"origin": "LP-PPA-ondrej-php", "kind": "third_party"}})
    assert sig["severity"] == "medium" and "2025-12-31" in " ".join(sig["evidence"])
    assert "supported-versions" in sig["recommendation"][0]


def test_the_distributions_own_php_is_a_digest_line_not_a_finding():
    sig, line = _expose(outside={})
    assert sig is None and "the distribution's own, checked" in line


def test_nothing_is_said_without_a_network_facing_web_server_or_php():
    assert _expose(listeners=[x for x in LISTEN if x["port"] != 80]) == (None, None)       # only loopback php-fpm
    assert _expose(packages=[PHP[2]]) == (None, None)
    assert _expose(listeners=None) == (None, None)


def test_an_unseen_listener_on_a_web_port_counts():
    unseen = [{"port": 443, "proto": "tcp", "seen": False, "exe": None, "address": "::"}]
    sig, _ = _expose(listeners=unseen)
    assert sig is not None and "a web server on port(s) 443" in sig["evidence"][0]


# ---------------------------------------------------------------- end to end on stored data
def _store_crashes(data_dir, n: int = 4, start: float | None = None):
    start = start if start is not None else datetime.now(timezone.utc).timestamp() - 3600
    events = [C.from_parsed(firewall.to_parsed(_rec(f"php-fpm8.3[{500 + i}]: segfault at 0 ip 1 sp 2 error 4",
                                                    ts=start + i * 20)),
                            ctx=C.ReadContext(target=HOST, transport="ssh", read="sync_firewall"), dataset="kratos.firewall") for i in range(n)]
    assert EventStore(data_dir / "kratos.db").add(events) == n


def test_the_snapshot_and_findings_come_from_stored_crash_events(tmp_path):
    from kratos.adapters import findings_engine as FE

    _store_crashes(tmp_path)
    doc = R.run(tmp_path, HOST)
    assert doc["crashes_seen"] == 4
    [sig] = [s for s in doc["signals"] if s["rule"] == "WEB-001"]
    assert sig["severity"] == "medium"
    assert "worker crash bursts: PHP" in R.summary_line(doc)
    src = FE.SNAPSHOT_SOURCES["web_signals"]
    loaded = src.load(doc["file"] and __import__("pathlib").Path(doc["file"]))
    assert [f.id for f in src.build(loaded)] == ["WEB-001"]
    assert FE.find_latest_inputs(tmp_path, HOST)["web_signals"] is not None
    assert not doc["complete"]                      # no package list / process read yet: can't close anything


def test_rules_are_known_to_the_lifecycle_and_attack_table():
    from kratos.attack import mapping
    from kratos.lifecycle.rules import rule_info

    assert rule_info("WEB-001").kind == "occurrence" and rule_info("WEB-002").kind == "condition"
    assert "T1190" in str(mapping.RULE_ATTACK["WEB-001"])
    assert type(mapping.RULE_ATTACK["WEB-002"]).__name__ == "Posture"


def test_parser_dataset_field_is_optional_for_every_other_parser():
    assert LP.Parsed(ts=0, action="x").dataset is None


def test_listener_addresses_are_decoded_from_proc_net():
    from kratos.live.record import proc_net_address

    assert proc_net_address("3500007F") == "127.0.0.53" and proc_net_address("0102000A") == "10.0.2.1"
    assert proc_net_address("00000000000000000000000001000000") == "::1" and proc_net_address("x") is None
    assert J._loopback("127.0.0.53") and J._loopback("::ffff:127.0.0.1") and J._loopback("0.0.0.0") is False
