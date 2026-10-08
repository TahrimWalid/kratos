"""
Review v2 F-10: failed logins are limited per source without ever wiping
everyone's counters, wrong pairing codes are capped across all sources, and
the always-on listener can listen only where paired machines dial.
"""
from __future__ import annotations

import asyncio
import ipaddress

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import core_listener as CL
from kratos.subagent import core_server as CS
from kratos.subagent import protocol as proto

from test_subagent_execution_channel import _free_port


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_a_blocked_source_stays_blocked_while_others_spray():
    clock = _Clock()
    lim = CS.AuthFailureLimiter(clock)
    for _ in range(CS.AUTH_FAILURE_LIMIT):
        lim.note_failure("198.51.100.7")
    assert lim.source_blocked("198.51.100.7")
    # 4096+ other addresses fail later -- the old code cleared every counter here
    for i in range(CS.AUTH_TRACKED_SOURCES_MAX + 50):
        clock.t += 0.001
        lim.note_failure(str(ipaddress.ip_address(0x0A000000 + i)))
    assert lim.tracked_sources() <= CS.AUTH_TRACKED_SOURCES_MAX
    assert lim.source_blocked("198.51.100.7")            # not pushed out by the spray


def test_expired_sources_are_evicted_before_live_ones():
    clock = _Clock()
    lim = CS.AuthFailureLimiter(clock)
    for _ in range(CS.AUTH_FAILURE_LIMIT):
        lim.note_failure("198.51.100.7")
    clock.t += CS.AUTH_FAILURE_WINDOW_SECONDS + 1
    for i in range(CS.AUTH_TRACKED_SOURCES_MAX):
        lim.note_failure(str(ipaddress.ip_address(0x0A000000 + i)))
    assert not lim.source_blocked("198.51.100.7")       # its window passed
    assert lim.tracked_sources() == CS.AUTH_TRACKED_SOURCES_MAX


def test_ipv6_is_limited_per_slash_64():
    lim = CS.AuthFailureLimiter(_Clock())
    for i in range(CS.AUTH_FAILURE_LIMIT):
        lim.note_failure(f"2001:db8:1:2::{i + 1:x}")       # one host rotating its interface id
    assert lim.source_blocked("2001:db8:1:2::ffff")
    assert not lim.source_blocked("2001:db8:1:3::1")
    assert CS.AuthFailureLimiter.source_key("::ffff:192.0.2.1") == "192.0.2.1"


def test_wrong_pairing_codes_are_capped_across_all_sources():
    clock = _Clock()
    lim = CS.AuthFailureLimiter(clock)
    for i in range(CS.PAIRING_GUESS_LIMIT):
        lim.note_failure(f"10.1.{i // 250}.{i % 250}", pairing_code=True)
    assert lim.pairing_paused()
    clock.t += CS.AUTH_FAILURE_WINDOW_SECONDS + 1
    assert not lim.pairing_paused()


def test_a_paused_pairing_never_looks_the_code_up_and_tokens_still_work(tmp_path, monkeypatch):
    """Real listener over a loopback socket: once pairing is paused, even the
    RIGHT code is refused without a lookup; a paired agent's token still logs in."""
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        good = store.create_pairing_code(name="x")["code"]
        token_target = store.redeem_pairing_code(store.create_pairing_code(name="y")["code"], "a1", "y", "0.3.5")
        port = _free_port()
        server = CS.CoreServer(store, host="127.0.0.1", port=port)
        server._server = await asyncio.start_server(server._handle_connection, "127.0.0.1", port)
        lookups = []
        real = store.redeem_pairing_code
        monkeypatch.setattr(store, "redeem_pairing_code", lambda *a, **k: lookups.append(a) or real(*a, **k))
        for _ in range(CS.PAIRING_GUESS_LIMIT):
            server._auth_limiter.note_failure("192.0.2.9", pairing_code=True)

        async def hello(auth):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            await proto.write_frame(w, proto.build_hello("agent-x", auth, "h", "0.3.5", session_nonce="ab" * 16))
            reply = await proto.read_frame(r)
            w.close()
            return reply

        try:
            refused = await hello({"pairing_code": good})
            assert refused["type"] == proto.MSG_HELLO_REJECT and "pairing is paused" in refused["reason"]
            assert lookups == []
            ok = await hello({"token": token_target["token"]})
            assert ok["type"] == proto.MSG_HELLO_ACK
        finally:
            server._server.close()
            server._drop_live_connections()

    asyncio.run(run())


# --- binding ------------------------------------------------------------
def test_parse_bind_hosts():
    assert CS.parse_bind_hosts("127.0.0.1, 100.64.1.2,127.0.0.1") == ["127.0.0.1", "100.64.1.2"]
    assert CS.parse_bind_hosts(["::1", "0.0.0.0"]) == ["::1", "0.0.0.0"]
    for bad in ("", "a b", "1.2.3.4;id", "--x"):
        with pytest.raises(ValueError):
            CS.parse_bind_hosts(bad)


def test_recommended_bind_is_narrow_only_when_every_address_is_this_machines(monkeypatch):
    from kratos.subagent import agent as agent_mod

    mine = {"100.97.1.2", "192.168.1.5"}
    monkeypatch.setattr(agent_mod, "local_interface_of", lambda ip: "eth0" if str(ip) in mine else None)
    assert CL.recommended_bind_hosts(["100.97.1.2"]) == ["127.0.0.1", "100.97.1.2"]
    assert CL.recommended_bind_hosts(["100.97.1.2", "192.168.1.5"]) == ["127.0.0.1", "100.97.1.2", "192.168.1.5"]
    assert CL.recommended_bind_hosts(["100.97.1.2", "203.0.113.9"]) == ["0.0.0.0"]   # forwarded public IP
    assert CL.recommended_bind_hosts(["kratos.example.com"]) == ["0.0.0.0"]          # hostname
    assert CL.recommended_bind_hosts(None) == ["0.0.0.0"]                           # unknown address
    assert CL.recommended_bind_hosts([]) == ["0.0.0.0"]


def test_bind_covers():
    assert CL.bind_covers(["0.0.0.0"], "anything.example")
    assert CL.bind_covers(["127.0.0.1", "100.97.1.2"], "100.97.1.2")
    assert not CL.bind_covers(["127.0.0.1", "100.97.1.2"], "192.168.1.5")
    assert not CL.bind_covers(["127.0.0.1"], "kratos.local")


def test_installed_bind_hosts_reads_the_unit(tmp_path, monkeypatch):
    monkeypatch.setattr(CL.Path, "home", lambda: tmp_path)
    assert CL.installed_bind_hosts(None) is None
    assert CL.installed_bind_hosts("user") is None
    unit = tmp_path / ".config/systemd/user" / f"{CL.CORE_SERVICE_NAME}.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(CL.core_service_unit(tmp_path, bind_host=["127.0.0.1", "100.97.1.2"], user_mode=True))
    assert CL.installed_bind_hosts("user") == ["127.0.0.1", "100.97.1.2"]
    unit.write_text("[Service]\nExecStart=/usr/bin/kratos subagent-serve --port 8765\n")
    assert CL.installed_bind_hosts("user") == ["0.0.0.0"]


def test_dial_addresses_come_from_connections_then_pairings(tmp_path):
    store = SubAgentStore(tmp_path / "kratos.db")
    assert store.dial_addresses() == []
    old = store.redeem_pairing_code(store.create_pairing_code(name="old")["code"], "a0", "old", "0.1")
    assert store.dial_addresses() is None                    # paired with no recorded address
    store.record_connected(old["target_id"], "old", "0.3.5", core_addr="100.97.1.2")
    code = store.create_pairing_code(name="new", core_host="192.168.1.5")["code"]
    assert store.dial_addresses() == ["100.97.1.2", "192.168.1.5"]
    store.redeem_pairing_code(code, "a1", "new", "0.3.5")
    assert store.dial_addresses() == ["100.97.1.2", "192.168.1.5"]   # from its pairing until it connects


def test_a_listener_bound_to_two_addresses_accepts_on_both_and_records_which(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        t = store.redeem_pairing_code(store.create_pairing_code(name="x")["code"], "a1", "x", "0.3.5")
        port = _free_port()
        server = CS.CoreServer(store, host="127.0.0.1,::1", port=port)
        task = asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.2)
        seen = []
        try:
            for host in ("127.0.0.1", "::1"):
                r, w = await asyncio.open_connection(host, port)
                await proto.write_frame(w, proto.build_hello("a1", {"token": t["token"]}, "x", "0.3.5",
                                                             session_nonce="ab" * 16))
                assert (await proto.read_frame(r))["type"] == proto.MSG_HELLO_ACK
                await asyncio.sleep(0.1)
                seen.append(store.get_target(t["target_id"])["core_addr"])
                w.close()
                await asyncio.sleep(0.2)
        finally:
            await server.close()
            task.cancel()
        return seen

    assert asyncio.run(run()) == ["127.0.0.1", "::1"]
