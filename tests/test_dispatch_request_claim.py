"""
Review v2 F-6 and its follow-up: a queued dispatch request is sent at most
once, only if the machine still has execution consent at the moment of
sending, and only while it is fresh. A request nobody sent while the person
waited is cancelled, so it can't run hours later.

Execution here only ever reaches a loopback test agent; nothing touches a real
machine.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from datetime import timedelta

from kratos.storage import whitelist_store as ws_mod
from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import core_server as core_mod
from kratos.utils.timeutil import utc_now

from test_subagent_execution_channel import _free_port, _pair_agent, _start_server, _stop_agent, _wait_until


def _store(tmp_path, opt_in=True):
    wl = WhitelistStore(tmp_path / "kratos.db")
    wl.set_execution_opt_in("t1", opt_in)
    return wl


def _request(wl, target="t1"):
    wl.set_execution_opt_in(target, True)
    return wl.create_dispatch_request(target, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 1)


def _age(tmp_path, request_id, seconds):
    conn = sqlite3.connect(tmp_path / "kratos.db")
    conn.execute("UPDATE whitelist_dispatch_requests SET requested_at = ? WHERE request_id = ?",
                 ((utc_now() - timedelta(seconds=seconds)).isoformat(), request_id))
    conn.commit()
    conn.close()


def test_a_fresh_request_is_claimed_once(tmp_path):
    wl = _store(tmp_path)
    rid = _request(wl)
    claimed = wl.claim_dispatch_request(rid)
    assert claimed["status"] == "claimed" and claimed["slot_values"] == {"jail": "sshd", "ip": "8.8.8.8"}
    assert wl.claim_dispatch_request(rid) is None             # never sent twice
    assert wl.list_pending_dispatch_requests("t1") == []


def test_turning_execution_off_after_the_request_refuses_it(tmp_path):
    wl = _store(tmp_path)
    rid = _request(wl)
    wl.set_execution_opt_in("t1", False)
    assert wl.claim_dispatch_request(rid) is None
    row = wl.get_dispatch_request(rid)
    assert row["status"] == "done" and row["result"]["status"] == "refused"
    assert "turned off" in row["result"]["reason"]


def test_a_stale_request_expires_instead_of_running_late(tmp_path):
    wl = _store(tmp_path)
    rid = _request(wl)
    _age(tmp_path, rid, ws_mod.DISPATCH_REQUEST_TTL_SECONDS + 1)
    assert wl.claim_dispatch_request(rid) is None
    assert "expired" in wl.get_dispatch_request(rid)["result"]["reason"]


def test_cancel_is_definite_before_sending_and_honest_after(tmp_path):
    wl = _store(tmp_path)
    rid = _request(wl)
    assert wl.cancel_dispatch_request(rid, "gave up") == "cancelled"
    assert wl.claim_dispatch_request(rid) is None             # a cancelled request can't be sent
    rid2 = _request(wl)
    wl.claim_dispatch_request(rid2)
    assert wl.cancel_dispatch_request(rid2, "gave up") == "claimed"  # already sent: outcome unknown
    assert wl.cancel_dispatch_request("nope", "x") == "missing"


def test_two_listeners_racing_claim_it_exactly_once(tmp_path):
    wl = _store(tmp_path)
    rids = [_request(wl) for _ in range(20)]
    wins: list[str] = []
    barrier = threading.Barrier(4)

    def worker():
        store = WhitelistStore(tmp_path / "kratos.db")
        barrier.wait()
        for rid in rids:
            if store.claim_dispatch_request(rid) is not None:
                wins.append(rid)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(wins) == sorted(rids)                       # each one claimed, none twice


def test_listener_never_sends_a_request_whose_consent_was_withdrawn(tmp_path, monkeypatch):
    """Real CoreServer + agent over a loopback socket: the request is queued
    with consent, consent is withdrawn before the listener's next tick, and
    nothing is ever dispatched to the agent."""
    monkeypatch.setattr(core_mod, "WHITELIST_WATCH_INTERVAL_SECONDS", 0.05)

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wl = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port, whitelist_store=wl)
        sent: list = []
        real = server.dispatch_action

        async def spy(*a, **kw):
            sent.append(a)
            return await real(*a, **kw)

        server.dispatch_action = spy
        try:
            agent, task, tid = await _pair_agent(store, port, tmp_path)
            try:
                # Queue while the listener's tick is paused, then withdraw consent.
                server._watch_task.cancel()
                wl.set_execution_opt_in(tid, True)
                rid = wl.create_dispatch_request(tid, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 0)
                wl.set_execution_opt_in(tid, False)
                server._watch_task = asyncio.create_task(server._whitelist_watch_loop())
                await _wait_until(lambda: wl.get_dispatch_request(rid)["status"] == "done")
                assert sent == []
                assert "turned off" in wl.get_dispatch_request(rid)["result"]["reason"]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_a_request_the_screen_cancelled_never_reaches_the_machine(tmp_path, monkeypatch):
    monkeypatch.setattr(core_mod, "WHITELIST_WATCH_INTERVAL_SECONDS", 0.05)

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wl = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port, whitelist_store=wl)
        sent: list = []

        async def spy(*a, **kw):
            sent.append(a)
            return {"status": "ok"}

        server.dispatch_action = spy
        try:
            agent, task, tid = await _pair_agent(store, port, tmp_path)
            try:
                server._watch_task.cancel()
                wl.set_execution_opt_in(tid, True)
                rid = wl.create_dispatch_request(tid, "fail2ban.ban_ip", {"jail": "sshd", "ip": "8.8.8.8"}, 0)
                assert wl.cancel_dispatch_request(rid, "screen gave up") == "cancelled"
                server._watch_task = asyncio.create_task(server._whitelist_watch_loop())
                await asyncio.sleep(0.4)
                assert sent == []
                result = json.loads(sqlite3.connect(tmp_path / "kratos.db").execute(
                    "SELECT result_json FROM whitelist_dispatch_requests").fetchone()[0])
                assert result["reason"] == "cancelled: screen gave up"
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


# --- the approval screen's wait -------------------------------------------
def _screen_wait(tmp_path, monkeypatch, listener):
    """Run WhitelistScreen._dispatch_and_poll with `listener(wl, request_id)`
    playing the listener's part; returns the screen's log lines."""
    from test_tui_mk2_whitelist import _Host, _log_texts, _pair

    from kratos.subagent import whitelist as W
    from kratos.tui_mk2.screens import whitelist as wl_mod

    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(wl_mod, "_ANSWER_TIMEOUT_SECONDS", 0.1)
    sa, wl = SubAgentStore(tmp_path / "kratos.db"), WhitelistStore(tmp_path / "kratos.db")
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = wl_mod.WhitelistScreen(tmp_path, target_id=tid)
    spec = next(s for s in W.list_builtin_action_specs() if s.id == "fail2ban.ban_ip")
    real_create = wl.create_dispatch_request

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            def create(*a, **kw):
                rid = real_create(*a, **kw)
                listener(wl, rid)
                return rid

            screen._wl_store.create_dispatch_request = create
            await screen._dispatch_and_poll(spec, {"jail": "sshd", "ip": "8.8.8.8"}, "low")
            return _log_texts(screen)

    return asyncio.run(run())


def test_screen_says_outcome_unknown_when_sent_but_never_answered(tmp_path, monkeypatch):
    texts = _screen_wait(tmp_path, monkeypatch, lambda wl, rid: wl.claim_dispatch_request(rid))
    joined = "\n".join(texts)
    assert "sent to the machine" in joined and "outcome is unknown" in joined
    assert "nothing ran" not in joined


def test_screen_shows_the_answer_when_it_arrives(tmp_path, monkeypatch):
    def listener(wl, rid):
        wl.claim_dispatch_request(rid)
        wl.complete_dispatch_request(rid, {"status": "ok", "exit_code": 0})

    joined = "\n".join(_screen_wait(tmp_path, monkeypatch, listener))
    assert "fail2ban.ban_ip: ok" in joined and "unknown" not in joined
