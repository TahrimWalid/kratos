"""D.2 fleet questions: groups, parallel collection, the fleet answer and its per-machine checks.

No real machine and no real model: ``ssh_remote.probe_reachable`` and ``collect.runner.prepare``
are replaced per machine, and the model is a scripted queue of replies. Everything else --
the group store, the collector's threads and limits, the digest, the per-machine answer
checks, the summary, the run rows -- runs as shipped.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from kratos import kratos_config
from kratos import llm_interface
from kratos.collect.runner import CheckOutcome, CollectionReport
from kratos.fleet import answer as fleet_answer
from kratos.fleet import collect as fleet_collect
from kratos.fleet import groups as G
from kratos.fleet import record as fleet_record
from kratos.fleet import run as fleet_run
from kratos.lifecycle.decide import Actor

ME = Actor(user="alice", interface="cli")
A, B, C, D, E = "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"

HIGH = {"id": "PRIV-001", "title": "A new account can become root", "severity": "high",
        "subject": "bob", "entities": ["bob"], "evidence": ["bob was added to sudo"], "state": "new"}


class Chat:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []
        self.systems: list[str] = []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.systems.append(system_prompt)
        self.prompts.append(user_prompt)
        if not self.responses:
            raise AssertionError("scripted model ran out of replies")
        r = self.responses.pop(0)
        return r if isinstance(r, str) else json.dumps(r)


def make_report(target: str, findings=(), *, gaps=(), statuses=("ok",), correlated=True) -> CollectionReport:
    now = time.time()
    checks = []
    for i, st in enumerate(statuses):
        checks.append(CheckOutcome(
            name=f"c{i}", label=f"check {i}", cost="quick", status=st, source="ran" if st == "ok" else "skipped",
            summary="read" if st == "ok" else "not checked this time", finished_at=now, age_seconds=0.0,
            tools=["list_privileged_accounts"] if st == "ok" else [], inputs=(),
            gaps=list(gaps) if i == 0 else ([] if st == "ok" else [f"check {i}: not checked this time"]),
            steps=[{"tool": "list_privileged_accounts", "args": {},
                    "observation": {"status": "ok", "result": {"target": target}}}] if st == "ok" else []))
    corr = {"findings": [dict(f) for f in findings], "staleness_warning": None} if correlated else None
    return CollectionReport(target=target, target_key=target, transport="ssh", checks=checks, correlation=corr,
                            correlation_step={"tool": "correlate_findings", "args": {},
                                              "observation": {"status": "ok", "result": corr}} if corr else None,
                            started=now, finished=now, budget_seconds=15)


@pytest.fixture
def dd(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(kratos_config, "get_active_data_dir", lambda: d)
    return d


class Lab:
    """Per-machine fakes: reachable or not, a report, an optional hang or exception."""

    def __init__(self, monkeypatch) -> None:
        self.reports: dict[str, CollectionReport] = {}
        self.down: dict[str, str] = {}
        self.hang: set[str] = set()
        self.boom: set[str] = set()
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()
        self.prepared: list[str] = []
        self.pinned_seen: dict[str, str] = {}
        from kratos.adapters import ssh_remote
        from kratos.collect import runner

        monkeypatch.setattr(ssh_remote, "probe_reachable", self.probe)
        monkeypatch.setattr(runner, "prepare", self.prepare)
        monkeypatch.setattr(runner, "_default_dispatch", lambda: self.dispatch)
        self.measured: list[str] = []

    def dispatch(self, tool, args, data_dir):
        """The period measurement and re-correlation the collector runs by code."""
        host = kratos_config.get_active_target()
        if tool == "measure_auth_activity":
            from kratos.timewin.windows import current_context

            self.measured.append(host)
            ctx = current_context()
            if ctx is not None:   # what the real tool's window resolution records
                ctx.queried.setdefault((args.get("window") or {}).get("id"), set()).add(tool)
            return {"status": "ok", "window": {"id": (args.get("window") or {}).get("id"), "label": "this week"},
                    "counts": {"sudo_sessions": 1 if host == A else 0}, "failed_login_sources": []}
        if tool == "correlate_findings":
            rep = self.reports.get(host) or make_report(host)
            return {"status": "ok", "result": rep.correlation}
        raise AssertionError(f"unexpected read {tool}")

    def probe(self):
        host = kratos_config.get_active_target()
        if host in self.down:
            return False, self.down[host], None
        return True, "", 0.4

    def prepare(self, host, data_dir, **kw):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.prepared.append(host)
            self.pinned_seen[host] = kratos_config.get_active_target()
        try:
            if host in self.hang:
                time.sleep(30)
            if host in self.boom:
                raise RuntimeError("boom")
            time.sleep(0.05)
            return self.reports.get(host) or make_report(host)
        finally:
            with self.lock:
                self.active -= 1


@pytest.fixture
def lab(monkeypatch) -> Lab:
    return Lab(monkeypatch)


def _machines_reply(answers: dict[str, str], summary: str = "Checked.") -> dict[str, Any]:
    return {"reasoning": "done", "machines": [{"machine": k, "answer": v, "claims": []} for k, v in answers.items()],
            "summary": summary}


def _ask(dd: Path, group, chat: Chat, monkeypatch, question="who gained sudo anywhere this week?", **kw):
    monkeypatch.setattr(llm_interface, "agent_chat", chat)
    return fleet_run.run_fleet(fleet_run.FleetRequest(question=question, group=group, data_dir=dd, actor=ME, **kw))


# --- groups -------------------------------------------------------------------------


def test_groups_are_people_only_recorded_and_feed_the_asset_record(dd):
    from kratos import settings_store
    from kratos.assets import store as AS

    g = G.create_group(dd, "web", ME, members=[A, "ubuntu@10.0.0.12"])
    assert g.members == (A, B)
    assert AS.get(dd, A).groups == ("web",)
    assert any(e["field"] == "groups" and e["actor"] == "alice" for e in AS.events(dd, A))
    with pytest.raises(G.GroupError):
        G.create_group(dd, "all", ME)
    with pytest.raises(G.GroupError):
        G.create_group(dd, "web", Actor(user="x", interface="serve"))
    with settings_store.tool_call_scope("run_config_audit"):
        with pytest.raises(G.GroupError, match="agent tools may not"):
            G.add_members(dd, "web", [C], ME)
    G.remove_members(dd, "web", [A], ME)
    assert G.get_group(dd, "web").members == (B,)
    # the asset editor's groups field is the same membership
    AS.update(dd, C, ME, groups="web, db")
    assert set(G.groups_of(dd, C)) == {"web", "db"}
    assert C in G.get_group(dd, "db").members
    G.delete_group(dd, "db", ME)
    assert G.groups_of(dd, C) == ("web",)


def test_all_is_every_machine_with_an_asset_record(dd):
    from kratos.assets import store as AS

    for m in (A, B, C):
        AS.update(dd, m, ME, criticality="medium")
    assert G.resolve(dd, "@all").machines == [A, B, C]


def test_resolve_narrows_to_scope_and_never_names_the_rest(dd):
    G.create_group(dd, "lab", ME, members=[A, B, C, D, E])
    r = G.resolve(dd, "@lab", scope=[A, "10.0.0.12"])
    assert r.machines == [A, B] and r.outside_scope == 3
    with pytest.raises(G.GroupError):
        G.resolve(dd, "@lab", scope=["10.9.9.9"])


def test_an_address_and_an_agent_link_to_the_same_machine_count_once(dd):
    from kratos.storage.subagent_store import SubAgentStore

    SubAgentStore(dd / "kratos.db")   # creates the sub-agent tables
    import sqlite3

    conn = sqlite3.connect(dd / "kratos.db")
    conn.execute("INSERT INTO subagent_targets (target_id, name, token, paired_at) VALUES ('tgt_1', 'db-01', 't', 'x')")
    conn.execute("INSERT INTO subagent_links (host, target_id, mode, created_at, updated_at) "
                 "VALUES ('10.0.0.11', 'tgt_1', 'subagent', 'x', 'x')")
    conn.execute("INSERT INTO subagent_links (host, target_id, mode, created_at, updated_at) "
                 "VALUES ('db01.lab', 'tgt_1', 'subagent', 'x', 'x')")
    conn.commit()
    conn.close()
    G.create_group(dd, "dup", ME, members=["db-01", A, "db01.lab", B])
    g = G.get_group(dd, "dup")
    assert g.members == (A, "db01.lab", B)          # the agent's name is stored as its address
    r = G.resolve(dd, "@dup")
    assert r.machines == [A, B]
    assert r.duplicates == [("db01.lab", A)]


# --- collection ---------------------------------------------------------------------


def test_collection_is_bounded_pinned_and_one_failure_never_stops_the_others(dd, lab):
    lab.boom.add(C)
    lab.down[D] = "ssh: connect to host 10.0.0.14 port 22: Connection timed out"
    res = fleet_collect.collect_fleet([A, B, C, D, E], dd, max_parallel=2, machine_seconds=20)
    by = {r.machine: r for r in res}
    assert lab.max_active <= 2
    assert all(lab.pinned_seen[m] == m for m in lab.pinned_seen)          # each read pinned to its own machine
    assert by[A].outcome == by[B].outcome == by[E].outcome == "ok"
    assert by[C].outcome == "failed" and "RuntimeError" in by[C].reason
    assert by[D].outcome == "unreachable" and "timed out" in by[D].reason
    assert D not in lab.prepared                                           # not reached: nothing collected


def test_a_hanging_machine_stops_at_its_limit(dd, lab):
    lab.hang.add(B)
    t0 = time.monotonic()
    res = fleet_collect.collect_fleet([A, B], dd, max_parallel=2, machine_seconds=1)
    assert time.monotonic() - t0 < 10
    by = {r.machine: r for r in res}
    assert by[A].outcome == "ok" and by[B].outcome == "timeout" and "1 s" in by[B].reason


def test_a_machine_locked_by_another_run_is_reported_busy(dd, lab):
    from kratos.agent import target_lock

    h = target_lock.try_acquire_target(dd, B)
    try:
        res = fleet_collect.collect_fleet([A, B], dd, max_parallel=2, machine_seconds=1)
    finally:
        target_lock.release_target(h)
    assert {r.machine: r.outcome for r in res} == {A: "ok", B: "busy"}


def test_partial_read_is_partial_with_what_was_missed(dd, lab):
    lab.reports[A] = make_report(A, statuses=("ok", "skipped"))
    (r,) = fleet_collect.collect_fleet([A], dd, max_parallel=1, machine_seconds=20)
    assert r.outcome == "partial" and "check 1" in r.reason


# --- the answer, checked per machine ------------------------------------------------


def test_machine_a_high_finding_cannot_make_machine_b_nothing_found_pass_and_vice_versa(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    lab.reports[B] = make_report(B, [])
    # m1/m2 are assigned in group order: m1 = A (the HIGH one), m2 = B (clean).
    chat = Chat(_machines_reply({"m1": "No suspicious activity; the system appears clean.",
                                 "m2": "No new sudo accounts on this machine."}),
                _machines_reply({"m1": "No suspicious activity; the system appears clean.",
                                 "m2": "No new sudo accounts on this machine."}),
                _machines_reply({"m1": "No suspicious activity; the system appears clean.",
                                 "m2": "No new sudo accounts on this machine."}))
    out = _ask(dd, "@pair", chat, monkeypatch)
    m1, m2 = out.answer.machines
    # A is held to ITS high finding (rejected, then NOTE-tagged and listed by Kratos) ...
    assert "REJECTED (dismissive-verdict contradiction)" in chat.prompts[1]
    assert "MACHINE m1" in chat.prompts[1] and "MACHINE m2: REJECTED" not in chat.prompts[1]
    assert "[NOTE: this answer's overall verdict conflicts" in m1.text and "PRIV-001" in m1.block
    # ... and B's clean answer passes on B's own evidence: A's finding never reaches it.
    assert m2.passed and "PRIV-001" not in m2.text and not m2.notes


def test_a_claim_about_another_machine_is_rejected(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    chat = Chat(_machines_reply({"m1": "Nothing new here, but 10.0.0.12 has a new sudo user.", "m2": "Nothing new."}),
                _machines_reply({"m1": "Nothing new here.", "m2": "Nothing new."}))
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert "REJECTED (another machine named)" in chat.prompts[1] and "10.0.0.12" in chat.prompts[1]
    assert all(m.passed for m in out.answer.machines)


def test_another_machines_address_in_this_machines_own_logs_is_not_a_cross_claim(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    rep = make_report(A, [])
    rep.checks[0].steps[0]["observation"]["result"]["failed_from"] = [B]
    lab.reports[A] = rep
    chat = Chat(_machines_reply({"m1": "Failed logins came from 10.0.0.12.", "m2": "Nothing new."}))
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert len(chat.prompts) == 1 and out.answer.machines[0].passed


def test_unreachable_machine_is_named_everywhere_and_kratos_writes_its_answer(dd, lab, monkeypatch):
    G.create_group(dd, "trio", ME, members=[A, B, C])
    lab.down[C] = "ssh: connect to host 10.0.0.13 port 22: No route to host"
    chat = Chat(_machines_reply({"m1": "Nothing new.", "m2": "Nothing new.", "m3": "All good here too."},
                                summary="No machine gained a sudo user this week."))
    out = _ask(dd, "@trio", chat, monkeypatch)
    assert "MACHINE m3" in chat.prompts[0] and "NOT CHECKED" in chat.prompts[0]
    m3 = out.answer.machines[2]
    assert m3.kratos_text.startswith("Not checked by Kratos") and "No route to host" in m3.text
    assert "All good" not in m3.text and "left out" in m3.text
    assert "1 not checked" in out.answer.summary and "No route to host" in out.answer.summary
    # "no machine ..." speaks for the group, but m3 wasn't read: the sentence is left out
    assert not out.answer.model_summary and "not every machine was fully read" in out.answer.model_summary_dropped
    assert "10.0.0.13" in out.text and "not reached" in out.text


def test_pooled_summary_is_allowed_only_when_every_machine_was_fully_read(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    chat = Chat(_machines_reply({"m1": "Nothing new.", "m2": "Nothing new."},
                                summary="No machine gained a sudo user this week."))
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert out.answer.model_summary == "No machine gained a sudo user this week."


def test_invalid_json_gets_one_correction_then_kratos_writes_the_facts(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    chat = Chat("not json at all", "still not json")
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert len(chat.prompts) == 2 and "not the required JSON" in chat.prompts[1]
    assert out.status == "fallback"
    m1, m2 = out.answer.machines
    assert "PRIV-001" in m1.block and "no checked answer from the model" in m1.notes
    assert "0 open findings" in m2.text


def test_summary_is_built_by_code(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    chat = Chat(_machines_reply({"m1": "PRIV-001: bob was added to sudo; review it.", "m2": "Nothing new."},
                                summary="Everything is fine."))
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert out.answer.summary.startswith("2 machines · 1 with HIGH/CRITICAL findings · 2 fully read")


def test_missing_machine_answer_is_asked_for(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    chat = Chat(_machines_reply({"m1": "Nothing new."}), _machines_reply({"m1": "Nothing new.", "m2": "Nothing new."}))
    _ask(dd, "@pair", chat, monkeypatch)
    assert "no answer for m2" in chat.prompts[1]


# --- extra reads --------------------------------------------------------------------


def test_extra_reads_are_capped_pinned_and_attached_to_their_machine_only(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    calls: list[tuple[str, str]] = []

    def fake_dispatch(tool, args, data_dir):
        calls.append((tool, kratos_config.get_active_target()))
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": []}}
        return {"status": "ok", "result": {"marker": f"read-of-{kratos_config.get_active_target()}"}}

    from kratos.agent import loop as agent_loop

    monkeypatch.setattr(agent_loop, "execute_tool_call", fake_dispatch)
    reads = {"reasoning": "need more", "reads": [
        {"read": "list_processes", "machine": "m2", "args": {"target": "10.9.9.9"}},
        {"read": "run_linux_command", "machine": "m1", "args": {"command": "id"}},
        {"read": "list_processes", "machine": "m9", "args": {}},
        {"read": "read_journalctl", "machine": "m1", "args": {}},
        {"read": "list_open_files", "machine": "m1", "args": {}},
        {"read": "list_processes", "machine": "m1", "args": {}},
    ]}
    chat = Chat(reads, _machines_reply({"m1": "Nothing new.", "m2": "Nothing new."}))
    monkeypatch.setattr("kratos.fleet.settings.get",
                        lambda key, d: {"fleet.extra_reads": 2}.get(key, __import__("kratos.settings_store",
                                                                    fromlist=["get"]).get(key, data_dir=d)))
    out = _ask(dd, "@pair", chat, monkeypatch)
    ran = [r for r in out.answer.extra_reads if r["ran"]]
    assert [(r["tool"], r["machine"]) for r in ran] == [("list_processes", B), ("read_journalctl", A)]
    refused = {r["tool"]: r["why"] for r in out.answer.extra_reads if not r["ran"]}
    assert "not a read Kratos may run" in refused["run_linux_command"]
    assert any("over the allowance" in w for w in refused.values())
    # every read ran pinned to its own machine, and the model's "target" was dropped
    assert ("list_processes", B) in calls and ("read_journalctl", A) in calls
    assert all(t != "10.9.9.9" for _tool, t in calls)
    # the result reaches THAT machine's block only
    assert "read-of-10.0.0.12" in chat.prompts[1].split("MACHINE m2")[1].split("<<end")[0]
    assert "read-of-10.0.0.12" not in chat.prompts[1].split("MACHINE m1")[1].split("<<end")[0]
    assert "Extra reads: list_processes on 10.0.0.12" in out.text


def test_a_read_result_from_a_cannot_support_a_claim_about_b(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])

    def fake_dispatch(tool, args, data_dir):
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": []}}
        return {"status": "ok", "result": {"failed_from": ["203.0.113.50"]}}

    from kratos.agent import loop as agent_loop

    monkeypatch.setattr(agent_loop, "execute_tool_call", fake_dispatch)
    chat = Chat({"reasoning": "r", "reads": [{"read": "read_journalctl", "machine": "m1", "args": {}}]},
                _machines_reply({"m1": "Failed logins from 203.0.113.50.", "m2": "Failed logins from 203.0.113.50."}))
    out = _ask(dd, "@pair", chat, monkeypatch)
    m1, m2 = out.answer.machines
    assert m1.passed
    assert not m2.passed and "203.0.113.50, which appears in nothing Kratos read" in m2.notes


# --- digest ---------------------------------------------------------------------------


def test_digest_is_capped_orders_serious_first_and_counts_what_it_shortened(dd, lab):
    from kratos.fleet import digest

    lab.reports[C] = make_report(C, [HIGH])
    res = fleet_collect.collect_fleet([A, B, C, D, E], dd, max_parallel=5, machine_seconds=20)
    ids = digest.assign_ids(res)
    d = digest.build("q", res, ids=ids, time_block="", cap=2500, run_tag="t", outside_scope=2)
    assert len(d.text) < 4000 and d.shortened
    assert f"{len(d.shortened)} machine block(s) were shortened" in d.text
    assert d.text.index("MACHINE m3") < d.text.index("MACHINE m1")      # the HIGH machine first
    assert "2 machine(s) in this group are outside the asker's access" in d.text


def test_machine_text_in_the_digest_is_cleaned(dd, lab, monkeypatch):
    from kratos.fleet import digest

    corpus = json.loads((Path(__file__).parent / "fixtures/untrusted/corpus.json").read_text())
    nasty = next(v for k, v in corpus.items() if k.startswith("ansi"))
    nasty = nasty if isinstance(nasty, str) else str(nasty.get("text") or nasty.get("value") or nasty)
    (r,) = fleet_collect.collect_fleet([A], dd, max_parallel=1, machine_seconds=20)
    r.label = nasty
    text = digest.machine_block("m1", r)
    framed = digest.build("q", [r], ids={"m1": A}, time_block="", cap=20000, run_tag="t").text
    assert "\x1b" not in framed and "<<machine run=t" in framed and text


# --- scope, budget, notification, fix channel ---------------------------------------


def test_a_token_scope_gets_only_its_machines_and_the_outside_line(dd, lab, monkeypatch):
    G.create_group(dd, "lab", ME, members=[A, B, C, D, E])
    chat = Chat(_machines_reply({"m1": "Nothing new.", "m2": "Nothing new."}))
    out = _ask(dd, "@lab", chat, monkeypatch, scope=[A, B], source="web",
               )
    assert sorted(lab.prepared) == [A, B]
    assert "3 machine(s) in this group are outside your access" in out.text
    assert all(m not in chat.prompts[0] for m in (C, D, E))


def test_an_unattended_group_question_over_the_cap_is_refused_before_any_read(dd, lab, monkeypatch):
    from kratos import settings_store

    G.create_group(dd, "lab", ME, members=[A, B, C, D, E])
    settings_store.set("budget.run_tokens", 1000, data_dir=dd, actor="test")
    chat = Chat()
    out = _ask(dd, "@lab", chat, monkeypatch, source="schedule")
    assert out.status == "refused_by_budget" and "per-run limit" in out.text
    assert lab.prepared == [] and chat.prompts == []


def test_the_estimate_is_shown_and_a_no_stops_before_any_read(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    seen: list[str] = []
    out = _ask(dd, "@pair", Chat(), monkeypatch, confirm=lambda est: seen.append(est.text()) or False)
    assert out.status == "cancelled" and lab.prepared == []
    assert "2 machine(s) collected by Kratos, then one model call" in seen[0]


def test_one_grouped_notification_per_fleet_run(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    sent: list[tuple[str, str]] = []
    out = fleet_run.run_fleet(fleet_run.FleetRequest(
        question="", group="@pair", data_dir=dd, actor=Actor("schedule:nightly", "schedule"), source="schedule",
        kind="audit", notify=True, notifier=lambda m, s: sent.append((m, s)) or {"status": "sent"}, name="nightly"))
    assert out.status == "audit" and out.notified and len(sent) == 1
    msg, sev = sent[0]
    assert msg.startswith("HIGH on @pair:") and "PRIV-001" in msg and sev == "critical"
    assert "bob" not in msg                                 # no accounts in a phone notification


def test_fleet_runs_are_recorded_per_machine(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.down[B] = "Connection refused"
    out = _ask(dd, "@pair", Chat(_machines_reply({"m1": "Nothing new."})), monkeypatch)
    (run,) = fleet_record.recent(dd)
    assert run["group_ref"] == "@pair" and run["actor"] == "alice" and run["interface"] == "cli"
    rows = {r["machine"]: r for r in fleet_record.machines_of(dd, run["run_id"])}
    assert rows[A]["outcome"] == "ok" and rows[A]["passed"] == 1
    assert rows[B]["outcome"] == "unreachable" and rows[B]["passed"] is None and "refused" in rows[B]["reason"]
    assert out.run_id == run["run_id"]


def test_a_fleet_run_needs_an_actor(dd, lab):
    with pytest.raises(fleet_run.FleetError):
        fleet_run.run_fleet(fleet_run.FleetRequest(question="q", group=[A], data_dir=dd, actor=None))  # type: ignore[arg-type]


def test_fix_channel_refusal_text_names_the_single_machine_path():
    assert "/look" in fleet_run.FIX_CHANNEL_REFUSAL and "/run-fix" in fleet_run.FIX_CHANNEL_REFUSAL


def test_extra_read_tools_never_include_execution_or_approval_tools():
    allowed = set(fleet_answer.extra_read_tools())
    assert allowed and not allowed & {"run_linux_command", "capture_traffic", "send_notification",
                                      "parse_auth_log", "collect_system_context", "check_ip_reputation",
                                      "run_vuln_scan"}


# --- surfaces -------------------------------------------------------------------------


def _client(*targets: str):
    from kratos.serve.auth import Client

    return Client(token_id="tok1", name="t", targets=tuple(targets), doors=("openai", "mcp"))


def test_chat_models_list_groups_the_token_can_see_and_scope_stays_machines(dd):
    from kratos.serve import openai_routes as O

    G.create_group(dd, "lab", ME, members=[A, B, C])
    G.create_group(dd, "far", ME, members=[D, E])
    client = _client(A, B)
    # @all is listed (two of its machines are visible); @far isn't (none are)
    assert O.group_models_for(client, dd) == [("kratos/@all", "@all"), ("kratos/@lab", "@lab")]
    assert O.target_for_model(client, "kratos/@lab", dd) == "@lab"
    assert O.target_for_model(client, "kratos/@far", dd) is None
    assert O.target_for_model(client, "kratos/@lab") is None          # no data folder: machines only
    assert O.scope_machines(client) == [A, B]


def test_a_chat_fleet_turn_is_narrowed_to_the_tokens_machines_and_refuses_commands(dd, monkeypatch):
    import asyncio

    from kratos.serve import openai_routes as O

    seen: dict[str, Any] = {}

    def fake_run(req):
        seen.update(scope=list(req.scope), actor=req.actor, source=req.source, group=req.group)
        return fleet_run.FleetOutcome("final_answer", "summary", group_label="@lab")

    monkeypatch.setattr(fleet_run, "run_fleet", fake_run)

    class Slots:
        def acquire(self, **kw):
            return True

        def release(self):
            pass

    state = type("S", (), {"data_dir": dd, "slots": Slots(), "note_runs": lambda self: None})()

    async def go(message):
        h = O.TurnHandle()
        O._serve_fleet_turn(h, state=state, client=_client(A, B), group="@lab", message=message, session_id="s",
                            link_hosts=[])
        return h.result

    res = asyncio.run(go("/run-fix"))
    assert "never runs a fix on several machines" in res["content"] and not seen
    asyncio.run(go("who gained sudo?"))
    assert seen["scope"] == [A, B] and seen["source"] == "web"
    assert seen["actor"].interface == "serve" and seen["actor"].user == "token:tok1"


def test_mcp_stdio_investigate_with_a_group_is_a_fleet_question(dd, lab, monkeypatch):
    from kratos import mcp_server

    G.create_group(dd, "pair", ME, members=[A, B])
    lab.down[B] = "Connection refused"
    monkeypatch.setattr(llm_interface, "agent_chat", Chat(_machines_reply({"m1": "Nothing new."})))
    out = mcp_server._mcp_investigation("who gained sudo?", "@pair", 5, dd)
    assert out["fleet"]["group"] == "@pair"
    assert [(m["machine"], m["outcome"]) for m in out["fleet"]["machines"]] == [(A, "ok"), (B, "unreachable")]
    assert "Connection refused" in out["final_answer"]


def test_a_schedule_on_a_group_sends_one_grouped_notification(dd, lab, monkeypatch):
    from kratos.agent import scheduled_run, schedules

    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    schedules.save_schedule(dd, name="nightly", kind="audit", target="@pair", cadence="daily", deliver=["ntfy"])
    sched = schedules.load_schedule(dd, "nightly")
    sent: list[str] = []
    rec = scheduled_run.run_scheduled(sched, dd, notifier=lambda m, s: sent.append(m) or {"status": "sent"})
    assert rec["fleet"] and rec["status"] == "completed" and rec["machines"] == {A: "ok", B: "ok"}
    assert len(sent) == 1 and sent[0].startswith("HIGH on @pair")
    assert lab.prepared.count(A) == 1 and lab.prepared.count(B) == 1


def test_hunt_group_scopes_to_the_groups_machines_and_never_widens(dd):
    from kratos.hunt import front

    G.create_group(dd, "lab", ME, members=[A, B, C])
    req = front.parse_command("203.0.113.9 --group lab")
    assert front.resolve_hunt(req, data_dir=dd).machines == [A, B, C]
    req = front.parse_command("203.0.113.9 --group lab")
    assert front.resolve_hunt(req, scope=[A], data_dir=dd).machines == [A]


def test_a_fleet_answer_may_not_invent_an_act_decision_for_a_machine(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[A] = make_report(A, [HIGH])
    chat = Chat(_machines_reply({"m1": "An Act decision is required because of PRIV-001.", "m2": "No Act decision."}),
                _machines_reply({"m1": "PRIV-001: bob gained sudo; there is no Act decision.", "m2": "No Act decision."}))
    out = _ask(dd, "@pair", chat, monkeypatch, question="Which machines have an Act decision?")
    assert "MACHINE m1: REJECTED (decision not made by Kratos)" in chat.prompts[1]
    assert "MACHINE m2: REJECTED" not in chat.prompts[1]
    assert all(m.passed for m in out.answer.machines)


def test_a_machine_whose_period_could_not_be_measured_is_partly_read_not_fully(dd, lab, monkeypatch):
    orig = lab.dispatch

    def failing(tool, args, data_dir):
        if tool == "measure_auth_activity" and kratos_config.get_active_target() == B:
            return {"status": "error", "observation": "measurement failed: No route to host"}
        return orig(tool, args, data_dir)

    from kratos.collect import runner

    monkeypatch.setattr(runner, "_default_dispatch", lambda: failing)
    G.create_group(dd, "pair", ME, members=[A, B])
    # m2's period was never measured: Guard 6 sends m2 back (twice), then NOTEs it.
    chat = Chat(*[_machines_reply({"m1": "Nothing new.", "m2": "Nothing new."})] * 3)
    out = _ask(dd, "@pair", chat, monkeypatch)
    by = {r.machine: r for r in out.results}
    assert "MACHINE m2: REJECTED (time period not queried)" in chat.prompts[1]
    assert by[A].outcome == "ok"
    assert by[B].outcome == "partial" and "not measured (measurement failed: No route to host)" in by[B].reason
    assert "1 partly read" in out.answer.summary


def test_a_machine_kratos_read_may_not_be_called_unreachable(dd, lab, monkeypatch):
    G.create_group(dd, "pair", ME, members=[A, B])
    lab.reports[B] = make_report(B, statuses=("ok", "skipped"))
    chat = Chat(_machines_reply({"m1": "Nothing new.", "m2": "Machine unreachable; status unknown."}),
                _machines_reply({"m1": "Nothing new.", "m2": "Machine unreachable."}),
                _machines_reply({"m1": "Nothing new.", "m2": "Machine unreachable."}))
    out = _ask(dd, "@pair", chat, monkeypatch)
    assert "MACHINE m2: REJECTED (called unreachable): Kratos DID read m2 (partly read" in chat.prompts[1]
    m2 = out.answer.machines[1]
    assert not m2.passed and "the answer's \"unreachable\" is wrong" in m2.notes
    assert fleet_answer.called_unreachable("It was not unreachable.") is False


def test_fifty_machines_stay_bounded_and_every_one_is_in_the_digest(dd, lab, monkeypatch):
    from kratos.fleet import digest

    machines = [f"10.1.0.{i}" for i in range(1, 51)]
    for m in machines[:3]:
        lab.reports[m] = make_report(m, [HIGH])
    t0 = time.monotonic()
    res = fleet_collect.collect_fleet(machines, dd, max_parallel=4, machine_seconds=20)
    wall = time.monotonic() - t0
    assert lab.max_active <= 4 and all(r.outcome == "ok" for r in res)
    assert wall < 50 * 0.05                                  # parallel: well under the serial time
    d = digest.build("q", res, ids=digest.assign_ids(res), time_block="", cap=16000, run_tag="t")
    assert len(d.text) <= 16000                              # the cap holds
    assert d.shortened and f"{len(d.shortened)} machine block(s) were shortened" in d.text
    assert all(f"MACHINE m{i} " in d.text for i in range(1, 51))      # nobody silently dropped
    first = d.text.index("MACHINE m1 ")
    assert first < d.text.index("MACHINE m4 ")              # the HIGH machines lead


def test_scope_is_applied_before_duplicates_so_no_out_of_scope_name_is_shown(dd):
    """Security review: a token scoped to A saw "B is A (counted once)" for a twin address
    B of its own machine, and "D is C" for another machine it may not see at all."""
    import sqlite3

    from kratos.storage.subagent_store import SubAgentStore

    SubAgentStore(dd / "kratos.db")
    conn = sqlite3.connect(dd / "kratos.db")
    for tid in ("tgt_1", "tgt_2"):
        conn.execute("INSERT INTO subagent_targets (target_id, name, token, paired_at) VALUES (?, ?, ?, 'x')",
                     (tid, tid, tid + "tok"))
    for host, tid in (("10.0.0.12", "tgt_1"), ("10.0.0.11", "tgt_1"), ("10.0.0.13", "tgt_2"), ("10.0.0.14", "tgt_2")):
        conn.execute("INSERT INTO subagent_links (host, target_id, mode, created_at, updated_at) "
                     "VALUES (?, ?, 'subagent', 'x', 'x')", (host, tid))
    conn.commit()
    conn.close()
    G.create_group(dd, "web", ME, members=[B, A, C, D])   # B is A's twin (listed first), C and D one other box
    r = G.resolve(dd, "@web", scope=[A])
    assert r.machines == [A]                              # the in-scope alias is kept, not dropped for B
    assert r.duplicates == []                             # nothing outside the scope is named
    assert r.outside_scope == 1                           # C+D are one machine; B is A itself
    full = G.resolve(dd, "@web")
    assert full.machines == [B, C] and full.duplicates == [(A, B), (D, C)]
