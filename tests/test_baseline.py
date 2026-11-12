"""E.3 learning and judging: what's normal per machine, from stored history (spec §6, §8)."""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import timedelta

import pytest

from _baseline_history import END, add_logins, at, machine, normal_days, raised, run, set_zone, write
from kratos.baseline import buckets as B
from kratos.baseline import judge as J
from kratos.baseline import learn as L


def _ready(tmp_path, *, zone="UTC", target=None, days=21, extra=None, gaps=None, note=None, seed=1):
    m = machine(0, zone=zone, target=target, seed=seed)
    normal_days(m, days=days)
    if extra:
        extra(m)
    return m, write(tmp_path / "home", [m], days=days, gaps=gaps, note=note)


def _dims(doc):
    return {n: s["status"] for n, s in doc["dims"].items()}


# ---------------------------------------------------------------- learning period
def test_learning_period_no_findings(tmp_path):
    m, data = _ready(tmp_path, days=2, extra=lambda m: m.logins.append(
        (END.timestamp() - 3 * 3600, "deploy", "192.0.2.9", "password")))
    doc = run(data, m.target)
    assert doc["deviations"] == []
    for name in ("login_source", "login_time", "login_method", "sudo_use", "listener", "outbound"):
        s = doc["dims"][name]
        assert s["status"] == "learning", (name, s)
        assert "of 14 covered days" in s["learning"]
    from kratos.baseline import findings, record

    note = [f for f in findings.build(doc) if f.id == "BASE-007"][0]
    assert any("still learning" in ln and "no deviation reported yet" in ln for ln in note.evidence)
    assert "still learning" in record.summary_line(doc) and "nothing unusual" not in record.summary_line(doc)
    assert [f.id for f in findings.build(doc)] == ["BASE-007"]


def test_coverage_aware_learning(tmp_path):
    gap = ((END - timedelta(days=16)).timestamp(), (END - timedelta(days=7)).timestamp())
    m, data = _ready(tmp_path, gaps=[gap], note="log sync was stopped")
    doc = run(data, m.target)
    s = doc["dims"]["login_source"]
    assert s["status"] == "learning"
    assert s["covered_days"] < 14 and s["learned_days"] >= 20
    assert "log sync was stopped" in s["learning"]           # the gap is named
    assert doc["dims"]["listener"]["status"] == "active"       # snapshot days are counted on their own


def test_covered_days_need_twenty_hours():
    day = 86400
    spans = [(0, 19 * 3600), (day, day + 21 * 3600), (2 * day, 2 * day + 10 * 3600), (2 * day + 10 * 3600,
                                                                                       2 * day + 22 * 3600)]
    assert L.covered_days_from_spans(spans) == [1, 2]


def test_not_learnable_dimension(tmp_path):
    m, data = _ready(tmp_path)
    doc = run(data, m.target)
    assert doc["dims"]["program"]["status"] == "not_learnable"
    assert "no auditd" in doc["dims"]["program"]["reason"]
    assert doc["dims"]["login_source"]["status"] == "active"


def test_unreadable_source(tmp_path):
    m = machine(0)
    normal_days(m)
    m.logins.clear()
    m.sudo.clear()
    data = write(tmp_path / "home", [m], gaps=[((END - timedelta(days=30)).timestamp(), END.timestamp())],
                 note="/var/log/auth.log can't be read by the SSH user")
    doc = run(data, m.target)
    for name in ("login_source", "login_method", "sudo_use"):
        assert doc["dims"][name]["status"] == "not_learnable"
        assert "can't be read by the SSH user" in doc["dims"][name]["reason"]
    assert doc["dims"]["listener"]["status"] == "active"
    assert doc["deviations"] == []


# ---------------------------------------------------------------- detection
def test_planted_deviations_are_raised_with_the_usual_pattern(tmp_path):
    m = machine(0)
    normal_days(m)
    for p in ("new_source", "odd_hour", "password", "sudo_root", "listener", "outbound"):
        m.plant(p, END)
    data = write(tmp_path / "home", [m])
    doc = run(data, m.target)
    planted = {(p["rule"], p["subject"], p["key"]) for p in m.planted}
    assert planted <= raised(doc)
    by = {(d["rule"], d["subject"]): d for d in doc["deviations"]}
    src = by[("BASE-001", "deploy")]
    assert src["usual"][0] == "from 10.20.0.0/24"          # the new bucket isn't listed as usual
    assert "weekdays 08:00-18:59" in "; ".join(src["usual"])
    assert by[("BASE-003", "deploy")]["severity"] == "medium"
    assert by[("BASE-004", "carol")]["severity"] == "medium"
    assert by[("BASE-005", "/tmp/.x/nc")]["severity"] == "low"
    assert "learned over" in src["learned"]


def test_severity_never_above_medium():
    for sev in ("info", "low", "medium", "high", "critical"):
        assert J.RANK[J.cap(sev)] <= J.RANK["medium"]
    dev = L.Deviation("login_source", "BASE-001", "root", "192.0.2.0/24", 0.0, "new", {"class": "public"})
    assert J.severity(dev, privileged={"root"}, sudo_users=set()) == "medium"
    dev2 = L.Deviation("login_method", "BASE-003", "root", "password", 0.0, "new", {})
    assert J.severity(dev2, privileged={"root"}, sudo_users=set()) == "medium"


def test_public_source_for_a_privileged_account_is_medium(tmp_path):
    def extra(m):
        m.logins.append((at("2026-11-11T10:00"), "alice", "203.0.113.50", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    doc = run(data, m.target)
    d = [d for d in doc["deviations"] if d["rule"] == "BASE-001" and d["subject"] == "alice"][0]
    assert d["key"] == "203.0.113.0/24" and d["severity"] == "medium"


def test_own_logins_set_aside(tmp_path):
    m, data = _ready(tmp_path)
    doc = run(data, m.target)
    assert doc["own_set_aside"] >= 21 * 24 * 2 - 48
    con = sqlite3.connect(data / "kratos.db")
    subjects = {r[0] for r in con.execute("SELECT DISTINCT subject FROM baseline_entries WHERE dim IN "
                                          "('login_source', 'login_method', 'login_time', 'sudo_use')")}
    assert "ubuntu" not in subjects and {"deploy", "alice", "backup"} <= subjects
    assert all(d["subject"] != "ubuntu" for d in doc["deviations"])


def test_single_source_nat(tmp_path):
    m = machine(0)
    normal_days(m)
    m.logins = [(ts, u, "10.9.9.9" if method != "own" else ip, method) for ts, u, ip, method in m.logins]
    data = write(tmp_path / "home", [m])
    doc = run(data, m.target)
    assert not [d for d in doc["deviations"] if d["rule"] == "BASE-001"]
    con = sqlite3.connect(data / "kratos.db")
    keys = {r[0] for r in con.execute("SELECT DISTINCT key FROM baseline_entries WHERE dim = 'login_source'")}
    assert keys == {"10.9.9.0/24"}


def test_bucket_classes():
    assert B.bucket("100.101.5.6") == B.Bucket("100.101.5.0/24", "tailnet")
    assert B.bucket("10.1.2.3").cls == "private" and B.bucket("192.168.4.4").cls == "private"
    assert B.bucket("169.254.1.1").cls == "link-local"
    assert B.bucket("127.0.0.1") == B.Bucket("loopback", "loopback")
    assert B.bucket("203.0.113.9") == B.Bucket("203.0.113.0/24", "public")
    assert B.bucket("8.8.4.4").cls == "public"
    assert B.bucket("not-an-ip").cls == "unknown" and not B.bucket("not-an-ip").public
    for private in ("10.0.0.1", "100.64.0.1", "172.16.5.5", "fd00::1", "fe80::1"):
        assert not B.bucket(private).public, private


def test_ipv6_buckets():
    a, b = B.bucket("2001:db8:aaaa:1:1111:2222:3333:4444"), B.bucket("2001:db8:aaaa:7:9999:8888:7777:6666")
    assert a == b and a.bucket == "2001:db8:aaaa::/48" and a.cls == "public"
    u1, u2 = B.bucket("fd12:3456:789a:1::5"), B.bucket("fd12:3456:789a:1:abcd::9")
    assert u1 == u2 and u1.cls == "ula" and u1.bucket.endswith("/64")
    assert B.bucket("::ffff:10.0.0.7") == B.bucket("10.0.0.7")


def test_dynamic_ip_budget(tmp_path):
    def extra(m):
        day = at("2026-11-10T10:00")
        for n in range(12):                      # twelve new public /24s in one day
            m.logins.append((day + n * 60, "alice", f"198.18.{n}.5" if False else f"192.0.{n}.5", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    doc = run(data, m.target)
    that_day = [d for d in doc["deviations"] if d["machine_time"].startswith("2026-11-10")]
    assert len(that_day) <= 5
    assert doc["today"]["over_budget"] >= 7
    from kratos.baseline import findings

    note = [f for f in findings.build(doc) if f.id == "BASE-007"][0]
    assert any("beyond the daily limit" in ln for ln in note.evidence)


def test_daily_budget(tmp_path):
    def extra(m):
        t = at("2026-11-11T13:00")
        for n in range(20):
            m.sudo.append((t + n * 30, "alice", "root", f"/usr/local/bin/tool{n}"))
    m, data = _ready(tmp_path, extra=extra)
    doc = run(data, m.target)
    assert len([d for d in doc["deviations"] if d["machine_time"].startswith("2026-11-11")]) == 5
    assert doc["today"]["over_budget"] >= 15


def test_cooldown_and_snapshot_keeps_the_day(tmp_path):
    m = machine(0)
    normal_days(m)
    m.plant("listener", END)
    data = write(tmp_path / "home", [m])
    first = run(data, m.target)
    assert ("BASE-005", "/tmp/.x/nc", "tcp/4444") in raised(first)
    again = run(data, m.target, now=END.timestamp() + 600)
    assert ("BASE-005", "/tmp/.x/nc", "tcp/4444") in raised(again)          # still today's deviation
    assert len([d for d in again["deviations"] if d["rule"] == "BASE-005"]) == 1
    later = run(data, m.target, now=END.timestamp() + 2 * 86400)
    assert not raised(later)                                               # a day later: gone (inactive)


def test_automation_account(tmp_path):
    m, data = _ready(tmp_path)
    doc = run(data, m.target)
    assert not [d for d in doc["deviations"] if d["subject"] == "backup"]
    con = sqlite3.connect(data / "kratos.db")
    hours = {r[0] for r in con.execute("SELECT key FROM baseline_entries WHERE dim = 'login_time' AND "
                                       "subject = 'backup'")}
    assert len(hours) == 48                                              # every hour, weekday and weekend


def test_dst_hours(tmp_path):
    m = machine(0, zone="Europe/Helsinki")
    for day in range(21):
        local = (END.astimezone(m.zone) - timedelta(days=21 - day)).replace(hour=8, minute=10, second=0,
                                                                              microsecond=0)
        if local.weekday() < 5:
            for k in range(3):
                m.logins.append(((local + timedelta(minutes=k)).timestamp(), "deploy", "10.20.0.5", "publickey"))
    data = write(tmp_path / "home", [m])
    set_zone(data, m.target, "Europe/Helsinki", stamp=5)
    doc = run(data, m.target)
    con = sqlite3.connect(data / "kratos.db")
    keys = {r[0] for r in con.execute("SELECT key FROM baseline_entries WHERE dim = 'login_time' AND "
                                      "subject = 'deploy'")}
    assert keys == {"08 weekday"}, keys                       # the same hour on both sides of 25 October
    assert doc["zone"] == "Europe/Helsinki"


def test_tz_change_relearn(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    set_zone(data, m.target, "America/New_York", stamp=50)
    add_logins(data, m.target, [(END.timestamp() + 3600 * h, "deploy", "10.20.0.5", "publickey") for h in range(1, 4)])
    doc = run(data, m.target, now=END.timestamp() + 5 * 3600)
    s = doc["dims"]["login_time"]
    assert s["generation"] == 2 and s["status"] == "learning"
    assert not [d for d in doc["deviations"] if d["rule"] == "BASE-002"]      # no flood of "unusual hour"
    assert any("time zone changed from UTC to America/New_York" in n for n in doc["notes"])
    con = sqlite3.connect(data / "kratos.db")
    old = con.execute("SELECT ended_at, note FROM baseline_profiles WHERE dim = 'login_time' AND generation = 1"
                      ).fetchone()
    assert old[0] is not None                              # kept, labelled as history
    assert doc["dims"]["login_source"]["generation"] == 1  # the other kinds keep learning
    from kratos.baseline import present

    v = present.view(data, m.target)
    assert any(h["dim"] == "login_time" and h["generation"] == 1 for h in v["history"])


def test_skew(tmp_path):
    def extra(m):
        m.logins.append((END.timestamp() - 300, "deploy", "192.0.2.44", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    doc = run(data, m.target, now=END.timestamp() - 600)        # Kratos's clock 10 minutes behind the machine
    d = [d for d in doc["deviations"] if d["rule"] == "BASE-001"][0]
    assert d["key"] == "192.0.2.0/24" and d["machine_time"].startswith("2026-11-12 11:55")


def test_renamed_account(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    ctx = data / "context"
    for f in ctx.glob("privileged_accounts_*.json"):
        doc = json.loads(f.read_text())
        doc["local_accounts"] = ["root", "alice", "backup", "ubuntu"]     # deploy is gone
        f.write_text(json.dumps(doc))
    from kratos.baseline import present

    v = present.view(data, m.target)
    tops = [t for d in v["dims"] if d["name"] == "login_source" for t in d["top"]]
    assert [t["gone"] for t in tops if t["subject"] == "deploy"] == [True]
    assert not [t for t in tops if t["subject"] == "alice" and t["gone"]]
    assert "account no longer on the machine" in present.to_text(v)


def test_event_cap(tmp_path):
    from kratos import settings_store
    from kratos.baseline import settings as BS

    m, data = _ready(tmp_path)
    settings_store.set(BS.MAX_EVENTS_PER_RUN, 1000, data_dir=data, actor="test")
    doc = run(data, m.target)
    assert doc["read"]["events"] == 1000 and doc["read"]["waiting_events"] > 0
    assert not doc["complete"] and any("wait for the next run" in g for g in doc["coverage_gaps"])
    for _ in range(10):
        doc = run(data, m.target)
        if doc["complete"]:
            break
    assert doc["complete"] and doc["read"]["waiting_events"] == 0


def test_eviction_no_false_new(tmp_path):
    from kratos import settings_store
    from kratos.baseline import settings as BS

    def extra(m):
        t = at("2026-10-25T10:00")
        for n in range(80):
            m.sudo.append((t + n * 60, "alice", "root", f"/opt/once/tool{n}"))
    m, data = _ready(tmp_path, extra=extra)
    settings_store.set(BS.MAX_ENTRIES, 50, data_dir=data, actor="test")
    first = run(data, m.target)
    assert first["dims"]["sudo_use"]["evicted"] > 0
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT evicted_at IS NOT NULL FROM baseline_entries WHERE dim = 'sudo_use' AND "
                       "key = 'as root: tool3'").fetchone()[0] == 1          # set aside, never deleted
    add_logins(data, m.target, [], sudo=[(END.timestamp() + 600, "alice", "root", "/opt/once/tool3")])
    doc = run(data, m.target, now=END.timestamp() + 900)
    assert ("BASE-004", "alice", "as root: tool3") not in raised(doc)   # evicted, but known: not "first time"
    assert con.execute("SELECT evicted_at IS NULL FROM baseline_entries WHERE dim = 'sudo_use' AND "
                       "key = 'as root: tool3'").fetchone()[0] == 1          # back in use


def test_repair_keeps_profile(tmp_path):
    m, data = _ready(tmp_path)
    run(data, m.target)
    doc = run(data, f"ubuntu@{m.target}", now=END.timestamp() + 60)     # the same machine, re-paired / respelled
    assert doc["dims"]["login_source"]["status"] == "active"
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT COUNT(DISTINCT target_key) FROM baseline_profiles").fetchone()[0] == 1


def test_same_hostname_separate(tmp_path):
    a, b = machine(0, target="10.200.0.31"), machine(1, target="10.200.0.32")
    normal_days(a)
    normal_days(b)
    b.logins = [(ts, u, "10.77.0.5" if method != "own" else ip, method) for ts, u, ip, method in b.logins]
    data = write(tmp_path / "home", [a, b])
    run(data, a.target)
    run(data, b.target)
    con = sqlite3.connect(data / "kratos.db")
    ka = {r[0] for r in con.execute("SELECT key FROM baseline_entries WHERE target_key = ? AND dim = 'login_source'",
                                    (a.target,))}
    kb = {r[0] for r in con.execute("SELECT key FROM baseline_entries WHERE target_key = ? AND dim = 'login_source'",
                                    (b.target,))}
    assert "10.77.0.0/24" in kb and "10.77.0.0/24" not in ka


def test_poisoning_hold_and_release(tmp_path):
    attack = at("2026-11-11T10:00")

    def extra(m):
        m.logins.append((attack + 300, "deploy", "192.0.2.66", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    from kratos.lifecycle import store as LS

    with LS.opened(data) as conn:
        conn.execute("INSERT INTO finding_records (finding_key, rule_id, target, subject, kind, state, severity, "
                     "title, entities, latest, first_seen, last_seen, times_seen) VALUES ('k1', 'PERSIST-003', ?, "
                     "'', 'condition', 'open', 'high', 't', '[]', '{}', ?, ?, 1)", (m.target, attack, attack + 9e4))
    doc = run(data, m.target)
    d = [d for d in doc["deviations"] if d["rule"] == "BASE-001"][0]
    assert d["held"] and doc["held_back"] >= 1                  # still raised, not learned
    con = sqlite3.connect(data / "kratos.db")
    row = con.execute("SELECT weight, count, held FROM baseline_entries WHERE dim = 'login_source' AND "
                      "subject = 'deploy' AND key = '192.0.2.0/24'").fetchone()
    assert row[1] == 0 and json.loads(row[2])["k1"][0] == 1
    with LS.opened(data) as conn:
        conn.execute("UPDATE finding_records SET state = 'false_positive' WHERE finding_key = 'k1'")
    doc2 = run(data, m.target, now=END.timestamp() + 600)
    assert doc2["released"] >= 1
    row = con.execute("SELECT weight, count, held FROM baseline_entries WHERE dim = 'login_source' AND "
                      "subject = 'deploy' AND key = '192.0.2.0/24'").fetchone()
    assert row[1] == 1 and row[0] > 0 and json.loads(row[2]) == {}


def test_hold_window_is_one_hour_around_the_finding():
    holds = [L.Hold(1000.0 - 3600, 1000.0 + 3600, "k", "R")]
    assert L.held_by(holds, 1000.0 + 3599) is not None and L.held_by(holds, 1000.0 + 3601) is None


def test_hostile_names(tmp_path):
    hostile = "\x1b[31mevil\x1b]8;;http://x\x07[bold]x[/bold]\u202e"

    def extra(m):
        m.sudo.append((at("2026-11-11T10:00"), "alice", "root", f"/usr/bin/{hostile}"))
        m.logins.append((at("2026-11-11T11:00"), "[red]mallory[/red]", "192.0.2.5", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    doc = run(data, m.target)
    from kratos.baseline import findings, present

    for f in findings.build(doc):
        assert "mallory" not in f.title and "evil" not in f.title          # names never in a title
    for d in doc["deviations"]:
        assert "\x1b" not in d["key"] and "\x1b" not in d["subject"]     # control characters dropped
    text = present.to_text(present.view(data, m.target))
    assert "\x1b" not in text


def test_findings_have_literal_ids_and_entities_are_keys(tmp_path):
    m = machine(0)
    normal_days(m)
    m.plant("new_source", END)
    data = write(tmp_path / "home", [m])
    doc = run(data, m.target)
    from kratos.baseline import findings

    fs = {f.id: f for f in findings.build(doc)}
    f = fs["BASE-001"]
    assert f.subject == "deploy" and f.entities == ["192.0.2.0/24"] and f.source_ips == ["192.0.2.77"]
    assert "deploy" not in f.title and any(ln.startswith("Usual:") for ln in f.evidence)
    assert fs["BASE-007"].severity == "info"


def test_a_frozen_profile_raises_but_learns_nothing(tmp_path):
    m, data = _ready(tmp_path)
    from kratos.baseline import store as S

    run(data, m.target)
    with S.opened(data) as conn:
        conn.execute("UPDATE baseline_profiles SET frozen = 1")
    add_logins(data, m.target, [(END.timestamp() + 600, "deploy", "192.0.2.99", "publickey")])
    doc = run(data, m.target, now=END.timestamp() + 900)
    assert ("BASE-001", "deploy", "192.0.2.0/24") in raised(doc)
    assert doc["dims"]["login_source"]["status"] == "frozen"
    con = sqlite3.connect(data / "kratos.db")
    assert con.execute("SELECT COUNT(*) FROM baseline_entries WHERE key = '192.0.2.0/24'").fetchone()[0] == 0


def test_decay_halves_after_the_half_life():
    e = L.Entry("s", "k", 8.0, 0.0, 8, 0.0, 0.0)
    assert L.decayed(e, 30 * L.DAY, 30 * L.DAY) == pytest.approx(4.0)
    L.add_weight(e, 30 * L.DAY, 1.0, 30 * L.DAY)
    assert e.weight == pytest.approx(5.0)


def test_rare_key_is_raised_like_new(tmp_path):
    def extra(m):
        m.logins.append((at("2026-10-23T10:00"), "deploy", "192.0.2.20", "publickey"))   # once, three weeks ago
        m.logins.append((at("2026-11-11T10:00"), "deploy", "192.0.2.21", "publickey"))
    m, data = _ready(tmp_path, extra=extra)
    from kratos import settings_store
    from kratos.baseline import settings as BS

    settings_store.set(BS.HALF_LIFE_DAYS, 3, data_dir=data, actor="test")
    doc = run(data, m.target)
    d = [d for d in doc["deviations"] if d["rule"] == "BASE-001" and d["subject"] == "deploy"]
    assert d and d[0]["kind"] == "rare" and d[0]["seen_before"] == 1


def test_run_is_fast_on_three_weeks(tmp_path):
    m, data = _ready(tmp_path)
    t0 = time.monotonic()
    run(data, m.target)
    assert time.monotonic() - t0 < 10
