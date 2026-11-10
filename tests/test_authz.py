"""D.7 users and permissions: the permission table, scopes, fail-closed lookups, the audit
trail, token expiry and rotation, per-user sessions (docs/phaseD/D.7 §7)."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from kratos import authz
from kratos.authz import audit as AU
from kratos.authz import permissions as P
from kratos.authz import users as U
from kratos.lifecycle.decide import Actor

M1, M2, M3 = "192.0.2.10", "192.0.2.11", "192.0.2.12"


@pytest.fixture
def dd(tmp_path):
    from kratos import kratos_config

    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    return tmp_path


OWNER = authz.owner_actor("cli")


def _token(dd: Path, user: str, *, machines=(), mcp=True, name=None, days=None):
    from kratos.serve import auth

    token, row = auth.create_token(dd, name=name or f"{user}-t", user=user, targets=list(machines), mcp=mcp,
                                   expires=days)
    return token, row


def _serve_actor(dd: Path, name: str, row) -> Actor:
    u = U.find(dd, name)
    return Actor(user=u.name, interface="serve", user_id=u.user_id, credential=f"token:{row['token_id']}")


def _as_owner(fn, *a, **k):
    with authz.acting_as(OWNER):
        return fn(*a, **k)


def _people(dd):
    U.add_user(dd, "vic", "viewer", OWNER, scopes=[M1])
    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1, M2])
    U.add_user(dd, "ada", "admin", OWNER, scopes=[M1])
    out = {}
    for n in ("vic", "ivy", "ada"):
        _tok, row = _token(dd, n)
        out[n] = _serve_actor(dd, n, row)
    return out


# --- the table --------------------------------------------------------------------
@pytest.mark.parametrize("role", P.ROLES)
@pytest.mark.parametrize("action", sorted(P.ACTIONS))
def test_every_action_by_every_role_matches_the_table(dd, role, action):
    U.add_user(dd, "p", role, OWNER, scopes=[M1])
    _t, row = _token(dd, "p")
    actor = _serve_actor(dd, "p", row)
    expected = P.allowed(role, action) and action not in P.LOCAL_ONLY    # admin actions: never over the network
    if expected:
        authz.require(actor, action, data_dir=dd)
    else:
        with pytest.raises(authz.Denied):
            authz.require(actor, action, data_dir=dd)


def test_viewer_cannot_investigate_ask_a_fleet_retest_or_decide(dd):
    a = _people(dd)
    for action in (P.INVESTIGATE, P.FLEET_ASK, P.RETEST, P.FINDING_DECIDE):
        with pytest.raises(authz.Denied) as e:
            authz.require(a["vic"], action, M1, data_dir=dd)
        assert "viewers can't" in str(e.value) and "investigator access" in str(e.value)
    authz.require(a["vic"], P.FINDINGS_READ, M1, data_dir=dd)
    authz.require(a["vic"], P.HUNT, data_dir=dd)


def test_investigator_manages_nothing(dd):
    a = _people(dd)
    authz.require(a["ivy"], P.INVESTIGATE, M2, data_dir=dd)
    for action in sorted(P.LOCAL_ONLY):
        with pytest.raises(authz.Denied):
            authz.require(a["ivy"], action, data_dir=dd)


def test_admin_actions_are_refused_over_the_network_for_every_role_including_the_owner(dd):
    a = _people(dd)
    _t, row = _token(dd, "owner", name="own")
    owner_net = Actor(user="sysadmin", interface="serve", user_id="owner", credential=f"token:{row['token_id']}")
    for actor in (a["ada"], owner_net, Actor(user="x", interface="mcp", user_id="owner")):
        for action in sorted(P.LOCAL_ONLY):
            with pytest.raises(authz.Denied) as e:
                authz.require(actor, action, data_dir=dd)
            assert "Kratos computer" in str(e.value)
    authz.require(OWNER, P.USERS_MANAGE, data_dir=dd)        # the owner at the CLI: fine
    authz.require(authz.owner_actor("tui"), P.SETTINGS_CHANGE, data_dir=dd)


def test_unknown_action_is_a_programming_error(dd):
    with pytest.raises(ValueError):
        authz.require(OWNER, "findings.reed", data_dir=dd)


# --- scope -------------------------------------------------------------------------
def test_effective_scope_is_user_scope_and_token_machines(dd):
    from kratos.serve.openai_routes import scope_machines
    from kratos.serve import auth

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1, M2])
    _t, wide = _token(dd, "ivy", name="wide")
    _t, narrow = _token(dd, "ivy", machines=[M2, M3], name="narrow")
    for row, want in ((wide, [M1, M2]), (narrow, [M2])):           # M3 is in the token but not the user's scope
        actor = _serve_actor(dd, "ivy", row)
        with authz.acting_as(actor):
            assert scope_machines(auth.client_from_row(row), dd) == want
        with pytest.raises(authz.Denied):
            authz.require(actor, P.READ, M3, data_dir=dd)


def test_a_group_scope_follows_the_groups_membership(dd):
    from kratos.fleet import groups as G

    G.create_group(dd, "lab", OWNER, members=[M1])
    U.add_user(dd, "ivy", "investigator", OWNER, scopes=["@lab"])
    _t, row = _token(dd, "ivy")
    actor = _serve_actor(dd, "ivy", row)
    authz.require(actor, P.INVESTIGATE, M1, data_dir=dd)
    with pytest.raises(authz.Denied):
        authz.require(actor, P.INVESTIGATE, M2, data_dir=dd)
    G.add_members(dd, "lab", [M2], OWNER)
    authz.require(actor, P.INVESTIGATE, M2, data_dir=dd)            # joined the group -> now visible


def test_a_machine_outside_scope_is_not_named_in_the_refusal_as_existing(dd):
    a = _people(dd)
    with pytest.raises(authz.Denied) as e:
        authz.require(a["vic"], P.FINDINGS_READ, M3, data_dir=dd)
    assert "that you may see" in str(e.value)


def test_hunt_scope_comes_from_the_person_not_the_token(dd):
    from kratos.serve import auth
    from kratos.serve.openai_routes import visible_machines

    U.add_user(dd, "vic", "viewer", OWNER, scopes=[M1])
    _t, row = _token(dd, "vic", machines=[M1, M2, M3])
    with authz.acting_as(_serve_actor(dd, "vic", row)):
        assert visible_machines(auth.client_from_row(row), dd) == [M1]
    # no person attached (outside a request): a non-owner token sees nothing
    assert visible_machines(auth.client_from_row(row), dd) == []


def test_narrowing_scope_mid_run_stops_at_the_next_read(dd):
    from kratos import kratos_config
    from kratos.agent import loop as L
    from kratos.agent.tools import TOOL_REGISTRY, Tool

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1, M2])
    _t, row = _token(dd, "ivy")
    actor = _serve_actor(dd, "ivy", row)
    reads = []
    TOOL_REGISTRY["authz_probe"] = Tool(name="authz_probe", description="x", parameters={},
                                        handler=lambda: reads.append(kratos_config.get_active_target()) or {"ok": 1})
    try:
        with authz.acting_as(actor, action=P.INVESTIGATE), kratos_config.pinned_target(M2):
            assert L.execute_tool_call("authz_probe", {}, dd)["status"] == "ok"
            U.set_scopes(dd, "ivy", [M1], OWNER)                        # the owner narrows ivy mid-run
            with pytest.raises(authz.AccessRemoved) as e:
                L.execute_tool_call("authz_probe", {}, dd)
        assert f"your access to {M2} was removed" in str(e.value)
        assert reads == [M2]                                            # the second read never ran
    finally:
        TOOL_REGISTRY.pop("authz_probe", None)


@pytest.mark.parametrize("change", ["disable", "demote", "revoke"])
def test_disabling_demoting_or_revoking_also_stops_a_running_investigation(dd, change):
    from kratos import kratos_config
    from kratos.serve import auth

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1])
    _t, row = _token(dd, "ivy")
    actor = _serve_actor(dd, "ivy", row)
    with authz.acting_as(actor, action=P.INVESTIGATE), kratos_config.pinned_target(M1):
        authz.check_run_access(data_dir=dd)
        {"disable": lambda: U.set_disabled(dd, "ivy", True, OWNER),
         "demote": lambda: U.set_role(dd, "ivy", "viewer", OWNER),
         "revoke": lambda: _as_owner(auth.revoke, dd, row["token_id"])}[change]()   # the owner, elsewhere
        with pytest.raises(authz.AccessRemoved):
            authz.check_run_access(data_dir=dd)


# --- fail closed ---------------------------------------------------------------------
def test_every_lookup_failure_is_a_refusal_with_a_reason(dd, monkeypatch):
    a = _people(dd)
    cases = {
        "no actor": None,
        "no user id over the network": Actor(user="x", interface="serve"),
        "unknown user": Actor(user="x", interface="serve", user_id="u_nobody", credential=a["vic"].credential),
        "unknown interface": Actor(user="x", interface="carrier-pigeon", user_id="owner"),
        "bad credential": Actor(user="vic", interface="serve", user_id=a["vic"].user_id, credential="cookie:1"),
        "missing token": Actor(user="vic", interface="serve", user_id=a["vic"].user_id, credential="token:" + "0" * 12),
        "someone else's token": Actor(user="ivy", interface="serve", user_id=a["ivy"].user_id,
                                      credential=a["vic"].credential),
    }
    for why, actor in cases.items():
        with pytest.raises(authz.Denied) as e:
            authz.require(actor, P.FINDINGS_READ, M1, data_dir=dd)
        assert str(e.value), why
    # an unknown role in the record
    with sqlite3.connect(dd / "kratos.db") as c:
        c.execute("UPDATE users SET role = 'superuser' WHERE name = 'vic'")
    with pytest.raises(authz.Denied, match="not known"):
        authz.require(a["vic"], P.FINDINGS_READ, M1, data_dir=dd)
    # a scope that can't be read
    from kratos.authz import scope as SC

    monkeypatch.setattr(SC, "user_machines", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(authz.Denied, match="scope could not be read"):
        authz.require(a["ivy"], P.FINDINGS_READ, M1, data_dir=dd)
    # an audit row that can't be written: the action is not allowed
    monkeypatch.undo()
    monkeypatch.setattr(AU, "record", lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    with pytest.raises(authz.Denied, match="audit trail"):
        authz.require(a["ivy"], P.INVESTIGATE, M1, data_dir=dd)


def test_a_network_request_never_falls_back_to_the_owner(dd, monkeypatch):
    from kratos.run_context import run_scope

    with run_scope("web"):
        assert authz.current_actor() is None
    monkeypatch.setattr("kratos.authz.check._network_process", True)
    assert authz.current_actor() is None
    with pytest.raises(authz.AccessRemoved):
        authz.check_run_access(M1, data_dir=dd)


def test_the_owner_at_the_kratos_host_is_unchanged(dd):
    # existing single-owner installs: no users, no setup -- the owner may do everything, everywhere
    assert U.owner(dd).role == "admin"
    p = authz.require(OWNER, P.INVESTIGATE, "203.0.113.200", data_dir=dd)
    assert p.scope.every
    authz.check_run_access("203.0.113.200", data_dir=dd)


def test_the_owner_cannot_be_disabled_demoted_or_scoped(dd):
    for fn in (lambda: U.set_disabled(dd, "owner", True, OWNER), lambda: U.set_role(dd, "owner", "viewer", OWNER),
               lambda: U.set_scopes(dd, "owner", [M1], OWNER)):
        with pytest.raises(U.UserError):
            fn()


def test_user_management_is_refused_inside_a_tool_call_and_over_the_network(dd):
    from kratos import settings_store

    a = _people(dd)
    with settings_store.tool_call_scope("evil"):
        with pytest.raises(authz.Denied, match="agent tools"):
            U.add_user(dd, "mallory", "admin", OWNER)
    with pytest.raises(authz.Denied):
        U.add_user(dd, "mallory", "admin", a["ada"])


# --- the audit trail -----------------------------------------------------------------
def test_allowed_and_refused_actions_are_recorded_with_person_door_and_credential(dd):
    a = _people(dd)
    authz.require(a["ivy"], P.INVESTIGATE, M1, data_dir=dd, obj="look")
    with pytest.raises(authz.Denied):
        authz.require(a["vic"], P.INVESTIGATE, M1, data_dir=dd, obj="look")
    rows = AU.query(dd, action=P.INVESTIGATE)
    assert [(r["user_name"], r["result"]) for r in rows] == [("vic", "refused"), ("ivy", "allowed")]
    assert rows[0]["interface"] == "serve" and rows[0]["credential"].startswith("token:")
    assert rows[0]["reason"] and rows[0]["machine"] == M1


def test_audit_rows_cannot_be_changed_or_deleted_by_hand(dd):
    authz.require(OWNER, P.USERS_MANAGE, data_dir=dd)
    with sqlite3.connect(dd / "kratos.db") as c:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            c.execute("UPDATE audit_log SET result = 'refused'")
        with pytest.raises(sqlite3.IntegrityError, match="kratos audit prune"):
            c.execute("DELETE FROM audit_log")


def test_audit_prune_is_people_only_and_recorded(dd):
    a = _people(dd)
    old = time.time() - 400 * 86400
    AU.record(dd, interface="cli", action=P.READ, result="allowed", user_id="owner", now=old)
    with pytest.raises(authz.Denied):
        AU.prune(dd, time.time() - 365 * 86400, a["ada"])
    assert AU.prune_preview(dd, time.time() - 365 * 86400) == 1
    assert AU.prune(dd, time.time() - 365 * 86400, OWNER) == 1
    last = AU.query(dd, action=P.AUDIT_PRUNE)
    assert last and "removed 1 rows" in last[0]["object"]


# --- tokens: expiry and rotation -----------------------------------------------------
def test_an_expired_token_is_refused_with_its_date(dd):
    from kratos.serve import auth

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1])
    token, row = _token(dd, "ivy", days=1)
    with sqlite3.connect(dd / "kratos.db") as c:
        c.execute("UPDATE serve_tokens SET expires_at = ? WHERE token_id = ?", (time.time() - 60, row["token_id"]))
    client = auth.verify(dd, token)
    assert client is not None and client.expired and "expired on" in client.expired_text
    with pytest.raises(authz.Denied, match="expired on"):
        authz.require(_serve_actor(dd, "ivy", row), P.READ, data_dir=dd)


def test_new_tokens_expire_and_only_the_owner_may_have_one_that_never_does(dd):
    from kratos.serve import auth

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1])
    _t, row = _token(dd, "ivy")
    assert 89 * 86400 < row["expires_at"] - time.time() <= 90 * 86400
    with pytest.raises(auth.TokenError, match="only the owner"):
        _token(dd, "ivy", days="never", name="forever")
    _t, mine = auth.create_token(dd, name="mine", expires="never")
    assert mine["expires_at"] is None


def test_rotation_keeps_user_scope_and_doors_and_kills_the_old_token(dd):
    from kratos.serve import auth

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1, M2])
    old_token, old = _token(dd, "ivy", machines=[M2], mcp=True)
    new_token, new, _ = auth.rotate(dd, old["token_id"])
    assert (new["user_id"], new["targets"], new["doors"]) == (old["user_id"], old["targets"], old["doors"])
    assert auth.verify(dd, old_token) is None
    assert auth.verify(dd, new_token).user_id == old["user_id"]


def test_tokens_cannot_be_made_from_a_network_request(dd):
    from kratos.serve import auth
    from kratos.run_context import run_scope

    with run_scope("web"), pytest.raises(auth.TokenError):
        auth.create_token(dd, name="sneaky")


# --- sessions -------------------------------------------------------------------------
def test_sessions_belong_to_their_user_and_existing_ones_to_the_owner(dd):
    from kratos.storage.session_store import SessionStore

    store = SessionStore(dd / "kratos.db")
    mine = store.create_session([M1], "m")                          # at the CLI: the owner's
    a = _people(dd)
    with authz.acting_as(a["ivy"]):
        hers = store.create_session([M1], "m")
    assert store.get_session(mine)["owner_user_id"] == "owner"
    assert store.get_session(hers)["owner_user_id"] == a["ivy"].user_id
    assert [s["session_id"] for s in store.list_recent_sessions(owner_user_id=a["ivy"].user_id)] == [hers]
    assert {s["session_id"] for s in store.list_recent_sessions()} == {mine, hers}   # the owner's view: all


def test_a_session_with_no_person_attached_is_refused(dd):
    from kratos.run_context import run_scope
    from kratos.storage.session_store import SessionStore

    with run_scope("web"), pytest.raises(PermissionError):
        SessionStore(dd / "kratos.db").create_session([M1], "m")


def test_migration_gives_existing_tokens_and_sessions_to_the_owner(tmp_path):
    """A pre-D.7 kratos.db: tokens with no user column, sessions with no owner column."""
    db = tmp_path / "kratos.db"
    from kratos.serve import store as SS
    from kratos.storage.migrations import migrate

    c = sqlite3.connect(db)
    c.isolation_level = None
    migrate(c, "serve", (SS._step_1,))
    c.execute("INSERT INTO serve_tokens (token_id, name, secret_hash, salt, kdf, targets, doors, created_at, "
              "created_by) VALUES ('aaaaaaaaaaaa', 'old', 'x', 'y', '{}', '[\"192.0.2.10\"]', '[\"openai\"]', 1, 'cli')")
    c.execute("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, last_active_at TEXT "
              "NOT NULL, targets TEXT NOT NULL, model_backend TEXT, status TEXT NOT NULL DEFAULT 'active')")
    c.execute("INSERT INTO sessions VALUES ('s1', 'a', 'a', '[]', 'm', 'active')")
    c.close()
    row = SS.get_token(tmp_path, "aaaaaaaaaaaa")
    assert (row["user_id"], row["kind"], row["expires_at"], row["targets"]) == ("owner", "person", None,
                                                                               ["192.0.2.10"])
    from kratos.storage.session_store import SessionStore

    assert SessionStore(db).get_session("s1")["owner_user_id"] == "owner"
    assert U.owner(tmp_path).role == "admin"


def test_the_fleet_collector_skips_a_machine_whose_access_was_removed(dd, monkeypatch):
    from types import SimpleNamespace

    from kratos.adapters import ssh_remote
    from kratos.collect import runner
    from kratos.fleet import collect as FC

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1])            # M2 is no longer hers
    _t, row = _token(dd, "ivy")
    read = []
    monkeypatch.setattr(ssh_remote, "probe_reachable", lambda: (True, "", 0.0))

    def fake_prepare(host, data_dir, **kw):
        read.append(host)
        return SimpleNamespace(checks=[], correlation_step=None, disabled_reason="test", correlation=None)

    monkeypatch.setattr(runner, "prepare", fake_prepare)
    with authz.acting_as(_serve_actor(dd, "ivy", row), action=P.FLEET_ASK):
        results = FC.collect_fleet([M1, M2], dd, max_parallel=2, machine_seconds=20)
    by = {r.machine: r for r in results}
    assert by[M2].outcome == "access-removed" and M2 not in read
    assert "removed" in by[M2].status_text


def test_a_dropped_audit_trigger_comes_back_at_the_next_open(dd):
    authz.require(OWNER, P.USERS_MANAGE, data_dir=dd)
    with sqlite3.connect(dd / "kratos.db") as c:
        c.execute("DROP TRIGGER audit_log_no_delete")
    authz.require(OWNER, P.USERS_MANAGE, data_dir=dd)            # any recorded action reopens the store
    with sqlite3.connect(dd / "kratos.db") as c:
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("DELETE FROM audit_log")


@pytest.mark.parametrize("tool, args", [("parse_auth_log", {}), ("collect_system_context", {}),
                                        ("run_nmap_scan", {"target": "127.0.0.1"}),
                                        ("run_vuln_scan", {"target": "localhost"}),
                                        ("send_notification", {"message": "click here", "severity": "critical"})])
def test_a_scoped_person_cannot_make_the_model_read_the_kratos_host_or_page_the_owner(dd, tool, args):
    """Security review (D.7): the per-read check looked only at the run's machine; a scoped
    investigator could ask for the Kratos host's own logs, a loopback scan, or a push to the
    owner's phone."""
    from kratos import kratos_config
    from kratos.agent import loop as L
    from kratos.agent.tools import TOOL_REGISTRY

    U.add_user(dd, "ivy", "investigator", OWNER, scopes=[M1])
    _t, row = _token(dd, "ivy")
    ran = []
    real = TOOL_REGISTRY[tool]
    TOOL_REGISTRY[tool] = type(real)(name=tool, description=real.description, parameters=real.parameters,
                                     handler=lambda **k: ran.append(k) or {"ok": 1},
                                     requires_approval=False)
    try:
        with authz.acting_as(_serve_actor(dd, "ivy", row), action=P.INVESTIGATE), kratos_config.pinned_target(M1):
            out = L.execute_tool_call(tool, dict(args), dd)
    finally:
        TOOL_REGISTRY[tool] = real
    assert out["status"] == "error" and not ran
    assert AU.query(dd, result="refused", user="ivy")
    # the owner at the Kratos host is unaffected
    TOOL_REGISTRY[tool] = type(real)(name=tool, description=real.description, parameters=real.parameters,
                                     handler=lambda **k: ran.append(k) or {"ok": 1}, requires_approval=False)
    try:
        with kratos_config.pinned_target(M1):
            assert L.execute_tool_call(tool, dict(args), dd)["status"] == "ok"
    finally:
        TOOL_REGISTRY[tool] = real


def test_only_one_live_gateway_token_and_rotation_keeps_its_secret(dd):
    from kratos.authz import openwebui as OW
    from kratos.serve import auth

    _t, gw = auth.create_token(dd, name="gw", gateway=True)
    OW.write_secret(dd, gw["token_id"], "s" * 43)
    with pytest.raises(auth.TokenError, match="one shared Open WebUI"):
        auth.create_token(dd, name="gw2", gateway=True)
    _t, new, _old = auth.rotate(dd, "gw")
    assert new["kind"] == "gateway" and OW.read_secret(dd, new["token_id"]) == "s" * 43
