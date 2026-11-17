"""E.5b: `kratos connect` -- one-step chat-app connection (docs/phaseE/E.5b §6, §8).

Everything runs on a tmp data folder with injected host facts: no real systemctl, docker,
podman or network call. Each test is one row of the spec's edge-case table (named as the
spec names it) or a §8 rule.
"""
from __future__ import annotations

import ast
import json
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from kratos import authz, kratos_config, settings_store
from kratos.authz import audit as AU
from kratos.serve import connect as CN
from kratos.serve import connect_store as CS
from kratos.serve import store as SS

M1, M2 = "192.0.2.10", "192.0.2.11"
OWNER = authz.owner_actor("cli")


@pytest.fixture
def dd(tmp_path):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target(M1)
    return tmp_path


def _facts(**kw):
    base = dict(serve_running=True, serve_port=8770, systemd_user=True, linger=True, engine="docker",
                engine_needs_sudo=False, docker_desktop=False, existing_openwebui=None, free_port=3000)
    base.update(kw)
    return CN.Facts(**base)


def _connect(dd, app="openwebui", *, facts=None, machines=(M1,), **kw):
    replace = kw.pop("replace", False)
    enable = kw.pop("enable_agui", False)
    p = CN.plan(dd, app, machines=list(machines), facts=facts or _facts(), **kw)
    return CN.apply(dd, p, actor=OWNER, replace=replace or bool(p.replaces), enable_agui=enable)


def _token_row(dd, token_id):
    return SS.get_token(dd, token_id)


# ------------------------------------------------------------------ the plan
def test_plan_is_pure(dd):
    f = _facts()
    a = CN.plan(dd, "openwebui", machines=[M1], facts=f)
    b = CN.plan(dd, "openwebui", machines=[M1], facts=f)
    assert (a.app, a.machines, a.doors, a.mode, a.webui_port, a.token_name) == \
        (b.app, b.machines, b.doors, b.mode, b.webui_port, b.token_name)
    assert SS.list_tokens(dd) == []
    assert not (dd / "connect").exists()
    assert CS.live(dd) == []


def test_unknown_app_lists_the_apps(dd):
    with pytest.raises(CN.ConnectError, match="openwebui, ag-ui, other"):
        CN.plan(dd, "librechat", facts=_facts())


def test_doors_are_least_privilege(dd):
    assert CN.plan(dd, "openwebui", machines=[M1], facts=_facts()).doors == ["openai"]
    assert CN.plan(dd, "openwebui", machines=[M1], tools=True, facts=_facts()).doors == ["openai", "mcp"]
    assert CN.plan(dd, "other", machines=[M1], facts=_facts()).doors == ["openai"]
    assert CN.plan(dd, "ag-ui", machines=[M1], facts=_facts()).doors == ["agents"]
    with pytest.raises(CN.ConnectError):
        CN.plan(dd, "other", machines=[M1], tools=True, facts=_facts())


def test_default_machine_is_the_active_target(dd):
    assert CN.plan(dd, "other", facts=_facts()).machines == [M1]
    with pytest.raises(CN.ConnectError, match="groups"):
        CN.plan(dd, "other", machines=["@lab"], facts=_facts())
    with pytest.raises(CN.ConnectError):
        CN.plan(dd, "other", machines=["not a host; rm -rf /"], facts=_facts())


# ------------------------------------------------------------------ the env file and the command
def test_env_file_and_command(dd):
    r = _connect(dd)
    env = dd / "connect" / "openwebui.env"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert stat.S_IMODE((dd / "connect").stat().st_mode) == 0o700
    lines = [ln for ln in env.read_text().splitlines() if ln and not ln.startswith("#")]
    keys = [ln.split("=", 1)[0] for ln in lines]
    assert keys == ["HOST", "PORT", "OPENAI_API_BASE_URL", "OPENAI_API_KEY", "ENABLE_FORWARD_USER_INFO_HEADERS",
                    "ENABLE_OLLAMA_API", "WEBUI_SECRET_KEY_FILE"]
    assert "AIOHTTP_CLIENT_TIMEOUT" not in env.read_text()              # v0.13: no timeout by default
    vals = dict(ln.split("=", 1) for ln in lines)
    assert vals["HOST"] == "127.0.0.1" and vals["PORT"] == "3000"
    assert vals["OPENAI_API_BASE_URL"] == "http://127.0.0.1:8770/v1" and vals["OPENAI_API_KEY"] == r.token
    assert not any('"' in v or "'" in v for v in vals.values())                      # Docker env-file: no quotes
    assert "--env-file" in r.command and str(env) in r.command and r.token not in r.command
    assert "--network host" in r.command and f":{CN.OPENWEBUI_TESTED_TAG}" in r.command
    assert f"--name {CN.OPENWEBUI_CONTAINER}" in r.command and CN.OPENWEBUI_CONTAINER != "open-webui"
    assert r.address == "http://127.0.0.1:3000" and not r.paste
    assert r.token not in " ".join(r.notes)
    keep = _connect(dd, keep_ollama=True)
    assert "ENABLE_OLLAMA_API" not in (dd / "connect" / "openwebui.env").read_text() and keep.command


def test_tools_adds_kratos_as_an_mcp_tool_server(dd):
    r = _connect(dd, tools=True)
    env = (dd / "connect" / "openwebui.env").read_text()
    line = next(ln for ln in env.splitlines() if ln.startswith("TOOL_SERVER_CONNECTIONS="))
    entry = json.loads(line.split("=", 1)[1])[0]
    assert entry["type"] == "mcp" and entry["auth_type"] == "bearer" and entry["key"] == r.token
    assert entry["url"] == "http://127.0.0.1:8770/mcp" and entry["config"] == {"enable": True}
    assert _token_row(dd, r.token_id)["doors"] == ["openai", "mcp"] and r.token not in r.command


def test_token_rows(dd):
    r = _connect(dd)
    row = _token_row(dd, r.token_id)
    assert row["name"] == "connect-openwebui" and row["created_by"] == "connect"
    assert row["doors"] == ["openai"] and row["targets"] == [M1] and row["kind"] == "person"
    assert row["user_id"] == "owner"
    days = (row["expires_at"] - row["created_at"]) / 86400
    assert 89.9 < days < 90.1                                                       # G1: users.token_days


# ------------------------------------------------------------------ §6 rows
def test_offers_user_service_when_down(dd):
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts(serve_running=False))
    assert any("user service" in n for n in p.notes)
    cmds = CN.serve_service_commands(dd)
    assert cmds[-1] == "systemctl --user enable --now kratos-serve.service"
    assert "sudo" not in "\n".join(cmds)
    unit = cmds[1]
    assert "ExecStart=" in unit and " serve" in unit and "Restart=on-failure" in unit
    ran = []
    status_file = dd / "serve" / "status.json"

    def runner(cmd):
        ran.append(cmd)
        if cmd.startswith("systemctl --user enable"):               # the server "starts"
            from kratos.serve import status as ST

            ST.write(dd, running=True, host="127.0.0.1", port=8770)
        return 0, ""

    ok, words = CN.install_serve_service(dd, actor=OWNER, wait_seconds=3, runner=runner)
    assert ok and status_file.exists() and len(ran) == 4 and "kratos-serve" in words


def test_service_unit_carries_kratos_home_and_data_dir(dd, monkeypatch):
    monkeypatch.setenv("KRATOS_HOME", "/srv/kratos-home")
    unit = CN.serve_service_commands(dd)[1]
    assert "Environment=KRATOS_HOME=/srv/kratos-home" in unit
    assert f"--data-dir {dd.resolve()} serve" in unit                 # not the default folder: named


def test_no_systemd_falls_back_to_terminal(dd):
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts(serve_running=False, systemd_user=False))
    assert any("run `kratos serve` in a terminal" in n for n in p.notes)


def test_linger_off_is_explained(dd, monkeypatch):
    from kratos.subagent import core_listener as CL

    monkeypatch.setattr(CL, "linger_enabled", lambda user=None: False)

    def runner(cmd):
        if cmd.startswith("systemctl --user enable"):
            from kratos.serve import status as ST

            ST.write(dd, running=True, host="127.0.0.1", port=8770)
        return 0, ""

    ok, words = CN.install_serve_service(dd, actor=OWNER, wait_seconds=3, runner=runner)
    assert ok and "sudo loginctl enable-linger $USER" in words and "log out" in words


def test_no_engine_shows_pip_route(dd):
    r = _connect(dd, facts=_facts(engine=None))
    assert "WEBUI_SECRET_KEY_FILE" not in (dd / "connect" / "openwebui.env").read_text()   # pip: its own folder
    assert "pip install open-webui" in r.command and "--port 3000" in r.command and "docker" not in r.command
    assert r.token not in r.command


def test_docker_socket_not_accessible_uses_sudo(dd):
    r = _connect(dd, facts=_facts(engine_needs_sudo=True))
    assert r.command.startswith("sudo docker run")
    assert any("docker group" in n and "root-equivalent" in n for n in r.notes)


def test_podman_is_used_when_there_is_no_docker(dd):
    r = _connect(dd, facts=_facts(engine="podman"))
    assert r.command.startswith("podman run") and any("podman-restart" in n for n in r.notes)


def test_picks_a_free_port(dd):
    f = CN.gather(dd, which=lambda name: None, probe=lambda url: False, port_free=lambda p: p >= 3002)
    assert f.free_port == 3002
    r = _connect(dd, facts=_facts(free_port=3002))
    assert "PORT=3002" in (dd / "connect" / "openwebui.env").read_text() and r.address.endswith(":3002")
    with pytest.raises(CN.ConnectError, match="3000-3099"):
        CN.plan(dd, "openwebui", machines=[M1], facts=_facts(free_port=None))


def test_existing_openwebui_detected(dd):
    f = CN.gather(dd, which=lambda name: None, probe=lambda url: url.endswith(":3000"), port_free=lambda p: True)
    assert f.existing_openwebui == "http://127.0.0.1:3000"
    r = _connect(dd, facts=f)
    assert r.plan.mode == "existing" and not r.command
    labels = dict(r.paste)
    assert labels["URL"] == "http://127.0.0.1:8770/v1" and labels["API key"] == r.token
    assert (dd / "connect" / "openwebui.key").read_text().startswith("Authorization: Bearer ")
    assert CS.live(dd, "openwebui")[0]["mode"] == "existing"
    # --new: a separate Open WebUI for Kratos even though one answers
    r2 = _connect(dd, facts=_facts(existing_openwebui="http://127.0.0.1:3000"), new=True)
    assert r2.plan.mode == "new" and r2.command and "--env-file" in r2.command


def test_existing_path_mentions_host_network(dd):
    r = _connect(dd, facts=_facts(existing_openwebui="http://127.0.0.1:3000"))
    assert any("--network host" in n and "--new" in n for n in r.notes)


def test_openwebui_marker():
    assert CN._looks_like_openwebui({"status": True, "name": "Open WebUI", "version": "0.13.3"})
    assert CN._looks_like_openwebui({"name": "Open WebUI (Kratos)"})
    assert not CN._looks_like_openwebui({"name": "Grafana"}) and not CN._looks_like_openwebui(["Open WebUI"])


def test_rerun_replaces_not_duplicates(dd):
    first = _connect(dd)
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts())
    assert p.replaces and p.replaces["token_id"] == first.token_id
    with pytest.raises(CN.ConnectError, match="already connected"):
        CN.apply(dd, p, actor=OWNER, replace=False)                 # declined: nothing changes
    assert _token_row(dd, first.token_id)["revoked_at"] is None and len(CS.live(dd)) == 1
    second = CN.apply(dd, p, actor=OWNER, replace=True)
    assert _token_row(dd, first.token_id)["revoked_at"] is not None
    assert second.replaced_token == first.token_id
    live = [t for t in SS.list_tokens(dd) if not t["revoked_at"] and t["name"].startswith("connect-openwebui")]
    assert len(live) == 1 and len(CS.live(dd, "openwebui")) == 1


def test_renew_keeps_the_connection_it_renews(dd):
    """Lab bug: --renew probed again, found ANOTHER Open WebUI on :3000 and switched to
    'existing', pointing the person at the wrong address. It keeps the connection's own
    mode and address."""
    _connect(dd, facts=_facts(free_port=3001, existing_openwebui="http://127.0.0.1:3000"), new=True)
    row = CS.live(dd, "openwebui")[0]
    assert row["mode"] == "new" and row["app_url"] == "http://127.0.0.1:3001"
    r = CN.renew(dd, "openwebui", actor=OWNER, facts=_facts(free_port=3002, existing_openwebui="http://127.0.0.1:3000"))
    assert r.address == "http://127.0.0.1:3001" and r.plan.mode == "new" and r.command is None
    assert "PORT=3001" in (dd / "connect" / "openwebui.env").read_text()
    assert dict(r.paste)["API key"] == r.token and any("paste" in n and "3001" in n for n in r.notes)
    assert not any("recreat" in n and "command above" in n for n in r.notes)


def test_renew_changes_machines(dd):
    _connect(dd)
    r = CN.renew(dd, "openwebui", actor=OWNER, machines=[M1, M2], facts=_facts())
    assert _token_row(dd, r.token_id)["targets"] == [M1, M2]
    st = CN.status(dd)[0]
    assert st.machines == [M1, M2]
    assert any("paste" in n for n in r.notes) and dict(r.paste)["API key"] == r.token
    with pytest.raises(CN.ConnectError, match="isn't connected"):
        CN.renew(dd, "other", actor=OWNER, facts=_facts())


def test_expiry_warning_and_expired_state(dd):
    r = _connect(dd)
    conn = SS.connect(dd)
    try:
        conn.execute("UPDATE serve_tokens SET expires_at = ? WHERE token_id = ?", (time.time() + 9 * 86400, r.token_id))
        conn.commit()
    finally:
        conn.close()
    from kratos.serve import status as ST

    ST.write(dd, running=True, host="127.0.0.1", port=8770)
    s = CN.status(dd)[0]
    assert s.state == "expiring" and "renew soon" in s.words()
    assert CN.status_bar_text(dd) in ("openwebui token expires in 8 days", "openwebui token expires in 9 days")
    assert CN.doctor_rows(dd)[0][0] == "warn"
    conn = SS.connect(dd)
    try:
        conn.execute("UPDATE serve_tokens SET expires_at = ? WHERE token_id = ?", (time.time() - 60, r.token_id))
        conn.commit()
    finally:
        conn.close()
    s = CN.status(dd)[0]
    assert s.state == "expired" and "--renew" in s.words()
    assert CN.status_bar_text(dd) == "openwebui token expired: /connect"
    assert CN.doctor_rows(dd)[0][0] == "fail"


def test_port_change_detected(dd):
    from kratos.serve import settings as SSet

    _connect(dd)
    settings_store.set(SSet.PORT, 8790, data_dir=dd, actor="test")
    s = CN.status(dd)[0]
    assert s.state == "port changed" and "8770 to 8790" in s.words()
    r = CN.renew(dd, "openwebui", actor=OWNER, facts=_facts(serve_port=8790))
    assert "OPENAI_API_BASE_URL=http://127.0.0.1:8790/v1" in (dd / "connect" / "openwebui.env").read_text()
    assert dict(r.paste)["API key"] == r.token


def test_docker_desktop_is_named(dd):
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts(docker_desktop=True))
    assert any("Docker Desktop" in n and "GUIDE" in n for n in p.notes)


def test_docker_desktop_detected_by_its_socket_without_calling_docker(dd, tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".docker" / "desktop").mkdir(parents=True)
    (home / ".docker" / "desktop" / "docker.sock").touch()
    monkeypatch.setenv("HOME", str(home))
    f = CN.gather(dd, which=lambda n: "/usr/bin/docker" if n == "docker" else None, probe=lambda u: False,
                  port_free=lambda p: True)
    assert f.docker_desktop and f.engine == "docker"


def test_connect_refused_outside_local_owner(dd):
    from kratos.lifecycle.decide import Actor

    p = CN.plan(dd, "other", machines=[M1], facts=_facts())
    net = Actor(user="sysadmin", interface="serve", user_id="owner", credential="token:000000000000")
    with pytest.raises(CN.ConnectError, match="refused"):
        CN.apply(dd, p, actor=net)
    with pytest.raises(CN.ConnectError, match="refused"):
        CN.undo(dd, "other", actor=net)
    token = settings_store._IN_TOOL.set("run_linux_command")
    try:
        with pytest.raises(CN.ConnectError, match="agent tools"):
            CN.apply(dd, p, actor=OWNER)
    finally:
        settings_store._IN_TOOL.reset(token)
    assert SS.list_tokens(dd) == [] and CS.live(dd) == []
    assert any(r["result"] == "refused" and "connect" in (r["object"] or "") for r in AU.query(dd))


def test_failed_env_write_leaves_no_token(dd, monkeypatch):
    from kratos import paths

    def boom(path, text):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(paths, "write_private_text", boom)
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts())
    with pytest.raises(CN.ConnectError, match="nothing was made"):
        CN.apply(dd, p, actor=OWNER)
    assert all(t["revoked_at"] for t in SS.list_tokens(dd)) and CS.live(dd) == []


def test_failed_env_write_keeps_the_old_connection(dd, monkeypatch):
    first = _connect(dd)
    from kratos import paths

    monkeypatch.setattr(paths, "write_private_text", lambda path, text: (_ for _ in ()).throw(OSError("ro")))
    p = CN.plan(dd, "openwebui", machines=[M1], facts=_facts())
    with pytest.raises(CN.ConnectError):
        CN.apply(dd, p, actor=OWNER, replace=True)
    assert _token_row(dd, first.token_id)["revoked_at"] is None            # still works
    assert CS.live(dd, "openwebui")[0]["token_id"] == first.token_id


def test_concurrent_connect_one_wins(dd):
    results, errors = [], []

    def go():
        try:
            p = CN.plan(dd, "other", machines=[M1], facts=_facts())
            results.append(CN.apply(dd, p, actor=OWNER, replace=False))
        except CN.ConnectError as e:
            errors.append(str(e))

    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 1 and len(errors) == 1 and "already connected" in errors[0]
    assert len(CS.live(dd, "other")) == 1
    assert len([t for t in SS.list_tokens(dd) if not t["revoked_at"]]) == 1


def test_one_live_row_per_app_is_enforced_by_the_store(dd):
    import sqlite3

    CS.record(dd, app="other", token_id="a" * 12, machines=[M1], doors=["openai"], secret_file="connect/other.headers",
              serve_port=8770, app_port=None, created_by="x")
    with pytest.raises(sqlite3.IntegrityError):
        CS.record(dd, app="other", token_id="b" * 12, machines=[M1], doors=["openai"],
                  secret_file="connect/other.headers", serve_port=8770, app_port=None, created_by="x")


def test_token_never_in_transcript_or_records(dd):
    from kratos.storage.session_store import SessionStore

    r = _connect(dd, "other")
    hay = []
    for path in dd.rglob("*"):
        if path.is_file() and path.name != "other.headers":
            try:
                hay.append(path.read_bytes())
            except OSError:
                pass
    blob = b"".join(hay)
    secret_part = r.token.split("_", 2)[2].encode()
    assert secret_part not in blob                                        # not in kratos.db, audit, any other file
    assert r.token_id.encode() in blob                                     # the id is recorded
    assert SessionStore(dd / "kratos.db").list_recent_sessions(limit=5) == []


def test_no_secret_on_non_tty_without_flag(dd, monkeypatch, capsys):
    import argparse

    from kratos.cli import connect_cmd as CC

    monkeypatch.setattr(CN, "gather", lambda data_dir, url=None, **k: _facts())
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    args = argparse.Namespace(data_dir=str(dd), app="other", machines=M1, tools=False, url=None, keep_ollama=False,
                              new=False, renew=False, undo=False, print_command=False, yes=True)
    assert CC.cmd_connect(args) == 0
    out = capsys.readouterr()
    token = (dd / "connect" / "other.headers").read_text().split("Bearer ", 1)[1].strip()
    assert token not in out.out and token not in out.err and "--print-command" in out.err
    args.print_command, args.yes = True, True
    assert CC.cmd_connect(args) == 0
    out = capsys.readouterr()
    token2 = (dd / "connect" / "other.headers").read_text().split("Bearer ", 1)[1].strip()
    assert out.out.strip() == token2 and token2 not in out.err


def test_agui_declined_makes_nothing(dd):
    from kratos.serve.a2a import settings as AS

    p = CN.plan(dd, "ag-ui", machines=[M1], facts=_facts())
    assert p.enable_agui
    with pytest.raises(CN.ConnectError, match="AG-UI is off"):
        CN.apply(dd, p, actor=OWNER, enable_agui=False)
    assert SS.list_tokens(dd) == [] and CS.live(dd) == []
    assert settings_store.get(AS.AGUI_ENABLED, data_dir=dd) is False
    r = CN.apply(dd, p, actor=OWNER, enable_agui=True)
    assert settings_store.get(AS.AGUI_ENABLED, data_dir=dd) is True
    assert _token_row(dd, r.token_id)["doors"] == ["openai", "agents"]
    hdr = dd / "connect" / "ag-ui.headers"
    assert stat.S_IMODE(hdr.stat().st_mode) == 0o600
    assert f"-H @{hdr}" in r.check and r.token not in r.check and "/ag-ui/run" in r.check
    assert json.loads(r.check.split("-d '", 1)[1].rstrip("'"))["forwardedProps"]["kratos"]["machine"] == M1


def test_agui_text_mentions_browser_refusal(dd):
    p = CN.plan(dd, "ag-ui", machines=[M1], facts=_facts())
    assert any("browser" in n and "server side" in n for n in p.notes)


def test_no_gateway_tokens_from_connect(dd):
    for app in CN.APPS:
        r = _connect(dd, app, enable_agui=True, replace=True)
        assert _token_row(dd, r.token_id)["kind"] == "person"
    src = Path(CN.__file__).read_text()
    assert "gateway=True" not in src


def test_remote_url_points_to_remote_access(dd):
    with pytest.raises(CN.ConnectError, match="Remote access"):
        CN.plan(dd, "openwebui", url="http://192.0.2.50:3000", facts=_facts())
    f = CN.gather(dd, url="http://192.0.2.50:3000", which=lambda n: None, probe=lambda u: True,
                  port_free=lambda p: True)
    assert f.existing_openwebui is None                                  # never probed as "existing"
    assert settings_store.get("serve.allow_non_loopback", data_dir=dd) is False


def test_undo_revokes_then_cleans(dd):
    r = _connect(dd)
    env = dd / "connect" / "openwebui.env"
    (dd / "connect" / "keep.txt").write_text("not ours")
    u = CN.undo(dd, "openwebui", actor=OWNER)
    assert _token_row(dd, r.token_id)["revoked_at"] is not None and not env.exists() and u.removed_file
    assert (dd / "connect" / "keep.txt").exists()                        # only that file
    assert CS.live(dd) == [] and any(CN.OPENWEBUI_CONTAINER in c for c in u.cleanup)
    assert any("volume rm" in c and "ONLY if" in c for c in u.cleanup)
    with pytest.raises(CN.ConnectError, match="isn't connected"):
        CN.undo(dd, "openwebui", actor=OWNER)


def test_connect_secret_in_backup_plan(dd):
    from kratos import datainv
    from kratos.backup import stores as BS

    cats = {c.key: c for c in datainv.CATEGORIES}
    assert cats["chat_app_secrets"].backup == datainv.BACKUP_SECRET and cats["chat_app_secrets"].files == ("connect",)
    assert cats["chat_app_secrets"].personal == datainv.SECRET
    assert cats["chat_app_connections"].backup == datainv.BACKUP_INCLUDE
    assert "kratos.serve.connect_store" in BS.MIGRATED


def test_migration_on_old_db(dd):
    import sqlite3

    sqlite3.connect(dd / "kratos.db").close()                             # an older kratos.db: no connect_apps
    assert CN.status(dd) == []
    assert CN.doctor_rows(dd) == [] and CN.status_bar_text(dd) is None


def test_machine_names_are_cleaned(dd):
    import asyncio

    from textual.app import App

    from kratos.tui_mk2.screens.connect import ConnectScreen

    CS.record(dd, app="other", token_id="c" * 12, machines=["web-01\x1b[31m‮"], doors=["openai"],
              secret_file="connect/other.headers", serve_port=8770, app_port=None, created_by="x")

    class _Host(App):
        def on_mount(self):
            self.push_screen(ConnectScreen(dd))

    async def run():
        app = _Host()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            await pilot.pause()
            return app.export_screenshot()

    svg = asyncio.run(run())
    assert "\x1b" not in svg and "‮" not in svg and "web-01" in svg


# ------------------------------------------------------------------ §8 rules
def test_kratos_never_runs_a_container_engine():
    """Source scan: no subprocess call in the connect code names docker or podman."""
    files = [Path(CN.__file__), Path(CN.__file__).parents[1] / "cli" / "connect_cmd.py",
             Path(CN.__file__).parents[1] / "tui_mk2" / "screens" / "connect.py"]
    for f in files:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if name in ("run", "Popen", "call", "check_call", "check_output", "system", "_run_quiet"):
                    text = ast.unparse(node)
                    assert "docker" not in text and "podman" not in text, (f.name, text)


def test_audit_row_has_token_id_never_token(dd):
    r = _connect(dd, "other")
    rows = AU.query(dd)
    assert any(x["action"] == "tokens.manage" and "connect other" in (x["object"] or "") for x in rows)
    assert r.token not in json.dumps(rows) and r.token.split("_", 2)[2] not in json.dumps(rows)


def test_tui_connect_flow(dd, monkeypatch):
    """The /connect screen end to end with canned modal answers at 80x24: machines -> chat
    only -> confirm -> the one command in a copy box; the log never shows the token."""
    import asyncio

    from textual.app import App

    from kratos.tui_mk2.screens import connect as SC

    monkeypatch.setattr(CN, "gather", lambda data_dir, url=None, **k: _facts())
    shown = []

    class _Host(App):
        def on_mount(self):
            self.push_screen(SC.ConnectScreen(dd))

    async def run():
        app = _Host()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            answers = iter([M1, False, True, None, None])

            async def wait(modal):
                shown.append(modal)
                return next(answers)

            monkeypatch.setattr(app, "push_screen_wait", wait)
            screen = app.screen
            screen.action_connect()
            for _ in range(200):
                await pilot.pause()
                if CS.live(dd):
                    break
            for _ in range(50):
                await pilot.pause()
            return screen

    screen = asyncio.run(run())
    live = CS.live(dd, "openwebui")
    assert live and live[0]["machines"] == [M1]
    from kratos.tui_mk2.modals import CommandModal

    boxes = [m for m in shown if isinstance(m, CommandModal)]
    assert boxes and "--env-file" in boxes[0]._command
    token = (dd / "connect" / "openwebui.env").read_text().split("OPENAI_API_KEY=", 1)[1].split("\n", 1)[0]
    log = " ".join(t.plain for t in screen._lines)
    assert token not in log and live[0]["token_id"] in log
