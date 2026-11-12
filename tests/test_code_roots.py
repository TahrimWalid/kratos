"""E.7a §3.1, §3.5: finding the code a machine serves (with reasons), the never list, people-only
decisions, and the closed web-server subset that decides served / executed."""
from __future__ import annotations

import pytest

from kratos import settings_store
from kratos.code import roots as R
from kratos.code import store as S
from kratos.code import webconf as W
from kratos.lifecycle.decide import Actor

M = "192.0.2.20"
NGINX = {
    "/etc/nginx/nginx.conf": "events {} http { include /etc/nginx/sites-enabled/*; include mime.types; }",
    "/etc/nginx/sites-enabled/shop": """
server { listen 80; server_name shop.example.test; root /var/www/shop;
  location / { try_files $uri $uri/ /index.php?$args; }
  location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }
  location ~ /\\.(git|env) { deny all; }
  location ^~ /static/ { }
  location /api/ { proxy_pass http://127.0.0.1:8000; }
}""",
}


def cfg_of(files: dict[str, str]) -> W.Config:
    return W.parse({k: {"status": "ok", "text": v} for k, v in files.items()})


def owner(interface: str = "cli") -> Actor:
    return Actor(user="owner", interface=interface, user_id="owner")


# ----------------------------------------------------------------------------- webconf
def test_nginx_served_and_executed_decisions():
    c = cfg_of(NGINX)
    assert W.decide(c, "/var/www/shop", "index.php")["executed"]
    assert W.decide(c, "/var/www/shop", "uploads/x.php")["executed"]
    v = W.decide(c, "/var/www/shop", "static/x.php")          # ^~ stops the PHP regex: served as text
    assert v["served"] and not v["executed"]
    assert not W.decide(c, "/var/www/shop", ".git/config")["served"]
    assert not W.decide(c, "/var/www/shop", "api/x")["served"]
    assert W.decide(c, "/srv/elsewhere", "a.php")["how"].startswith("not served")


def test_webconf_include_cycle():
    files = {"/etc/nginx/nginx.conf": "http { include /etc/nginx/a.conf; }",
             "/etc/nginx/a.conf": "include /etc/nginx/b.conf; server { root /var/www/a; }",
             "/etc/nginx/b.conf": "include /etc/nginx/a.conf;"}
    c = cfg_of(files)
    assert any("cycle" in n for n in c.notes)
    assert [r["path"] for r in c.served_roots()] == ["/var/www/a"]
    many = {"/etc/nginx/nginx.conf": "http { include /etc/nginx/x/*.conf; }",
            **{f"/etc/nginx/x/{i:03d}.conf": "server { root /var/www/s; }" for i in range(250)}}
    assert any(f"more than {W.MAX_INCLUDES}" in n for n in cfg_of(many).notes)


def test_webconf_variable_root():
    c = cfg_of({"/etc/nginx/nginx.conf": "http { server { root $site_root; } }"})
    assert c.served_roots() == []
    assert any("root uses a variable" in n and "add the folder by path" in n for n in c.notes)


def test_unparseable_regex_counts_as_executed_safe_direction():
    c = cfg_of({"/etc/nginx/nginx.conf": "http { server { root /var/www/x; location ~ ([ { fastcgi_pass 1:9; } } }"})
    assert W.decide(c, "/var/www/x", "a.php")["executed"]


def test_apache_documentroot_php_and_denies():
    files = {"/etc/apache2/apache2.conf": "<Directory />\n Require all denied\n</Directory>\n"
                                          "<Directory /var/www/>\n Require all granted\n</Directory>\n"
                                          "IncludeOptional sites-enabled/*.conf\nIncludeOptional mods-enabled/*.conf\n"
                                          "<FilesMatch \"^\\.ht\">\n Require all denied\n</FilesMatch>\n",
             "/etc/apache2/sites-enabled/000.conf": "<VirtualHost *:80>\n DocumentRoot /var/www/html\n</VirtualHost>",
             "/etc/apache2/mods-enabled/php8.3.load": "LoadModule php_module x"}
    c = cfg_of(files)
    assert W.decide(c, "/var/www/html", "x.php")["executed"]
    assert not W.decide(c, "/var/www/html", ".htaccess")["served"]
    assert W.decide(c, "/var/www/html", "a.css") == {"served": True, "executed": False,
                                                    "how": "served as a static file by Apache"}


def test_saved_form_round_trips():
    c = cfg_of(NGINX)
    c2 = W.from_json(W.to_json(c))
    for rel in ("index.php", "static/x.php", ".git/config", "api/x"):
        assert W.decide(c, "/var/www/shop", rel) == W.decide(c2, "/var/www/shop", rel)


# ----------------------------------------------------------------------------- discovery
def live(*items: dict) -> dict:
    return {"checked_at": "2026-11-12T00:00:00Z", "via": "agent", "listeners": list(items), "local_addresses": []}


def L(port: int, cwd: str | None, exe: str = "/usr/bin/python3", address: str = "0.0.0.0", **kw) -> dict:
    return {"port": port, "proto": "tcp", "address": address, "seen": True, "exe": exe, "pid": 100 + port,
            "cwd": cwd, "unit": kw.get("unit"), "parent_cwd": kw.get("parent_cwd"), "comm": kw.get("comm")}


def test_no_candidates():
    cands, notes = R.candidates(live(), {}, W.Config(), None)
    assert cands == [] and notes == []


def test_cwd_root_never_offered():
    cands, _n = R.candidates(live(L(22, "/", "/usr/sbin/sshd"), L(80, "/", "/usr/sbin/nginx")), {}, cfg_of(NGINX), None)
    assert [c["path"] for c in cands] == ["/var/www/shop"]           # its config-derived root instead


def test_candidates_carry_reasons_and_serving():
    facts = {"units": {"/etc/systemd/system/app.service": ["WorkingDirectory=/srv/app", "ExecStart=/srv/app/run"]}}
    cands, _n = R.candidates(live(L(8000, "/srv/app", address="127.0.0.1", unit="app.service"),
                                  L(80, "/", "/usr/sbin/nginx")), facts, cfg_of(NGINX), None)
    by = {c["path"]: c for c in cands}
    assert set(by) == {"/srv/app", "/var/www/shop"}
    kinds = {w["kind"] for w in by["/srv/app"]["why"]}
    assert {"listener", "systemd"} <= kinds
    # the app on 127.0.0.1:8000 is reached through nginx (the site passes /api/ to it)
    assert any(s.get("via") == "web server" and s["port"] == 80 for s in by["/srv/app"]["serving"])
    assert any("passes requests to it" in w["detail"] for w in by["/srv/app"]["why"])


def test_home_folder_only_with_a_listening_cwd_inside():
    c = cfg_of({"/etc/nginx/nginx.conf": "http { server { root /home/alice/site; } }"})
    cands, _n = R.candidates(live(), {}, c, None)
    assert cands == []
    cands, _n = R.candidates(live(L(3000, "/home/alice/site")), {}, c, None)
    assert [x["path"] for x in cands] == ["/home/alice/site"]


def test_container_mount_root():
    cont = {"rows": [{"name": "web", "running": True, "ports": ["0.0.0.0:8080->80/tcp"],
                      "mounts": [{"type": "bind", "source": "/srv/www", "destination": "/usr/share/nginx/html"}]},
                     {"name": "stopped", "running": False, "ports": ["x"],
                      "mounts": [{"type": "bind", "source": "/srv/off", "destination": "/x"}]}]}
    cands, _n = R.candidates(None, {}, W.Config(), cont)
    assert [c["path"] for c in cands] == ["/srv/www"]


@pytest.mark.parametrize("path", ["/", "/etc", "/etc/nginx", "/root/app", "/proc/1", "/sys/x", "/usr/lib/app",
                                  "/var/lib/docker/overlay2/x", "/var/lib/containerd/x", "/home/u/.ssh/app"])
def test_never_list(path):
    assert R.never_reason(path)


@pytest.mark.parametrize("path", ["/var/www/html", "/srv/app", "/opt/app", "/usr/share/nginx/html", "/usr/local/app"])
def test_allowed(path):
    assert R.never_reason(path) is None and R.shape_reason(path) is None


# ----------------------------------------------------------------------------- people-only
def test_confirm_ignore_add_and_events(tmp_path):
    S.offer(tmp_path, M, [{"path": "/srv/app", "why": [{"kind": "listener", "detail": "x"}], "serving": []}])
    r = R.confirm(tmp_path, M, "/srv/app", actor=owner())
    assert r["status"] == "confirmed" and r["decided_by"] == "owner"
    R.ignore(tmp_path, M, "/srv/app", actor=owner())
    S.offer(tmp_path, M, [{"path": "/srv/app", "why": [], "serving": []}])        # stays ignored
    assert S.roots(tmp_path, M)[0]["status"] == "ignored"
    R.add(tmp_path, M, "/srv/other", actor=owner(), exists=lambda p: None)
    kinds = [e["kind"] for r in S.roots(tmp_path, M) for e in S.events(tmp_path, r["id"])]
    assert kinds.count("offered") == 1 and {"confirmed", "ignored", "added"} <= set(kinds)
    with pytest.raises(R.CodeRootError):
        R.add(tmp_path, M, "/etc/app", actor=owner())
    with pytest.raises(R.CodeRootError):
        R.add(tmp_path, M, "/srv/gone", actor=owner(), exists=lambda p: "not found")


def test_root_confirm_people_only(tmp_path):
    S.offer(tmp_path, M, [{"path": "/srv/app", "why": [], "serving": []}])
    for iface in ("mcp", "serve", "schedule"):
        with pytest.raises(R.CodeRootError):
            R.confirm(tmp_path, M, "/srv/app", actor=owner(iface))
    with settings_store.tool_call_scope("run_nmap_scan"):
        with pytest.raises(R.CodeRootError, match="agent tools"):
            R.confirm(tmp_path, M, "/srv/app", actor=owner())
    with pytest.raises(R.CodeRootError):
        R.confirm(tmp_path, M, "/srv/app", actor=None)            # type: ignore[arg-type]
    assert S.roots(tmp_path, M)[0]["status"] == "candidate"


def test_max_roots(tmp_path, monkeypatch):
    from kratos.code import settings as CS

    monkeypatch.setattr(CS, "get", lambda key, dd: 2 if key == CS.MAX_ROOTS else settings_store.get(key, data_dir=dd))
    R.add(tmp_path, M, "/srv/a", actor=owner())
    R.add(tmp_path, M, "/srv/b", actor=owner())
    with pytest.raises(R.CodeRootError, match="code.max_roots"):
        R.add(tmp_path, M, "/srv/c", actor=owner())


def test_events_are_append_only(tmp_path):
    import sqlite3

    R.add(tmp_path, M, "/srv/a", actor=owner())
    conn = S.connect(tmp_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM code_root_events")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE code_root_events SET kind = 'x'")
    finally:
        conn.close()


def test_same_repo_two_machines(tmp_path):
    R.add(tmp_path, M, "/srv/app", actor=owner())
    R.add(tmp_path, "192.0.2.21", "/srv/app", actor=owner())
    a, b = S.roots(tmp_path, M), S.roots(tmp_path, "192.0.2.21")
    assert len(a) == len(b) == 1 and a[0]["id"] != b[0]["id"]


def test_a_systemd_unit_that_is_not_running_is_never_offered():
    facts = {"units": {"/lib/systemd/system/oneshot.service": ["WorkingDirectory=/var/lib/oneshot"],
                       "/etc/systemd/system/app.service": ["WorkingDirectory=/srv/app"]}}
    unseen = {"port": 80, "proto": "tcp", "address": "0.0.0.0", "seen": False, "exe": None, "pid": None, "cwd": None}
    lv = {**live(unseen), "running_units": ["app.service", "ssh.service"]}
    cands, _n = R.candidates(lv, facts, W.Config(), None)
    assert [c["path"] for c in cands] == ["/srv/app"]
    assert "is running" in cands[0]["why"][0]["detail"]


def test_an_unseen_listener_on_port_80_stands_in_for_the_web_server():
    unseen = {"port": 80, "proto": "tcp", "address": "0.0.0.0", "seen": False, "exe": None, "pid": None, "cwd": None}
    cands, _n = R.candidates(live(unseen), {}, cfg_of(NGINX), None)
    serving = cands[0]["serving"]
    assert serving and serving[0]["port"] == 80 and "not visible to this login" in serving[0]["exe"]


def test_a_candidate_no_longer_offered_goes_stale_and_comes_back(tmp_path):
    S.offer(tmp_path, M, [{"path": "/srv/a", "why": [], "serving": []}, {"path": "/srv/b", "why": [], "serving": []}])
    R.confirm(tmp_path, M, "/srv/b", actor=owner())
    S.offer(tmp_path, M, [])
    st = {r["path"]: r["status"] for r in S.roots(tmp_path, M)}
    assert st == {"/srv/a": "stale", "/srv/b": "confirmed"}            # a confirmed folder is never touched
    S.offer(tmp_path, M, [{"path": "/srv/a", "why": [], "serving": []}])
    assert {r["path"]: r["status"] for r in S.roots(tmp_path, M)}["/srv/a"] == "candidate"


def test_empty_glob_includes_in_read_folders_are_not_partial_reads():
    c = cfg_of({"/etc/nginx/nginx.conf": "include /etc/nginx/modules-enabled/*.conf; http { include "
                "/etc/nginx/conf.d/*.conf; include /opt/app/nginx/*.conf; include /etc/nginx/extra.conf; }"})
    assert c.notes == ["config partly read: include /opt/app/nginx/*.conf not read",
                       "config partly read: include /etc/nginx/extra.conf not read"]
