"""Which folders a machine serves code from, and people's decisions about them (E.7a §3.1).

Candidates, each with why (Kratos's own words around machine text):

- the working folder of a process that listens on the network, and of its parent process
  (gunicorn / uwsgi / php-fpm / node masters), from the newest running-process read (A.5);
- ``root`` / ``alias`` / ``DocumentRoot`` / ``Alias`` / ``ScriptAlias`` of the web servers
  (kratos.code.webconf over the `code_roots_facts` read), and PHP-FPM pools' ``chdir``;
- ``WorkingDirectory=`` of systemd units whose main process listens (or that Kratos can't
  tell about over SSH: offered, said so);
- bind-mount sources of containers that publish a port (D.5's snapshot).

Never offered: ``/``, ``/etc``, ``/root``, ``/proc``, ``/sys``, ``/dev``, ``/run``, ``/boot``,
``/usr`` (except ``/usr/share/nginx/html`` and ``/usr/local/<app>``), the system binary and
library folders, the temp folders, ``/var/lib/docker``, ``/var/lib/containerd``; a home
folder only when a listening process works inside it.

**A person confirms each root** (people-only, `code.root_confirm`, the owner at the Kratos
host's TUI or CLI; refused inside a tool run, from MCP and from the chat server). A person
may also add one by path, ignore one (it stays ignored until a person changes that), and
accept a folder's current state as its baseline (a deploy without git). Unconfirmed
candidates are only listed -- never read.
"""
from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Any, Callable

from kratos import settings_store
from kratos.adapters import code_facts as CF
from kratos.code import settings as CS
from kratos.code import store as S
from kratos.lifecycle.decide import Actor
from kratos.target_key import target_key

ACTOR_INTERFACES = ("tui", "cli")
ROOT_RE = CF.ROOT_RE
never_reason = CF.never_reason
shape_reason = CF.shape_reason


class CodeRootError(ValueError):
    """A forbidden caller or a refused path; nothing was written."""


_WEB_SERVERS = ("nginx", "apache2", "httpd", "caddy", "lighttpd", "openresty")


def _is_web_server(item: dict[str, Any]) -> bool:
    exe = str(item.get("exe") or "").rsplit("/", 1)[-1]
    return exe in _WEB_SERVERS or str(item.get("comm") or "") in _WEB_SERVERS


def _loopback_port(target: Any) -> int | None:
    import re as _re

    m = _re.match(r"^(?:https?://|uwsgi://|fastcgi://)?(127\.0\.0\.1|localhost|\[::1\])?:?(\d{1,5})\b", str(target or ""))
    return int(m.group(2)) if m and m.group(1) else None


def _home_of(path: str) -> str | None:
    parts = path.split("/")
    return "/".join(parts[:3]) if len(parts) >= 3 and parts[1] == "home" and parts[2] else None


# --------------------------------------------------------------------------- discovery
def candidates(live: dict[str, Any] | None, facts: dict[str, Any] | None, cfg: Any,
               containers: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[str]]:
    """([{path, why: [{kind, detail}], serving: [...]}], notes). Pure: from saved reads."""
    found: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    listening_homes: set[str] = set()

    def add(path: Any, kind: str, detail: str, serving: dict[str, Any] | None = None) -> None:
        if not isinstance(path, str) or not path.startswith("/"):
            return
        p = posixpath.normpath(path)
        it = found.setdefault(p, {"path": p, "why": [], "serving": []})
        if not any(w["kind"] == kind and w["detail"] == detail for w in it["why"]):
            it["why"].append({"kind": kind, "detail": detail[:300]})
        if serving and serving not in it["serving"]:
            it["serving"].append(serving)

    listeners = [x for x in (live or {}).get("listeners") or [] if isinstance(x, dict)]
    listening_units: set[str] = set()
    for item in listeners:
        addr = item.get("address") or "?"
        where = f"[{addr}]:{item.get('port')}" if ":" in str(addr) else f"{addr}:{item.get('port')}"
        serving = {"pid": item.get("pid"), "exe": item.get("exe"), "address": item.get("address"),
                   "port": item.get("port"), "proto": item.get("proto")}
        prog = item.get("exe") or item.get("comm") or "a program"
        if item.get("unit"):
            listening_units.add(str(item["unit"]))
        for key, label in (("cwd", "works in this folder"), ("parent_cwd", "'s parent process works in this folder")):
            cwd = item.get(key)
            if isinstance(cwd, str) and cwd.startswith("/") and cwd != "/":
                add(cwd, "listener", f"{prog}, listening on {where}, {label}".replace(", 's", "'s"), serving)
                home = _home_of(posixpath.normpath(cwd))
                if home:
                    listening_homes.add(home)
    web_servers = [x for x in listeners if _is_web_server(x)]
    web_serving = [{"pid": x.get("pid"), "exe": x.get("exe"), "address": x.get("address"), "port": x.get("port"),
                    "proto": x.get("proto"), "via": "web server"} for x in web_servers]
    if cfg is not None:
        for r in cfg.served_roots():
            add(r["path"], "web_root", f"{r['how']} of {r['site']}")
            for s in web_serving:
                add(r["path"], "web_root", f"{r['how']} of {r['site']}", s)
        # an app on a loopback port that a site passes requests to is reached through the web server
        for b in cfg.backends():
            port = _loopback_port(b.get("target"))
            if port is None:
                continue
            for item in listeners:
                if item.get("port") == port and isinstance(item.get("cwd"), str):
                    for s in web_serving:
                        add(item["cwd"], "listener", f"{b['site']} passes requests to it (port {port})", s)
        for pool in cfg.pools:
            if pool.get("chdir"):
                add(pool["chdir"], "php_fpm", f"PHP-FPM pool {pool.get('name')} changes into it")
        notes.extend(cfg.notes)
    units = (facts or {}).get("units") or {}
    for unit_path, lines in sorted(units.items()):
        unit = unit_path.rsplit("/", 1)[-1]
        if unit.endswith(".conf"):                       # a drop-in: <unit>.service.d/x.conf
            unit = unit_path.rsplit("/", 2)[-2][:-2] if unit_path.rsplit("/", 2)[-2].endswith(".d") else unit
        wd = next((ln.split("=", 1)[1].strip() for ln in lines if ln.strip().startswith("WorkingDirectory=")), None)
        if not wd:
            continue
        wd = wd.lstrip("-")
        if unit in listening_units:
            add(wd, "systemd", f"systemd unit {unit} sets WorkingDirectory and its process listens")
        elif not listeners or any(not x.get("seen") for x in listeners):
            add(wd, "systemd", f"systemd unit {unit} sets WorkingDirectory (this read couldn't tell whether it listens)")
    for row in (containers or {}).get("rows") or []:
        if not isinstance(row, dict) or not row.get("running") or not row.get("ports"):
            continue
        for m in row.get("mounts") or []:
            if isinstance(m, dict) and m.get("type") == "bind" and m.get("source"):
                add(m["source"], "container", f"container {row.get('name')} publishes {', '.join(row['ports'][:2])} "
                                              f"and mounts it at {m.get('destination')}")
    out: list[dict[str, Any]] = []
    for p, it in sorted(found.items()):
        if never_reason(p) or shape_reason(p):
            if shape_reason(p) and not never_reason(p):
                notes.append(f"a candidate folder has characters Kratos won't send ({len(p)} characters): add a "
                             "differently named folder by path if it holds code")
            continue
        home = _home_of(p)
        if home and home not in listening_homes:
            continue
        out.append(it)
    return out, notes


# --------------------------------------------------------------------------- people's decisions
def _check_actor(actor: Any, data_dir: Path | str, machine: str, obj: str) -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise CodeRootError(f"agent tools may not confirm or change code roots (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in ACTOR_INTERFACES or not str(actor.user or "").strip():
        raise CodeRootError("a code-root decision needs a person: an Actor from the TUI or the CLI")
    from kratos import authz

    try:
        authz.require(actor, authz.P.CODE_ROOT_CONFIRM, machine, data_dir=data_dir, obj=obj)
    except authz.Denied as e:
        raise CodeRootError(str(e)) from None


def _check_path(path: str) -> str:
    why = shape_reason(path)
    if why:
        raise CodeRootError(f"not a folder Kratos can check: use {why}")
    never = never_reason(path)
    if never:
        raise CodeRootError(f"Kratos won't read that folder: {never}")
    return path


def _confirmed_count(data_dir: Path | str, tk: str) -> int:
    return len(S.roots(data_dir, tk, status="confirmed"))


def confirm(data_dir: Path | str, machine: str, path: str, *, actor: Actor) -> dict[str, Any]:
    """A person confirms that `path` holds deployed code: Kratos reads it on every code check."""
    _check_actor(actor, data_dir, machine, f"code root {path}")
    _check_path(path)
    tk = target_key(machine)
    known = {r["path"]: r for r in S.roots(data_dir, tk)}
    if known.get(path, {}).get("status") == "confirmed":
        return known[path]
    if _confirmed_count(data_dir, tk) >= int(CS.get(CS.MAX_ROOTS, data_dir)):
        raise CodeRootError(f"this machine already has {CS.get(CS.MAX_ROOTS, data_dir)} confirmed code folders "
                            "(code.max_roots): ignore one first")
    source = known[path]["source"] if path in known else "person"
    return S.decide(data_dir, tk, path, "confirmed", actor=actor, source=source,
                    kind="confirmed" if path in known else "added")


def ignore(data_dir: Path | str, machine: str, path: str, *, actor: Actor) -> dict[str, Any]:
    """A person says `path` is not code to check: it stays ignored until a person changes that."""
    _check_actor(actor, data_dir, machine, f"code root {path}")
    tk = target_key(machine)
    known = {r["path"]: r for r in S.roots(data_dir, tk)}
    if path not in known:
        raise CodeRootError("Kratos doesn't know that folder for this machine (see `kratos code roots`)")
    return S.decide(data_dir, tk, path, "ignored", actor=actor, source=known[path]["source"], kind="ignored")


def add(data_dir: Path | str, machine: str, path: str, *, actor: Actor,
        exists: Callable[[str], str | None] | None = None) -> dict[str, Any]:
    """A person adds a folder by path and confirms it. `exists(path)` -> None when the folder
    is there, else why not (a quick read of the machine; skipped when None)."""
    _check_actor(actor, data_dir, machine, f"code root {path}")
    _check_path(path)
    if exists is not None:
        why = exists(path)
        if why:
            raise CodeRootError(f"can't add {path}: {why}")
    return confirm(data_dir, machine, path, actor=actor)


def accept_state(data_dir: Path | str, machine: str, path: str, *, actor: Actor) -> dict[str, Any]:
    """A person accepts a confirmed root's current state (a deploy): the latest complete
    inventory becomes the baseline that 'changed since' is measured against."""
    _check_actor(actor, data_dir, machine, f"code root {path}")
    tk = target_key(machine)
    root = next((r for r in S.roots(data_dir, tk) if r["path"] == path), None)
    if root is None or root["status"] != "confirmed":
        raise CodeRootError("only a confirmed code folder has a state to accept")
    current = S.files(data_dir, root["id"], "current")
    if not current:
        raise CodeRootError("Kratos has no complete read of that folder yet: run `kratos collect --force` first")
    S.replace_files(data_dir, root["id"], "baseline", list(current.values()))
    S.set_accepted(data_dir, root, actor=actor, detail=f"{len(current)} files")
    return {**root, "accepted_files": len(current)}
