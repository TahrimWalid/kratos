"""`kratos connect` / `/connect`: connect a chat app to Kratos in one step (docs/phaseE/E.5b).

The person picks the app and the machines; Kratos does every Kratos-side step and gives
them at most one thing to paste:

* **openwebui** -- a new Open WebUI: Kratos writes the app's settings, including the token,
  to an env file (`<data_dir>/connect/openwebui.env`, 0600) and prints ONE `docker run`
  command that reads it with `--env-file`. The token is never on a command line, in shell
  history or in `ps`. An Open WebUI that already answers gets the two values to paste
  instead: its own settings, once saved, win over the environment.
* **ag-ui** -- an AG-UI app (E.5's door): the endpoint, the header and a `curl -N` smoke
  test that reads the header from a 0600 file.
* **other** -- any OpenAI-compatible chat app: the base URL, the key and a `curl` check.

Kratos never runs Docker, Podman or Open WebUI (it prints the command; the person runs
it), never asks for the docker group, and detects what it needs with `shutil.which`, a
socket's permissions and local HTTP probes only. It never listens beyond 127.0.0.1.

One person token per app, the owner's, made by the D.7 token code with only the doors the
app uses (Open WebUI and other: `openai`, plus `mcp` with `--tools`; AG-UI: `agents`).
Re-running connect for an app replaces its token -- never two live connect tokens for one
app. Every change is the owner's, at the Kratos computer: `tokens.manage` (local only),
refused inside an agent tool, recorded in the audit trail with the token's id only.
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import socket
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

APPS = ("openwebui", "ag-ui", "other")
APP_WORDS = {"openwebui": "Open WebUI", "ag-ui": "an AG-UI app", "other": "an OpenAI-compatible chat app"}
FOLDER = "connect"
SERVE_SERVICE = "kratos-serve"
OPENWEBUI_IMAGE = "ghcr.io/open-webui/open-webui"
OPENWEBUI_TESTED_TAG = "v0.13.3"          # the release the E.5b lab run verified end to end
# Kratos's own names, never the stock `open-webui`: an older Open WebUI's container or data
# volume of that name would be reused, and its saved settings would win over Kratos's.
OPENWEBUI_VOLUME = "kratos-open-webui"
OPENWEBUI_CONTAINER = "kratos-open-webui"
WEBUI_PORT_FIRST, WEBUI_PORT_LAST = 3000, 3099
EXISTING_PROBE_PORTS = (3000, 8080)
EXPIRY_WARN_DAYS = 14
_SECRET_FILE = {"openwebui": "openwebui.env", "ag-ui": "ag-ui.headers", "other": "other.headers"}
_DOORS = {"openwebui": ["openai"], "ag-ui": ["agents"], "other": ["openai"]}
REMOTE_ACCESS = ("Kratos's chat server listens only on this computer. For an app on another computer, put a TLS "
                 "reverse proxy in front of it -- see the GUIDE, \"Remote access\". `kratos connect` never opens "
                 "Kratos to the network.")
SERVER_DOWN_NOTE = "Kratos's chat server isn't running: the app can't reach Kratos until it does"
BROWSER_NOTE = ("AG-UI apps must call Kratos from their server side. A page that calls it straight from the browser "
                "is refused: Kratos refuses web pages, so a site you visit can't use your token.")


class ConnectError(ValueError):
    """Refused or impossible, in plain words."""


# --------------------------------------------------------------------------- facts
@dataclass
class Facts:
    """What Kratos can see about this computer -- gathered by reads only (no docker call)."""
    serve_running: bool = False
    serve_port: int = 8770
    serve_build_older: bool = False
    serve_service: str | None = None       # "user" | "system" when kratos-serve runs as a service
    systemd_user: bool = False             # a user systemd manager answers (systemctl --user)
    linger: bool | None = None
    engine: str | None = None              # "docker" | "podman" | None
    engine_needs_sudo: bool = False        # docker's socket isn't open to this user
    docker_desktop: bool = False           # Docker Desktop (a VM) -- host networking isn't the host's
    existing_openwebui: str | None = None  # the address of an Open WebUI that already answers
    free_port: int | None = WEBUI_PORT_FIRST


def _port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _looks_like_openwebui(body: Any) -> bool:
    """Open WebUI's own `/api/config` names it (`"name": "Open WebUI"`, the default
    WEBUI_NAME, which may carry a suffix)."""
    return isinstance(body, dict) and "open webui" in str(body.get("name") or "").lower()


def probe_openwebui(url: str, timeout: float = 1.5) -> bool:
    """Whether `url` answers as Open WebUI (a GET of its public `/api/config`)."""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/config", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 -- a loopback address we built
            return _looks_like_openwebui(json.loads(r.read(200_000).decode("utf-8", "replace")))
    except (OSError, ValueError):
        return False


def _is_loopback_url(url: str) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1")


def _docker_socket_needs_sudo() -> bool:
    """Docker's socket exists but isn't readable and writable by this user (and we aren't
    root). A rootless Docker's socket under $XDG_RUNTIME_DIR counts as usable. No docker call."""
    if os.geteuid() == 0:
        return False
    rootless = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "docker.sock"
    if rootless.exists() and os.access(rootless, os.R_OK | os.W_OK):
        return False
    system = Path("/var/run/docker.sock")
    return system.exists() and not os.access(system, os.R_OK | os.W_OK)


def gather(data_dir: Path, *, url: str | None = None, which: Callable[[str], str | None] = shutil.which,
           probe: Callable[[str], bool] = probe_openwebui, port_free: Callable[[int], bool] = _port_free) -> Facts:
    """Read what this computer looks like right now. Reads only."""
    from kratos import settings_store
    from kratos.serve import settings as SS
    from kratos.serve import status as ST
    from kratos.subagent import core_listener as CL

    f = Facts()
    st = ST.read(data_dir)
    f.serve_running = bool(st.get("running"))
    f.serve_port = int(st.get("port") or settings_store.get(SS.PORT, data_dir=data_dir)) if f.serve_running else \
        int(settings_store.get(SS.PORT, data_dir=data_dir))
    if f.serve_running and st.get("build"):
        from kratos.utils.build_info import current_disk_build, same_code

        f.serve_build_older = not same_code(str(st.get("build")), current_disk_build())
    if which("systemctl"):
        f.systemd_user = CL._run_quiet(["systemctl", "--user", "show-environment"])[0] == 0
        f.serve_service = CL.service_scope(SERVE_SERVICE)
        f.linger = CL.linger_enabled() if f.systemd_user else None
    f.engine = "docker" if which("docker") else "podman" if which("podman") else None
    f.engine_needs_sudo = f.engine == "docker" and _docker_socket_needs_sudo()
    f.docker_desktop = f.engine == "docker" and (Path.home() / ".docker" / "desktop" / "docker.sock").exists()
    candidates = [url] if url else [f"http://127.0.0.1:{p}" for p in EXISTING_PROBE_PORTS]
    f.existing_openwebui = next((c for c in candidates if c and _is_loopback_url(c) and probe(c)), None)
    f.free_port = next((p for p in range(WEBUI_PORT_FIRST, WEBUI_PORT_LAST + 1) if port_free(p)), None)
    return f


# --------------------------------------------------------------------------- the plan
@dataclass
class Plan:
    """What `apply` would do and what it would show -- decided without side effects."""
    app: str
    machines: list[str]
    doors: list[str]
    token_name: str
    facts: Facts
    tools: bool = False
    keep_ollama: bool = False
    url: str | None = None
    replaces: dict[str, Any] | None = None      # the live connection this replaces
    mode: str = ""                               # openwebui: "new" | "existing"
    enable_agui: bool = False                    # AG-UI is off and must be turned on
    webui_port: int | None = None
    notes: list[str] = field(default_factory=list)
    model_ids: list[str] = field(default_factory=list)

    @property
    def secret_file(self) -> str:
        return f"{FOLDER}/{_SECRET_FILE[self.app]}"

    def summary(self) -> list[str]:
        """What will be made, in plain words (for the confirm step)."""
        out = [f"A token for {APP_WORDS[self.app]}: {self.token_name}, doors {', '.join(self.doors)}, "
               f"machines {', '.join(self.machines)}, expires after users.token_days (90 days by default)."]
        if self.replaces:
            out.append(f"It replaces the current {self.app} connection (token {self.replaces['token_id']}), which "
                       "stops working at once.")
        if self.enable_agui:
            out.append("AG-UI is off: this turns it on (agui.enabled = yes).")
        out.append(f"The token is written to {self.secret_file} in Kratos's data folder (only you can read it).")
        return out


def _clean_machines(data_dir: Path, machines: list[str] | None) -> list[str]:
    from kratos import kratos_config
    from kratos.tui_mk2.target_input import validate_targets

    wanted = [m.strip() for m in (machines or []) if str(m).strip()]
    if not wanted:
        active = kratos_config.get_active_target() or ""
        active = active.rsplit("@", 1)[-1].strip().strip("[]")
        if not active:
            raise ConnectError("name the machines it may ask about (--machines web-01,db-01)")
        wanted = [active]
    if any(w.startswith("@") for w in wanted):
        raise ConnectError("a token names machines, not groups -- list the machines; a group whose machines are all "
                           "in the token is offered to the app as kratos/@<group>")
    cleaned, err = validate_targets(wanted)
    if err:
        raise ConnectError(err)
    out: list[str] = []
    for c in cleaned:
        c = c.lower()
        if c not in out:
            out.append(c)
    return out


def _model_ids(data_dir: Path, machines: list[str]) -> list[str]:
    from kratos import kratos_config

    default = (kratos_config.process_target() or "").rsplit("@", 1)[-1].strip().strip("[]").lower()
    ids = (["kratos"] if default and default in machines else []) + [f"kratos/{m}" for m in machines]
    try:
        from kratos.fleet import groups as G

        for g in G.list_groups(data_dir):
            try:
                G.resolve(data_dir, f"@{g.name}", scope=machines)
            except G.GroupError:
                continue
            ids.append(f"kratos/@{g.name}")
    except Exception:  # noqa: BLE001 -- no group store yet
        pass
    return ids


def plan(data_dir: Path, app: str, *, machines: list[str] | None = None, tools: bool = False,
         url: str | None = None, keep_ollama: bool = False, new: bool = False, facts: Facts | None = None) -> Plan:
    """Decide what connecting `app` means here. Pure apart from reading `facts` (gathered
    when not given): no token, file or setting is touched."""
    from kratos import settings_store
    from kratos.serve import connect_store as CS
    from kratos.serve.a2a import settings as AS

    app = str(app or "").strip().lower()
    if app not in APPS:
        raise ConnectError(f"unknown app {app!r} -- one of: {', '.join(APPS)}")
    if tools and app != "openwebui":
        raise ConnectError("--tools is for Open WebUI (its tool servers use Kratos's MCP door)")
    if url and app != "openwebui":
        raise ConnectError("--url is for an Open WebUI that already runs")
    if url and not _is_loopback_url(url):
        raise ConnectError(REMOTE_ACCESS)
    if new and (app != "openwebui" or url):
        raise ConnectError("--new is for a new Open WebUI (not with --url)")
    f = facts if facts is not None else gather(data_dir, url=url)
    p = Plan(app=app, machines=_clean_machines(data_dir, machines), doors=list(_DOORS[app]) + (["mcp"] if tools else []),
             token_name=f"connect-{app}", facts=f, tools=tools, keep_ollama=keep_ollama, url=url)
    live = CS.live(data_dir, app)
    p.replaces = live[0] if live else None
    p.model_ids = _model_ids(data_dir, p.machines)
    if not f.serve_running:
        p.notes.append(SERVER_DOWN_NOTE
                       + (" -- Kratos can install it as a user service (kratos-serve) that starts by itself."
                          if f.systemd_user else
                          ". There's no systemd user manager here: run `kratos serve` in a terminal and keep it open; "
                          "the app works only while it runs."))
    elif f.serve_build_older:
        p.notes.append("The chat server runs an older build than the code on disk: restart it (`kratos serve`, or "
                       f"`systemctl --user restart {SERVE_SERVICE}`) to use the new version.")
    if app == "openwebui":
        if f.existing_openwebui and not new:
            p.mode = "existing"
        else:
            p.mode = "new"
            if f.engine is None:
                p.notes.append("No Docker or Podman here: Open WebUI can also run from pip (shown below).")
            if f.docker_desktop:
                p.notes.append("This looks like Docker Desktop, which runs containers in a VM: there --network host "
                               "doesn't reach this computer's 127.0.0.1, so the one-step command won't work. Use the "
                               "manual steps in the GUIDE (\"Doing it by hand\").")
            if f.free_port is None:
                raise ConnectError(f"ports {WEBUI_PORT_FIRST}-{WEBUI_PORT_LAST} are all in use -- free one, or connect "
                                   "an Open WebUI you start yourself with --url http://127.0.0.1:<port>")
            p.webui_port = f.free_port
    if app == "ag-ui":
        p.enable_agui = not bool(settings_store.get(AS.AGUI_ENABLED, data_dir=data_dir))
        p.notes.append(BROWSER_NOTE)
    return p


# --------------------------------------------------------------------------- what is shown
def env_file_text(plan_: Plan, token: str) -> str:
    """Open WebUI's settings for a new install, in Docker's --env-file format (KEY=value, no
    quotes). The OpenAI connection settings are read on Open WebUI's FIRST start only, then
    kept in its own database (its "persistent config")."""
    lines = [
        "# Written by `kratos connect openwebui` -- holds a Kratos token: keep it private.",
        "HOST=127.0.0.1",                                 # Open WebUI listens on this computer only
        f"PORT={plan_.webui_port}",
        f"OPENAI_API_BASE_URL=http://127.0.0.1:{plan_.facts.serve_port}/v1",
        f"OPENAI_API_KEY={token}",
        "ENABLE_FORWARD_USER_INFO_HEADERS=true",          # one Open WebUI chat = one Kratos session
    ]
    if not plan_.keep_ollama:
        lines.append("ENABLE_OLLAMA_API=false")
    return "\n".join(lines) + "\n"


def run_command(plan_: Plan, env_path: Path) -> str:
    """The one command that starts a new Open WebUI (Kratos never runs it)."""
    engine = plan_.facts.engine or "docker"
    sudo = "sudo " if plan_.facts.engine_needs_sudo else ""
    return (f"{sudo}{engine} run -d --name {OPENWEBUI_CONTAINER} --network host --env-file {env_path} "
            f"-v {OPENWEBUI_VOLUME}:/app/backend/data --restart unless-stopped "
            f"{OPENWEBUI_IMAGE}:{OPENWEBUI_TESTED_TAG}")


def pip_route(plan_: Plan, env_path: Path) -> str:
    """No container engine: Open WebUI from pip (it ignores PORT, so the port is a flag)."""
    return (f"python3 -m venv ~/open-webui-venv && ~/open-webui-venv/bin/pip install open-webui\n"
            f"set -a; . {env_path}; set +a; ~/open-webui-venv/bin/open-webui serve --host 127.0.0.1 "
            f"--port {plan_.webui_port}")


def _payload(machine: str) -> str:
    return json.dumps({"threadId": "kratos-connect-check", "runId": "check-1",
                       "messages": [{"id": "m1", "role": "user", "content": "Is anything suspicious running?"}],
                       "forwardedProps": {"kratos": {"machine": machine}}}, separators=(",", ":"))


@dataclass
class Result:
    plan: Plan
    token: str                                   # shown once, never stored by Kratos except in the 0600 file
    token_id: str
    secret_path: Path
    command: str | None = None                   # Open WebUI new install: the one command
    address: str | None = None                   # where to open Open WebUI
    paste: list[tuple[str, str]] = field(default_factory=list)   # (label, value) the person pastes
    check: str | None = None                     # a curl that proves it works
    notes: list[str] = field(default_factory=list)
    replaced_token: str | None = None

    @property
    def needs_paste(self) -> bool:
        return bool(self.paste)


# --------------------------------------------------------------------------- side effects
def _authorize(data_dir: Path, actor: Any, what: str) -> Any:
    """`tokens.manage`: the owner, at the Kratos computer (local only), never in a tool call."""
    from kratos import authz

    try:
        return authz.require(actor if actor is not None else authz.current_actor(), authz.P.TOKENS_MANAGE,
                             data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise ConnectError(f"refused: {e}") from None


@contextmanager
def _locked(data_dir: Path) -> Iterator[None]:
    """One connect at a time on this data folder (two windows, a script beside the TUI)."""
    from kratos import paths

    d = paths.ensure_private_dir(Path(data_dir) / FOLDER)
    fd = os.open(d / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _free_name(data_dir: Path, base: str) -> str:
    from kratos.serve import store as SS

    if not SS.name_in_use(data_dir, base):
        return base
    n = 2
    while SS.name_in_use(data_dir, f"{base}-r{n}"):
        n += 1
    return f"{base}-r{n}"


def _secret_text(plan_: Plan, token: str) -> str:
    if plan_.app == "openwebui" and plan_.mode == "new":
        return env_file_text(plan_, token)
    return f"Authorization: Bearer {token}\n"


def apply(data_dir: Path, plan_: Plan, *, actor: Any = None, replace: bool = False, enable_agui: bool = False,
          created_by: str = "cli") -> Result:
    """Make the connection `plan_` describes: the token, the 0600 file, the record -- in that
    order, with nothing half-made left behind (a token whose file couldn't be written is
    revoked again). `replace`: the person agreed to replace the app's live connection.
    `enable_agui`: they agreed to turn AG-UI on."""
    import sqlite3

    from kratos import paths, settings_store
    from kratos.serve import auth as A
    from kratos.serve import connect_store as CS
    from kratos.serve.a2a import settings as AS

    data_dir = Path(data_dir)
    principal = _authorize(data_dir, actor, f"connect {plan_.app}")
    who = getattr(principal.user, "name", None) or "owner"
    with _locked(data_dir):
        live = CS.live(data_dir, plan_.app)
        current = live[0] if live else None
        if current and not replace:
            raise ConnectError(f"{APP_WORDS[plan_.app]} is already connected (token {current['token_id']}) -- re-run "
                               "and agree to replace it, or use --renew")
        if plan_.app == "ag-ui" and plan_.enable_agui:
            if not enable_agui:
                raise ConnectError("AG-UI is off and stays off -- nothing was made (agui.enabled)")
            settings_store.set(AS.AGUI_ENABLED, True, data_dir=data_dir, actor=f"{created_by}:connect")
        token, row = A.create_token(data_dir, name=_free_name(data_dir, plan_.token_name), targets=plan_.machines,
                                    mcp="mcp" in plan_.doors, agents="agents" in plan_.doors, created_by="connect",
                                    user=None)
        secret = data_dir / plan_.secret_file
        try:
            paths.write_private_text(secret, _secret_text(plan_, token))
            CS.record(data_dir, app=plan_.app, token_id=row["token_id"], machines=plan_.machines, doors=plan_.doors,
                      secret_file=plan_.secret_file, serve_port=plan_.facts.serve_port, app_port=plan_.webui_port,
                      created_by=who, replaces=current["id"] if current else None)
        except (OSError, sqlite3.Error) as e:
            # Nothing half-made: the token goes again (the old connection, if any, is untouched).
            from kratos.serve import store as SS

            SS.revoke_token(data_dir, row["token_id"])
            if isinstance(e, sqlite3.IntegrityError):
                raise ConnectError(f"another `kratos connect {plan_.app}` finished first -- run it again") from None
            raise ConnectError(f"could not write {plan_.secret_file} ({e.__class__.__name__}): nothing was made") \
                from None
        replaced = None
        if current:
            from kratos.serve import store as SS

            SS.revoke_token(data_dir, current["token_id"], rotated_to=row["token_id"])
            replaced = current["token_id"]
    return _result(data_dir, plan_, token, row["token_id"], secret, replaced)


def _result(data_dir: Path, p: Plan, token: str, token_id: str, secret: Path, replaced: str | None) -> Result:
    port = p.facts.serve_port
    r = Result(plan=p, token=token, token_id=token_id, secret_path=secret, notes=list(p.notes), replaced_token=replaced)
    base = f"http://127.0.0.1:{port}"
    if p.app == "openwebui" and p.mode == "new":
        r.address = f"http://127.0.0.1:{p.webui_port}"
        if p.facts.engine is None:
            r.command = pip_route(p, secret)
        else:
            r.command = run_command(p, secret)
            if p.facts.engine_needs_sudo:
                r.notes.append("The command uses sudo: Docker's socket isn't open to your user (Kratos never asks to "
                               "join the docker group -- that is root-equivalent).")
            if p.facts.engine == "podman":
                r.notes.append("With Podman, --restart unless-stopped survives a reboot only when the podman-restart "
                               "service is enabled (systemctl --user enable podman-restart).")
        r.notes.append(f"Open {r.address}: the first account you create is Open WebUI's admin; the Kratos models "
                       f"({', '.join(p.model_ids)}) are already in its model list.")
        r.notes.append(f"The image is pinned to {OPENWEBUI_TESTED_TAG}, the version tested with Kratos "
                       f"({OPENWEBUI_IMAGE}:main is the rolling latest).")
        if p.replaces:
            r.notes.append("Open WebUI keeps the key it was started with in its own settings: if this Open WebUI is "
                           "already running, paste the new key in Admin Settings -> Connections -> the Kratos "
                           "connection, or recreate it with the command above (its data volume is kept).")
            r.paste = [("API key", token)]
    elif p.app == "openwebui":
        r.address = p.facts.existing_openwebui
        r.paste = [("URL", f"{base}/v1"), ("API key", token)]
        r.notes.append(f"In Open WebUI: Admin Settings -> Connections -> OpenAI -> +, paste the URL and the key, "
                       "save. (Its saved settings win over the environment, so Kratos can't set them for you.)")
        r.notes.append("If that Open WebUI runs in Docker without --network host it can't reach Kratos (which "
                       "listens on 127.0.0.1 only) -- answers will fail with a connection error. Then run a separate "
                       "Open WebUI for Kratos instead: `kratos connect openwebui --new` (its own container and data "
                       f"volume, {OPENWEBUI_CONTAINER}).")
    elif p.app == "ag-ui":
        r.paste = [("Endpoint", f"{base}/ag-ui/run"), ("Header", f"Authorization: Bearer {token}")]
        r.check = (f"curl -N -H @{secret} -H 'Content-Type: application/json' {base}/ag-ui/run "
                   f"-d '{_payload(p.machines[0])}'")
        r.notes.append("Name the machine in your run's forwardedProps: {\"kratos\": {\"machine\": \"<name>\"}} -- "
                       f"this token may ask about {', '.join(p.machines)}.")
    else:
        r.paste = [("Base URL", f"{base}/v1"), ("API key", token)]
        r.check = f"curl -s -H @{secret} {base}/v1/models"
        r.notes.append(f"Models: {', '.join(p.model_ids)}. Set the app's request timeout to 15 minutes if it has one "
                       "-- an investigation can take a few minutes.")
    if p.tools:
        r.notes.append(f"Tools (MCP): in Open WebUI, Admin Settings -> External Tools -> +, type MCP (Streamable HTTP), "
                       f"URL {base}/mcp, auth Bearer with the same key. With Gemini models set the model's Function "
                       "Calling to Legacy (Advanced Params).")
    return r


def renew(data_dir: Path, app: str, *, actor: Any = None, machines: list[str] | None = None,
          created_by: str = "cli", facts: Facts | None = None) -> Result:
    """A new token for the app's live connection (same machines and doors unless
    `machines`), the old one revoked, the file rewritten."""
    from kratos.serve import connect_store as CS

    live = CS.live(data_dir, app)
    if not live:
        raise ConnectError(f"{APP_WORDS.get(app, app)} isn't connected -- run `kratos connect {app}`")
    cur = live[0]
    p = plan(data_dir, app, machines=machines or cur["machines"], tools="mcp" in cur["doors"], facts=facts)
    if app == "openwebui" and p.mode == "existing":
        pass                                   # an Open WebUI answers: the key is pasted
    elif app == "openwebui" and cur.get("app_port"):
        p.webui_port = int(cur["app_port"])     # keep the port the person already opens
    p.enable_agui = False
    r = apply(data_dir, p, actor=actor, replace=True, created_by=created_by)
    if app == "openwebui" and not r.paste:
        r.paste = [("API key", r.token)]
    if app == "openwebui":
        r.notes.insert(0, "Open WebUI keeps the key it was first started with in its own settings, so the new key has to "
                          "be pasted once: Admin Settings -> Connections -> the Kratos connection -> key.")
    return r


@dataclass
class Undone:
    app: str
    token_id: str
    removed_file: bool
    cleanup: list[str]


def undo(data_dir: Path, app: str, *, actor: Any = None) -> Undone:
    """Disconnect the app: revoke its token first (it stops working at once), remove its
    0600 file (only that file), close the record. The container stays -- its commands are
    returned for the person to run if they want."""
    from kratos.serve import connect_store as CS
    from kratos.serve import store as SS

    app = str(app or "").strip().lower()
    if app not in APPS:
        raise ConnectError(f"unknown app {app!r} -- one of: {', '.join(APPS)}")
    _authorize(Path(data_dir), actor, f"connect {app} --undo")
    with _locked(Path(data_dir)):
        live = CS.live(data_dir, app)
        if not live:
            raise ConnectError(f"{APP_WORDS[app]} isn't connected")
        cur = live[0]
        SS.revoke_token(data_dir, cur["token_id"])
        path = Path(data_dir) / cur["secret_file"]
        removed = False
        if path.parent == Path(data_dir) / FOLDER and path.name in _SECRET_FILE.values():
            try:
                path.unlink()
                removed = True
            except FileNotFoundError:
                pass
        CS.close(data_dir, cur["id"], "undone")
    cleanup = ([f"docker rm -f {OPENWEBUI_CONTAINER}   # stops and removes the container",
                f"docker volume rm {OPENWEBUI_VOLUME}   # ONLY if you also want Open WebUI's chats and accounts gone"]
               if app == "openwebui" else [])
    return Undone(app=app, token_id=cur["token_id"], removed_file=removed, cleanup=cleanup)


# --------------------------------------------------------------------------- the chat server as a service
def serve_exec_start(data_dir: Path) -> str:
    from kratos import paths
    from kratos.subagent import core_listener as CL

    exe = CL._kratos_executable()
    dd = Path(data_dir).resolve()
    default = Path(paths.default_data_dir()).resolve()
    return f"{exe} serve" if dd == default else f"{exe} --data-dir {dd} serve"


def serve_service_commands(data_dir: Path) -> list[str]:
    """Install `kratos serve` as the systemd USER service kratos-serve (no sudo)."""
    from kratos.subagent import core_listener as CL

    env = {"KRATOS_HOME": os.environ["KRATOS_HOME"]} if os.environ.get("KRATOS_HOME", "").strip() else None
    unit = CL.service_unit(description="Kratos chat server (kratos serve)", exec_start=serve_exec_start(data_dir),
                           user_mode=True, restart="on-failure", environment=env)
    return CL.service_install_commands(unit, SERVE_SERVICE, user_mode=True)


def install_serve_service(data_dir: Path, *, actor: Any = None, wait_seconds: float = 15.0,
                          runner: Callable[[str], tuple[int, str]] | None = None) -> tuple[bool, str]:
    """Run the user-service commands (the person agreed), then wait until the server
    answers. (ok, plain words). Never runs sudo: lingering, when off, is explained."""
    import subprocess

    from kratos.serve import status as ST
    from kratos.subagent import core_listener as CL

    _authorize(Path(data_dir), actor, "install the kratos-serve user service")

    def default_runner(cmd: str) -> tuple[int, str]:
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)  # noqa: S602 -- our text
            return p.returncode, (p.stderr or p.stdout or "").strip()
        except (OSError, subprocess.SubprocessError) as e:
            return 1, str(e)

    run = runner or default_runner
    for cmd in serve_service_commands(data_dir):
        rc, out = run(cmd)
        if rc != 0:
            return False, f"`{cmd.splitlines()[0]}` failed: {out[:300]}"
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if ST.read(data_dir).get("running"):
            break
        time.sleep(0.5)
    else:
        return False, (f"the service was installed but the chat server didn't answer within {int(wait_seconds)}s -- "
                       f"see `systemctl --user status {SERVE_SERVICE}`")
    words = f"The chat server runs as the user service {SERVE_SERVICE}: it keeps running after you close Kratos."
    linger = CL.linger_enabled()
    if linger is False:
        words += (" Lingering is OFF for your user, so it stops when you log out and won't start at boot -- run once: "
                  "sudo loginctl enable-linger $USER")
    elif linger:
        words += " It starts at boot."
    return True, words


# --------------------------------------------------------------------------- status
@dataclass
class Status:
    app: str
    token_id: str
    token_name: str
    machines: list[str]
    doors: list[str]
    expires_at: float | None
    revoked: bool
    last_used_at: float | None
    serve_running: bool
    port_now: int
    port_then: int
    secret_file: str
    secret_present: bool

    @property
    def days_left(self) -> float | None:
        return None if self.expires_at is None else (self.expires_at - time.time()) / 86400.0

    @property
    def state(self) -> str:
        """ok | expiring | expired | revoked | server down | port changed"""
        if self.revoked:
            return "revoked"
        if self.days_left is not None and self.days_left <= 0:
            return "expired"
        if self.port_now != self.port_then:
            return "port changed"
        if not self.serve_running:
            return "server down"
        if self.days_left is not None and self.days_left <= EXPIRY_WARN_DAYS:
            return "expiring"
        return "ok"

    def words(self) -> str:
        s = self.state
        exp = ("never expires" if self.expires_at is None else
               "expired " + time.strftime("%Y-%m-%d", time.localtime(self.expires_at)) if s == "expired" else
               "expires " + time.strftime("%Y-%m-%d", time.localtime(self.expires_at)))
        out = f"{APP_WORDS[self.app]}: token {self.token_name} ({', '.join(self.machines)}), {exp}"
        out += {"expired": f" -- run `kratos connect {self.app} --renew`",
                "expiring": f" -- renew soon: `kratos connect {self.app} --renew`",
                "revoked": f" -- the token was revoked; `kratos connect {self.app} --renew`",
                "port changed": (f" -- the chat server moved from port {self.port_then} to {self.port_now}: run "
                                 f"`kratos connect {self.app} --renew` and paste the new address"),
                "server down": " -- the chat server isn't running, so the app gets no answer",
                "ok": ""}[s]
        return out


def status(data_dir: Path) -> list[Status]:
    from kratos import settings_store
    from kratos.serve import connect_store as CS
    from kratos.serve import settings as SS
    from kratos.serve import status as ST
    from kratos.serve import store as TS

    st = ST.read(data_dir)
    port_now = int(st.get("port") or settings_store.get(SS.PORT, data_dir=data_dir)) if st.get("running") else \
        int(settings_store.get(SS.PORT, data_dir=data_dir))
    out: list[Status] = []
    for row in CS.live(data_dir):
        tok = TS.get_token(data_dir, row["token_id"]) or {}
        out.append(Status(app=row["app"], token_id=row["token_id"], token_name=str(tok.get("name") or "?"),
                          machines=row["machines"], doors=row["doors"], expires_at=tok.get("expires_at"),
                          revoked=bool(tok.get("revoked_at")) or not tok, last_used_at=tok.get("last_used_at"),
                          serve_running=bool(st.get("running")), port_now=port_now, port_then=int(row["serve_port"]),
                          secret_file=row["secret_file"],
                          secret_present=(Path(data_dir) / row["secret_file"]).exists()))
    return out


def doctor_rows(data_dir: Path) -> list[tuple[str, str, str]]:
    """(status, check, detail) for `/doctor`: one row per connected app; none when nothing is."""
    rows = []
    for s in status(data_dir):
        level = {"ok": "info", "expiring": "warn", "server down": "warn"}.get(s.state, "fail")
        rows.append((level, f"chat app: {s.app}", s.words()))
    return rows


def status_bar_text(data_dir: Path) -> str | None:
    """The TUI footer's note: 'chat app token expires in 9 days' / '... expired'."""
    worst = None
    for s in status(data_dir):
        if s.state == "expired":
            return f"{s.app} token expired: /connect"
        if s.state == "expiring" and s.days_left is not None:
            days = max(0, int(s.days_left))
            worst = f"{s.app} token expires in {days} day{'s' if days != 1 else ''}"
    return worst
