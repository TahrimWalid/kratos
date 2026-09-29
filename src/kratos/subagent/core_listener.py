"""
Core-side listener lifecycle helpers, so a user never has to open a second
terminal and run `kratos subagent-serve` by hand.

Two ways the listener can run, most-reliable first:

- **Always-on service** (recommended for monitoring): `kratos subagent-serve`
  installed as a systemd service on the core, so telemetry keeps arriving even
  when the TUI is closed and survives a reboot. `core_service_unit()` /
  `core_service_install_commands()` produce the unit + the commands to install
  it (run for the user when sudo is passwordless, shown to paste otherwise).
- **In-process** (fallback / interactive): the TUI runs `CoreServer.serve_forever`
  as a worker while it's open -- zero setup, but only receives telemetry while
  Kratos is running. The app starts this ONLY when nothing is already listening
  (so it defers to the always-on service when that exists).

This module is pure/host-side: `listener_running()` does a local TCP connect,
the rest is text generation. It never runs anything with sudo itself.
"""
from __future__ import annotations

import os
import shutil
import socket
import sys
from pathlib import Path

DEFAULT_PORT = 8765
# Bind all interfaces so the listener is reachable via whichever path a target
# dials (LAN IP or Tailscale IP) without coupling the listener's bind address to
# the installer's --core-host. The pairing token authenticates every connection;
# tighten with Tailscale ACLs / a firewall if the LAN is untrusted.
DEFAULT_BIND_HOST = "0.0.0.0"
CORE_SERVICE_NAME = "kratos-core-listener"


def listener_running(port: int = DEFAULT_PORT, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    """Is something already accepting connections on the core listener port?"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _kratos_executable() -> str:
    """Path to the `kratos` CLI for a service ExecStart line.

    The console script installed beside the RUNNING interpreter comes first: it
    is the same install the user is running now, and it works from a venv that
    was never put on PATH (a systemd service has no activated venv). Then PATH,
    then `<python> -m kratos.cli.app` (which cli/app.py's __main__ guard runs)."""
    beside = Path(sys.executable).parent / "kratos"
    if beside.is_file() and os.access(beside, os.X_OK):
        return str(beside)
    found = shutil.which("kratos")
    if found:
        return found
    return f"{sys.executable} -m kratos.cli.app"


def core_service_exec_start(data_dir: Path, port: int = DEFAULT_PORT, bind_host: str = DEFAULT_BIND_HOST) -> str:
    exe = _kratos_executable()
    data_dir = Path(data_dir).resolve()
    return f"{exe} --data-dir {data_dir} subagent-serve --host {bind_host} --port {port}"


def core_service_unit(data_dir: Path, port: int = DEFAULT_PORT, bind_host: str = DEFAULT_BIND_HOST, user_mode: bool = False) -> str:
    """A systemd unit that runs the core telemetry listener always-on."""
    exec_start = core_service_exec_start(data_dir, port=port, bind_host=bind_host)
    wanted_by = "default.target" if user_mode else "multi-user.target"
    # A SYSTEM service runs as root unless told otherwise, and would then create
    # root-owned kratos.db-wal/-shm files the user's own TUI/CLI can't write.
    # Run it as the installing user (a user service already is).
    run_as = ""
    if not user_mode and os.geteuid() != 0:
        import grp
        import pwd

        run_as = f"User={pwd.getpwuid(os.getuid()).pw_name}\nGroup={grp.getgrgid(os.getgid()).gr_name}\n"
    return (
        "[Unit]\n"
        "Description=Kratos sub-agent telemetry listener (core)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"{run_as}"
        f"ExecStart={exec_start}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        f"WantedBy={wanted_by}\n"
    )


def core_service_install_commands(
    data_dir: Path,
    port: int = DEFAULT_PORT,
    bind_host: str = DEFAULT_BIND_HOST,
    user_mode: bool = False,
    service_name: str = CORE_SERVICE_NAME,
) -> list[str]:
    """The exact shell commands to install + start the core listener service.

    ``user_mode`` uses ``systemctl --user`` (no root); otherwise a system
    service via ``sudo``. Returned as a list so the caller can run them (when
    sudo is passwordless) or present them for the user to paste (one-time).
    """
    unit = core_service_unit(data_dir, port=port, bind_host=bind_host, user_mode=user_mode)
    if user_mode:
        unit_path = f"$HOME/.config/systemd/user/{service_name}.service"
        return [
            "mkdir -p $HOME/.config/systemd/user",
            f"cat > {unit_path} <<'UNIT'\n{unit}UNIT",
            "systemctl --user daemon-reload",
            f"systemctl --user enable --now {service_name}.service",
        ]
    unit_path = f"/etc/systemd/system/{service_name}.service"
    return [
        f"sudo tee {unit_path} >/dev/null <<'UNIT'\n{unit}UNIT",
        "sudo systemctl daemon-reload",
        f"sudo systemctl enable --now {service_name}.service",
    ]


def core_service_restart_commands(*, user_mode: bool, service_name: str = CORE_SERVICE_NAME) -> list[str]:
    """Restart an installed listener service (e.g. to load a newer build)."""
    if user_mode:
        return ["systemctl --user daemon-reload", f"systemctl --user restart {service_name}.service"]
    return ["sudo -n systemctl daemon-reload", f"sudo -n systemctl restart {service_name}.service"]


def passwordless_sudo_available() -> bool:
    """True if `sudo -n true` succeeds -- i.e. we can install a system service
    without an interactive password prompt (which a TUI can't show)."""
    import subprocess

    if shutil.which("sudo") is None:
        return False
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------------------
# Who is listening, and will it survive closing Kratos? (connection-UX WS2)
# ---------------------------------------------------------------------------
def _run_quiet(cmd: list[str], timeout: float = 3.0) -> tuple[int, str]:
    import subprocess

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def service_scope(service_name: str = CORE_SERVICE_NAME) -> str | None:
    """"user" or "system" if the always-on listener service is active in that
    systemd scope, else None."""
    if shutil.which("systemctl") is None:
        return None
    if _run_quiet(["systemctl", "--user", "is-active", f"{service_name}.service"])[1] == "active":
        return "user"
    if _run_quiet(["systemctl", "is-active", f"{service_name}.service"])[1] == "active":
        return "system"
    return None


def linger_enabled(user: str | None = None) -> bool | None:
    """Whether systemd keeps this user's services running without a login
    session (so a USER service starts at boot). None if unknown."""
    import getpass

    if shutil.which("loginctl") is None:
        return None
    rc, out = _run_quiet(["loginctl", "show-user", user or getpass.getuser(), "-p", "Linger", "--value"])
    return {"yes": True, "no": False}.get(out) if rc == 0 else None


def describe_listener(
    listeners: list[dict],
    *,
    in_process_here: bool,
    disk_build: str,
    scope: str | None,
    linger: bool | None,
) -> tuple[str, str, bool]:
    """(message, severity, offer_L) for the /subagent listener line. Pure.

    `listeners` are the live registrations (subagent_store.live_listeners);
    `scope`/`linger` describe the always-on service when one is installed."""
    if not listeners:
        return ("Not listening: paired servers can't check in right now. Press L to install the always-on "
                "listener (recommended), or keep Kratos open on this screen.", "critical", True)
    lst = listeners[0]
    extra = ""
    if len(listeners) > 1:
        extra = f" ({len(listeners)} listeners registered -- only one can hold the port; the others are retrying)"
    older = lst.get("build") and lst["build"] != disk_build
    from kratos.utils.build_info import display_build

    stale = (f" It runs an older build ({display_build(lst['build'])}); press L to restart it on the current one."
             if older else "")
    mode = lst.get("mode")
    if mode == "service":
        where = f"{scope} service" if scope else "systemd service"
        if scope == "user" and linger is False:
            return (f"Always-on listener ({where}, pid {lst.get('pid')}) -- but lingering is OFF, so it stops when "
                    f"you log out and won't start at boot. Press L to fix.{stale}{extra}", "attention", True)
        boot = " Starts at boot." if scope == "system" or linger else ""
        return (f"Always-on listener ({where}, pid {lst.get('pid')}): keeps receiving after you close Kratos."
                f"{boot}{stale}{extra}", "attention" if older else "ok", bool(older))
    if mode == "in_process" and in_process_here:
        return ("Listening inside this Kratos window: telemetry STOPS when you quit. Press L to keep it "
                f"running always.{extra}", "attention", True)
    if mode == "in_process":
        return (f"Listening inside another Kratos window (pid {lst.get('pid')}): telemetry stops when that window "
                f"closes. Press L for an always-on listener.{extra}", "attention", True)
    return (f"Listening in a terminal (`kratos subagent-serve`, pid {lst.get('pid')}): stops when that terminal "
            f"closes. Press L for an always-on listener.{stale}{extra}", "attention", True)


def service_plan(*, passwordless_sudo: bool, linger: bool | None, scope_now: str | None) -> tuple[bool, str]:
    """(user_mode, explanation) shown BEFORE `L` does anything."""
    if scope_now:
        return scope_now == "user", (
            f"The always-on listener is already installed as a {scope_now} service. This restarts it so it runs the "
            "build that is on disk now. Connected servers reconnect on their own within a minute.")
    if passwordless_sudo:
        return False, ("Installs a SYSTEM service (you have passwordless sudo). It runs as your user, starts at boot "
                       "and keeps receiving whether or not anyone is logged in.")
    linger_note = {
        True: "Lingering is already ON for your user, so it also starts at boot without a login.",
        False: "Lingering is OFF for your user, so it would stop when you log out; Kratos will try to turn it on "
               "(`loginctl enable-linger`) and show you the command if that needs admin rights.",
        None: "Kratos couldn't tell whether lingering is on; if the service stops when you log out, run "
              "`sudo loginctl enable-linger $USER` once.",
    }[linger]
    return True, ("Installs a USER service (no passwordless sudo here): it runs as you and keeps receiving after you "
                  f"close Kratos. {linger_note}")
