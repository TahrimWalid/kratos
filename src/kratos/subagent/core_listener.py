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
