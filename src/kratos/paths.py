"""Where Kratos keeps its settings and its data.

Three layouts, decided once at import:

* **checkout** -- running from a git clone (including ``pip install -e .``).
  Everything stays next to the code, exactly where it always was:
  ``<repo>/.env``, ``<repo>/data``, ``<repo>/kept_tools``, ``<repo>/sandbox_staging``,
  ``<repo>/vulscan``, ``<repo>/llm/models``, ``<repo>/tests/self_write_harnesses``.
* **installed** -- a normal ``pip install`` (the package lives in site-packages,
  which is not ours to write to and is replaced on upgrade). Settings go to
  ``$XDG_CONFIG_HOME/kratos/.env`` (``~/.config/kratos/.env``) and everything else
  under ``$XDG_DATA_HOME/kratos`` (``~/.local/share/kratos``), laid out like a checkout.
* **custom** -- ``KRATOS_HOME`` is set in the real environment: settings AND data
  live under that one folder (``$KRATOS_HOME/.env``, ``$KRATOS_HOME/data``, ...).
  It has to be a real environment variable, not a line in ``.env``, since it
  decides where ``.env`` is.

None of this depends on the current working directory: starting ``kratos`` from
another folder never creates a fresh, empty ``data/`` there. An explicit
``--data-dir`` still wins for the data folder.

Nothing here creates directories on import; callers create what they write.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent  # .../kratos


def _checkout_root() -> Path | None:
    """The repository root when running from a source checkout (src layout), else None."""
    src = _PKG_DIR.parent
    root = src.parent
    if src.name == "src" and (root / "pyproject.toml").is_file():
        return root
    return None


def _xdg(var: str, fallback: str) -> Path:
    # The XDG spec says a relative value must be ignored.
    value = os.environ.get(var, "").strip()
    if value and os.path.isabs(value):
        return Path(value)
    return Path.home() / fallback


def _resolve_layout() -> tuple[str, Path, Path]:
    """(layout, config_dir, state_root)."""
    home = os.environ.get("KRATOS_HOME", "").strip()
    if home:
        root = Path(home).expanduser().resolve()
        return "custom", root, root
    checkout = _checkout_root()
    if checkout is not None:
        return "checkout", checkout, checkout
    return ("installed",
            _xdg("XDG_CONFIG_HOME", ".config") / "kratos",
            _xdg("XDG_DATA_HOME", ".local/share") / "kratos")


LAYOUT, CONFIG_DIR, STATE_ROOT = _resolve_layout()


def env_file() -> Path:
    """The settings file (model profiles, API keys, ntfy, SSH options)."""
    return CONFIG_DIR / ".env"


def default_data_dir() -> Path:
    """Sessions, scans, logs, reports, the session database, presets, schedules."""
    return STATE_ROOT / "data"


def kept_tools_dir() -> Path:
    """Tools you approved with /evolve, and their metadata."""
    return STATE_ROOT / "kept_tools"


def sandbox_staging_dir() -> Path:
    """Candidate tools waiting for their sandbox test (disposable)."""
    return STATE_ROOT / "sandbox_staging"


def harness_dir() -> Path:
    """Where /evolve saves the pytest harness that defines a new tool's behaviour."""
    if LAYOUT == "checkout":
        return STATE_ROOT / "tests" / "self_write_harnesses"
    return STATE_ROOT / "evolve_harnesses"


def vulscan_dir() -> Path:
    """nmap's vulscan script and its CVE list (`kratos vulscan-install`)."""
    return STATE_ROOT / "vulscan"


def threat_intel_cache_dir() -> Path:
    """The offline AlienVault OTX reputation cache."""
    return STATE_ROOT / "data" / "threat_intel_cache"


def llm_models_dir() -> Path:
    """Local GGUF model files for the in-process llama.cpp backend."""
    return STATE_ROOT / "llm" / "models"


def describe() -> list[tuple[str, Path]]:
    """Labelled locations, for `kratos init` and /doctor."""
    return [
        ("Settings file", env_file()),
        ("Data folder", default_data_dir()),
        ("Kept tools", kept_tools_dir()),
        ("vulscan CVE data", vulscan_dir()),
    ]


def layout_note() -> str:
    if LAYOUT == "checkout":
        return "running from a source checkout: settings and data live next to the code"
    if LAYOUT == "custom":
        return "KRATOS_HOME is set: settings and data live under that folder"
    return "installed copy: settings in ~/.config/kratos, data in ~/.local/share/kratos (XDG)"


def ensure_private_dir(path: Path) -> Path:
    """Create `path` (and any missing parents). Every directory created here is
    owner-only (0700): the data folder holds findings and the settings folder
    holds API keys. Directories that already exist keep their permissions."""
    path = Path(path)
    missing: list[Path] = []
    probe = path
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            continue
        try:
            directory.chmod(0o700)  # mkdir's mode is filtered by the umask
        except OSError:
            pass
    return path


def write_private_text(path: Path, text: str) -> None:
    """Atomically write a file that may hold secrets (the settings file).

    A new file is created owner-only (0600) in an owner-only folder; an existing
    file keeps its permissions. Written to a temp file in the same folder and
    renamed over the target, so a crash never leaves a half-written file. A
    symlinked settings file is written through to its real target."""
    target = Path(path)
    if target.is_symlink():
        target = target.resolve()
    ensure_private_dir(target.parent)
    mode = (target.stat().st_mode & 0o777) if target.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
