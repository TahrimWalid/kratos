#!/usr/bin/env python3
"""Build the sub-agent bundle from the repository and check it on the oldest Python
the agent supports (3.8) -- with nothing installed, as on a monitored machine.

    agent_bundle.py build <dir>   write <dir>/subagent/ exactly as the installer lays it out
    agent_bundle.py check         build into a temp folder, import every bundle module
                                  isolated (-I: no site-packages), run the bundle's own
                                  tests (tests/agent_bundle/, unittest only)

This script must itself run on Python 3.8 and import nothing from kratos (kratos needs
3.10), so it reads the bundle's file list from installer.py's source text.
tests/test_agent_bundle_list.py checks that list against the installer's real one.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = REPO / "src" / "kratos"
INSTALLER = PKG / "subagent" / "installer.py"
BUNDLE_TESTS = REPO / "tests" / "agent_bundle"
OLDEST = (3, 8)


def bundle_sources(installer_text: str | None = None) -> dict[str, Path]:
    """{name in the bundle: source file}, read from installer.py (BUNDLE_FILES +
    EXTRA_BUNDLE_FILES) and the starter YARA rules folder."""
    text = installer_text if installer_text is not None else INSTALLER.read_text(encoding="utf-8")
    m = re.search(r"^BUNDLE_FILES[^=]*=\s*\((.*?)\)\n", text, re.S | re.M)
    if not m:
        raise SystemExit("installer.py: BUNDLE_FILES not found")
    out = {name: PKG / "subagent" / name for name in re.findall(r'"([A-Za-z0-9_]+\.py)"', m.group(1))}
    m = re.search(r"^EXTRA_BUNDLE_FILES[^=]*=\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        raise SystemExit("installer.py: EXTRA_BUNDLE_FILES not found")
    for name, parts in re.findall(r'"([A-Za-z0-9_]+\.py)":\s*_PACKAGE_ROOT((?:\s*/\s*"[A-Za-z0-9_.]+")+)', m.group(1)):
        out[name] = PKG.joinpath(*re.findall(r'"([^"]+)"', parts))
    rules = PKG / "yara_rules"
    for f in sorted(rules.iterdir()):
        if f.is_file():
            out["yara_rules/" + f.name] = f
    return out


BUNDLE_INIT = '"""Kratos sub-agent bundle (built by scripts/ci/agent_bundle.py for testing)."""\n'


def build(dest: Path) -> Path:
    pkg = dest / "subagent"
    if pkg.exists():
        shutil.rmtree(pkg)
    (pkg / "yara_rules").mkdir(parents=True)
    (pkg / "__init__.py").write_text(BUNDLE_INIT, encoding="utf-8")
    for name, src in bundle_sources().items():
        shutil.copyfile(src, pkg / name)
    return pkg


def _run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> int:
    print("$ " + " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=str(cwd), env=env).returncode


def import_check(parent: Path, python: str = sys.executable) -> int:
    """Import every bundle module with `python -I -S`: no site-packages, so a bundle
    file that needs anything outside the standard library fails here."""
    modules = sorted(p.stem for p in (parent / "subagent").glob("*.py") if p.stem != "__init__")
    code = ("import importlib, sys\n"
            f"sys.path.insert(0, {str(parent)!r})\n"
            f"mods = {modules!r}\n"
            "for m in mods:\n"
            "    importlib.import_module('subagent.' + m)\n"
            "from subagent import agent\n"
            "print('imported', len(mods), 'bundle modules; agent', agent.AGENT_VERSION)\n")
    return _run([python, "-I", "-S", "-c", code], parent)


def run_bundle_tests(parent: Path, python: str = sys.executable) -> int:
    env = dict(os.environ, KRATOS_AGENT_BUNDLE_DIR=str(parent), PYTHONDONTWRITEBYTECODE="1")
    return _run([python, "-I", "-S", "-m", "unittest", "discover", "-s", str(BUNDLE_TESTS), "-t",
                 str(BUNDLE_TESTS), "-v"], parent, env)


def check() -> int:
    if sys.version_info[:2] != OLDEST:
        print(f"note: running on {sys.version.split()[0]}, not the oldest supported {OLDEST[0]}.{OLDEST[1]}")
    tmp = Path(tempfile.mkdtemp(prefix="kratos-bundle-"))
    try:
        build(tmp)
        print(f"bundle built from {INSTALLER.relative_to(REPO)}'s file list; Python {sys.version.split()[0]}")
        failed = import_check(tmp)
        failed |= run_bundle_tests(tmp)
        return 1 if failed else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "build":
        print(build(Path(argv[1])))
        return 0
    if argv == ["check"]:
        return check()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
