#!/usr/bin/env python3
"""Package checks: what the built wheel must contain, and that an installed wheel works.

    package_check.py contents <wheel>            every file the code opens at runtime is in the wheel
    package_check.py install <wheel> [--python X] a fresh venv installs the wheel and runs the checks

The contents check does not trust a hand-written list. It reads Kratos's source
(`src/kratos`) and resolves every path the code builds from its own location --
`Path(__file__).resolve().parents[1] / "yara_rules"`, `files("kratos.attack").joinpath(...)`,
`os.path.join(os.path.dirname(os.path.abspath(__file__)), ...)`, through module-level
names -- to a path inside the package. Each such file (or every file in such a
folder) must be in the wheel. Every non-Python file under `src/kratos` must be in
the wheel too, so a new data file that is opened in a way the resolver can't
follow is still caught.

Stdlib only: it runs before anything is installed.
"""
from __future__ import annotations

import argparse
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
PACKAGE = "kratos"

# Paths the code builds from its own location that are deliberately NOT in the
# package, with the reason. Anything else that resolves to a missing path fails.
NOT_IN_PACKAGE = {
    # reads.py runs on a monitored machine as part of the sub-agent bundle; the
    # installer writes the starter rules next to it there (installer.YARA_RULES_SOURCE).
    "kratos/subagent/yara_rules": "exists only in an installed sub-agent bundle",
}


# --------------------------------------------------------------------------- resolver

class _PkgPath:
    """A path relative to `src/` (e.g. kratos/attack), or None when not resolvable."""

    __slots__ = ("parts",)

    def __init__(self, parts: tuple[str, ...]) -> None:
        self.parts = parts

    def child(self, *names: str) -> "_PkgPath":
        out = list(self.parts)
        for n in names:
            for piece in PurePosixPath(n).parts:
                if piece == "..":
                    if out:
                        out.pop()
                elif piece not in (".", ""):
                    out.append(piece)
        return _PkgPath(tuple(out))

    def parent(self, n: int = 1) -> "_PkgPath":
        return _PkgPath(self.parts[: max(0, len(self.parts) - n)])

    def rel(self) -> str:
        return "/".join(self.parts)


class _Resolver(ast.NodeVisitor):
    def __init__(self, module_rel: str) -> None:
        self.file = _PkgPath(tuple(module_rel.split("/")))
        self.names: dict[str, object] = {}      # module-level name -> str constant / _PkgPath / tuple
        self.found: list[tuple[str, int]] = []  # (resolved rel path, line)

    # -- values --
    def value(self, node: ast.AST) -> object | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            if node.id == "__file__":
                return self.file
            return self.names.get(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            vals = [self.value(e) for e in node.elts]
            return tuple(vals) if all(isinstance(v, str) for v in vals) else None
        if isinstance(node, ast.Attribute):
            base = self.value(node.value)
            if isinstance(base, _PkgPath) and node.attr == "parent":
                return base.parent()
            return None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
            base = self.value(node.value.value)
            idx = node.slice
            if isinstance(base, _PkgPath) and isinstance(idx, ast.Constant) and isinstance(idx.value, int):
                return base.parent(idx.value + 1)
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left, right = self.value(node.left), self.value(node.right)
            if isinstance(left, _PkgPath) and isinstance(right, str):
                return left.child(right)
            return None
        if isinstance(node, ast.Call):
            return self._call(node)
        return None

    def _call(self, node: ast.Call) -> object | None:
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
        args = [self.value(a) for a in node.args]
        if name in ("Path", "PurePath", "PosixPath") and len(args) == 1:
            return args[0] if isinstance(args[0], _PkgPath) else None
        if name in ("resolve", "absolute", "expanduser") and isinstance(fn, ast.Attribute):
            base = self.value(fn.value)
            return base if isinstance(base, _PkgPath) else None
        if name in ("abspath", "realpath", "normpath") and len(args) == 1 and isinstance(args[0], _PkgPath):
            return args[0]
        if name == "dirname" and len(args) == 1 and isinstance(args[0], _PkgPath):
            return args[0].parent()
        if name == "join" and args and isinstance(args[0], _PkgPath) and all(isinstance(a, str) for a in args[1:]):
            return args[0].child(*args[1:])  # type: ignore[arg-type]
        if name == "files" and len(args) == 1 and isinstance(args[0], str) and args[0].split(".")[0] == PACKAGE:
            return _PkgPath(tuple(args[0].split(".")))
        if name == "joinpath" and isinstance(fn, ast.Attribute):
            base = self.value(fn.value)
            if isinstance(base, _PkgPath) and args and all(isinstance(a, str) for a in args):
                return base.child(*args)  # type: ignore[arg-type]
        return None

    # -- walk --
    def note(self, node: ast.AST) -> None:
        """Record a path built from the module's own location that names something
        (a base folder like `Path(__file__).parent` -- an ancestor -- names nothing)."""
        v = self.value(node)
        if not isinstance(v, _PkgPath) or v.parts[:1] != (PACKAGE,):
            return
        if v.parts == self.file.parts[: len(v.parts)]:
            return  # the module itself or one of its parent folders
        self.found.append((v.rel(), getattr(node, "lineno", 0)))

    def run(self, tree: ast.Module) -> list[tuple[str, int]]:
        for stmt in tree.body:   # module-level names first, in order
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                v = self.value(stmt.value)
                for t in targets:
                    if isinstance(t, ast.Name) and v is not None:
                        self.names[t.id] = v
        for node in ast.walk(tree):
            if isinstance(node, (ast.BinOp, ast.Call)):
                self.note(node)
        return self.found


def referenced_paths(src: Path = SRC) -> dict[str, list[str]]:
    """{package-relative path the code builds from its own location: ["file:line", ...]}."""
    out: dict[str, list[str]] = {}
    for py in sorted((src / PACKAGE).rglob("*.py")):
        if "__pycache__" in py.parts:
            continue
        rel = py.relative_to(src).as_posix()
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for path, line in _Resolver(rel).run(tree):
            out.setdefault(path, []).append(f"{rel}:{line}")
    return out


def required_files(src: Path = SRC) -> tuple[set[str], list[str]]:
    """(every file the wheel must hold, problems). Problems are referenced paths that
    don't exist in the source tree and aren't listed in NOT_IN_PACKAGE."""
    required: set[str] = set()
    problems: list[str] = []
    for rel, where in sorted(referenced_paths(src).items()):
        p = src / rel
        if p.is_file():
            required.add(rel)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and "__pycache__" not in f.parts:
                    required.add(f.relative_to(src).as_posix())
        elif rel not in NOT_IN_PACKAGE:
            problems.append(f"{rel} (built at {', '.join(where)}) does not exist in src/ -- "
                            "add the file, or list it in NOT_IN_PACKAGE with the reason")
    for f in (src / PACKAGE).rglob("*"):
        if f.is_file() and f.suffix not in (".py", ".pyc") and "__pycache__" not in f.parts:
            required.add(f.relative_to(src).as_posix())
    return required, problems


def missing_from_wheel(wheel_names: list[str] | set[str], required: set[str]) -> list[str]:
    names = set(wheel_names)
    return sorted(r for r in required if r not in names)


def check_contents(wheel: Path) -> int:
    required, problems = required_files()
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
    missing = missing_from_wheel(names, required)
    for p in problems:
        print(f"PROBLEM  {p}")
    for m in missing:
        print(f"MISSING  {m}")
    data = sorted(r for r in required if not r.endswith(".py"))
    print(f"{wheel.name}: {len(required)} required files ({len(data)} data files), "
          f"{len(missing)} missing, {len(problems)} unresolved")
    return 1 if missing or problems else 0


# --------------------------------------------------------------------------- install check

# Modules that need an optional extra -- imported only when that extra is installed.
EXTRA_MODULES = {"kratos.trace.otel": "otel"}


def import_all_modules_code() -> str:
    """Python source that imports every module of the installed package (a missing
    dependency surfaces as an ImportError here, not on a user's first click)."""
    skip = sorted(EXTRA_MODULES)
    return (
        "import importlib, pkgutil, sys, kratos\n"
        f"skip = set({skip!r})\n"
        "bad = []\n"
        "n = 0\n"
        "for m in pkgutil.walk_packages(kratos.__path__, 'kratos.'):\n"
        "    if m.name in skip or m.name.endswith('__main__'):\n"
        "        continue\n"
        "    try:\n"
        "        importlib.import_module(m.name); n += 1\n"
        "    except Exception as e:\n"
        "        bad.append(f'{m.name}: {type(e).__name__}: {e}')\n"
        "print(f'imported {n} modules')\n"
        "for b in bad: print('IMPORT FAILED', b)\n"
        "sys.exit(1 if bad else 0)\n"
    )


Step = tuple[str, list[str], dict[str, str], tuple[int, ...]]


def installed_checks(python: str, scratch: Path) -> list[Step]:
    """(label, argv, extra env, accepted exit codes) for each step of the install
    check, against the `python` of a venv that has the wheel installed."""
    bindir = Path(python).parent
    kratos = str(bindir / "kratos")
    home = scratch / "home"
    env = {"KRATOS_HOME": str(home), "HOME": str(scratch / "user"), "PYTHONDONTWRITEBYTECODE": "1"}
    installer = scratch / "agent-install.sh"
    ok = (0,)
    steps: list[Step] = [
        ("import every module", [python, "-c", import_all_modules_code()], env, ok),
        ("kratos --help --all", [kratos, "--help", "--all"], env, ok),
        ("kratos init", [kratos, "init"], env, ok),
        # no model or machine is configured here: doctor must run and report, and may say "not ready"
        ("kratos doctor", [kratos, "doctor"], env, (0, 1)),
        ("kratos subagent-install", [kratos, "subagent-install", "--core-host", "127.0.0.1",
                                     "--code", "ABCD-1234", "-o", str(installer)], env, ok),
        ("sh -n on the installer", ["sh", "-n", str(installer)], env, ok),
        ("kratos attack-layer", [kratos, "attack-layer", "--out", "-"], env, ok),
        ("event schema via importlib.resources", [python, "-c",
            "import json; from kratos.events.write_schema import committed_schema_text as t; "
            "d = json.loads(t()); assert d.get('$schema') and d.get('properties'), 'schema empty'; "
            "print('schema ok:', len(d['properties']), 'top-level fields')"], env, ok),
        ("starter YARA rules ship", [python, "-c",
            "from kratos.agent.tools import DEFAULT_YARA_RULES_DIR as d; n = sorted(p.name for p in d.glob('*.yar')); "
            "assert n, f'no rules in {d}'; print('yara rules:', n)"], env, ok),
        ("kratos serve token create", [kratos, "serve", "token", "create", "--name", "ci"], env, ok),
        # the chat server's app is built and answers in-process (Starlette/uvicorn are imported
        # lazily, so "import every module" alone would not catch them missing from the wheel)
        ("kratos serve app answers", [python, "-c",
            "import os, pathlib; from starlette.testclient import TestClient; "
            "from kratos.serve.app import create_app; "
            "d = pathlib.Path(os.environ['KRATOS_HOME']) / 'data'; d.mkdir(parents=True, exist_ok=True); "
            "c = TestClient(create_app(d), base_url='http://127.0.0.1:8770'); "
            "r = c.get('/v1/models'); assert r.status_code == 401, r.status_code; print('serve app ok: 401 without a token')"],
         env, ok),
        ("kratos serve status", [kratos, "serve", "status"], env, ok),
        ("installed, not the checkout", [python, "-c",
            "import kratos, sys; p = kratos.__file__; assert 'site-packages' in p, p; print(p)"], env, ok),
    ]
    return steps


def run_steps(steps: list[Step], cwd: Path) -> list[tuple[str, bool, str]]:
    results = []
    for label, argv, extra, codes in steps:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("KRATOS_", "LLM_", "PYTHONPATH"))}
        env.update(extra)
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        try:
            r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
            ok, out = r.returncode in codes, (r.stdout + r.stderr)
        except (OSError, subprocess.TimeoutExpired) as e:
            ok, out = False, str(e)
        results.append((label, ok, out))
    return results


def check_install(wheel: Path, python: str = sys.executable, extras: str = "") -> int:
    scratch = Path(tempfile.mkdtemp(prefix="kratos-install-check-"))
    try:
        env_dir = scratch / "venv"
        r = subprocess.run([python, "-m", "venv", str(env_dir)], capture_output=True, text=True)
        if r.returncode:
            print(f"FAIL  create venv with {python}: {r.stderr.strip()}")
            return 1
        vpy = str(env_dir / "bin" / "python")
        spec = f"{wheel.resolve()}[{extras}]" if extras else str(wheel.resolve())
        r = subprocess.run([vpy, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", spec],
                           capture_output=True, text=True)
        if r.returncode:
            print(f"FAIL  pip install {wheel.name}\n{r.stdout}{r.stderr}")
            return 1
        ver = subprocess.run([vpy, "-c", "import sys; print(sys.version.split()[0])"], capture_output=True,
                             text=True).stdout.strip()
        print(f"installed {wheel.name} on Python {ver} (not editable)")
        failed = 0
        # run from an empty folder: nothing from the checkout can be imported by accident
        cwd = scratch / "cwd"
        cwd.mkdir()
        for label, ok, out in run_steps(installed_checks(vpy, scratch), cwd):
            last = (out.strip().splitlines() or [""])[-1][:120]
            print(f"{'ok  ' if ok else 'FAIL'}  {label}  {last}")
            if not ok:
                failed += 1
                print("      " + out.strip().replace("\n", "\n      ")[-3000:])
        return 1 if failed else 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("contents")
    c.add_argument("wheel", type=Path)
    i = sub.add_parser("install")
    i.add_argument("wheel", type=Path)
    i.add_argument("--python", default=sys.executable)
    i.add_argument("--extras", default="")
    a = ap.parse_args(argv)
    if a.cmd == "contents":
        return check_contents(a.wheel)
    return check_install(a.wheel, a.python, a.extras)


if __name__ == "__main__":
    sys.exit(main())
