"""Lockfiles and installed-package metadata -> (ecosystem, package, version) (E.7a §3.7).

Parsed on Kratos from bytes the `code_read` (purpose `deps`) fetched; nothing here runs a
package manager. Stdlib JSON / TOML; YAML only through ``yaml_safe`` (the ``code`` extra).

Python: ``requirements*.txt`` (only ``==`` / ``===`` pins; everything else "not pinned"),
``poetry.lock``, ``Pipfile.lock``, ``uv.lock``, installed ``*.dist-info/METADATA``.
JavaScript: ``package-lock.json`` v1/v2/v3, ``node_modules/.package-lock.json`` (installed),
``yarn.lock`` v1 and berry, ``pnpm-lock.yaml`` v6 / v9. PHP: ``composer.lock``,
``vendor/composer/installed.json`` (installed). Go: ``go.mod`` (``go.sum`` when there is no
go.mod). Ruby: ``Gemfile.lock``. Rust: ``Cargo.lock``.

Ecosystem names are OSV's: PyPI, npm, Packagist, Go, RubyGems, crates.io.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from kratos.code.deps import yaml_safe

PYPI, NPM, PACKAGIST, GO, RUBYGEMS, CRATES = "PyPI", "npm", "Packagist", "Go", "RubyGems", "crates.io"
ECOSYSTEMS = (PYPI, NPM, PACKAGIST, GO, RUBYGEMS, CRATES)
_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===?)\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*$")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQUIREMENTS = re.compile(r"^requirements[A-Za-z0-9._-]*\.txt$")
_INCLUDE = re.compile(r"^(?:-r|--requirement|-c|--constraint)\s*=?\s*(\S+)")
PNPM_VERSIONS = ("6.0", "6.1", "9.0")


@dataclass
class Dep:
    ecosystem: str
    package: str
    version: str
    source_file: str
    installed: bool = False


@dataclass
class Parsed:
    deps: list[Dep] = field(default_factory=list)
    unpinned: int = 0                  # lines/entries with no exact version (can't match)
    notes: list[str] = field(default_factory=list)   # "<file> not read: <reason>" -- Kratos's words
    includes: list[str] = field(default_factory=list)  # requirements -r files wanted, relative to the root


def pypi_name(name: str) -> str:
    """PEP 503 normalised name (what OSV's PyPI advisories use)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def kind_of(rel: str) -> str | None:
    """Which parser reads this inventory path, or None."""
    name = rel.rsplit("/", 1)[-1]
    if _REQUIREMENTS.match(name):
        return "requirements"
    if name == "METADATA" and ".dist-info/" in rel:
        return "dist_info"
    if rel.endswith("node_modules/.package-lock.json"):
        return "npm_installed"
    if rel.endswith("vendor/composer/installed.json"):
        return "composer_installed"
    return {"poetry.lock": "poetry", "Pipfile.lock": "pipfile", "uv.lock": "uv", "package-lock.json": "npm",
            "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "composer.lock": "composer", "go.mod": "gomod",
            "go.sum": "gosum", "Gemfile.lock": "gemfile", "Cargo.lock": "cargo"}.get(name)


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace").lstrip("﻿")


def _ok_version(v: Any) -> str | None:
    s = str(v or "").strip()
    return s if s and len(s) <= 128 and re.match(r"^[A-Za-z0-9][A-Za-z0-9._+~:!-]*$", s) else None


def _ok_name(n: Any) -> str | None:
    s = str(n or "").strip()
    return s if s and len(s) <= 214 and re.match(r"^[@A-Za-z0-9][A-Za-z0-9@._/+~-]*$", s) else None


def _add(out: Parsed, eco: str, name: Any, version: Any, rel: str, installed: bool = False) -> None:
    n, v = _ok_name(name), _ok_version(version)
    if not n or not v:
        out.unpinned += 1
        return
    out.deps.append(Dep(eco, pypi_name(n) if eco == PYPI else n, v, rel, installed))


# --------------------------------------------------------------------------- Python
def requirements(data: bytes, rel: str, out: Parsed) -> None:
    base = posixpath.dirname(rel)
    for raw in _text(data).splitlines():
        line = raw.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        m = _INCLUDE.match(line)
        if m:
            inc = posixpath.normpath(posixpath.join(base, m.group(1)))
            if inc.startswith("../") or inc.startswith("/") or inc == "..":
                out.notes.append(f"{rel}: an include outside the folder was not followed")
            else:
                out.includes.append(inc)
            continue
        if line.startswith("-"):           # -e / --index-url / --hash on its own line
            if line.startswith(("-e", "--editable")):
                out.unpinned += 1
            continue
        line = line.split(";", 1)[0]                       # environment markers
        line = re.split(r"\s--hash[ =]", line)[0].strip()  # hashes
        line = line.rstrip("\\").strip()
        m = _REQ_LINE.match(line)
        if m:
            _add(out, PYPI, m.group(1), m.group(3), rel)
        elif _REQ_NAME.match(line) or "://" in line:
            out.unpinned += 1


def dist_info(data: bytes, rel: str, out: Parsed) -> None:
    name = version = None
    for line in _text(data).splitlines()[:200]:
        if not line.strip():
            break
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            version = line[8:].strip()
    _add(out, PYPI, name, version, rel, installed=True)


def _toml_packages(data: bytes, rel: str, out: Parsed, eco: str, *, need_source: bool = False) -> None:
    try:
        doc = tomllib.loads(_text(data))
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        out.notes.append(f"{rel} not read: not valid TOML")
        return
    pkgs = doc.get("package") if isinstance(doc, dict) else None
    if not isinstance(pkgs, list):
        out.notes.append(f"{rel} not read: no [[package]] list")
        return
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        if need_source and not p.get("source"):
            continue                      # the project's own crate / a path dependency
        if eco == PYPI and isinstance(p.get("source"), dict) and (
                "editable" in p["source"] or "virtual" in p["source"] or "path" in p["source"]):
            continue                      # uv: the project itself
        _add(out, eco, p.get("name"), p.get("version"), rel)


def pipfile(data: bytes, rel: str, out: Parsed) -> None:
    try:
        doc = json.loads(_text(data))
    except (ValueError, RecursionError):
        out.notes.append(f"{rel} not read: not valid JSON")
        return
    for section in ("default", "develop"):
        for name, spec in ((doc or {}).get(section) or {}).items():
            v = str((spec or {}).get("version") or "") if isinstance(spec, dict) else ""
            if v.startswith("=="):
                _add(out, PYPI, name, v[2:], rel)
            else:
                out.unpinned += 1


# --------------------------------------------------------------------------- JavaScript
def _npm_name_from_path(key: str) -> str | None:
    idx = key.rfind("node_modules/")
    return key[idx + len("node_modules/"):] if idx >= 0 else None


def npm(data: bytes, rel: str, out: Parsed, installed: bool = False) -> None:
    try:
        doc = json.loads(_text(data))
    except (ValueError, RecursionError):
        out.notes.append(f"{rel} not read: not valid JSON")
        return
    if not isinstance(doc, dict):
        out.notes.append(f"{rel} not read: not a package lock")
        return
    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):                         # lockfileVersion 2 / 3
        for key, p in pkgs.items():
            if not key or not isinstance(p, dict) or p.get("link"):
                continue
            name = p.get("name") or _npm_name_from_path(key)
            if name:
                _add(out, NPM, name, p.get("version"), rel, installed)
        return
    stack = [doc.get("dependencies") or {}]            # lockfileVersion 1 (nested)
    seen = 0
    while stack and seen < 200_000:
        deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for name, p in deps.items():
            seen += 1
            if isinstance(p, dict):
                v = str(p.get("version") or "")
                if v.startswith(("file:", "link:", "git", "http")):
                    out.unpinned += 1
                else:
                    _add(out, NPM, name, v, rel, installed)
                if isinstance(p.get("dependencies"), dict):
                    stack.append(p["dependencies"])


def _yarn_name(descriptor: str) -> str | None:
    d = descriptor.strip().strip('"').strip()
    at = d.find("@", 1)
    return d[:at] if at > 0 else None


def yarn(data: bytes, rel: str, out: Parsed) -> None:
    names: list[str] = []
    for line in _text(data).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            if line.rstrip().endswith(":"):
                head = line.rstrip()[:-1]
                names = [n for n in (_yarn_name(x) for x in head.split(",")) if n]
                if head.strip('"') == "__metadata" or "@workspace:" in head or "@patch:" in head \
                        or "@link:" in head or "@portal:" in head or "@file:" in head:
                    names = []
            continue
        m = re.match(r'^\s{2}version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and names:
            for n in dict.fromkeys(names):
                _add(out, NPM, n, m.group(1), rel)
            names = []


def _pnpm_key(key: str) -> tuple[str, str] | None:
    k = key.lstrip("/")
    k = k.split("(", 1)[0]
    at = k.rfind("@")
    if at > 0:
        return k[:at], k[at + 1:]
    if k.count("/") >= 1:                               # v5: /name/version
        name, _, version = k.rpartition("/")
        return name, version
    return None


def pnpm(data: bytes, rel: str, out: Parsed) -> None:
    if not yaml_safe.available():
        out.notes.append(f"{rel} not read: install kratos-security-assistant[code] (YAML support)")
        return
    try:
        doc = yaml_safe.load(data)
    except yaml_safe.YamlRefused as e:
        out.notes.append(f"{rel} not read: {e}")
        return
    if not isinstance(doc, dict):
        out.notes.append(f"{rel} not read: not a pnpm lockfile")
        return
    ver = str(doc.get("lockfileVersion") or "")
    if ver not in PNPM_VERSIONS:
        out.notes.append(f"{rel} not read: lockfileVersion {ver[:20] or '(none)'} is not one Kratos reads "
                         f"({', '.join(PNPM_VERSIONS)})")
        return
    pkgs = doc.get("packages")
    if not isinstance(pkgs, dict):
        return
    for key in pkgs:
        got = _pnpm_key(str(key))
        if got:
            _add(out, NPM, got[0], got[1], rel)
        else:
            out.unpinned += 1


# --------------------------------------------------------------------------- PHP, Go, Ruby, Rust
def composer(data: bytes, rel: str, out: Parsed, installed: bool = False) -> None:
    try:
        doc = json.loads(_text(data))
    except (ValueError, RecursionError):
        out.notes.append(f"{rel} not read: not valid JSON")
        return
    if isinstance(doc, list):
        lists = [doc]                                   # installed.json v1
    elif isinstance(doc, dict):
        lists = [doc.get("packages") or [], doc.get("packages-dev") or []]
    else:
        lists = []
    for lst in lists:
        for p in lst if isinstance(lst, list) else []:
            if isinstance(p, dict):
                v = str(p.get("version") or "")
                if v.startswith("dev-"):
                    out.unpinned += 1
                    continue
                _add(out, PACKAGIST, str(p.get("name") or "").lower(), v[1:] if v[:1] == "v" else v, rel, installed)


def gomod(data: bytes, rel: str, out: Parsed) -> None:
    block = False
    for raw in _text(data).splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        parts = line.split()
        if block and len(parts) >= 2:
            _add(out, GO, parts[0], parts[1], rel)
        elif parts[:1] == ["require"] and len(parts) >= 3:
            _add(out, GO, parts[1], parts[2], rel)


def gosum(data: bytes, rel: str, out: Parsed) -> None:
    seen: set[tuple[str, str]] = set()
    for line in _text(data).splitlines():
        parts = line.split()
        if len(parts) >= 3 and not parts[1].endswith("/go.mod") and (parts[0], parts[1]) not in seen:
            seen.add((parts[0], parts[1]))
            _add(out, GO, parts[0], parts[1], rel)


def gemfile(data: bytes, rel: str, out: Parsed) -> None:
    section = ""
    for line in _text(data).splitlines():
        if line and not line.startswith(" "):
            section = line.strip()
            continue
        if section == "GEM":
            m = re.match(r"^ {4}([A-Za-z0-9][A-Za-z0-9._-]*) \(([0-9][^-)\s]*)(?:-[^)]*)?\)\s*$", line)
            if m:
                _add(out, RUBYGEMS, m.group(1), m.group(2), rel)


def parse(rel: str, data: bytes, out: Parsed) -> None:
    kind = kind_of(rel)
    try:
        if kind == "requirements":
            requirements(data, rel, out)
        elif kind == "dist_info":
            dist_info(data, rel, out)
        elif kind == "poetry":
            _toml_packages(data, rel, out, PYPI)
        elif kind == "uv":
            _toml_packages(data, rel, out, PYPI)
        elif kind == "pipfile":
            pipfile(data, rel, out)
        elif kind == "npm":
            npm(data, rel, out)
        elif kind == "npm_installed":
            npm(data, rel, out, installed=True)
        elif kind == "yarn":
            yarn(data, rel, out)
        elif kind == "pnpm":
            pnpm(data, rel, out)
        elif kind == "composer":
            composer(data, rel, out)
        elif kind == "composer_installed":
            composer(data, rel, out, installed=True)
        elif kind == "gomod":
            gomod(data, rel, out)
        elif kind == "gosum":
            gosum(data, rel, out)
        elif kind == "gemfile":
            gemfile(data, rel, out)
        elif kind == "cargo":
            _toml_packages(data, rel, out, CRATES, need_source=True)
    except RecursionError:
        out.notes.append(f"{rel} not read: nested too deeply")


def reconcile(deps: list[Dep]) -> tuple[list[Dep], list[str]]:
    """Installed beats lockfile: when a folder has installed metadata for an ecosystem, a
    lockfile's version of the same package that differs is reported (mismatch) and the
    installed one is what is matched. Returns (deps to match, mismatch notes)."""
    installed: dict[tuple[str, str, str], set[str]] = {}
    for d in deps:
        if d.installed:
            installed.setdefault((d.ecosystem, d.package, _project(d.source_file)), set()).add(d.version)
    keep: list[Dep] = []
    notes: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for d in deps:
        key = (d.ecosystem, d.package, _project(d.source_file))
        if not d.installed and key in installed:
            if d.version not in installed[key]:
                notes.append(f"{d.package} {d.version} in {d.source_file}, but {', '.join(sorted(installed[key]))} "
                             "is installed (the installed version is checked)")
            continue
        k4 = (d.ecosystem, d.package, d.version, d.source_file)
        if k4 not in seen:
            seen.add(k4)
            keep.append(d)
    return keep, notes


def _project(rel: str) -> str:
    """The project folder a lockfile or installed folder belongs to."""
    for marker in ("/node_modules/", "/vendor/", "/.venv/", "/venv/"):
        i = ("/" + rel).find(marker)
        if i >= 0:
            return ("/" + rel)[:i].lstrip("/")
    return posixpath.dirname(rel)
