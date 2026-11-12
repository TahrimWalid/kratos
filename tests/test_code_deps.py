"""E.7a §3.7: lockfile parsers, the YAML loader's guards (gate decision 2026-11-12), and offline
matching against OSV language-ecosystem records written by the real index writer."""
from __future__ import annotations

import json
import re
import resource
import sqlite3
import time
from pathlib import Path

import pytest

from kratos.code.deps import parsers as P
from kratos.code.deps import yaml_safe as Y
from kratos.pkgvuln import index as I
from kratos.pkgvuln import update as U
from kratos.pkgvuln.ecosystems import parse_selector


def parse(rel: str, text: str | bytes) -> P.Parsed:
    out = P.Parsed()
    P.parse(rel, text.encode() if isinstance(text, str) else text, out)
    return out


def triples(p: P.Parsed) -> set[tuple[str, str, str]]:
    return {(d.ecosystem, d.package, d.version) for d in p.deps}


# ----------------------------------------------------------------------------- formats
def test_requirements_variants():
    p = parse("app/requirements-prod.txt", "\n".join([
        "Flask==2.0.1", "requests>=2.0", "Jinja2[i18n]==3.0.0 ; python_version > '3' \\",
        "    --hash=sha256:abcd", "-r base.txt", "--requirement=../../outside.txt", "-e git+https://x/y.git#egg=y",
        "  # comment", "Django===4.2.1", "urllib3 == 1.26.5  # pinned", "git+https://example.test/p.git"]))
    assert triples(p) == {("PyPI", "flask", "2.0.1"), ("PyPI", "jinja2", "3.0.0"), ("PyPI", "django", "4.2.1"),
                          ("PyPI", "urllib3", "1.26.5")}
    assert p.unpinned == 3 and p.includes == ["app/base.txt"]
    assert any("outside the folder" in n for n in p.notes)


def test_python_lockfiles_and_installed():
    poetry = '[[package]]\nname = "Werkzeug"\nversion = "2.0.0"\n\n[[package]]\nname = "click"\nversion = "8.0.0"\n'
    assert triples(parse("poetry.lock", poetry)) == {("PyPI", "werkzeug", "2.0.0"), ("PyPI", "click", "8.0.0")}
    pip = {"default": {"pyyaml": {"version": "==5.3"}, "x": {"git": "y"}}, "develop": {"pytest": {"version": "==7.0"}}}
    p = parse("Pipfile.lock", json.dumps(pip))
    assert triples(p) == {("PyPI", "pyyaml", "5.3"), ("PyPI", "pytest", "7.0")} and p.unpinned == 1
    uv = ('[[package]]\nname = "app"\nversion = "0.1"\nsource = { editable = "." }\n\n'
          '[[package]]\nname = "idna"\nversion = "3.6"\nsource = { registry = "https://pypi.org/simple" }\n')
    assert triples(parse("uv.lock", uv)) == {("PyPI", "idna", "3.6")}
    p = parse(".venv/lib/python3.12/site-packages/Flask-3.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: Flask\n"
              "Version: 3.0.0\n\nBody: Version: 9\n")
    assert triples(p) == {("PyPI", "flask", "3.0.0")} and p.deps[0].installed


def test_npm_lockfiles_v1_v2_v3_and_installed():
    v3 = {"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
                                             "node_modules/@scope/x": {"version": "1.0.0"},
                                             "node_modules/a/node_modules/lodash": {"version": "4.17.4"},
                                             "node_modules/local": {"link": True}}}
    assert triples(parse("package-lock.json", json.dumps(v3))) == {
        ("npm", "lodash", "4.17.20"), ("npm", "@scope/x", "1.0.0"), ("npm", "lodash", "4.17.4")}
    v1 = {"lockfileVersion": 1, "dependencies": {"minimist": {"version": "0.0.8", "dependencies": {
        "x": {"version": "1.2.3"}}}, "file-dep": {"version": "file:../x"}}}
    p = parse("package-lock.json", json.dumps(v1))
    assert triples(p) == {("npm", "minimist", "0.0.8"), ("npm", "x", "1.2.3")} and p.unpinned == 1
    p = parse("web/node_modules/.package-lock.json", json.dumps(v3))
    assert all(d.installed for d in p.deps)


def test_yarn_v1_and_berry():
    v1 = ('# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n  resolved "x"\n\n'
          'lodash@^4.17.0:\n  version "4.17.15"\n')
    assert triples(parse("yarn.lock", v1)) == {("npm", "@babel/core", "7.1.2"), ("npm", "lodash", "4.17.15")}
    berry = ('__metadata:\n  version: 6\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n\n'
             '"axios@npm:^0.21.0":\n  version: 0.21.0\n  resolution: "axios@npm:0.21.0"\n')
    assert triples(parse("yarn.lock", berry)) == {("npm", "axios", "0.21.0")}


def test_php_go_ruby_rust():
    comp = {"packages": [{"name": "Guzzlehttp/Guzzle", "version": "v7.4.0"}], "packages-dev": [
        {"name": "x/y", "version": "dev-main"}]}
    p = parse("composer.lock", json.dumps(comp))
    assert triples(p) == {("Packagist", "guzzlehttp/guzzle", "7.4.0")} and p.unpinned == 1
    assert triples(parse("vendor/composer/installed.json", json.dumps({"packages": [{"name": "a/b", "version": "1.0"}]}))) \
        == {("Packagist", "a/b", "1.0")}
    gomod = "module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n" \
            "require github.com/c/d v0.1.0\n"
    assert triples(parse("go.mod", gomod)) == {("Go", "golang.org/x/net", "v0.7.0"), ("Go", "github.com/a/b", "v1.2.3"),
                                               ("Go", "github.com/c/d", "v0.1.0")}
    gosum = "golang.org/x/net v0.7.0 h1:x=\ngolang.org/x/net v0.7.0/go.mod h1:y=\n"
    assert triples(parse("go.sum", gosum)) == {("Go", "golang.org/x/net", "v0.7.0")}
    gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n" \
          "    rack (2.2.3)\n\nPLATFORMS\n  ruby\n"
    assert triples(parse("Gemfile.lock", gem)) == {("RubyGems", "nokogiri", "1.13.0"), ("RubyGems", "rack", "2.2.3")}
    cargo = ('[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
    assert triples(parse("Cargo.lock", cargo)) == {("crates.io", "smallvec", "1.6.0")}


def test_installed_beats_lockfile():
    deps = [P.Dep("npm", "lodash", "4.17.20", "web/package-lock.json"),
            P.Dep("npm", "lodash", "4.17.21", "web/node_modules/.package-lock.json", installed=True),
            P.Dep("npm", "other", "1.0.0", "web/package-lock.json")]
    keep, notes = P.reconcile(deps)
    assert {(d.package, d.version) for d in keep} == {("lodash", "4.17.21"), ("other", "1.0.0")}
    assert len(notes) == 1 and "4.17.21 is installed" in notes[0]


def test_garbage_lockfiles_are_notes_not_crashes():
    for rel in ("package-lock.json", "composer.lock", "Pipfile.lock"):
        assert parse(rel, "{not json").notes
    assert parse("poetry.lock", "[[package\n").notes
    assert parse("package-lock.json", "[" * 100_000).notes                 # deep nesting


# ----------------------------------------------------------------------------- YAML (pnpm)
PNPM9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash: {specifier: ^4, version: 4.17.20}\n" \
        "packages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n  '@scope/x@1.0.0(react@18.0.0)':\n" \
        "    resolution: {integrity: sha512-y}\n"
PNPM6 = "lockfileVersion: '6.0'\npackages:\n  /minimist@0.0.8:\n    resolution: {integrity: sha512-z}\n"


@pytest.mark.skipif(not Y.available(), reason="the code extra (PyYAML) is not installed")
def test_pnpm_v9_and_v6():
    assert triples(parse("pnpm-lock.yaml", PNPM9)) == {("npm", "lodash", "4.17.20"), ("npm", "@scope/x", "1.0.0")}
    assert triples(parse("pnpm-lock.yaml", PNPM6)) == {("npm", "minimist", "0.0.8")}


@pytest.mark.skipif(not Y.available(), reason="the code extra (PyYAML) is not installed")
def test_alias_bomb_is_refused_quickly_without_memory_growth():
    lines = ["lockfileVersion: '9.0'", "a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 12):
        lines.append(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]")
    lines.append("packages: *a11")
    bomb = "\n".join(lines) + "\n"
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    t0 = time.monotonic()
    p = parse("pnpm-lock.yaml", bomb)
    assert time.monotonic() - t0 < 1.0
    assert resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - rss0 < 50_000      # KiB
    assert p.deps == [] and any("anchors or aliases" in n for n in p.notes)


@pytest.mark.skipif(not Y.available(), reason="the code extra (PyYAML) is not installed")
def test_deep_nesting_and_unknown_version_and_not_a_mapping():
    deep = "lockfileVersion: '9.0'\npackages: " + "[" * 5000 + "]" * 5000 + "\n"
    assert any("nested deeper" in n for n in parse("pnpm-lock.yaml", deep).notes)
    assert any("lockfileVersion 5.4" in n for n in parse("pnpm-lock.yaml", "lockfileVersion: 5.4\npackages: {}\n").notes)
    assert any("not a pnpm lockfile" in n for n in parse("pnpm-lock.yaml", "- a\n- b\n").notes)
    assert any("not valid YAML" in n for n in parse("pnpm-lock.yaml", "a: [\n").notes)


def test_missing_extra_is_a_stated_gap(monkeypatch):
    monkeypatch.setattr(Y, "_yaml", None)
    p = parse("pnpm-lock.yaml", PNPM9)
    assert p.deps == [] and any("install kratos-security-assistant[code]" in n for n in p.notes)


def test_the_safe_loader_is_the_only_yaml_entry_point():
    src = Path(P.__file__).parents[2]
    bad = re.compile(r"yaml\.(load\(|unsafe_load|full_load|Loader\b|FullLoader|UnsafeLoader)")
    hits = [f"{p.relative_to(src)}:{i}" for p in src.rglob("*.py") for i, ln in enumerate(p.read_text().splitlines(), 1)
            if bad.search(ln)]
    assert hits == []


# ----------------------------------------------------------------------------- matching
def _rec(osv_id: str, eco: str, name: str, events: list[dict], *, kind: str = "SEMVER", aliases=(),
         withdrawn: str | None = None, severity: str = "HIGH") -> dict:
    r = {"id": osv_id, "modified": "2026-01-01T00:00:00Z", "aliases": list(aliases),
         "database_specific": {"severity": severity},
         "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": kind, "events": events}]}]}
    if withdrawn:
        r["withdrawn"] = withdrawn
    return r


@pytest.fixture()
def index(tmp_path) -> Path:
    path = I.path_for(tmp_path)
    path.parent.mkdir(parents=True)
    conn = sqlite3.connect(path)
    I.create_schema(conn)
    sels = [parse_selector(x) for x in ("pypi", "npm", "go", "packagist", "rubygems", "crates.io")]
    w = U._Writer(conn, sels)
    w.apply("PyPI", _rec("PYSEC-2021-1", "PyPI", "Flask", [{"introduced": "0"}, {"fixed": "2.0.2"}], kind="ECOSYSTEM",
                         aliases=["CVE-2021-0001"]))
    w.apply("npm", _rec("GHSA-aaaa-bbbb-cccc", "npm", "lodash", [{"introduced": "0"}, {"fixed": "4.17.21"}],
                        aliases=["CVE-2021-23337"]))
    w.apply("npm", _rec("GHSA-wwww-wwww-wwww", "npm", "lodash", [{"introduced": "0"}], withdrawn="2026-01-02"))
    w.apply("npm", _rec("MAL-2026-1", "npm", "evil-pkg", [{"introduced": "0"}]))
    w.apply("Go", _rec("GO-2023-1", "Go", "golang.org/x/net", [{"introduced": "0"}, {"fixed": "0.17.0"}]))
    conn.execute("INSERT INTO kev (cve, date_added) VALUES ('CVE-2021-23337', '2026-01-01')")
    conn.execute("INSERT OR REPLACE INTO info (key, value) VALUES ('built_at', ?)", (json.dumps(time.time()),))
    conn.execute("INSERT OR REPLACE INTO info (key, value) VALUES ('selectors', ?)", (json.dumps([s.key for s in sels]),))
    conn.commit()
    conn.close()
    return tmp_path


def test_osv_withdrawn_and_alias(index):
    from kratos.code.deps import match as M

    deps = [P.Dep("PyPI", "flask", "2.0.1", "requirements.txt"), P.Dep("npm", "lodash", "4.17.20", "package-lock.json"),
            P.Dep("npm", "lodash", "4.17.21", "x/package-lock.json"), P.Dep("npm", "evil-pkg", "1.0.0", "p.json"),
            P.Dep("Go", "golang.org/x/net", "v0.7.0", "go.mod"), P.Dep("Packagist", "a/b", "1.0", "composer.lock")]
    r = M.match(index, deps)
    by = {(h.package, h.version): h for h in r.hits}
    assert set(by) == {("flask", "2.0.1"), ("lodash", "4.17.20"), ("evil-pkg", "1.0.0"), ("golang.org/x/net", "v0.7.0")}
    lodash = by[("lodash", "4.17.20")]
    assert [a.osv_id for a in lodash.advisories] == ["GHSA-aaaa-bbbb-cccc"]          # withdrawn one ignored
    assert lodash.advisories[0].cves == ["CVE-2021-23337"] and lodash.severity == "critical"   # KEV through the alias
    assert by[("evil-pkg", "1.0.0")].severity == "critical"                           # malicious package report
    assert by[("flask", "2.0.1")].advisories[0].fixed_in == "2.0.2"
    assert by[("golang.org/x/net", "v0.7.0")].severity in ("medium", "high")
    assert "Packagist" in r.missing_ecosystems                                         # never downloaded: said so


def test_missing_ecosystem_gap(tmp_path):
    from kratos.code.deps import match as M

    r = M.match(tmp_path, [P.Dep("npm", "x", "1.0.0", "package-lock.json")])
    assert r.hits == [] and r.missing_ecosystems == ["npm"] and not r.index_present
