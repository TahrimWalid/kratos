"""The shipped Sigma rule pack (src/kratos/detect/packs/): valid, 50-100 rules, every
rule with its samples, attribution (Detection Rule License 1.1) on every rule, every
not-shipped candidate with its reason, the vendored sources and licence text, and a
pack that is exactly what the build script makes from those sources.

Second opinion: every sample also goes through pySigma's SQLite backend
(pysigma-backend-sqlite), which compiles the ORIGINAL SigmaHQ rule independently of
Kratos's backend -- a test-only reference, not shipped (the A.2 pattern)."""
from __future__ import annotations

import itertools
import json
import sqlite3
from pathlib import Path

import pytest

from kratos.events import sigma_fields as SF
from kratos.subagent import detect as D

PACKS = Path(__file__).resolve().parents[1] / "src" / "kratos" / "detect" / "packs"
PACK_FILES = sorted(PACKS.glob("sigma-linux-*.json"))


@pytest.fixture(scope="module")
def raw():
    assert len(PACK_FILES) == 1, "ship exactly one sigma-linux pack"
    return json.loads(PACK_FILES[0].read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def pack(raw):
    return D.load_pack(raw)


def test_the_pack_is_valid_and_its_size_is_in_range(raw, pack):
    assert raw["pack_id"] == "sigma-linux" and PACK_FILES[0].name == f"sigma-linux-{raw['pack_version']}.json"
    assert 50 <= len(pack.rules) <= 100
    assert D.parse_pack_bytes(PACK_FILES[0].read_bytes())["sha256"] == raw["sha256"]


def test_every_shipped_rule_passes_its_samples(pack):
    assert D.check_samples(pack) == []
    for rule in pack.rules:
        s = rule.meta["samples"]
        assert s["match"] and s["no_match"], rule.id


def test_every_rule_carries_its_attribution(raw):
    commit = raw["source"]["commit"]
    for r in raw["rules"]:
        assert r["author"].strip() and r["sigma_id"] and r["title"], r["id"]
        assert r["license"] == "DRL-1.1"
        src = r["source"]
        assert src["commit"] == commit and src["path"].startswith("rules/linux/")
        assert src["url"] == f"https://github.com/SigmaHQ/sigma/blob/{commit}/{src['path']}"
        assert r["id"] == "SIGMA-" + "".join(c for c in r["sigma_id"].lower() if c in "0123456789abcdef")[:8].upper()


def test_every_candidate_not_shipped_has_a_reason(raw):
    shipped = {r["source"]["path"] for r in raw["rules"]}
    for s in raw["skipped"]:
        assert s["reason"].strip() and s["kind"] in {"status", "logsource", "condition", "field", "correlation",
                                                     "metadata", "parse", "selection"}, s
        assert "regex" not in s["reason"] or "regular expression" in s["reason"]
    paths = shipped | {s["path"] for s in raw["skipped"]}
    assert len(paths) == raw["source"]["candidates"]          # every rules/linux file is accounted for


def test_vendored_sources_licence_and_notice_ship_with_the_pack(raw):
    drl = (PACKS / "LICENSE.DRL").read_text(encoding="utf-8")
    assert drl.startswith("# Detection Rule License (DRL) 1.1")
    import hashlib
    assert hashlib.sha256(drl.rstrip("\n").encode()).hexdigest() == raw["source"]["license_sha256"] or \
        hashlib.sha256(drl.encode()).hexdigest() == raw["source"]["license_sha256"]
    notice = (PACKS / "NOTICE").read_text(encoding="utf-8")
    assert raw["source"]["commit"] in notice and "LICENSE.DRL" in notice
    vendored = {p.relative_to(PACKS / "sigma").as_posix() for p in (PACKS / "sigma").rglob("*.yml")}
    assert vendored == {r["source"]["path"] for r in raw["rules"]}
    for r in raw["rules"]:
        assert f"{r['id']} -- {r['title']} -- {r['author']}" in notice


def test_the_pack_has_no_regular_expressions_or_code(raw):
    def walk(node):
        assert node["op"] in D.ALL_OPS
        for c in node.get("args") or ([node["arg"]] if "arg" in node else []):
            walk(c)
    for r in raw["rules"]:
        walk(r["match"])
        if r["scope"]["where"]:
            walk(r["scope"]["where"])


def test_attack_tags_are_current_v19_techniques(raw):
    from kratos.attack import table

    for r in raw["rules"]:
        for tid in r["attack"]:
            assert table.is_current(tid), (r["id"], tid)
    for d in raw["source"]["attack_dropped"]:
        assert d["reason"]


# ---------------------------------------------------------------------------- rebuilt from the vendored sources
def test_the_pack_is_what_the_compiler_makes_from_its_vendored_sources(raw):
    pytest.importorskip("sigma.collection")         # pySigma needs Python 3.11+
    from kratos.detect.sigma_build.compile import Source, compile_sources, select_for_shipping
    from kratos.detect.sigma_build.samples import add_samples

    commit = raw["source"]["commit"]
    srcs = [Source(path=r["source"]["path"], text=(PACKS / "sigma" / r["source"]["path"]).read_text(encoding="utf-8"),
                   commit=commit, url=r["source"]["url"]) for r in raw["rules"]]
    compiled = compile_sources(srcs)
    ship, left = select_for_shipping(compiled)
    assert not compiled.skipped and not left
    for r in ship:
        assert add_samples(r) is None
    by_id = {r["id"]: r for r in raw["rules"]}
    for r in ship:
        assert json.loads(json.dumps(r)) == by_id[r["id"]], f"{r['id']} differs from the pack -- edited by hand?"


# ---------------------------------------------------------------------------- the SQLite backend's second opinion
FULLTEXT = "kratos_fulltext"


def _sigma_rows(rule: dict, ev: dict) -> list[dict[str, str]]:
    """A sample event in the original rule's own field names (one row per combination of
    list elements: a Sigma backend sees one record per audit record)."""
    ls = SF.LOGSOURCES[(rule["logsource"]["product"], rule["logsource"]["service"], rule["logsource"]["category"])]
    reverse = {target: sigma for sigma, target in ls.fields.items()}
    row: dict[str, list[str]] = {}
    for field, value in ev.items():
        if field == "process.args" and ls.key == ("linux", "auditd", None):
            for i, v in enumerate(value):
                row[f"a{i}"] = [v]
            continue
        if field in reverse:
            row[reverse[field]] = value if isinstance(value, list) else [str(value)]
    text = " ".join(str(ev.get(f, "")) for f in SF.KEYWORD_FIELDS)
    row[FULLTEXT] = [text]
    keys = sorted(row)
    return [dict(zip(keys, combo)) for combo in itertools.product(*(row[k] for k in keys))]


def _matches_in_sqlite(query: str, rows: list[dict[str, str]]) -> bool:
    conn = sqlite3.connect(":memory:")
    cols = sorted({c for r in rows for c in r} | set(_columns_in(query)))
    # NUMERIC affinity: a number in the rule (a1: 777) equals the text '777' a log carries
    conn.execute(f"CREATE TABLE logs ({', '.join(f'{c!r} NUMERIC' for c in cols)})")
    for r in rows:
        conn.execute(f"INSERT INTO logs ({', '.join(f'{c!r}' for c in r)}) VALUES ({', '.join('?' for _ in r)})",
                     list(r.values()))
    try:
        return bool(conn.execute(query).fetchall())
    finally:
        conn.close()


def _columns_in(query: str) -> list[str]:
    import re
    names = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s+(?:LIKE|=|IS|GLOB|IN)\b", query))
    return [n for n in names if n.upper() not in {"NOT", "AND", "OR", "WHERE", "SELECT", "FROM"}]


def test_every_sample_agrees_with_pysigmas_sqlite_backend(raw):
    pytest.importorskip("sigma.backends.sqlite")     # the test extra; pySigma needs Python 3.11+
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection

    checked = scope_only = 0
    disagreements = []
    for r in raw["rules"]:
        text = (PACKS / "sigma" / r["source"]["path"]).read_text(encoding="utf-8")
        query = sqliteBackend(fulltext_field=FULLTEXT).convert(SigmaCollection.from_yaml(text))[0]
        match = r["samples"]["match"][0]
        for kind, ev, want in (("match", match, True), ("no_match", r["samples"]["no_match"][0], False)):
            changed = {k for k in set(ev) | set(match) if ev.get(k) != match.get(k)} - {"event.id"}
            if not want and changed <= {"event.dataset", "event.action"}:
                scope_only += 1          # differs only in which log it came from: outside Sigma's own condition
                continue
            got = _matches_in_sqlite(query, _sigma_rows(r, ev))
            checked += 1
            if got != want:
                disagreements.append((r["id"], r["title"], kind))
    assert disagreements == []
    assert scope_only == 0 and checked == len(raw["rules"]) * 2
