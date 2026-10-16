"""The data inventory (kratos.datainv, docs/phaseB/B.5 §5.1): every table and data folder
the code creates is listed, and the measurements match what is on disk."""
from __future__ import annotations

import ast
import json
import re
import sqlite3
from pathlib import Path

import pytest

from kratos import datainv

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"

_CREATE_RE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?!IF\b)([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)

# Path pieces the scan finds that are not entries of the data folder (repo files, the
# remote machine, paths under a folder already listed).
NOT_DATA_DIR = {"pyproject.toml", "packed-refs", "vulscan.nse", "systemd", "data"}


def _source_files():
    for p in sorted(SRC.rglob("*.py")):
        yield p, p.read_text(encoding="utf-8")


def created_tables() -> dict[str, str]:
    out = {}
    for p, text in _source_files():
        for m in _CREATE_RE.finditer(text):
            out[m.group(1)] = str(p.relative_to(SRC))
    return out


def _literal_prefix(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        head = ""
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                head += v.value
            else:
                return head + "*"
        return head
    return None


def _is_data_dir_expr(node: ast.AST) -> bool:
    """`data_dir`, `self._data_dir`, `Path(data_dir)`, `get_active_data_dir()`,
    `paths.default_data_dir()` or `<state root> / "data"` -- not `presets_dir(data_dir)`
    (a sub-folder of something already listed)."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        return "data_dir" in ast.unparse(node) or ast.unparse(node) == "dd"
    if isinstance(node, ast.Call):
        func = ast.unparse(node.func)
        if func.endswith("data_dir"):
            return True
        if func in ("Path", "pathlib.Path") and node.args:
            return _is_data_dir_expr(node.args[0])
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _literal_prefix(node.right) == "data"
    return False


def _module_constants(tree: ast.Module) -> dict[str, str]:
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = _literal_prefix(node.value)
            if v is not None:
                out[node.targets[0].id] = v
    return out


def data_dir_names() -> dict[str, str]:
    """Every first-level name the code joins onto the data folder:
    `<data_dir expr> / "name"` (a literal, an f-string, or a module constant), and
    module constants named like a data folder (`*_DIR`, `*DIRNAME`, `DIR_NAME`,
    `SOCKET_NAME`)."""
    found: dict[str, str] = {}
    for p, text in _source_files():
        tree = ast.parse(text)
        consts = _module_constants(tree)
        rel = str(p.relative_to(SRC))
        for node in ast.walk(tree):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and _is_data_dir_expr(node.left):
                name = _literal_prefix(node.right)
                if name is None and isinstance(node.right, ast.Name):
                    name = consts.get(node.right.id)
                if name:
                    found.setdefault(name.split("/")[0], rel)
        for n, v in consts.items():
            if re.fullmatch(r"_?[A-Z_]*(_DIR|DIRNAME|DIR_NAME|SOCKET_NAME)", n) and v and "/" not in v and "$" not in v:
                found.setdefault(v, rel)
    return found


def test_every_created_table_is_in_an_inventory_category():
    listed = datainv.all_tables()
    missing = {t: f for t, f in created_tables().items() if t not in listed}
    assert not missing, (
        "tables the code creates that kratos.datainv.CATEGORIES does not list -- add each to a category "
        f"(what it is, where, personal or not, how it grows): {missing}")


def test_inventory_lists_no_table_the_code_does_not_create():
    created = set(created_tables())
    stale = datainv.all_tables() - created
    assert not stale, f"CATEGORIES lists tables nothing creates: {sorted(stale)}"


def test_every_data_folder_entry_the_code_creates_is_owned():
    found = data_dir_names()
    # the scan sees the real ones (literal, constant and f-string forms)
    assert {"sessions", "reports", "fss", "kratos_local_config.json", "kratos-subagent-install-*"} <= set(found)
    missing = {n: f for n, f in found.items()
               if n not in NOT_DATA_DIR and datainv.owner_of(n.replace("*", "x")) is None}
    assert not missing, (
        "names the code creates under the data folder that no kratos.datainv category owns "
        f"(add it to a category, or to RUNTIME_ENTRIES if it is a lock/socket/scratch): {missing}")


def test_the_scan_catches_a_new_folder(tmp_path, monkeypatch):
    fake = tmp_path / "kratos"
    (fake / "x").mkdir(parents=True)
    (fake / "x" / "new.py").write_text('def f(data_dir):\n    return data_dir / "brand_new_store"\n')
    monkeypatch.setattr(__import__(__name__), "SRC", fake)
    assert "brand_new_store" in data_dir_names()
    assert datainv.owner_of("brand_new_store") is None


def test_every_category_says_what_it_is():
    keys = [c.key for c in datainv.CATEGORIES]
    assert len(keys) == len(set(keys))
    for c in datainv.CATEGORIES:
        assert c.name and c.description and c.grows
        assert c.personal in (datainv.PERSONAL, datainv.NOT_PERSONAL, datainv.SECRET)
        assert c.files or c.tables or c.state_files
    assert datainv.category("traces").personal == datainv.PERSONAL
    assert datainv.category("seal_keys").personal == datainv.SECRET


def _fixture_data_dir(tmp_path: Path) -> Path:
    dd = tmp_path / "data"
    (dd / "sessions").mkdir(parents=True)
    (dd / "sessions" / "s1_turn1.json").write_text("x" * 1000)
    (dd / "sessions" / "s1_turn2.json").write_text("y" * 500)
    (dd / "traces" / "2026-10-16").mkdir(parents=True)
    (dd / "traces" / "2026-10-16" / "abc.json").write_text("z" * 2000)
    (dd / "fss").mkdir()
    (dd / "fss" / "m.json").write_text("{}")
    (dd / "attack_logs").mkdir()  # made by a lab script, not by Kratos
    conn = sqlite3.connect(dd / "kratos.db")
    conn.execute("CREATE TABLE host_events (id INTEGER PRIMARY KEY, ts REAL, doc TEXT)")
    conn.executemany("INSERT INTO host_events (ts, doc) VALUES (?, ?)",
                     [(1_700_000_000.0 + i, json.dumps({"i": i}) * 20) for i in range(300)])
    conn.execute("CREATE TABLE goal_history (turn_id INTEGER PRIMARY KEY, started_at TEXT)")
    conn.execute("INSERT INTO goal_history (started_at) VALUES ('2026-10-01T10:00:00+00:00')")
    conn.commit()
    conn.close()
    return dd


def test_measure_on_a_fixture_data_dir(tmp_path):
    dd = _fixture_data_dir(tmp_path)
    by = {m.category.key: m for m in datainv.measure(dd, state_root=tmp_path)}
    assert by["traces"].bytes == 2000 and by["traces"].items == 1
    assert by["seal_keys"].items == 1
    s = by["sessions"]
    assert s.items == 2 + 1  # two transcript files + one goal_history row
    assert s.bytes >= 1500
    he = by["host_events"]
    assert he.items == 300
    assert he.bytes > 0  # dbstat page sizes
    assert he.oldest == pytest.approx(1_700_000_000.0) and he.newest == pytest.approx(1_700_000_299.0)
    assert datainv.unlisted(dd) == [dd / "attack_logs"]


def test_measure_opens_the_database_read_only(tmp_path):
    dd = _fixture_data_dir(tmp_path)
    before = sorted((p.name, p.stat().st_mtime_ns) for p in dd.iterdir())
    datainv.measure(dd, state_root=tmp_path)
    assert sorted((p.name, p.stat().st_mtime_ns) for p in dd.iterdir()) == before


def test_measure_on_an_empty_folder(tmp_path):
    out = datainv.measure(tmp_path / "none", state_root=tmp_path)
    assert all(m.bytes == 0 and m.items == 0 for m in out)


@pytest.mark.parametrize("value,expected", [
    (1700000000, 1700000000.0), ("1700000000.5", 1700000000.5),
    ("2026-10-01T10:00:00+00:00", 1790848800.0), ("2026-10-01T10:00:00Z", 1790848800.0),
    (None, None), ("", None), ("garbage", None)])
def test_to_epoch(value, expected):
    assert datainv.to_epoch(value) == expected


def test_to_epoch_reads_a_naive_time_like_every_other_stored_time():
    from kratos.utils.timeutil import parse_stored_instant

    assert datainv.to_epoch("2026-10-01T10:00:00") == parse_stored_instant("2026-10-01T10:00:00").timestamp()
