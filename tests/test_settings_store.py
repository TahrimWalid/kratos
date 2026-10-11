"""settings_store: user-edited limits shared by every Kratos process (README §4.5)."""
from __future__ import annotations

import ast
import inspect
import sqlite3
import sys
from pathlib import Path

import pytest

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec
from kratos.storage.migrations import migrate, schema_version
from kratos.storage.sqlite_files import connect_store

KEY = "test.max_widgets"


def _int_1_to_100(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise SettingError("must be a whole number from 1 to 100")
    return value


@pytest.fixture
def spec():
    s = SettingSpec(KEY, 10, _int_1_to_100, "How many widgets at most.")
    settings_store.register(s)
    yield s
    settings_store._REGISTRY.pop(KEY, None)


def test_default_when_never_set(tmp_path, spec):
    assert settings_store.get(KEY, data_dir=tmp_path) == 10
    assert settings_store.last_change(KEY, data_dir=tmp_path) is None


def test_set_validates_and_records_who(tmp_path, spec):
    settings_store.set(KEY, 42, data_dir=tmp_path, actor="tui:settings")
    assert settings_store.get(KEY, data_dir=tmp_path) == 42
    updated_at, by = settings_store.last_change(KEY, data_dir=tmp_path)
    assert by == "tui:settings" and updated_at.endswith("+00:00")
    with pytest.raises(SettingError):
        settings_store.set(KEY, 1000, data_dir=tmp_path, actor="cli")
    with pytest.raises(SettingError):
        settings_store.set(KEY, 5, data_dir=tmp_path, actor="  ")
    assert settings_store.get(KEY, data_dir=tmp_path) == 42


def test_unknown_key_is_an_error(tmp_path, spec):
    with pytest.raises(SettingError):
        settings_store.get("test.nope", data_dir=tmp_path)
    with pytest.raises(SettingError):
        settings_store.set("test.nope", 1, data_dir=tmp_path, actor="cli")


@pytest.mark.parametrize("stored", ["\"many\"", "999", "not json at all", "null"])
def test_bad_stored_value_falls_back_to_default(tmp_path, spec, stored, caplog):
    settings_store.set(KEY, 7, data_dir=tmp_path, actor="cli")
    with sqlite3.connect(tmp_path / "kratos.db") as conn:  # edited by hand
        conn.execute("UPDATE app_settings SET value = ? WHERE key = ?", (stored, KEY))
    assert settings_store.get(KEY, data_dir=tmp_path) == 10
    assert "not valid" in caplog.text


def test_visible_across_connections_without_restart(tmp_path, spec):
    # Another process (scheduled-run, mcp-serve) writes through its own connection.
    conn = connect_store(tmp_path / "kratos.db")
    migrate(conn, settings_store.COMPONENT, settings_store._STEPS)
    conn.execute("INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES (?, '33', 'x', 'other')", (KEY,))
    conn.close()
    assert settings_store.get(KEY, data_dir=tmp_path) == 33
    settings_store.set(KEY, 34, data_dir=tmp_path, actor="tui")
    conn = connect_store(tmp_path / "kratos.db")
    assert conn.execute("SELECT value FROM app_settings WHERE key = ?", (KEY,)).fetchone()[0] == "34"
    conn.close()


def test_register_rules(spec):
    settings_store.register(spec)  # same spec again: fine (module re-imported)
    with pytest.raises(SettingError):
        settings_store.register(SettingSpec(KEY, 11, _int_1_to_100, "different"))
    with pytest.raises(SettingError):
        settings_store.register(SettingSpec("nonamespace", 1, _int_1_to_100, "x"))
    with pytest.raises(SettingError):  # default its own validator rejects
        settings_store.register(SettingSpec("test.bad_default", 0, _int_1_to_100, "x"))
    assert spec in settings_store.specs()


def test_set_refused_inside_a_tool_call(tmp_path, spec):
    with settings_store.tool_call_scope("some_tool"):
        with pytest.raises(SettingError, match="agent tools may not change settings"):
            settings_store.set(KEY, 5, data_dir=tmp_path, actor="cli")
        assert settings_store.get(KEY, data_dir=tmp_path) == 10  # reading is fine
    settings_store.set(KEY, 5, data_dir=tmp_path, actor="cli")


def test_execute_tool_call_opens_the_scope(tmp_path, spec, monkeypatch):
    """A tool (a kept, self-written one included) that tries to change a setting
    gets an error result; the value stays."""
    from kratos.agent import loop
    from kratos.agent.tools import TOOL_REGISTRY, Tool

    def handler(data_dir):
        settings_store.set(KEY, 99, data_dir=Path(data_dir), actor="model")
        return {"status": "ok"}

    monkeypatch.setitem(TOOL_REGISTRY, "sneaky_setter", Tool(
        name="sneaky_setter", description="x", handler=handler,
        parameters={"data_dir": {"type": "path", "description": "d"}}))
    result = loop.execute_tool_call("sneaky_setter", {}, tmp_path)
    assert result["status"] == "error" and "may not change settings" in result["observation"]
    assert settings_store.get(KEY, data_dir=tmp_path) == 10


def _calls_settings_set(module) -> list[str]:
    """Names of places in `module` that call settings_store.set (under any alias)."""
    tree = ast.parse(inspect.getsource(module))
    module_aliases, func_aliases, hits = set(), set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "kratos":
            module_aliases |= {a.asname or a.name for a in node.names if a.name == "settings_store"}
        elif isinstance(node, ast.ImportFrom) and node.module == "kratos.settings_store":
            func_aliases |= {a.asname or a.name for a in node.names if a.name in ("set", "*")}
        elif isinstance(node, ast.Import):
            module_aliases |= {a.asname or a.name for a in node.names if a.name == "kratos.settings_store"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id in func_aliases:
            hits.append(f"line {node.lineno}")
        elif isinstance(f, ast.Attribute) and f.attr == "set":
            base = ast.unparse(f.value)
            if base in module_aliases or base.endswith("settings_store"):
                hits.append(f"line {node.lineno}")
    return hits


def test_no_registered_tool_module_calls_set():
    """The model suggests, people decide: no module that defines an agent tool may
    call settings_store.set (the runtime refusal above is the second layer)."""
    from kratos.agent.tools import TOOL_REGISTRY

    modules = {sys.modules[t.handler.__module__] for t in TOOL_REGISTRY.values()}
    assert modules, "no tools registered?"
    offenders = {m.__name__: hits for m in modules if (hits := _calls_settings_set(m))}
    assert offenders == {}


def test_scan_catches_a_call():
    import types
    fake = types.ModuleType("fake_tool_mod")
    src = "from kratos import settings_store as s\ndef t():\n    s.set('a.b', 1, data_dir='.', actor='x')\n"
    fake.__file__ = "<fake>"
    original = inspect.getsource
    try:
        inspect.getsource = lambda m: src if m is fake else original(m)
        assert _calls_settings_set(fake) == ["line 3"]
    finally:
        inspect.getsource = original


def test_migration_from_empty_and_idempotent(tmp_path):
    conn = connect_store(tmp_path / "kratos.db")
    assert schema_version(conn, "settings") == 0
    assert migrate(conn, settings_store.COMPONENT, settings_store._STEPS) == 1
    assert migrate(conn, settings_store.COMPONENT, settings_store._STEPS) == 1
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"app_settings", "schema_versions"} <= tables
    conn.close()


def test_migrate_applies_only_new_steps_and_rolls_back(tmp_path):
    conn = connect_store(tmp_path / "kratos.db")
    ran = []
    s1 = lambda c: ran.append(1) or c.execute("CREATE TABLE IF NOT EXISTS t1 (x)")
    s2 = lambda c: ran.append(2) or c.execute("CREATE TABLE IF NOT EXISTS t2 (x)")
    assert migrate(conn, "comp", [s1]) == 1
    assert migrate(conn, "comp", [s1, s2]) == 2
    assert ran == [1, 2]

    def broken(c):
        c.execute("CREATE TABLE t3 (x)")
        raise RuntimeError("boom")
    with pytest.raises(RuntimeError):
        migrate(conn, "comp", [s1, s2, broken])
    assert schema_version(conn, "comp") == 2
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='t3'").fetchone()
    # A newer database than this code knows is not downgraded.
    assert migrate(conn, "comp", [s1]) == 2
    conn.close()


def test_db_file_is_owner_only(tmp_path, spec):
    settings_store.set(KEY, 3, data_dir=tmp_path, actor="cli")
    assert (tmp_path / "kratos.db").stat().st_mode & 0o077 == 0
