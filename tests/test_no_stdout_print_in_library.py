"""Library code never prints to stdout (B.4 lint).

`kratos mcp-serve` speaks JSON-RPC over stdout: one stray line from a tool, an adapter
or the model client breaks the client's connection (the d11c057 regression, where nmap's
report did exactly that). A progress or error message from library code goes to stderr
(or `logging`); only the command-line and app layers write to stdout.

Ruff's T201 can't tell `print(..., file=sys.stderr)` from a stdout print, so this is a
source scan instead: every `print(` under src/kratos outside cli/ and tui_mk2/ must pass
`file=` something other than sys.stdout, unless it is in a `main()` function, under
`if __name__ == "__main__":`, or listed below with the reason.
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
FRONT_ENDS = ("cli", "tui_mk2")
# (file, enclosing function): why its stdout print is right
ALLOWED = {
    ("subagent/agent.py", "reset_whitelist_floor"): "the sub-agent's own command line (--reset-whitelist-floor)",
}


def _enclosing_functions(tree: ast.AST) -> dict[ast.AST, str]:
    owner: dict[ast.AST, str] = {}

    def walk(node: ast.AST, fn: str, main_guard: bool) -> None:
        for child in ast.iter_child_nodes(node):
            name, guard = fn, main_guard
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name
            if isinstance(child, ast.If) and "__name__" in ast.unparse(child.test) and "__main__" in ast.unparse(child.test):
                guard = True
            owner[child] = "<main guard>" if guard else name
            walk(child, name, guard)

    walk(tree, "<module>", False)
    return owner


def _stdout_prints() -> list[str]:
    bad: list[str] = []
    for py in sorted(SRC.rglob("*.py")):
        rel = py.relative_to(SRC).as_posix()
        if rel.split("/")[0] in FRONT_ENDS or "__pycache__" in rel:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"):
                continue
            dest = next((k.value for k in node.keywords if k.arg == "file"), None)
            if dest is not None and ast.unparse(dest) not in ("sys.stdout", "stdout"):
                continue
            fn = owner.get(node, "<module>")
            if fn in ("main", "<main guard>") or (rel, fn) in ALLOWED:
                continue
            bad.append(f"{rel}:{node.lineno} in {fn}()")
    return bad


def test_no_library_code_prints_to_stdout():
    assert _stdout_prints() == [], "send these to stderr or logging (they would corrupt mcp-serve's stdout)"


def test_the_scan_catches_a_stdout_print(tmp_path, monkeypatch):
    pkg = tmp_path / "kratos"
    (pkg / "adapters").mkdir(parents=True)
    (pkg / "cli").mkdir()
    (pkg / "adapters" / "x.py").write_text(
        "import sys\n"
        "def a():\n    print('progress')\n"
        "def b():\n    print('ok', file=sys.stderr)\n"
        "def c():\n    print('x', file=sys.stdout)\n"
        "def main():\n    print('cli entry')\n"
        "if __name__ == '__main__':\n    print('also fine')\n")
    (pkg / "cli" / "y.py").write_text("print('front end')\n")
    monkeypatch.setattr(__import__(__name__), "SRC", pkg)
    assert _stdout_prints() == ["adapters/x.py:3 in a()", "adapters/x.py:7 in c()"]
