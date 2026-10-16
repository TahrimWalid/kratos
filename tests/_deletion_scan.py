"""Static scan: every place in src/kratos that deletes something.

Finds calls to `unlink`, `rmtree`, `remove`, `rmdir`, `truncate` (any receiver) and
SQL text containing DELETE FROM / DROP TABLE / VACUUM, and keys each by
(file relative to src/kratos, enclosing function, kind). Used by
tests/test_no_automatic_deletion.py.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"

CALL_KINDS = {"unlink": "unlink", "rmtree": "rmtree", "remove": "remove", "rmdir": "rmdir", "truncate": "truncate"}
SQL_RE = re.compile(r"(?:^|;)\s*(DELETE\s+FROM|DROP\s+TABLE|VACUUM)\b", re.IGNORECASE)  # a statement, any case


def _strings(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        return ["".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))]
    return []


def scan(src: Path = SRC) -> list[tuple[str, str, str, int]]:
    """[(file, function qualname or '<module>', kind, line)]"""
    out: list[tuple[str, str, str, int]] = []
    for path in sorted(src.rglob("*.py")):
        rel = str(path.relative_to(src))
        tree = ast.parse(path.read_text(encoding="utf-8"))

        def visit(node: ast.AST, scope: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit(child, f"{scope}.{child.name}" if scope != "<module>" else child.name)
                    continue
                if isinstance(child, ast.Call):
                    f = child.func
                    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
                    if name in CALL_KINDS:
                        out.append((rel, scope, CALL_KINDS[name], child.lineno))
                if not (isinstance(child, ast.Expr) and isinstance(getattr(child, "value", None), ast.Constant)):
                    for s in _strings(child):
                        for m in SQL_RE.finditer(s):
                            out.append((rel, scope, re.sub(r"\s+", " ", m.group(1).upper()), child.lineno))
                    if isinstance(child, ast.JoinedStr):
                        continue  # its parts were read above
                visit(child, scope)

        visit(tree, "<module>")
    return out
