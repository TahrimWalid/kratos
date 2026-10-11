"""Static check: every path into the model or a tool runs inside a run_scope.

A function "reaches" a run primitive if its body (nested defs and lambdas
included) references one -- `run_agent`, `agent_chat`, `execute_tool_call`, ...
-- or references another function that reaches one without opening a scope
itself. A reaching function is covered when it opens `run_scope(` itself, or when
every function that references it is covered. A reaching function that nothing
references (an entry point: a Textual handler, a CLI command dispatched by
argparse, an MCP tool) and that opens no scope is a gap.

Name-based, deliberately: a same-named function elsewhere can only add
referrers that must ALSO be covered, so collisions make the check stricter, not
looser. Used by tests/test_run_context.py.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"

# Calling any of these spends model tokens, runs an agent tool, or starts a
# whole run. (Every other model/tool path in the code goes through one of them.)
PRIMITIVES = frozenset({
    "agent_chat", "analyze_findings",          # the model interface
    "run_agent", "execute_tool_call",          # the agent loop and its tool dispatch
    "run_pipeline",                            # deterministic tool pipelines
    "run_self_write_loop",                     # evo-loop
})

# Not scanned: the model interface itself and the sub-agent bundle (it runs on
# the target and never calls the model).
_SKIP = ("llm_interface.py", "subagent/agent.py", "subagent/reads.py", "subagent/collector.py")


@dataclass
class Func:
    module: str
    qualname: str
    name: str
    lineno: int
    refs: set[str] = field(default_factory=set)
    opens_scope: bool = False
    tool_handler: bool = False   # @register_tool: only ever runs via execute_tool_call


def _module_name(path: Path) -> str:
    return "kratos." + ".".join(path.relative_to(SRC).with_suffix("").parts)


def _collect(path: Path) -> list[Func]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module = _module_name(path)
    # Import aliases of primitives (`import run_agent as run_agent_fn`).
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
    funcs: list[Func] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                f = Func(module, prefix + child.name, child.name, child.lineno)
                # @_with_run_scope(...) (tui_mk2/screens/session.py) opens one around the body.
                if any(ast.unparse(d).lstrip("@").split("(")[0].endswith("with_run_scope") for d in child.decorator_list):
                    f.opens_scope = True
                f.tool_handler = any(
                    isinstance(d, ast.Call) and getattr(d.func, "id", getattr(d.func, "attr", "")) == "register_tool"
                    for d in child.decorator_list)
                # Names bound inside the function (locals, parameters, loop and
                # comprehension targets) are variables, not references to functions.
                bound = {a.arg for sub in ast.walk(child) if isinstance(sub, ast.arguments)
                         for a in (*sub.posonlyargs, *sub.args, *sub.kwonlyargs, sub.vararg, sub.kwarg) if a}
                bound |= {sub.id for sub in ast.walk(child)
                          if isinstance(sub, ast.Name) and isinstance(sub.ctx, (ast.Store, ast.Del))}
                for sub in ast.walk(child):  # nested defs/lambdas count as this function
                    name = None
                    if isinstance(sub, ast.Name):
                        name = None if sub.id in bound else sub.id
                    elif isinstance(sub, ast.Attribute):
                        name = sub.attr
                    if name and name != child.name:
                        f.refs.add(aliases.get(name, name))
                    if isinstance(sub, ast.Call):
                        fn = sub.func
                        callee = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                        if callee.endswith("run_scope"):   # run_scope / _run_scope helpers
                            f.opens_scope = True
                funcs.append(f)

    visit(tree, "")
    return funcs


def scan() -> list[Func]:
    out: list[Func] = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        if rel.endswith(_SKIP) or "/__pycache__/" in rel:
            continue
        out.extend(_collect(path))
    return out


def uncovered_entry_points() -> list[str]:
    funcs = scan()
    by_name: dict[str, list[Func]] = defaultdict(list)
    for f in funcs:
        by_name[f.name].append(f)
    referrers: dict[str, list[Func]] = defaultdict(list)
    for f in funcs:
        for r in f.refs:
            if r in by_name:
                referrers[r].append(f)

    # Fixed point: which names reach a primitive without opening a scope on the way.
    reaching: set[str] = set(PRIMITIVES)
    changed = True
    while changed:
        changed = False
        for f in funcs:
            if f.name in reaching or f.opens_scope:
                continue
            if f.refs & reaching:
                reaching.add(f.name)
                changed = True

    # Covered: opens a scope, only runs via execute_tool_call (a tool handler), or
    # is referenced only by covered functions. Least fixed point, so a cycle of
    # functions that never reaches a scope stays uncovered.
    covered: set[int] = {id(f) for f in funcs if f.opens_scope or f.tool_handler}
    changed = True
    while changed:
        changed = False
        for f in funcs:
            if id(f) in covered:
                continue
            refs = referrers.get(f.name, [])
            if refs and all(id(r) in covered for r in refs):
                covered.add(id(f))
                changed = True

    gaps = []
    for f in funcs:
        if id(f) in covered or f.name in PRIMITIVES or not (f.refs & reaching):
            continue
        gaps.append(f"{f.module}:{f.qualname} (line {f.lineno})")
    return sorted(gaps)

if __name__ == "__main__":
    for g in uncovered_entry_points():
        print(g)
