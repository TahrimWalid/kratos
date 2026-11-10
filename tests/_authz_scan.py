"""Static check: every entry point checks permission (docs/phaseD/D.7 §5.2).

A function is *gated* when its body calls `require(` / `require_person(` /
`check_run_access(` / `unattended_refusal(` (kratos.authz), or calls a function that is
gated. Name-based like tests/_run_scope_scan.py, and strict about collisions: a name
counts as gated only if EVERY function of that name in the source is gated, so a
same-named ungated function makes the check fail, never pass.

Entry points scanned:

1. network doors -- every `@mcp.tool()` function (MCP over HTTP and stdio), every route
   handler in serve/openai_routes.py `_handlers`, and the chat turn's dispatchers;
2. people-only functions -- every function that refuses inside an agent tool call
   (`in_tool_call()`), except the justified list below;
3. local dispatch -- `cli.app.main` and `SessionScreen._dispatch_slash` check, every
   argparse subcommand and every slash command is listed in kratos.authz.entrypoints,
   and every "core" function an entry names is gated;
4. per-read -- tool dispatch, the fleet collector and the agent loop's stop points.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"

CHECKS = frozenset({"require", "require_person", "check_run_access", "unattended_refusal", "require_tui",
                    "require_cli"})

# Functions that call in_tool_call() but are not a person's action -- with the reason.
NOT_PEOPLE_ACTIONS = {
    "kratos.settings_store:set_by_upgrade": "a one-time upgrade step changing a default on its own (no person)",
    "kratos.budget.guard:ensure_upgrade_migration": "the same upgrade step's caller (skips inside a tool call)",
    "kratos.authz.check:require": "the check itself",
    "kratos.lifecycle.decide:_check_actor": "decision helper; every caller also calls _authorize (scanned)",
    "kratos.export.create:_refuse_in_tool": "export helper; create() calls require (scanned)",
}

# The chat door's per-message dispatch (each sub-action is checked inside).
NETWORK_HELPERS = ("kratos.serve.openai_routes:_serve_turn", "kratos.serve.openai_routes:_serve_fleet_turn",
                   "kratos.serve.openai_routes:command_reply", "kratos.serve.openai_routes:_retest_text",
                   "kratos.serve.openai_routes:_hunt_text", "kratos.serve.openai_routes:_decide_text")

PER_READ = ("kratos.agent.loop:_dispatch_tool_call", "kratos.fleet.collect:_collect_one",
            "kratos.agent.loop:_collect_first", "kratos.serve.runs:run_investigation")

_SKIP = ("subagent/agent.py", "subagent/reads.py", "subagent/collector.py")


@dataclass
class Func:
    module: str
    qualname: str
    name: str
    lineno: int
    calls: set[str] = field(default_factory=set)
    decorators: list[str] = field(default_factory=list)
    node: ast.AST | None = None

    @property
    def ref(self) -> str:
        return f"{self.module}:{self.qualname}"


def _module(src: Path, path: Path) -> str:
    parts = path.relative_to(src).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return "kratos." + ".".join(parts) if parts else "kratos"


def collect(src: Path = DEFAULT_SRC) -> list[Func]:
    out: list[Func] = []
    for path in sorted(src.rglob("*.py")):
        rel = path.relative_to(src).as_posix()
        if rel.endswith(_SKIP) or "__pycache__" in rel:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module = _module(src, path)

        def visit(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    visit(child, f"{prefix}{child.name}.")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    f = Func(module, prefix + child.name, child.name, child.lineno, node=child,
                             decorators=[ast.unparse(d) for d in child.decorator_list])
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.Call):
                            fn = sub.func
                            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                            if name:
                                f.calls.add(name)
                            # a function handed to another to call (asyncio.to_thread(require, ...),
                            # ctx.run(fn, ...)) is called too
                            for arg in sub.args:
                                ref = arg.id if isinstance(arg, ast.Name) else \
                                    arg.attr if isinstance(arg, ast.Attribute) else ""
                                if ref:
                                    f.calls.add(ref)
                    out.append(f)
                    visit(child, f"{prefix}{child.name}.")

        visit(tree, "")
    return out


def gated_names(funcs: list[Func]) -> set[str]:
    by_name: dict[str, list[Func]] = defaultdict(list)
    for f in funcs:
        by_name[f.name].append(f)
    gated: set[str] = set(CHECKS)
    changed = True
    while changed:
        changed = False
        for name, fs in by_name.items():
            if name in gated:
                continue
            if all(f.calls & gated for f in fs):
                gated.add(name)
                changed = True
    return gated


def is_gated(f: Func, gated: set[str]) -> bool:
    return bool(f.calls & gated)


@dataclass
class Report:
    network: list[str] = field(default_factory=list)
    people_only: list[str] = field(default_factory=list)
    local: list[str] = field(default_factory=list)
    per_read: list[str] = field(default_factory=list)
    counted: dict[str, int] = field(default_factory=dict)

    @property
    def gaps(self) -> list[str]:
        return self.network + self.people_only + self.local + self.per_read


def _find(funcs: list[Func], ref: str) -> list[Func]:
    return [f for f in funcs if f.ref == ref]


def scan(src: Path = DEFAULT_SRC) -> Report:
    funcs = collect(src)
    gated = gated_names(funcs)
    rep = Report()

    # 1. network doors
    tools = [f for f in funcs if any(d.startswith("mcp.tool") for d in f.decorators)]
    handlers = [f for f in funcs if f.module == "kratos.serve.openai_routes" and f.qualname.startswith("_handlers.")
                and isinstance(f.node, ast.AsyncFunctionDef)]
    helpers = [f for ref in NETWORK_HELPERS for f in _find(funcs, ref)]
    for ref in NETWORK_HELPERS:
        if not _find(funcs, ref):
            rep.network.append(f"{ref}: listed as a network entry point but not found")
    for f in tools + handlers + helpers:
        if not is_gated(f, gated):
            rep.network.append(f"{f.ref} (line {f.lineno}): a network entry point that never calls require()")
    rep.counted["network"] = len(tools) + len(handlers) + len(helpers)

    # 2. people-only functions
    people = [f for f in funcs if "in_tool_call" in f.calls and f.name != "in_tool_call"]
    for f in people:
        if f.ref in NOT_PEOPLE_ACTIONS:
            continue
        if not is_gated(f, gated):
            rep.people_only.append(f"{f.ref} (line {f.lineno}): refuses inside a tool call (a person's action) "
                                   "but never calls require()")
    rep.counted["people_only"] = len(people)

    # 3. local dispatch + the entry point tables
    import importlib.util

    spec = importlib.util.spec_from_file_location("_scanned_entrypoints", src / "authz" / "entrypoints.py")
    ep = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = ep          # dataclasses look their module up while being built
    try:
        spec.loader.exec_module(ep)      # the tables of THIS source tree (a test may edit a copy)
    finally:
        sys.modules.pop(spec.name, None)
    main = _find(funcs, "kratos.cli.app:main")
    if not main or "require_cli" not in main[0].calls:
        rep.local.append("kratos.cli.app:main no longer checks subcommands (require_cli)")
    disp = _find(funcs, "kratos.tui_mk2.screens.session:SessionScreen._dispatch_slash")
    if not disp or "require_tui" not in disp[0].calls:
        rep.local.append("SessionScreen._dispatch_slash no longer checks slash commands (require_tui)")
    cli_funcs = _cli_functions(src)
    for name in sorted(cli_funcs):
        if name not in ep.CLI:
            rep.local.append(f"kratos subcommand {name} is not listed in kratos.authz.entrypoints.CLI")
    words = _slash_words(src)
    for w in sorted(words):
        if w not in ep.TUI:
            rep.local.append(f"slash command {w} is not listed in kratos.authz.entrypoints.TUI")
    for table in (ep.CLI, ep.TUI):
        for key, entry in table.items():
            for ref in entry.core:
                found = _find(funcs, ref)
                if not found:
                    rep.local.append(f"{key}: core function {ref} not found")
                elif not all(is_gated(f, gated) or f.name in gated for f in found):
                    rep.local.append(f"{key}: core function {ref} never calls require()")
    rep.counted["cli"] = len(cli_funcs)
    rep.counted["tui"] = len(words)

    # 4. per-read checks
    for ref in PER_READ:
        found = _find(funcs, ref)
        if not found or "check_run_access" not in found[0].calls:
            rep.per_read.append(f"{ref} no longer re-checks access at each read (check_run_access)")
    stop = _find(funcs, "kratos.agent.loop:_run_agent_impl._check_stop") or \
        [f for f in funcs if f.module == "kratos.agent.loop" and f.name == "_check_stop"]
    if not stop or not all("check_run_access" in f.calls for f in stop):
        rep.per_read.append("the agent loop's stop check no longer re-checks access")
    return rep


def _cli_functions(src: Path) -> set[str]:
    out: set[str] = set()
    for path in (src / "cli").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "set_defaults":
                for kw in node.keywords:
                    if kw.arg == "func" and isinstance(kw.value, ast.Name):
                        out.add(kw.value.id)
    return out


def _slash_words(src: Path) -> set[str]:
    tree = ast.parse((src / "tui_mk2" / "screens" / "session.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_dispatch_slash_impl")
    words: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id == "cmd":
            for c in n.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    words.add(c.value)
                elif isinstance(c, ast.Tuple):
                    words.update(e.value for e in c.elts if isinstance(e, ast.Constant))
    return words
