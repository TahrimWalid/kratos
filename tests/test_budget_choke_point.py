"""Source scan: one function sends model requests (docs/phase0/0.4 §3.1).

Every request to a model must pass the budget guard, so there is exactly one
place a request is sent: `llm_interface._metered_call`, which calls the request
handed to it as `send`. This test fails if

  * a model request (`requests.post`, the in-process llama call) appears in
    llm_interface.py anywhere other than inside a nested `_send` function that
    is handed to `_metered_call` in the same function, or
  * anything outside llm_interface.py talks to a model endpoint directly
    (a chat-completions / Ollama URL, the llama_cpp library, a provider SDK).
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
LLM = SRC / "llm_interface.py"

_ENDPOINT_MARKERS = ("chat/completions", "/api/chat", "/api/generate", "/v1/completions")
_SDK_MODULES = ("llama_cpp", "openai", "anthropic", "google.generativeai", "google.genai", "litellm", "ollama")


def _is_request(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "post" and \
            isinstance(func.value, ast.Name) and func.value.id == "requests":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "_llama":
        return True
    return isinstance(func, ast.Name) and func.id in ("llama", "_llama")


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    out = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def test_every_model_request_in_llm_interface_goes_through_metered_call():
    tree = ast.parse(LLM.read_text(encoding="utf-8"))
    parents = _parents(tree)
    requests_found = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_request(node)):
            continue
        requests_found += 1
        fn = parents[node]
        while not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = parents[fn]
        assert fn.name == "_send", (
            f"llm_interface.py:{node.lineno} sends a model request outside a `_send` function "
            "handed to _metered_call -- it would skip the budget guard")
        outer = parents[fn]
        while not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
            outer = parents[outer]
        handed = [c for c in ast.walk(outer) if isinstance(c, ast.Call)
                  and getattr(c.func, "id", None) == "_metered_call"
                  and c.args and isinstance(c.args[0], ast.Name) and c.args[0].id == "_send"]
        assert handed, f"{outer.name}: its _send is never handed to _metered_call"
    assert requests_found == 3  # _query_server, _query_openai_compatible, LLMServer.infer


def test_only_metered_call_invokes_a_send():
    tree = ast.parse(LLM.read_text(encoding="utf-8"))
    callers = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for c in ast.walk(fn):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in ("send", "_send"):
                    callers.add(fn.name)
    assert callers == {"_metered_call"}


def test_metered_call_checks_the_budget_before_sending():
    tree = ast.parse(LLM.read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_metered_call")
    order = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
    names = [ast.unparse(c.func) for c in sorted(order, key=lambda c: (c.lineno, c.col_offset))]
    assert names.index("_budget.before_call") < names.index("send") < names.index("_budget.after_call")


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def test_nothing_else_talks_to_a_model_directly():
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path == LLM:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = _docstrings(tree)
        rel = path.relative_to(SRC)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                if any(m in node.value for m in _ENDPOINT_MARKERS):
                    offenders.append(f"{rel}:{node.lineno} model endpoint {node.value!r}")
            elif isinstance(node, ast.Import):
                offenders += [f"{rel}:{node.lineno} import {a.name}" for a in node.names
                              if a.name.split(".")[0] in _SDK_MODULES or a.name in _SDK_MODULES]
            elif isinstance(node, ast.ImportFrom) and node.module and (
                    node.module.split(".")[0] in _SDK_MODULES or node.module in _SDK_MODULES):
                offenders.append(f"{rel}:{node.lineno} from {node.module} import ...")
    assert offenders == [], "model requests must go through llm_interface._metered_call:\n" + "\n".join(offenders)


def test_the_scan_catches_a_new_unmetered_request(tmp_path):
    """The scan above isn't vacuous: a direct requests.post in a new function fails it."""
    bad = LLM.read_text(encoding="utf-8") + (
        "\n\ndef _sneaky(prompt):\n    return requests.post('http://x/v1/chat/completions', json={})\n")
    tree = ast.parse(bad)
    parents = _parents(tree)
    hits = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _is_request(n)]
    names = []
    for node in hits:
        fn = parents[node]
        while not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = parents[fn]
        names.append(fn.name)
    assert "_sneaky" in names
