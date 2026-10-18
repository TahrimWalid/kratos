"""B.2 §3.1: one place masks, every caller restores.

Source scans over llm_interface.py (as tests/test_budget_choke_point.py does for the
budget guard), then the HTTP layer itself: what the request body really carries.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("requests")

from kratos import kratos_config, llm_interface, settings_store
from kratos.privacy import mode as M

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
LLM = SRC / "llm_interface.py"
_RAW_TEXT_NAMES = {"system_prompt", "prompt", "user_prompt", "bundle_text"}


def _tree() -> ast.Module:
    return ast.parse(LLM.read_text(encoding="utf-8"))


def _functions(tree: ast.AST) -> list[ast.FunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]


def test_no_request_is_built_from_unmasked_text():
    """Each `_send` builds its request only from the texts it is handed: it may not
    reach the caller's raw system prompt or prompt."""
    sends = [f for f in _functions(_tree()) if f.name == "_send"]
    assert len(sends) == 3
    for fn in sends:
        params = {a.arg for a in fn.args.args}
        assert len(params) == 2, f"line {fn.lineno}: _send must take (system, prompt)"
        loaded = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        assert not loaded & _RAW_TEXT_NAMES, f"line {fn.lineno}: _send reads raw text {loaded & _RAW_TEXT_NAMES}"


def test_metered_call_sends_only_what_the_masker_returned():
    fn = next(f for f in _functions(_tree()) if f.name == "_metered_call")
    masked = None
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and \
                ast.unparse(node.value.func) == "masker.mask_request":
            masked = {e.id for e in node.targets[0].elts}
    assert masked, "_metered_call must mask with masker.mask_request"
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and ast.unparse(c.func) == "send"]
    assert len(calls) == 1 and {a.id for a in calls[0].args} == masked
    estimate = next(c for c in ast.walk(fn) if isinstance(c, ast.Call)
                    and ast.unparse(c.func) == "_budget.estimate_prompt_tokens")
    assert {a.id for a in estimate.args} == masked          # the bill is for what was sent
    order = sorted((c for c in ast.walk(fn) if isinstance(c, ast.Call)), key=lambda c: (c.lineno, c.col_offset))
    names = [ast.unparse(c.func) for c in order]
    assert names.index("masker.mask_request") < names.index("send")


def _own_nodes(fn: ast.FunctionDef):
    """`fn`'s nodes, not those of functions nested in it."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            stack.extend(ast.iter_child_nodes(node))


def test_every_caller_restores_what_it_returns():
    callers = []
    for fn in _functions(_tree()):
        if fn.name == "_metered_call":
            continue
        metered = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", None) == "_metered_call"]
        if not metered:
            continue
        callers.append(fn.name)
        for c in metered:
            assert any(k.arg == "masker" for k in c.keywords), f"{fn.name}: _metered_call without a masker"
        for ret in (n for n in _own_nodes(fn) if isinstance(n, ast.Return) and n.value is not None):
            if isinstance(ret.value, ast.Constant) and ret.value.value is None:
                continue
            assert isinstance(ret.value, ast.Call) and ast.unparse(ret.value.func) == "masker.restore", (
                f"{fn.name}:{ret.lineno} returns model text without masker.restore")
    assert sorted(callers) == ["_query_openai_compatible", "_query_server", "infer"]


def test_nothing_else_masks_or_restores_for_the_model():
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC)
        if rel.parts[0] == "privacy" or path == LLM:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in ("request_masker", "mask_request", "Masker("):
            if marker in text:
                offenders.append(f"{rel}: {marker}")
    assert offenders == []


# --- the HTTP layer -------------------------------------------------------------------------
class _Resp:
    def __init__(self, content: str):
        self._body = {"choices": [{"message": {"content": content}}],
                      "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._body


@pytest.fixture
def http(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("192.0.2.10")
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "m")
    state = {"bodies": [], "reply": "ok", "dir": tmp_path}

    def post(url, headers=None, json=None, timeout=None):
        state["bodies"].append(json)
        return _Resp(state["reply"](json) if callable(state["reply"]) else state["reply"])

    monkeypatch.setattr(llm_interface.requests, "post", post)
    return state


SYSTEM = "You are Kratos."
PROMPT = "alice@example.com saw 203.0.113.7 try bob@laptop9 on 192.0.2.10"


def test_mode_off_sends_byte_identical_text(http):
    settings_store.set(M.MODE_KEY, "off", data_dir=http["dir"], actor="test")
    assert llm_interface._query_openai_compatible(PROMPT, SYSTEM, 64) == "ok"
    msgs = http["bodies"][0]["messages"]
    assert msgs == [{"role": "system", "content": SYSTEM}, {"role": "user", "content": PROMPT}]


def test_standard_sends_placeholders_and_the_reply_is_restored(http):
    def echo(body):            # a model that names what it was sent
        return "Seen: " + body["messages"][1]["content"]

    http["reply"] = echo
    out = llm_interface._query_openai_compatible(PROMPT, SYSTEM, 64)
    sent = http["bodies"][0]["messages"]
    for value in ("alice@example.com", "203.0.113.7", "bob", "laptop9", "192.0.2.10"):
        assert value not in sent[1]["content"]
    assert sent[0]["content"].startswith(SYSTEM) and "placeholders" in sent[0]["content"]
    assert out == "Seen: " + PROMPT


def test_a_masking_failure_sends_nothing(http, monkeypatch):
    from kratos.privacy import mask as PM

    def broken(self, *_a):
        raise RuntimeError("bug")

    monkeypatch.setattr(PM.Masker, "_mask_pair", broken)
    assert llm_interface._query_openai_compatible(PROMPT, SYSTEM, 64) is None
    assert http["bodies"] == []
