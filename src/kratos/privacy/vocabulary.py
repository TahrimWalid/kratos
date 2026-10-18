"""Kratos's own words: never changed by masking.

Masking replaces values, not Kratos's text. A real account (or machine) whose name is
also a word Kratos writes to the model -- "status", "backup", "target", a word of a
finding's fixed description -- is replaced only where it appears as a name, so the
instructions, field names and finding descriptions reach the model exactly as written.

The fixed text is every string literal (docstrings excepted) in the modules that write
what the model reads: the system prompts, tool descriptions, finding titles and fixed
rule descriptions (`finding_facts.RULE_TEXT`), the digest, the router. Read once per
process from the source -- it changes only when Kratos does. The field names of the
request itself (`"status":`, `"severity":`) are added per request.
"""
from __future__ import annotations

import ast
import functools
import re
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]
# Where Kratos writes text the model reads. A new module that does: add it here.
FIXED_TEXT_SOURCES = (
    "agent/loop.py", "agent/tools.py", "agent/self_write.py", "agent/guided_evolve.py", "agent/pipeline_draft.py",
    "agent/plan_preview.py", "agent/clarify_intake.py", "finding_facts.py", "untrusted.py", "llm_config.py",
    "collect/digest.py", "collect/checks.py", "adapters/findings_engine.py", "lifecycle/rules.py",
    "tui_mk2/command_intent.py", "cli/repl.py", "privacy/mask.py", "remediation/catalogue.py",
)
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_JSON_KEY_RE = re.compile(r'\\?"([A-Za-z_][\w.-]{0,63})\\?"\s*:')


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _words(text: str) -> set[str]:
    return {w.lower().rstrip(".-") for w in _WORD_RE.findall(text)}


@functools.lru_cache(maxsize=1)
def fixed_words() -> frozenset[str]:
    """Every word of Kratos's fixed model-facing text (lower-case)."""
    words: set[str] = set()
    for rel in FIXED_TEXT_SOURCES:
        path = _PKG / rel
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        docs = _docstring_ids(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                words |= _words(node.value)
    return frozenset(w for w in words if w)


def request_vocabulary(prompt_texts: tuple[str, ...]) -> frozenset[str]:
    """Words masking must not change in this request: Kratos's fixed text plus the field
    names the request carries."""
    keys = {k.lower() for text in prompt_texts for k in _JSON_KEY_RE.findall(text or "")}
    return fixed_words() | frozenset(keys)
