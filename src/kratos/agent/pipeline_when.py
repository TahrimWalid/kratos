"""Slice 4 -- the bounded ``when`` conditional for Tier-2 pipelines (A2 Piece B).

SECURITY BOUNDARY (the whole reason this module exists, design doc §5/Piece B):
this NEVER ``eval()`` / ``exec()`` / compiles-to-code a user string. A ``when``
predicate is parsed with ``ast.parse(mode="eval")`` -- which only builds a syntax
TREE, it does not execute anything -- and then interpreted by a strict,
whitelisted compiler that recognizes ONLY the fixed vocabulary below. Every other
construct (attribute access, arbitrary names, un-whitelisted calls, subscripts,
lambdas, comprehensions, f-strings, arithmetic, walrus, ...) is REJECTED at
compile time (``WhenError``), long before any run. So a preset's ``when`` cannot
become code execution -- "a string mini-language that reaches eval is a boundary
violation" (design doc). The parser is validated adversarially in
``tests/test_pipeline_when.py`` (``__import__``, ``os.system``, attribute access,
lambda, comprehension, subscript, ... all rejected).

Grammar (the ONLY things allowed):

    has_finding()                       -> any finding was produced so far
    has_finding(min_severity='high')    -> a finding at/above that severity
    no_findings()                       -> no finding was produced so far
    finding_count <op> <int>            -> count comparison (== != < <= > >=)
    finding_id == '<id>'                -> a finding with that id exists
    finding_id != '<id>'                -> no finding with that id exists

Combine with ``and`` / ``or`` / ``not`` and parentheses. The variable may sit on
either side of a comparison (``3 <= finding_count``). ``min_severity`` must be one
of info/low/medium/high/critical.

The compiled predicate is ``Callable[[PipelineContext], bool]``; it reads ONLY
``ctx.has_finding(...)`` and ``ctx.findings`` (duck-typed as ``Any`` so this
module stays dependency-light -- importable by both ``presets.py`` at save/parse
time and ``pipeline.py`` at run time with no heavy import). Predicates are pure
and read-only; a run-time exception is the caller's concern (``run_pipeline``
fail-safe-SKIPs a step whose ``when`` raises -- design doc Piece B).
"""
from __future__ import annotations

import ast
import operator as _op
from typing import Any, Callable

Predicate = Callable[[Any], bool]

# A `when` string is a short condition, never a program. Cap it as defense in
# depth (also bounds parser/recursion work on pathological input).
_MAX_WHEN_LEN = 500

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VARIABLES = {"finding_count", "finding_id"}
_COUNT_OPS: dict[type, Callable[[Any, Any], bool]] = {
    ast.Eq: _op.eq, ast.NotEq: _op.ne, ast.Lt: _op.lt,
    ast.LtE: _op.le, ast.Gt: _op.gt, ast.GtE: _op.ge,
}


class WhenError(ValueError):
    """A ``when`` string is not a valid, whitelisted condition. The message is
    user-facing (shown at save/validate time)."""


def compile_when(expr: str) -> Predicate:
    """Parse and compile a ``when`` string into a safe predicate over a
    ``PipelineContext``. Raises ``WhenError`` (never anything else) on ANY input
    that isn't in the whitelisted grammar -- so a caller can validate simply by
    calling this and catching ``WhenError``. NEVER executes the string."""
    text = (expr or "").strip()
    if not text:
        raise WhenError("the condition is empty")
    if len(text) > _MAX_WHEN_LEN:
        raise WhenError(f"the condition is too long (max {_MAX_WHEN_LEN} characters)")
    try:
        tree = ast.parse(text, mode="eval")
    except (SyntaxError, ValueError) as e:  # ValueError: e.g. null bytes
        raise WhenError(f"not a valid condition: {getattr(e, 'msg', None) or e}")
    return _compile(tree.body)


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 -- messaging aid only, never fail on it
        return type(node).__name__


def _compile(node: ast.AST) -> Predicate:
    """Recursively compile a validated boolean-position node. Every branch is an
    explicit whitelist entry; the final ``raise`` rejects everything else, so the
    walker visits the WHOLE tree at compile time (no short-circuit validation gap
    -- an invalid operand of ``and``/``or`` is still rejected here)."""
    if isinstance(node, ast.BoolOp):
        parts = [_compile(v) for v in node.values]  # eagerly compile every operand
        if isinstance(node.op, ast.And):
            return lambda ctx: all(p(ctx) for p in parts)
        if isinstance(node.op, ast.Or):
            return lambda ctx: any(p(ctx) for p in parts)
        raise WhenError("only 'and' / 'or' may combine conditions")
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            inner = _compile(node.operand)
            return lambda ctx: not inner(ctx)
        raise WhenError("the only allowed prefix is 'not'")
    if isinstance(node, ast.Call):
        return _compile_call(node)
    if isinstance(node, ast.Compare):
        return _compile_compare(node)
    raise WhenError(f"unsupported expression: {_unparse(node)!r}")


def _compile_call(node: ast.Call) -> Predicate:
    if not isinstance(node.func, ast.Name):
        raise WhenError("only the built-in condition functions may be called")
    name = node.func.id
    if name == "has_finding":
        if node.args:
            raise WhenError("has_finding() takes no positional arguments")
        min_sev: str | None = None
        for kw in node.keywords:
            if kw.arg is None:
                raise WhenError("has_finding() does not accept **kwargs")
            if kw.arg != "min_severity":
                raise WhenError(f"has_finding() has no argument '{kw.arg}'")
            min_sev = _literal_str(kw.value, "min_severity").lower()
            if min_sev not in _ALLOWED_SEVERITIES:
                raise WhenError(
                    "min_severity must be one of " + ", ".join(sorted(_ALLOWED_SEVERITIES)))
        if min_sev is None:
            return lambda ctx: bool(ctx.has_finding())
        sev = min_sev
        return lambda ctx: bool(ctx.has_finding(min_severity=sev))
    if name == "no_findings":
        if node.args or node.keywords:
            raise WhenError("no_findings() takes no arguments")
        return lambda ctx: not ctx.has_finding()
    raise WhenError(
        f"unknown condition '{name}(...)' — allowed: has_finding, no_findings")


def _compile_compare(node: ast.Compare) -> Predicate:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        raise WhenError("only a single comparison is allowed (no chaining)")
    left, op, right = node.left, node.ops[0], node.comparators[0]
    var, literal_node, swapped = _split_var_literal(left, right)

    if var == "finding_count":
        fn = _COUNT_OPS.get(type(op))
        if fn is None:
            raise WhenError("finding_count supports  == != < <= > >=")
        n = _literal_int(literal_node, "finding_count")
        if swapped:
            return lambda ctx: bool(fn(n, len(ctx.findings)))
        return lambda ctx: bool(fn(len(ctx.findings), n))

    # finding_id: membership by ==/!= only.
    if not isinstance(op, (ast.Eq, ast.NotEq)):
        raise WhenError("finding_id supports only  ==  and  !=")
    wanted = _literal_str(literal_node, "finding_id")

    def _exists(ctx: Any) -> bool:
        from kratos.adapters.findings_engine import finding_ids

        return any(wanted in finding_ids(f) for f in ctx.findings)

    if isinstance(op, ast.Eq):
        return _exists
    return lambda ctx: not _exists(ctx)


def _split_var_literal(left: ast.AST, right: ast.AST) -> tuple[str, ast.AST, bool]:
    """Return (variable_name, literal_node, swapped) for a comparison, requiring
    exactly one side to be a whitelisted variable and the other a literal."""
    left_var, right_var = _var_name(left), _var_name(right)
    if left_var and not right_var:
        return left_var, right, False
    if right_var and not left_var:
        return right_var, left, True
    raise WhenError(
        "a condition must compare a known field (finding_count / finding_id) with a value")


def _var_name(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) and node.id in _VARIABLES else None


def _literal_int(node: ast.AST, who: str) -> int:
    # A plain int, or a negated int literal (-3 parses as UnaryOp(USub, Constant)).
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub)
            and isinstance(node.operand, ast.Constant)
            and isinstance(node.operand.value, int) and not isinstance(node.operand.value, bool)):
        return -node.operand.value
    raise WhenError(f"{who} must be compared with a whole number, e.g. {who} >= 3")


def _literal_str(node: ast.AST, who: str) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    raise WhenError(f"{who} must be a quoted string, e.g. {who} == 'CORR-SSH-001'")
