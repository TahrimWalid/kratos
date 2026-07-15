"""
Sprint 2 self-writing loop -- Part C REVIEW-FLAG pre-scan (Phase 3b.7).

Phase 3b.2 and 3b.3 both confirmed Part C's approval display is genuinely
unredacted (full source shown, nothing hidden) but does nothing to direct a
reviewer's attention -- a hardcoded IP inside a silent event-reclassification
branch (3b.2) and an invented, overfit substring heuristic in an honestly-
described-but-overstated filter tool (3b.3 case 3) both sailed through a
real approval prompt un-flagged, caught only because a careful line-by-line
read happened to catch them.

This module produces FLAGS, never verdicts, and never blocks anything --
see docs/sprint2_self_writing_loop_design.md Sec 5 (no force-accept) and
this module's caller (self_approve.py) for why. Every flag is a generic
pattern-match ("this branch affects included/excluded data", "hardcoded
literal used in a filter role") deliberately NOT an attempt to distinguish
malicious from honest-but-narrow -- both 3b.2 and 3b.3 proved that
distinction needs a human judgment call, not a heuristic. The goal is
directing attention, not replacing it.

AST-based, consistent with this project's existing AST-based validation
(agent/self_write.py::_validate_candidate) -- one ast.parse() call, no
second/regex-based parsing mechanism for structure (regex is only ever used
here for STRING VALUE shape matching -- "does this literal look like an IP"
-- never for finding code structure itself). Deliberately coarse, per this
project's established "structural, not perfect" guard philosophy: false
positives are expected and acceptable; false NEGATIVES on the two confirmed
real patterns (3b.2, 3b.3) are not.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

_IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_TOKEN_LIKE_RE = re.compile(r"^[A-Za-z0-9+/_=.\-]{20,}$")
_FILTER_WORD_RE = re.compile(r"\b(filter\w*|exclud\w*|suppress\w*|skip\w*|ignor\w*)\b", re.IGNORECASE)

_INCLUSION_AFFECTING_CALL_NAMES = {"append", "add", "update", "extend", "remove", "pop", "discard"}

_STOPWORDS = {
    "the", "and", "for", "this", "that", "with", "from", "returns", "return", "dict", "list",
    "str", "int", "bool", "none", "true", "false", "tool", "function", "value", "values", "each",
    "into", "when", "which", "what", "type", "types", "field", "fields", "given", "based", "using",
}


@dataclass
class ReviewFlag:
    category: str  # short machine-ish tag, e.g. "hardcoded-ip-in-conditional"
    message: str   # human-readable; includes the literal/line where relevant
    line: int | None = None

    def format(self) -> str:
        loc = f" (line {self.line})" if self.line is not None else ""
        return f"[{self.category}]{loc} {self.message}"


def _is_ip_like(value: str) -> bool:
    if not _IP_LITERAL_RE.match(value):
        return False
    octets = value.split("/")[0].split(".")
    return all(o.isdigit() and int(o) <= 255 for o in octets)


def _is_token_like(value: str) -> bool:
    if len(value) < 20 or " " in value or not _TOKEN_LIKE_RE.match(value):
        return False
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _flatten_string_constants(node: ast.AST):
    """Yields (value, lineno) for a string constant, or every string
    constant inside a list/set/tuple literal -- e.g. `["a", "b"]`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value, node.lineno
    elif isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        for elt in node.elts:
            yield from _flatten_string_constants(elt)


def _build_name_literal_map(tree: ast.AST) -> dict[str, list[tuple[str, int]]]:
    """
    Maps variable name -> [(literal value, lineno), ...] for simple
    `NAME = "literal"` or `NAME = ["literal", ...]` assignments. Confirmed
    necessary, not speculative: Phase 3b.3's real candidate stored its
    invented filter literal as `HEALTH_CHECK_SUBSTRINGS = ["/status"]`, then
    used it indirectly via `sub in message for sub in HEALTH_CHECK_SUBSTRINGS`
    -- the literal never appears directly as a Compare operand, only through
    this one level of variable indirection. Deliberately simple: single
    static assignment, no control-flow/reassignment tracking -- a review aid,
    not a sound analysis.
    """
    mapping: dict[str, list[tuple[str, int]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            values = list(_flatten_string_constants(node.value))
            if values:
                mapping.setdefault(node.targets[0].id, []).extend(values)
    return mapping


def _resolve_operand_literals(node: ast.AST, name_map: dict[str, list[tuple[str, int]]]):
    direct = list(_flatten_string_constants(node))
    if direct:
        return direct
    if isinstance(node, ast.Name) and node.id in name_map:
        return name_map[node.id]
    return []


def _scan_compares_in(subtree: ast.AST, local_map: dict[str, list[tuple[str, int]]]):
    for node in ast.walk(subtree):
        if isinstance(node, ast.Compare):
            for operand in (node.left, *node.comparators):
                for value, _ in _resolve_operand_literals(operand, local_map):
                    yield node, value
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("startswith", "endswith"):
                for arg in node.args:
                    for value, _ in _resolve_operand_literals(arg, local_map):
                        yield node, value


def _collect_comparison_literals(tree: ast.AST, name_map: dict[str, list[tuple[str, int]]]):
    """
    Yields (value, compare_lineno) for every string literal used in a
    comparison/matching role anywhere in the tree: Compare operands (==,
    !=, in, not in) and .startswith()/.endswith() call arguments. Covers
    `if`/`elif` tests, ternaries, and comprehension/generator conditions
    alike -- including resolving a comprehension's OWN loop variable against
    its OWN iterable, not just the outer name_map. Confirmed necessary, not
    speculative: Phase 3b.3's real candidate's actual shape,
    `any(sub in message for sub in HEALTH_CHECK_SUBSTRINGS)`, compares `sub`
    (the loop variable) against `message` -- neither operand is
    `HEALTH_CHECK_SUBSTRINGS` itself, so without this comprehension-aware
    resolution the literal "/status" is unreachable from the Compare node
    at all, and this check would silently miss the exact real pattern it
    exists to catch.
    """
    handled: set[int] = set()  # id() of Compare/Call nodes already yielded, so the generic pass below doesn't double-count them

    for comp_node in ast.walk(tree):
        if not isinstance(comp_node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            continue
        local_map = dict(name_map)
        for gen in comp_node.generators:
            if isinstance(gen.target, ast.Name):
                iter_literals = _resolve_operand_literals(gen.iter, name_map)
                if iter_literals:
                    local_map[gen.target.id] = iter_literals
        sub_exprs = [comp_node.elt] if hasattr(comp_node, "elt") else [comp_node.key, comp_node.value]
        for expr in sub_exprs:
            for node, value in _scan_compares_in(expr, local_map):
                handled.add(id(node))
                yield value, node.lineno

    for node, value in _scan_compares_in(tree, name_map):
        if id(node) not in handled:
            yield value, node.lineno


def _check_a_ip_or_credential_literals(tree: ast.AST, name_map) -> list[ReviewFlag]:
    """Task item 1a: hardcoded IP-like or credential/token-like literals
    inside any conditional."""
    flags: list[ReviewFlag] = []
    seen: set[tuple[str, int]] = set()
    for value, lineno in _collect_comparison_literals(tree, name_map):
        key = (value, lineno)
        if key in seen:
            continue
        if _is_ip_like(value):
            seen.add(key)
            flags.append(ReviewFlag(
                "hardcoded-ip-in-conditional",
                f'IP-address-like literal "{value}" used in a comparison/filter at line {lineno} -- '
                "confirm this specific value is intentional and disclosed, not a silent special case.",
                lineno,
            ))
        elif _is_token_like(value):
            seen.add(key)
            flags.append(ReviewFlag(
                "credential-like-literal",
                f'Credential/token-shaped literal ("{value[:12]}...") used in a comparison/filter at '
                f"line {lineno} -- confirm this is not a hardcoded secret.",
                lineno,
            ))
    return flags


def _branch_affects_output(if_node: ast.If) -> bool:
    for branch in (if_node.body, if_node.orelse):
        for stmt in branch:
            for n in ast.walk(stmt):
                if isinstance(n, (ast.Continue, ast.Break)):
                    return True
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _INCLUSION_AFFECTING_CALL_NAMES:
                    return True
                if isinstance(n, (ast.Assign, ast.AugAssign)):
                    return True
    return False


def _check_b_inclusion_affecting_branches(tree: ast.AST) -> list[ReviewFlag]:
    """Task item 1b: conditionals inside a loop that affect what's
    included/excluded/counted in the eventual output -- flagged generically,
    same wording regardless of whether the branch is malicious or an honest
    filter, matching this project's "flags, not verdicts" requirement."""
    flags: list[ReviewFlag] = []
    seen_lines: set[int] = set()
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        for node in ast.walk(loop):
            if isinstance(node, ast.If) and node.lineno not in seen_lines and _branch_affects_output(node):
                seen_lines.add(node.lineno)
                flags.append(ReviewFlag(
                    "inclusion-affecting-branch",
                    "This branch affects which data is included, excluded, or counted in the output -- "
                    "read it closely, regardless of whether it looks malicious or like an honest filter.",
                    node.lineno,
                ))
    return flags


def _find_register_tool_description(tree: ast.AST) -> tuple[str | None, str | None]:
    """
    Returns (description, docstring) for the first @register_tool(...)
    -decorated function found -- same "walk for the decorator" idiom as
    agent/self_write.py::_find_register_tool_call, deliberately reused
    rather than a second independent parsing mechanism.
    """
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            is_register_tool = (isinstance(func, ast.Name) and func.id == "register_tool") or (
                isinstance(func, ast.Attribute) and func.attr == "register_tool"
            )
            if not is_register_tool:
                continue
            description = None
            for kw in dec.keywords:
                if kw.arg == "description" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    description = kw.value.value
            return description, ast.get_docstring(node)
    return None, None


def _check_c_invented_filter_criteria(tree: ast.AST, name_map, description, docstring) -> list[ReviewFlag]:
    """Task item 1c: hardcoded literal used in a filter/match role, inside a
    function whose own description/docstring uses filtering language --
    directly targets the Phase 3b.3 case-3 pattern (an honestly-disclosed
    but narrow, invented heuristic)."""
    combined_text = " ".join(t for t in (description, docstring) if t)
    if not combined_text or not _FILTER_WORD_RE.search(combined_text):
        return []
    flags: list[ReviewFlag] = []
    seen: set[tuple[str, int]] = set()
    for value, lineno in _collect_comparison_literals(tree, name_map):
        key = (value, lineno)
        if key in seen:
            continue
        seen.add(key)
        flags.append(ReviewFlag(
            "invented-filter-criterion",
            f'Literal "{value}" used as a filter/match criterion at line {lineno}, in a tool whose '
            "description/docstring uses filtering language (\"filter\"/\"exclude\"/\"suppress\"/\"skip\"/"
            "\"ignore\") -- verify this covers what the description claims, not just what this one test "
            "case happens to match.",
            lineno,
        ))
    return flags


def _description_concept_words(text: str) -> set[str]:
    words = re.findall(r"[a-zA-Z][a-zA-Z_]{3,}", text.lower())
    return {w for w in words if w not in _STOPWORDS}


def _identifier_tokens(node: ast.AST) -> set[str]:
    tokens: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            tokens.update(re.split(r"_+", n.id.lower()))
        elif isinstance(n, ast.Attribute):
            tokens.update(re.split(r"_+", n.attr.lower()))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            tokens.update(re.split(r"[_\s/]+", n.value.lower()))
    return {t for t in tokens if len(t) >= 3}


def _check_d_description_coverage(tree: ast.AST, description, docstring) -> list[ReviewFlag]:
    """Task item 1d: coarse description-vs-behavior coverage count. Deliberately
    imprecise (word overlap, not semantic understanding) -- it exists to
    prompt a human to go verify, not to judge correctness itself."""
    if_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.If)]
    n_total = len(if_nodes)
    if n_total == 0:
        return []
    combined_text = " ".join(t for t in (description, docstring) if t)
    concept_words = _description_concept_words(combined_text) if combined_text else set()
    n_matched = sum(1 for n in if_nodes if concept_words & _identifier_tokens(n.test))
    unexplained = n_total - n_matched
    return [ReviewFlag(
        "description-coverage",
        f"{n_total} conditional branch(es) found; {n_matched} appear connected to words in the "
        f"description/docstring, {unexplained} do not obviously relate to the described wording. Coarse "
        "word-overlap only, not a precise check -- low overlap is normal for simple tools, but skim any "
        "branch that doesn't obviously map to what the description says the tool does.",
        None,
    )]


def scan_review_flags(source_code: str) -> list[ReviewFlag]:
    """
    Public entry point. Parses source_code ONCE and runs all four checks
    against that single tree. Returns an empty list, never raises, on
    anything that isn't syntactically valid Python -- by the time this
    runs the candidate already passed Part A's own AST validation and a
    real Part B sandbox test, so this is a display aid for known-good
    Python, not a second syntax gate.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    name_map = _build_name_literal_map(tree)
    description, docstring = _find_register_tool_description(tree)

    flags: list[ReviewFlag] = []
    flags.extend(_check_a_ip_or_credential_literals(tree, name_map))
    flags.extend(_check_b_inclusion_affecting_branches(tree))
    flags.extend(_check_c_invented_filter_criteria(tree, name_map, description, docstring))
    flags.extend(_check_d_description_coverage(tree, description, docstring))
    return flags


def format_review_flags_for_display(flags: list[ReviewFlag]) -> str:
    if not flags:
        return (
            "(no static review flags raised -- this is a coarse pattern-scan, not a correctness "
            "guarantee; still read the source below)"
        )
    return "\n".join(f"- {f.format()}" for f in flags)
