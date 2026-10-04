"""
Self-writing tool loop -- Part C review-flag pre-scan.

Part C's approval display is genuinely unredacted (full source shown,
nothing hidden), but an unredacted wall of text still does nothing to
direct a reviewer's attention. Adversarial review testing found exactly
this gap: a hardcoded IP inside a silent event-reclassification branch,
and an invented, overfit substring heuristic in an honestly-described-but-
overstated filter tool, both sailed through an approval prompt unflagged,
caught only because a careful line-by-line read happened to catch them.

This module produces FLAGS, never verdicts, and never blocks anything --
see docs/DESIGN.md's "Self-writing tool loop" section (no force-accept) and
this module's caller (self_approve.py) for why. Every flag is a generic
pattern-match ("this branch affects included/excluded data", "hardcoded
literal used in a filter role") deliberately NOT an attempt to distinguish
malicious from honest-but-narrow -- that distinction needs a human judgment
call, not a heuristic. The goal is directing attention, not replacing it.

AST-based, consistent with this project's existing AST-based validation
(agent/self_write.py::_validate_candidate) -- one ast.parse() call, no
second/regex-based parsing mechanism for structure (regex is only ever used
here for STRING VALUE shape matching -- "does this literal look like an IP"
-- never for finding code structure itself). Deliberately coarse, per this
project's established "structural, not perfect" guard philosophy: false
positives are expected and acceptable; false negatives on the patterns this
module exists to catch are not.
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
    `NAME = "literal"` or `NAME = ["literal", ...]` assignments. This
    indirection matters in practice: one observed candidate stored its
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
    its OWN iterable, not just the outer name_map. This isn't speculative:
    an observed candidate's actual shape,
    `any(sub in message for sub in HEALTH_CHECK_SUBSTRINGS)`, compares `sub`
    (the loop variable) against `message` -- neither operand is
    `HEALTH_CHECK_SUBSTRINGS` itself, so without this comprehension-aware
    resolution the literal "/status" is unreachable from the Compare node
    at all, and this check would silently miss the exact pattern it exists
    to catch.
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


def _loop_call_assigned_names(loop: ast.AST) -> set[str]:
    """Names assigned anywhere in this loop from a direct function/method
    call (`x = some_call(...)`) -- the shape a per-item sub-fetch takes."""
    names: set[str] = set()
    for node in ast.walk(loop):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Call):
                names.add(node.targets[0].id)
    return names


def _branch_has_inclusion_call(stmts: list[ast.stmt]) -> bool:
    """True if this branch either calls an inclusion-affecting method
    (append/add/update/... -- see _INCLUSION_AFFECTING_CALL_NAMES) or does a
    dict/list-item assignment (`some_dict[key] = value`) -- the real
    enumerate_system_cron_jobs draft built its result via subscript
    assignment (`cron_jobs[user] = ...`), not a .append()/.update() call, so
    both shapes must count as "this branch includes something for the
    item"."""
    for stmt in stmts:
        for n in ast.walk(stmt):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _INCLUSION_AFFECTING_CALL_NAMES:
                return True
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Subscript) for t in n.targets):
                return True
    return False


def _if_test_root_name(test: ast.AST) -> str | None:
    """Best-effort: the base variable name an if-test is actually checking
    the truthiness/success of -- `x`, `x.ok`, `not x`, `x is not None` all
    resolve to "x". Deliberately gives up (returns None) on compound
    BoolOp tests (`x and y`) rather than guessing which operand matters."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _if_test_root_name(test.operand)
    if isinstance(test, ast.Name):
        return test.id
    if isinstance(test, ast.Attribute) and isinstance(test.value, ast.Name):
        return test.value.id
    if isinstance(test, ast.Compare) and isinstance(test.left, (ast.Name, ast.Attribute)):
        return _if_test_root_name(test.left)
    return None


def _check_e_silent_drop_on_subfetch_failure(tree: ast.AST) -> list[ReviewFlag]:
    """Added after two independent self-written tools both silently dropped
    an item from their result entirely when a per-item sub-fetch failed,
    instead of including it with a null/error marker -- see
    docs/DESIGN.md's "Self-writing tool loop" section. Distinct from check
    b (inclusion-affecting-branch, which flags ANY loop-nested conditional
    touching the output, with no attempt to characterize why) -- this one
    narrows specifically to the shape that broke twice: `x = some_call(...)`
    immediately
    followed by `if x: <append something for this item>` with NO
    corresponding else, so a falsy/failed `x` silently means the loop
    iteration contributes nothing at all for that item. A genuine,
    deliberate content filter (e.g. `if is_risky_port: results.append(...)`,
    where `is_risky_port` is a boolean expression, not a call result) is
    NOT this shape and is not flagged here -- see check b for that broader,
    non-specific case."""
    flags: list[ReviewFlag] = []
    seen_lines: set[int] = set()
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        call_assigned = _loop_call_assigned_names(loop)
        if not call_assigned:
            continue
        for node in ast.walk(loop):
            if not isinstance(node, ast.If) or node.lineno in seen_lines:
                continue
            root = _if_test_root_name(node.test)
            if root is None or root not in call_assigned:
                continue
            if not _branch_has_inclusion_call(node.body):
                continue
            if _branch_has_inclusion_call(node.orelse):
                continue  # a real else that also includes something -- not a silent drop
            seen_lines.add(node.lineno)
            flags.append(ReviewFlag(
                "silent-item-drop-on-subfetch-failure",
                f'This branch only adds an entry when "{root}" (assigned from a function/method call '
                "earlier in this loop) is truthy, with no else covering the failing case -- if that "
                "sub-step fails or comes back empty for one item, the item vanishes from the result "
                "entirely instead of being reported with a null/error marker. Confirm this is a "
                "deliberate filter, not an accidental drop of a failed per-item sub-fetch.",
                node.lineno,
            ))
    return flags


_REMOTE_CALLS = {"run_remote_command", "run_remote_script"}


def _remote_result_names(func: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            called = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None
            if called in _REMOTE_CALLS:
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def _ok_checks(test: ast.AST, name: str) -> tuple[bool, bool]:
    """(tests `name.ok` positively, tests it negatively / its returncode)."""
    positive = negative = False
    for node in ast.walk(test):
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = node.operand
            if isinstance(inner, ast.Attribute) and inner.attr == "ok" and \
                    isinstance(inner.value, ast.Name) and inner.value.id == name:
                negative = True
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == name:
            if node.attr == "returncode":
                negative = True
    for node in ast.walk(test):
        if isinstance(node, ast.Attribute) and node.attr == "ok" and \
                isinstance(node.value, ast.Name) and node.value.id == name:
            positive = True
    return positive and not negative, negative


def _is_empty_value(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return all(_is_empty_value(v) for v in node.values)
    if isinstance(node, ast.Constant):
        return node.value in (None, 0, "", False)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("list", "dict", "set"):
        return not node.args
    return False


def _check_f_failed_read_reported_as_empty(tree: ast.AST) -> list[ReviewFlag]:
    """Added after two kept target-facing tools turned a FAILED SSH read into
    an ordinary empty result ([] / users=[]) -- an investigation then reported
    "nothing is listening" on a box running sshd. Two shapes: an
    `if not result.ok: return <empty>`, and an `if result.ok ...:` with no
    branch anywhere handling the failed case (it falls through to the normal,
    empty return)."""
    flags: list[ReviewFlag] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for name in _remote_result_names(func):
            ifs = [n for n in ast.walk(func) if isinstance(n, ast.If)]
            handles_failure = False
            positive_only: list[ast.If] = []
            for node in ifs:
                pos, neg = _ok_checks(node.test, name)
                if neg:
                    body_return = next((st for st in node.body if isinstance(st, ast.Return)), None)
                    if body_return is not None and _is_empty_value(body_return.value):
                        flags.append(ReviewFlag(
                            "failed-read-returned-as-empty",
                            f'When the remote command fails ("{name}.ok" is false) this returns an EMPTY result, '
                            "which the investigation will read as \"nothing found\". A failed read should return "
                            'an error ({"status": "error", "observation": ...}) so it is never mistaken for a '
                            "clean answer.",
                            node.lineno,
                        ))
                    handles_failure = True
                elif pos and not node.orelse:
                    positive_only.append(node)
            if not handles_failure and positive_only:
                flags.append(ReviewFlag(
                    "failed-read-falls-through-as-empty",
                    f'Only the success case of "{name}" is handled -- if the remote command fails, the tool '
                    "skips parsing and returns its normal (empty) result, so a failed read looks like "
                    "\"nothing found\". Add an explicit error return for the failed case.",
                    positive_only[0].lineno,
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
    """Hardcoded literal used in a filter/match role, inside a function
    whose own description/docstring uses filtering language -- targets an
    honestly-disclosed but narrow, invented filter heuristic."""
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


# `for f in /some/dir/*` (or `ls /some/dir`) with no sudo, in a script that reads with
# sudo elsewhere. Seen live (demo pass 5): `for f in /var/spool/cron/crontabs/*; do sudo -n
# cat "$f"` -- the folder is root-only, the pattern silently expands to nothing, and the
# tool reports "no crontabs" on a box that may have some. Advisory: some folders ARE
# listable while their files are root-only, so this is a flag, not a rejection.
_UNPRIVILEGED_LISTING_RE = re.compile(
    r"^(?!.*\bsudo\b).*?(?:\bfor\s+\w+\s+in\s+(/[^\s;*\"']+)/\*|\bls\s+(?:-\w+\s+)*(/[^\s;|\"']+))",
    re.MULTILINE)


def _check_g_unprivileged_listing(tree: ast.AST) -> list[ReviewFlag]:
    flags: list[ReviewFlag] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str) and "sudo" in node.value):
            continue
        for m in _UNPRIVILEGED_LISTING_RE.finditer(node.value):
            folder = m.group(1) or m.group(2)
            flags.append(ReviewFlag(
                "folder-listed-without-sudo",
                f"{folder} is listed without sudo, but the script needs sudo to read files. If that folder is "
                "readable only by root, the list silently comes back empty and the tool reports \"nothing found\". "
                f"List it with sudo too (e.g. sudo -n find {folder} -type f).",
                getattr(node, "lineno", None),
            ))
    return flags


def scan_review_flags(source_code: str) -> list[ReviewFlag]:
    """
    Public entry point. Parses source_code ONCE and runs every check
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
    flags.extend(_check_e_silent_drop_on_subfetch_failure(tree))
    flags.extend(_check_f_failed_read_reported_as_empty(tree))
    flags.extend(_check_g_unprivileged_listing(tree))
    flags.extend(_check_d_description_coverage(tree, description, docstring))
    return flags


def format_review_flags_for_display(flags: list[ReviewFlag]) -> str:
    if not flags:
        return (
            "(no static review flags raised -- this is a coarse pattern-scan, not a correctness "
            "guarantee; still read the source below)"
        )
    return "\n".join(f"- {f.format()}" for f in flags)


# Plain-English gloss per flag category (A7 -- brief item 4, "review-flags
# readability for non-experts"). The technical message (ReviewFlag.format())
# stays available; this adds a "what this means / what to check" line a
# non-technical reviewer can act on. Additive: format_review_flags_for_display
# above is unchanged, so any caller relying on the terse form is unaffected.
_PLAIN_GLOSS: dict[str, str] = {
    "hardcoded-ip-in-conditional": (
        "A specific IP address is written into the tool's logic. Check it isn't quietly treating "
        "one machine differently from the rest."
    ),
    "credential-like-literal": (
        "Something shaped like a password, key, or token is written into the code. Make sure it "
        "isn't a hidden credential baked into the tool."
    ),
    "inclusion-affecting-branch": (
        "A decision inside a loop changes what ends up in the results. Check that nothing you'd "
        "want to see is being left out."
    ),
    "silent-item-drop-on-subfetch-failure": (
        "If one lookup fails, an item may vanish from the results entirely. A security tool should "
        "still LIST it (marked unknown), not hide it. Check this branch."
    ),
    "invented-filter-criterion": (
        "The tool filters or excludes things using a specific value it chose on its own. Check that "
        "filter really matches what the tool's description promises."
    ),
    "failed-read-returned-as-empty": (
        "If reading the machine fails, the tool reports \"nothing found\" instead of an error. Check "
        "it says the read failed, so a failure is never mistaken for a clean result."
    ),
    "failed-read-falls-through-as-empty": (
        "Only the successful read is handled; a failed read quietly becomes \"nothing found\". Check "
        "there is an error for the failed case."
    ),
    "folder-listed-without-sudo": (
        "A folder is listed without admin rights while its files are read with them. If only root can "
        "list that folder, the tool will find nothing and say so. Check how the folder is listed."
    ),
    "description-coverage": (
        "The tool's description may not mention everything its code actually does. Check the "
        "description is honest about all of its behavior."
    ),
}


def format_review_flags_plain(flags: list[ReviewFlag]) -> str:
    """Non-expert-friendly rendering: a plain 'what to check' per flag, with the
    precise technical detail kept underneath. Used by the approval display so a
    reviewer who doesn't read Python fluently still knows what to look at."""
    if not flags:
        return (
            "No automatic warnings were raised. (This is a quick scan, not a guarantee -- still "
            "look over what the tool does below.)"
        )
    lines = ["Kratos noticed a few things worth checking before you keep this tool:"]
    # One bullet per kind of warning: the same advice three times in a row (one per
    # line it applies to) reads as noise to a reviewer and hides the other warnings.
    groups: dict[tuple[str, str], list[ReviewFlag]] = {}
    for f in flags:
        groups.setdefault((f.category, f.message), []).append(f)
    for (category, message), same in groups.items():
        gloss = _PLAIN_GLOSS.get(category, "Worth a look.")
        nums = [str(f.line) for f in same if f.line is not None]
        loc = f" (line{'s' if len(nums) > 1 else ''} {', '.join(nums)})" if nums else ""
        lines.append(f"\n• {gloss}{loc}")
        lines.append(f"    ↳ technical detail: {message}")
    return "\n".join(lines)
