"""
Guided evo-loop -- an approachable surface over the write -> test -> approve
-> keep pipeline (see docs/DESIGN.md's "Self-writing tool loop" section).

This module is UI-AGNOSTIC by design: it drives the guided build through a
GuidedPrompter abstraction (ask a question / show something), so the SAME core
logic backs the mk2 Textual TUI today and a programmatic "build the missing
tool" hand-off from the presets flow. That hand-off threads
run_guided_build()'s GuidedBuildResult (kept tool name + requires_approval,
or a clean decline) back into its own pipeline draft.

What it does NOT do -- the invariants that never move:
  - It does not weaken the human-authored-test principle: the pytest harness
    still defines "correct"; an LLM-drafted harness is only ever SHOWN for
    review and never trusted unedited (saving is an explicit step).
  - It does not touch no-force-accept: the keep decision still fires INSIDE
    run_self_write_loop -> request_keep_approval, unchanged.
  - It does not touch the sandbox no-network guarantee (Part B).
  - It only wraps the SURFACE (pre-loop framing + a plain-English review of what
    the test checks + post-loop recovery guidance). The pipeline (Parts A-D) is
    called unmodified.

The plain-English harness "claims" (describe_harness_claims) are extracted from
the harness's own AST -- deliberately NOT an LLM summary. A summary could drift
from what the test actually asserts, silently reopening the exact rubber-stamp
risk the review-flags mechanism exists to close; a non-expert reviewing meaning
must be shown the REAL meaning. When an assertion is a human-authored message
string, that message IS the claim (the human's own words); when it's a
recognized structural shape it's glossed from the AST; anything unrecognized is
shown verbatim, never invented.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from kratos import paths as _paths
from kratos.agent import console as _console
from kratos.llm_interface import agent_chat
from kratos.llm_config import MAX_TOKENS

# ---------------------------------------------------------------------------
# Pure helpers (relocated here from cli/repl.py so the UI-agnostic core owns
# them -- repl.py re-exports these names for its own callers and the existing
# tests, so `kratos.cli.repl._draft_evolve_harness` etc. still resolve).
# ---------------------------------------------------------------------------

_EVOLVE_SLUG_MAX_WORDS = 4


def _slugify_name_hint(name_hint: str) -> str:
    words = re.findall(r"[a-z0-9]+", name_hint.lower())[:_EVOLVE_SLUG_MAX_WORDS]
    return "_".join(words) or "new_tool"


def _build_evolve_harness_template(slug: str, goal: str) -> str:
    """A starter pytest harness shown (never written to disk automatically
    -- see the caller) when the suggested/given path doesn't exist. Mirrors
    tests/self_write_harnesses/test_evolve_verification_ping.py's real shape
    exactly so what's shown is this project's actual convention, not a generic
    pytest example. The TODO'd assertion is deliberately trivial/obviously
    incomplete, not a plausible-looking real check -- this is scaffolding to
    save typing the boilerplate, not something that should ever be run against
    evo-loop unedited."""
    tool_name = slug or "new_tool"
    return f'''"""
Test harness for "{tool_name}" -- {goal}

TODO: replace the trivial assertion in test_{tool_name}_behaves_correctly
below with real checks against registered_handler's actual return shape.
This file is what defines "correct" for the tool evo-loop will write --
edit it BEFORE running /evolve again.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "{tool_name}"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip(
            "CANDIDATE_MODULE_PATH not set -- this harness is meant to be pointed at a staged "
            "candidate (by Part B) or a reference implementation (manual sanity check)."
        )
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY, (
        f"Candidate did not register a tool named '{{TOOL_NAME}}' via @register_tool -- "
        f"found instead: {{sorted(TOOL_REGISTRY.keys())}}"
    )
    return TOOL_REGISTRY[TOOL_NAME].handler


def test_{tool_name}_behaves_correctly(registered_handler):
    # TODO: call registered_handler(...) with real/representative arguments
    # and assert on its actual return shape -- this is the part that
    # defines "correct", not a placeholder to leave as-is.
    result = registered_handler()
    assert isinstance(result, dict)
'''


_EVOLVE_HARNESS_DRAFT_SYSTEM_PROMPT = '''You are drafting a PYTEST TEST HARNESS for a new Kratos tool that does not exist yet -- you are NOT writing the tool's implementation. This test file is what will later define "correct" for whatever code gets written against it, so its assertions must be concrete and specific to the goal given to you, not generic placeholders.

Kratos's self-writing pipeline loads a candidate tool module and exposes its path via the CANDIDATE_MODULE_PATH environment variable. Every harness in this project follows the EXACT same shape -- match it precisely, including the parts that look like fixed boilerplate:

```python
"""
<one or two sentences: what this test validates and why>
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "<the exact tool name given to you>"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip(
            "CANDIDATE_MODULE_PATH not set -- this harness is meant to be pointed at a staged "
            "candidate (by Part B) or a reference implementation (manual sanity check)."
        )
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY, (
        f"Candidate did not register a tool named '{TOOL_NAME}' via @register_tool -- "
        f"found instead: {sorted(TOOL_REGISTRY.keys())}"
    )
    return TOOL_REGISTRY[TOOL_NAME].handler


def test_<something_specific>(registered_handler):
    result = registered_handler(<real, representative arguments if the tool takes any>)
    <concrete, specific assertions on result's actual expected shape>
```

TARGET-FACING GOALS (the idea is about data on the MONITORED device Kratos watches over SSH --
users, processes, files, config, logs living THERE, not something Kratos already collected into
a local file): the candidate you're testing will reach the target via
`kratos.adapters.ssh_remote.run_remote_command`/`run_remote_script`. The sandbox that runs this
test has NO NETWORK ACCESS AT ALL, by design -- an unmocked call would hang or fail regardless of
whether the candidate's logic is correct. For a target-facing goal, your harness MUST mock the
SSH layer with realistic fake output instead of calling registered_handler() directly:

```python
from unittest.mock import patch
from kratos.adapters.ssh_remote import SSHResult

def test_<something_specific>(registered_handler):
    fake_output = "<realistic fake command output matching what the real target would return>"
    with patch(
        "kratos.adapters.ssh_remote.run_remote_command",
        return_value=SSHResult(ok=True, returncode=0, stdout=fake_output, stderr=""),
    ):
        result = registered_handler()
    <concrete, specific assertions on result's actual expected shape, reasoning about how the
    candidate should have PARSED fake_output above>
```

Patch `kratos.adapters.ssh_remote.run_remote_command` (module-qualified, exactly as shown) --
NOT some other path -- this works regardless of what name the candidate imports it under,
because it patches the function where ssh_remote.py itself defines it. Use `run_remote_script`
instead if the goal clearly needs a multi-line script rather than one command. Only do this for
a genuinely target-facing goal -- a goal about data Kratos already has locally (existing scan/log
files under data_dir) needs no mocking at all, call registered_handler() directly as shown in the
main template above.

RULES:
- Keep the CANDIDATE_MODULE_PATH/_load_candidate/registered_handler fixture EXACTLY as shown -- that machinery is fixed, not yours to redesign.
- TOOL_NAME must be exactly the tool name given to you, nothing else.
- Write 1-3 test functions with REAL, SPECIFIC assertions reasoning about what this tool's return value should actually contain, based on the goal -- e.g. if the goal is about listing users, assert on a real, named key you'd expect (like checking for a "sudo_members" key and that it's a list), not just "assert isinstance(result, dict)".
- Prefer to attach a short, plain-English message to each assertion (e.g. `assert "users" in result, "Result must list each user with sudo access"`) -- a non-technical reviewer reads those messages to understand what the test is really checking, so make them a faithful description of the assertion, not a restatement of the code.
- You do NOT know the real implementation yet -- you are proposing a REASONABLE interface (return dict shape) for it to be judged against. A human will review and adjust this before it's ever used, so make a concrete, defensible choice rather than a vague one.
- If the goal is target-facing (see above), mock the SSH layer as shown -- do not write a harness that will hang or fail in a no-network sandbox regardless of whether the candidate is correct.
- Fake the tool's ONE remote call with a fixed reply (`return_value=SSHResult(...)`). NEVER use a side_effect function that looks at the command or script text to decide what to return -- that ties the test to one way of writing the command and a correct tool fails it. When the tool needs several files, put them all in that one fake output, each after a marker line like `=== /etc/crontab ===` (the tool is told to print exactly such markers).
- Output ONLY the Python source code -- no markdown fences, no commentary before or after.
'''


def fragile_ssh_fakes(code: str) -> list[str]:
    """Fake SSH functions in a drafted test that decide their reply from the command
    text (e.g. `if "ls" in script: ...; path = script.split("cat ")[-1]`). Such a fake
    only accepts one particular way of writing the command, so a correct tool that
    reads everything in one script fails every attempt (seen live). A fixed
    return_value, or a list of replies, is fine."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    found: list[str] = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and call.args and isinstance(call.args[0], ast.Constant)
                and "ssh_remote.run_remote" in str(call.args[0].value)):
            continue
        for kw in call.keywords:
            if kw.arg != "side_effect":
                continue
            fn = kw.value
            if isinstance(fn, ast.Lambda):
                args, body, label = fn.args, fn.body, "a lambda"
            elif isinstance(fn, ast.Name) and fn.id in funcs:
                args, body, label = funcs[fn.id].args, funcs[fn.id], fn.id
            else:
                continue
            params = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
            params |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
            if params & {n.id for n in ast.walk(body) if isinstance(n, ast.Name)}:
                found.append(label)
    return found


_FRAGILE_FAKE_FEEDBACK = (
    "\n\nYour previous draft faked SSH with a side_effect function ({names}) that reads the command "
    "text to decide what to return. Rewrite it: fake the tool's ONE remote call with a fixed "
    "return_value=SSHResult(...); if several files are needed, put them all in that one output, each "
    "after a marker line like '=== /path ==='. Keep the same assertions."
)


def _draft_evolve_harness(console, slug: str, goal: str) -> str | None:
    """Drafts a real, idea-specific starter harness via the LLM -- reuses
    agent_chat (the same query mechanism agent/loop.py and agent/self_write.py's
    own write step already use) and self_write.py's own _extract_code
    fence-stripping. Returns None (never raises) on ANY failure -- LLM
    unavailable, invalid Python, or a TOOL_NAME that doesn't match what was
    actually asked for -- so the caller falls back to the plain static template
    rather than showing or saving something broken. The TOOL_NAME check is a
    real structural guard, not just a prompt instruction. This function only
    ever returns text -- it never writes to disk itself."""
    from kratos.agent.self_write import _extract_code

    user_prompt = f"Tool name: {slug}\nGoal: {goal}\n\nWrite the pytest harness now."
    raw = agent_chat(
        system_prompt=_EVOLVE_HARNESS_DRAFT_SYSTEM_PROMPT, user_prompt=user_prompt, max_tokens=MAX_TOKENS
    )
    if raw is None:
        _console.render_error(
            console, "Could not reach the LLM to draft a harness -- showing a plain starter template instead."
        )
        return None

    code = _extract_code(raw)
    try:
        ast.parse(code)
    except SyntaxError as e:
        _console.render_error(
            console, f"The drafted harness wasn't valid Python ({e}) -- showing a plain starter template instead."
        )
        return None

    if f'TOOL_NAME = "{slug}"' not in code and f"TOOL_NAME = '{slug}'" not in code:
        _console.render_error(
            console,
            f"The drafted harness didn't use TOOL_NAME = {slug!r} as required -- showing a plain "
            "starter template instead.",
        )
        return None

    fragile = fragile_ssh_fakes(code)
    if fragile:  # one redraft with the reason; a fake that reads the command fails correct tools
        redraft = _redraft_without_fragile_fakes(_EVOLVE_HARNESS_DRAFT_SYSTEM_PROMPT, user_prompt, slug, fragile)
        if redraft is not None:
            return redraft
        _console.render_note(
            console, "Note: this test's fake SSH reply depends on the exact command the tool runs, so a "
                     "correct tool may still fail it. Consider editing it to return one fixed output.")
    return code


def _redraft_without_fragile_fakes(system_prompt: str, user_prompt: str, tool_name: str,
                                   fragile: list[str]) -> str | None:
    """Ask once more, saying why; return the new draft only if it passes every guard."""
    from kratos.agent.self_write import _extract_code

    raw = agent_chat(system_prompt=system_prompt,
                     user_prompt=user_prompt + _FRAGILE_FAKE_FEEDBACK.format(names=", ".join(fragile)),
                     max_tokens=MAX_TOKENS)
    if raw is None:
        return None
    code = _extract_code(raw)
    try:
        ast.parse(code)
    except SyntaxError:
        return None
    if f'TOOL_NAME = "{tool_name}"' not in code and f"TOOL_NAME = '{tool_name}'" not in code:
        return None
    return None if fragile_ssh_fakes(code) else code


def _suggest_evolve_tool_name(goal: str) -> str | None:
    """LLM-based tool name suggestion. Returns None (never raises) on any LLM
    failure so the caller falls back to the mechanical slug rather than blocking
    on a naming step that couldn't complete. Reuses _slugify_name_hint to
    sanitize the response, regardless of whatever extra formatting the LLM's raw
    answer might include."""
    system_prompt = (
        "You name new tools for Kratos, a security investigation assistant. Given a "
        "short goal describing what a new tool should do, respond with EXACTLY ONE good, "
        "specific, descriptive tool name in snake_case Python-identifier form (lowercase "
        "letters, digits, underscores only; 2-5 words joined by underscores) -- nothing else, "
        "no explanation, no punctuation beyond underscores, no quotes, no markdown."
    )
    raw = agent_chat(system_prompt=system_prompt, user_prompt=f"Goal: {goal}\n\nTool name:", max_tokens=32)
    if raw is None:
        return None
    return _slugify_name_hint(raw) or None


_CLARIFY_OTHER = "__other__"

# Cost guard (review finding #3): assess_intake_clarity is a real, guaranteed
# extra LLM call on top of everything else a guided build already makes
# (naming, harness drafting, the write loop itself) -- worth paying for a
# genuinely short/thin idea, not worth paying for one that's already long and
# descriptive, since those are very unlikely to be judged "too thin" anyway.
# Word count, not character count, so punctuation/formatting doesn't skew it.
# Deliberately simple (no NLP) -- same "editable default, not a clever guess"
# philosophy as _slugify_name_hint's own word cap.
_CLARIFY_INTAKE_SKIP_WORD_COUNT = 25


def _maybe_clarify_idea(goal: str, prompter: "GuidedPrompter") -> str:
    """docs/clarify_expansion.md lever 3 -- "evolve idea" is named there as a
    thin-input entry point. One quick LLM check (agent/clarify_intake.py) on
    whether the idea is genuinely too thin/forked to build well; if so, ask
    ONE clarifying question through the SAME GuidedPrompter abstraction every
    other guided-build question already uses (works headlessly and in mk2
    alike). NEVER blocks and NEVER cancels the build: a declined/unanswered/
    failed check just returns `goal` unchanged, exactly like a no-provider
    clarify degrades to 'proceed' in agent/loop.py."""
    if len(goal.split()) >= _CLARIFY_INTAKE_SKIP_WORD_COUNT:
        return goal

    from kratos.agent.clarify_intake import assess_intake_clarity

    try:
        clarify = assess_intake_clarity(goal, purpose="a new Kratos tool to build")
    except Exception:  # noqa: BLE001 -- must never block the build
        clarify = None
    if clarify is None:
        return goal

    options: list[tuple[str, str]] = []
    for o in clarify.options:
        label = str(o.get("label", ""))
        if o.get("explanation"):
            label += f" — {o['explanation']}"
        if o.get("recommended"):
            label += "  (recommended)"
        options.append((str(o.get("label", "")), label))
    options.append((_CLARIFY_OTHER, "Something else… (type my own answer)"))

    choice = prompter.ask_choice(clarify.question, options, subtitle=f"Your idea: {goal}")
    if choice is None:
        return goal  # declined -- proceed with the original idea, unchanged
    if choice == _CLARIFY_OTHER:
        typed = prompter.ask_text("Your answer", clarify.question)
        if not typed or not typed.strip():
            return goal
        choice = typed.strip()
    return f"{goal}\n\n(Clarification -- {clarify.question}: {choice})"


# ---------------------------------------------------------------------------
# Plain-English harness claims -- AST-grounded, never an LLM summary.
# ---------------------------------------------------------------------------

@dataclass
class HarnessClaims:
    """What a harness actually checks, in plain English, extracted from its AST.

    claims:          human-readable descriptions of each assertion (a
                     human-authored assert message where present, else a gloss
                     of the recognized structural shape).
    verbatim_checks: raw source of any assertion we could not confidently gloss
                     -- shown as-is rather than fabricating a description.
    assumed_target_output: for a target-facing (SSH-mocked) harness, the fake
                     command output the test PRETENDS the target returns. This
                     is the single most useful thing for spotting a mock-vs-live
                     gap ("wait, that assumes root is always in the sudo group").
    is_target_facing: True if the harness mocks the ssh_remote layer.
    parse_error:     set if the source didn't parse at all.
    """
    claims: list[str] = field(default_factory=list)
    verbatim_checks: list[str] = field(default_factory=list)
    assumed_target_output: list[str] = field(default_factory=list)
    is_target_facing: bool = False
    parse_error: str | None = None


_SSH_MOCK_MARKERS = ("run_remote_command", "run_remote_script", "ssh_remote")


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001 -- unparse can choke on odd nodes; fall back
        return "<expression>"


def _gloss_compare(node: ast.Compare) -> str | None:
    """Gloss a single-op comparison (len(x) >= 1, result['k'] == 3, 'k' in d)."""
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left, op, right = node.left, node.ops[0], node.comparators[0]

    # membership: "key" in result  /  "root" in result["users"]  /  x not in y
    if isinstance(op, (ast.In, ast.NotIn)):
        verb = "includes" if isinstance(op, ast.In) else "does NOT include"
        rhs = _unparse(right)
        subject = "the result" if rhs == "result" else rhs
        return f"{subject} {verb} {_unparse(left)}"

    # len(x) <op> N
    if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "len" and left.args:
        subject = _unparse(left.args[0])
        n = _unparse(right)
        phrase = {
            ast.GtE: f"has at least {n} item(s)",
            ast.Gt: f"has more than {n} item(s)",
            ast.LtE: f"has at most {n} item(s)",
            ast.Lt: f"has fewer than {n} item(s)",
            ast.Eq: f"has exactly {n} item(s)",
        }.get(type(op))
        if phrase:
            return f"{subject} {phrase}"

    # x == V / x != V / x >= V ...  -- only when BOTH sides are simple
    # references/literals, so a compound expression (e.g. a["x"]+a["y"] > z*2)
    # is shown verbatim rather than half-glossed into awkward pseudo-English.
    phrase = {
        ast.Eq: "equals",
        ast.NotEq: "is not",
        ast.GtE: "is at least",
        ast.Gt: "is greater than",
        ast.LtE: "is at most",
        ast.Lt: "is less than",
    }.get(type(op))
    if phrase and _is_simple(left) and _is_simple(right):
        return f"{_unparse(left)} {phrase} {_unparse(right)}"
    return None


def _is_simple(node: ast.AST) -> bool:
    """A leaf-ish expression a reader can take at face value: a name, literal,
    attribute/subscript access, or a plain call. A BinOp/BoolOp/comparison
    operand is NOT simple -- those get shown verbatim instead of glossed."""
    return isinstance(node, (ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.Call))


def _gloss_test(test: ast.expr) -> str | None:
    """Best-effort plain-English gloss of an assert's test expression. Returns
    None when the shape isn't confidently recognized (caller shows it verbatim
    rather than inventing a description)."""
    # isinstance(x, T)  /  isinstance(x, (A, B))
    if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.func.id == "isinstance" and len(test.args) == 2:
        subj = _unparse(test.args[0])
        typ = test.args[1]
        if isinstance(typ, ast.Tuple):
            names = " or ".join(_unparse(e) for e in typ.elts)
        else:
            names = _unparse(typ)
        return f"{subj} is a {names}"

    # all(<cond> for <var> in <iter>)  /  any(...)
    if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.func.id in ("all", "any") and test.args:
        arg = test.args[0]
        if isinstance(arg, (ast.GeneratorExp, ast.ListComp)) and arg.generators:
            gen = arg.generators[0]
            iterable = _unparse(gen.iter)
            quant = "every" if test.func.id == "all" else "at least one"
            return f"{quant} item in {iterable} satisfies: {_unparse(arg.elt)}"
        return None

    if isinstance(test, ast.Compare):
        return _gloss_compare(test)

    # bare truthiness: assert result["ok"]  /  assert result.get("x")
    if isinstance(test, (ast.Subscript, ast.Attribute, ast.Name, ast.Call)):
        return f"{_unparse(test)} is present / truthy"

    return None


def _collect_ssh_mock_outputs(tree: ast.AST) -> tuple[bool, list[str]]:
    """Detect SSH mocking and pull the fake `stdout=` string literals the test
    feeds in -- i.e. what the harness pretends the real target returns."""
    is_target_facing = False
    outputs: list[str] = []

    for node in ast.walk(tree):
        # patch("...ssh_remote..run_remote_command..") / with patch(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "patch":
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and any(m in a.value for m in _SSH_MOCK_MARKERS):
                    is_target_facing = True
        # SSHResult(..., stdout="...")
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)):
            fname = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            if fname == "SSHResult":
                is_target_facing = True
                for kw in node.keywords:
                    if kw.arg == "stdout" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        val = kw.value.value.strip()
                        if val and val not in outputs:
                            outputs.append(val)
    return is_target_facing, outputs


def describe_harness_claims(source: str) -> HarnessClaims:
    """Extract plain-English claims from a pytest harness's own AST. Faithful by
    construction -- never an LLM gloss (see module docstring)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return HarnessClaims(parse_error=f"harness does not parse as Python: {e}")

    result = HarnessClaims()
    result.is_target_facing, result.assumed_target_output = _collect_ssh_mock_outputs(tree)

    # Only assertions INSIDE test_* functions are claims about the tool's
    # behavior. The registered_handler fixture's own `assert TOOL_NAME in
    # TOOL_REGISTRY` is fixed machinery, not a behavioral claim -- including it
    # would mislead the reviewer, so it's deliberately excluded.
    asserts: list[ast.Assert] = []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test_"):
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Assert):
                    asserts.append(sub)

    for node in asserts:
        # A human-authored message string is the most faithful claim -- it's the
        # test author's own description of what this assertion means.
        msg = node.msg
        if isinstance(msg, ast.Constant) and isinstance(msg.value, str) and msg.value.strip():
            text = msg.value.strip()
            if text not in result.claims:
                result.claims.append(text)
            continue
        gloss = _gloss_test(node.test)
        if gloss:
            if gloss not in result.claims:
                result.claims.append(gloss)
        else:
            raw = _unparse(node.test)
            if raw not in result.verbatim_checks:
                result.verbatim_checks.append(raw)

    return result


# ---------------------------------------------------------------------------
# Harness round-trip: regenerate a harness from corrected plain-English claims,
# gated on a mutation guard so a regenerated test can never silently rubber-stamp
# the trust anchor.
# ---------------------------------------------------------------------------

_REGEN_HARNESS_SYSTEM_PROMPT = '''You write ONE pytest harness for a Kratos tool from a list of plain-English CLAIMS a human has confirmed about what the tool must do. Each claim becomes a concrete assertion that actually checks it -- a test that would pass ANY implementation is useless and unacceptable.

Match this project's harness convention EXACTLY:
- Read the candidate path from the CANDIDATE_MODULE_PATH env var and import it (that triggers @register_tool).
- A `registered_handler` pytest fixture that imports the candidate and returns TOOL_REGISTRY[TOOL_NAME].handler.
- Set TOOL_NAME = "<the given tool name>" exactly.
- One or more `test_...` functions with real assertions on the handler's RETURN VALUE -- one per claim where possible.
- If the tool reaches the monitored device, mock kratos.adapters.ssh_remote.run_remote_command (module-qualified) with realistic canned output inside each test -- the sandbox has no network.

Output ONLY the Python source code -- no markdown fences, no commentary before or after.'''


def regenerate_harness_from_claims(tool_name: str, goal: str, corrected_claims: str) -> str | None:
    """Regenerate a pytest harness from a human's CORRECTED plain-English
    description of what the tool should do -- the round-trip that turns "spot a
    wrong test" into "author a correct one". Same structural guards as
    _draft_evolve_harness (valid Python + the exact TOOL_NAME); returns None
    (never raises) on any failure so the caller can fall back. The result is
    NEVER trusted on its own: the caller MUST run harness_discriminates() on it
    before it may become the correctness bar."""
    from kratos.agent.self_write import _extract_code

    corrected = (corrected_claims or "").strip()
    if not corrected:
        return None
    user_prompt = (
        f"Tool name: {tool_name}\n"
        f"What the tool is for: {goal}\n\n"
        f"CLAIMS the human confirmed the tool must satisfy (turn each into a real assertion on the "
        f"handler's return value):\n{corrected}\n\n"
        "Write the pytest harness now."
    )
    raw = agent_chat(system_prompt=_REGEN_HARNESS_SYSTEM_PROMPT, user_prompt=user_prompt, max_tokens=MAX_TOKENS)
    if raw is None:
        return None
    code = _extract_code(raw)
    try:
        ast.parse(code)
    except SyntaxError:
        return None
    if f'TOOL_NAME = "{tool_name}"' not in code and f"TOOL_NAME = '{tool_name}'" not in code:
        return None
    fragile = fragile_ssh_fakes(code)
    if fragile:
        return _redraft_without_fragile_fakes(_REGEN_HARNESS_SYSTEM_PROMPT, user_prompt, tool_name, fragile) or code
    return code


def harness_discriminates(harness_source: str, tool_name: str, *, timeout: int = 60) -> tuple[bool, str]:
    """Mutation / discrimination guard -- the precondition for accepting any
    regenerated harness. A harness is the trust anchor: once it approves a tool,
    that tool runs unsandboxed forever. So a regenerated harness must PROVE it
    tests something real by REJECTING a deliberately-wrong implementation --
    otherwise "edit the claims -> regenerate" is just a rubber stamp.

    Runs the harness under pytest against a mutant stub that registers `tool_name`
    with a handler returning obviously-wrong output. The mutant is our OWN safe
    code (no network, no LLM), run in a throwaway subprocess -- no sandbox needed,
    and it cannot touch the live TOOL_REGISTRY.

    Returns (ok, reason). ok is True ONLY if the harness RAN and FAILED the mutant
    (pytest exit 1). A pass (exit 0) means the test is a rubber stamp -> rejected;
    a non-runnable result (no tests collected / usage / internal error) -> rejected.
    Never raises.

    The guarantee is specifically "NOT a rubber stamp" -- a harness that fails the
    mutant for its OWN reason (a bug in the test itself) also passes here, but that
    is not a safety hole: it then fails every real candidate too, so the evo-loop
    build surfaces it visibly rather than silently accepting a wrong tool."""
    mutant = (
        "from kratos.agent.tools import register_tool\n\n"
        f'@register_tool(name="{tool_name}", description="deliberately-wrong mutant", '
        'parameters={"data_dir": {"type": "str", "default": None}})\n'
        "def _kratos_mutant(**kwargs):\n"
        '    return {"__kratos_mutant__": "deliberately wrong output"}\n'
    )
    try:
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            harness_path = dp / f"test_{tool_name}_discrimination.py"
            mutant_path = dp / f"{tool_name}_mutant.py"
            harness_path.write_text(harness_source, encoding="utf-8")
            mutant_path.write_text(mutant, encoding="utf-8")
            env = {**os.environ, "CANDIDATE_MODULE_PATH": str(mutant_path)}
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(harness_path), "-q",
                 "-p", "no:cacheprovider", "-o", "addopts="],
                capture_output=True, text=True, env=env, cwd=str(dp), timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return False, "the discrimination check timed out running the harness"
    except Exception as e:  # noqa: BLE001 -- a guard must never crash the caller
        return False, f"couldn't run the discrimination check ({e})"

    rc = proc.returncode
    if rc == 1:
        return True, "the test correctly rejects a deliberately-wrong implementation"
    if rc == 0:
        return False, ("this test PASSES even a deliberately-wrong implementation -- it isn't "
                       "actually checking the tool's behaviour, so it can't be trusted as the bar. "
                       "Make the claims more specific and try again.")
    return False, (f"the harness didn't run cleanly (pytest exit {rc}) -- it may be broken or have "
                   "no real tests. Try rephrasing the claims.")


# ---------------------------------------------------------------------------
# Name-collision info (UI-agnostic -- reports, does not prompt).
# ---------------------------------------------------------------------------

@dataclass
class NameCollision:
    exists: bool
    kind: Literal["builtin", "kept", "none"]
    kept_at: str | None = None


def check_name_collision(tool_name: str) -> NameCollision:
    """Whether tool_name already names a tool the agent can reach (built-in or
    previously-kept). Read-only. A collision means a kept candidate under the
    same name would REPLACE the existing one on approval, so the guided flow
    warns before doing any work."""
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

    if tool_name not in TOOL_REGISTRY:
        return NameCollision(exists=False, kind="none")
    metadata = _read_metadata(KEPT_TOOLS_DIR)
    if tool_name in metadata:
        return NameCollision(exists=True, kind="kept", kept_at=metadata[tool_name].get("kept_at"))
    return NameCollision(exists=True, kind="builtin")


# ---------------------------------------------------------------------------
# GuidedPrompter -- the UI abstraction, and the guided build itself.
# ---------------------------------------------------------------------------

class GuidedPrompter(ABC):
    """The surface the guided build talks through. mk2 supplies a Textual-backed
    implementation; a headless/automated caller (A2 Stage 3, tests) can supply
    one that answers programmatically. Every consequential answer fails safe:
    ask_confirm/ask_choice returning False/None (declined/cancelled) must never
    be interpreted as a go-ahead."""

    @abstractmethod
    def say(self, message: str, kind: Literal["note", "success", "error", "plain"] = "note") -> None:
        """Emit a status line into the conversation/log."""

    @abstractmethod
    def show(self, renderable: Any) -> None:
        """Show a rich renderable (a panel/table/text). May be a plain str."""

    @abstractmethod
    def ask_text(self, title: str, hint: str = "", default: str = "") -> str | None:
        """Free-text answer. None = the user cancelled (backed out entirely).
        An empty string is a distinct 'submitted nothing' the caller may treat
        as 'use the default'."""

    @abstractmethod
    def ask_confirm(self, title: str, body: str = "") -> bool:
        """Yes/no. Fail-safe: anything but an explicit yes is False."""

    @abstractmethod
    def ask_choice(self, title: str, options: list[tuple[str, str]], subtitle: str = "") -> str | None:
        """Pick one of options (value, label). None = cancelled."""


@dataclass
class GuidedBuildResult:
    """Outcome of a guided build. On status=='kept', tool_name and
    requires_approval are set (what A2 threads back into a pipeline draft);
    every other status means nothing was kept."""
    status: Literal[
        "kept", "declined", "cancelled", "no_harness",
        "write_failed", "stalled", "exhausted", "infra_error", "error",
    ]
    tool_name: str | None = None
    requires_approval: bool | None = None
    kept_path: Path | None = None
    message: str = ""


_HARNESS_DIR = _paths.harness_dir()

# Recovery guidance per non-kept loop outcome -- the concrete "what to try next"
# a non-expert needs, not just a status word (brief: "recovery guidance").
_RECOVERY: dict[str, str] = {
    "write_failed": (
        "The model never produced a testable tool (its code didn't even parse or match the "
        "required shape). Try rephrasing the idea more concretely, or simplify what you're asking "
        "for — one clear job per tool works best."
    ),
    "stalled": (
        "The model kept returning the same code and stopped improving it. The idea or the test may "
        "be pulling it in circles — try describing the tool differently, or loosen a test check "
        "that may be impossible to satisfy."
    ),
    "exhausted": (
        "The model tried several times but nothing passed your test. Most often the test asks for "
        "something the tool can't actually produce — re-read the plain-English checks above and "
        "relax or correct the one that's too strict, then run again."
    ),
    "infra_error": (
        "This wasn't a problem with the tool's code — the sandbox that safely tests it couldn't "
        "run (the Incus sandbox may be unavailable on this machine). Nothing was built; try again "
        "once the sandbox is back."
    ),
    "declined": (
        "A tool passed its test but you chose not to keep it. Nothing was saved — run /evolve again "
        "any time to revisit it."
    ),
}


def _render_claims(prompter: GuidedPrompter, claims: HarnessClaims, *, drafted: bool) -> None:
    """Show the plain-English review of what the test will check. This is the
    non-expert's window into the trust anchor: they review MEANING, not pytest."""
    from rich.panel import Panel
    from rich.text import Text as _Text

    body = _Text()
    if claims.parse_error:
        body.append(f"⚠ {claims.parse_error}\n", style=_console.ATTENTION)
    body.append("This test decides whether the new tool is 'correct'. It checks that:\n", style=_console.TEXT_PRIMARY)
    if claims.claims:
        for c in claims.claims:
            body.append("  • ", style=_console.ACCENT)
            body.append(f"{c}\n", style=_console.TEXT_PRIMARY)
    else:
        body.append("  • (no concrete checks found — this test would pass almost anything)\n", style=_console.ATTENTION)
    if claims.verbatim_checks:
        body.append("\nOther checks (shown exactly as written):\n", style=_console.TEXT_SECONDARY)
        for v in claims.verbatim_checks:
            body.append(f"  • {v}\n", style=_console.TEXT_SECONDARY)
    if claims.is_target_facing and claims.assumed_target_output:
        body.append("\nThe test pretends the target returns this (check it matches reality):\n", style=_console.TEXT_SECONDARY)
        for o in claims.assumed_target_output:
            shown = o if len(o) <= 200 else o[:200] + " …"
            body.append(f"  › {shown}\n", style=_console.TEXT_SECONDARY)
    body.append(
        "\nRead these as claims about the tool. If one looks wrong (e.g. a wrong assumption), "
        "edit the test before building.",
        style=_console.TEXT_SECONDARY,
    )
    title = (
        "What this test checks — DRAFTED by the model, review before saving"
        if drafted else "What this test checks"
    )
    prompter.show(Panel(body, title=title, title_align="left", border_style=_console.ATTENTION))


def _map_loop_status(loop_status: str) -> str:
    return {
        "approved": "kept",
        "denied": "declined",
        "write_failed": "write_failed",
        "stalled_no_variation": "stalled",
        "exhausted_retries": "exhausted",
        "infra_error": "infra_error",
    }.get(loop_status, "error")


def run_guided_build(
    goal: str,
    prompter: GuidedPrompter,
    *,
    suggested_name: str | None = None,
) -> GuidedBuildResult:
    """Drive the friendly path from a plain-language tool idea to a kept tool or
    a clean decline, talking through `prompter`. The heavy pipeline
    (run_self_write_loop) is called UNMODIFIED; this only wraps the surface.

    The conversational pipeline-drafting flow calls this programmatically with
    a goal already in hand when it hits a missing tool; the interactive mk2
    flow calls it with the user's idea. Either way the return carries the
    kept tool name + requires_approval (or a decline)."""
    goal = (goal or "").strip()
    if not goal:
        answer = prompter.ask_text(
            "New tool — what should it do?",
            'One sentence, e.g. "list which users have sudo on the target".',
        )
        if answer is None:
            return GuidedBuildResult(status="cancelled", message="No idea given.")
        goal = answer.strip().strip('"').strip("'").strip()
        if not goal:
            return GuidedBuildResult(status="cancelled", message="No idea given.")

    goal = _maybe_clarify_idea(goal, prompter)

    # --- Name -------------------------------------------------------------
    if suggested_name:
        default_name = _slugify_name_hint(suggested_name)
    else:
        default_name = _suggest_evolve_tool_name(goal) or _slugify_name_hint(goal)
    typed = prompter.ask_text("Name this tool", "Lowercase words joined by _ (snake_case).", default=default_name)
    if typed is None:
        return GuidedBuildResult(status="cancelled", message="Cancelled at naming.")
    tool_name = _slugify_name_hint(typed) if typed.strip() else default_name

    collision = check_name_collision(tool_name)
    if collision.exists:
        what = (
            f"a tool you built earlier (kept {collision.kept_at})" if collision.kind == "kept"
            else "a built-in Kratos tool"
        )
        proceed = prompter.ask_confirm(
            f"'{tool_name}' already exists",
            f"'{tool_name}' is already {what}. Building a new one under the same name will REPLACE it "
            "once you approve keeping it. Continue with this name?",
        )
        if not proceed:
            return GuidedBuildResult(status="cancelled", message="Backed out at name collision.")

    # --- Harness ----------------------------------------------------------
    harness_path = _HARNESS_DIR / f"test_{tool_name}.py"
    if harness_path.exists():
        # Existing harness: show what it checks, in plain English, then confirm.
        claims = describe_harness_claims(harness_path.read_text(encoding="utf-8"))
        prompter.say(f"Found a test for this tool at {harness_path}.")
        _render_claims(prompter, claims, drafted=False)
        if not prompter.ask_confirm("Build against this test?", "Start the write → test → keep loop now?"):
            return GuidedBuildResult(status="cancelled", message="Declined to build against the existing test.")
    else:
        result = _draft_or_template_harness(goal, tool_name, harness_path, prompter)
        if result is not None:
            return result  # cancelled / saved-to-edit / no build this run

    return _run_loop_and_report(goal, harness_path, prompter)


def _claims_roundtrip(
    goal: str, tool_name: str, current_code: str, current_claims: HarnessClaims,
    prompter: GuidedPrompter,
) -> str | None:
    """P1 harness round-trip: let the human correct what the test SHOULD check in
    plain English, regenerate the pytest from that, and accept the new version
    ONLY if it passes the mutation guard (it must FAIL a deliberately-wrong
    implementation). This is what lets a non-expert AUTHOR a correct test, not
    just spot a wrong one, WITHOUT the regeneration silently becoming a rubber
    stamp of the trust anchor. Returns the new harness source, or None to keep
    the current one."""
    default = "\n".join(current_claims.claims) if current_claims.claims else ""
    corrected = prompter.ask_text(
        "What should the test actually check?",
        "Describe in plain words what the tool must return or do (one point per line). "
        "I'll turn each point into a real check.",
        default=default,
    )
    if not corrected or not corrected.strip():
        return None
    prompter.say("Rewriting the test from your description (asks the model, a moment)…")
    new_code = regenerate_harness_from_claims(tool_name, goal, corrected)
    if not new_code:
        prompter.say(
            "Couldn't turn that into a valid test — keeping the current one. Rephrase and try "
            "again, or edit the file yourself.", kind="error")
        return None
    prompter.say("Checking the new test actually tests something (running it against a "
                 "deliberately-wrong tool)…")
    ok, reason = harness_discriminates(new_code, tool_name)
    if not ok:
        prompter.say(f"Not using that version — {reason}", kind="error")
        return None
    prompter.say("Good — the new test correctly rejects a wrong implementation.", kind="success")
    return new_code


def _draft_or_template_harness(
    goal: str, tool_name: str, harness_path: Path, prompter: GuidedPrompter,
) -> GuidedBuildResult | None:
    """Handle the missing-harness case. Returns a GuidedBuildResult when the run
    should STOP here (cancelled, or saved-for-editing), or None when a harness
    was saved AND the caller should proceed to build."""
    prompter.say(
        "Every tool needs a short test that decides whether it works — it's what keeps a "
        "self-written tool honest. There isn't one yet, so let's make a starter you can review."
    )
    want_draft = prompter.ask_confirm(
        "Draft a starter test with the model?",
        "I can draft one from your idea for you to review and edit — it is never trusted unedited. "
        "Draft one now? (No = I'll write my own.)",
    )
    code, drafted = None, False
    if want_draft:
        prompter.say("Drafting a starter test (asks the model, a moment)…")
        code = _draft_evolve_harness(_console.get_stderr_console(), tool_name, goal)
        drafted = bool(code)
    if not code:
        code = _build_evolve_harness_template(tool_name, goal)

    while True:
        claims = describe_harness_claims(code)
        _render_claims(prompter, claims, drafted=drafted)
        choice = prompter.ask_choice(
            "This test — what next?",
            [
                ("build", "Looks right — save it and build the tool now"),
                ("rewrite", "The checks are wrong — let me correct them in plain English"),
                ("edit", "Save it so I can edit the file myself first"),
                ("discard", "Discard — I'll write my own"),
            ],
            subtitle="The checks above are what decides 'correct'. Fix them if they're wrong.",
        )
        if choice != "rewrite":
            break
        new_code = _claims_roundtrip(goal, tool_name, code, claims, prompter)
        if new_code is not None:
            code, drafted = new_code, True
        # loop: re-show the (possibly regenerated) test and ask again

    if choice == "build":
        harness_path.parent.mkdir(parents=True, exist_ok=True)
        harness_path.write_text(code, encoding="utf-8")
        prompter.say(f"Saved to {harness_path} — building now.", kind="success")
        return None
    if choice == "edit":
        harness_path.parent.mkdir(parents=True, exist_ok=True)
        harness_path.write_text(code, encoding="utf-8")
        prompter.say(f"Saved to {harness_path}.", kind="success")
        prompter.say("Review it (especially the checks above), then run /evolve again to build.")
        return GuidedBuildResult(status="no_harness", message=f"Saved a draft to {harness_path} to edit.")
    return GuidedBuildResult(status="cancelled", message="Discarded the drafted test.")


def _run_loop_and_report(goal: str, harness_path: Path, prompter: GuidedPrompter) -> GuidedBuildResult:
    from kratos.agent.self_write import WriteRequest
    from kratos.agent.self_write_loop import run_self_write_loop

    prompter.say(f"Building '{harness_path.stem.replace('test_', '')}' — this can take a few minutes per try…")
    try:
        outcome = run_self_write_loop(WriteRequest(goal=goal, test_file=harness_path))
    except Exception as e:  # noqa: BLE001 -- never crash the caller
        prompter.say(f"Evo-loop hit an unexpected error: {e}", kind="error")
        return GuidedBuildResult(status="error", message=str(e))

    status = _map_loop_status(outcome.status)
    if status == "kept":
        kd = outcome.keep_decision
        prompter.say(
            f"Kept '{kd.tool_name}' — available now. "
            + ("It will ask before running each time." if kd.requires_approval else "It can run without asking."),
            kind="success",
        )
        return GuidedBuildResult(
            status="kept", tool_name=kd.tool_name, requires_approval=kd.requires_approval,
            kept_path=outcome.kept_path, message=f"Kept {kd.tool_name}.",
        )

    prompter.say(_RECOVERY.get(status, f"Evo-loop did not produce a tool (status: {outcome.status})."),
                 kind="error" if status not in ("declined",) else "note")
    return GuidedBuildResult(status=status, message=_RECOVERY.get(status, outcome.status))
