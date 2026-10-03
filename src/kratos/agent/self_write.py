"""
Self-writing tool loop -- WRITE step only (Part A of
write -> test -> human-approve -> keep; see docs/DESIGN.md's "Self-writing
tool loop" section for the full pipeline).

This module generates a CANDIDATE tool implementation against a human-authored
test file and stages it to disk. It does not execute, sandbox-test, seek
approval, or register the candidate anywhere TOOL_REGISTRY or
agent/loop.py's tool dispatch can reach it -- Parts B (sandbox test), C
(approval), D (registry persistence) are separate steps that consume
this step's output (a staged file PATH), not part of this module. Nothing
this module produces is imported, exec'd, or otherwise executed by it.

Design choice, stated explicitly rather than left implicit: the model IS
shown the full contents of the human-authored test file, not just the
natural-language goal. The test file is the only place the exact interface
contract lives -- the tool name TOOL_REGISTRY must carry, the handler's
exact argument names, and the expected return shape are all implicit in how
the test calls the candidate, not spelled out anywhere else in prose.
Withholding the test file would force the model to guess an interface a
human already pinned down, which is strictly worse: it can only produce more
retries against Part B's eventual sandbox test run for reasons that have
nothing to do with whether the candidate's core logic is correct.
"""
from __future__ import annotations

import ast
import difflib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from kratos import paths as _paths
from kratos.agent import console as _console
from kratos.llm_interface import agent_chat
from kratos.llm_config import MAX_TOKENS

# Staging root: deliberately NOT under src/kratos/ (nothing here sits on the
# package's normal import path), NOT agent/tools.py, and NOT anywhere
# TOOL_REGISTRY auto-loads from. Nothing written here is live or reachable
# by the running agent until a LATER, separate step (Part B/C/D) explicitly
# promotes one specific staged file after human approval.
DEFAULT_STAGING_DIR = _paths.sandbox_staging_dir()

# Bounded retry for SANITY-CHECK failures only (bad syntax / wrong
# registration shape) -- NOT a retry-on-test-failure loop. That loop depends
# on Part B's sandbox test results existing first and is explicitly out of
# scope here; see write_candidate_tool's docstring.
MAX_WRITE_ATTEMPTS = 3

# Retry-response structural guard: a retry response that parses and is
# correctly shaped can STILL be a from-scratch rewrite rather than a
# targeted fix on the previous attempt -- observed end-to-end against a
# local model, where each retry regenerated large parts of the file,
# letting already-correct imports and return-shape regress rather than
# making a minimal, localized fix.
# MIN_RETRY_SIMILARITY_RATIO is a difflib line-similarity floor (0=nothing
# in common, 1=identical) a retry response must clear against the
# immediately-preceding attempt to be accepted -- below it, the response is
# rejected and retried within the SAME bounded budget (MAX_WRITE_ATTEMPTS),
# with the actual diff shown back to the model, exactly like any other
# sanity-check failure. 0.6 is a deliberately moderate floor: a genuine
# single-fix edit (e.g. adding one missing import line to an otherwise
# unchanged ~35-line file) leaves the ratio well above 0.95; a near-total
# rewrite typically lands well below 0.5. Not a precise metric -- a cheap,
# code-level backstop against "room to drift" that prompt instructions
# alone cannot structurally close. See write_candidate_tool's design note.
MIN_RETRY_SIMILARITY_RATIO = 0.6

_CODE_FENCE_RE = re.compile(r"```(?:python)?\s*(.*?)\s*```", re.DOTALL)


@dataclass
class WriteRequest:
    goal: str                      # natural-language spec of what the tool should do
    test_file: Path                # human-authored test file this candidate must satisfy
    extra_context: str | None = None  # optional: extra background the model may need
    # Retry-specific: the immediately-preceding attempt's full source and
    # the real reason it failed, threaded through by the caller
    # (agent/self_write_loop.py's orchestrator, for a sandbox-test-failure
    # retry) so this attempt is shown a targeted-fix prompt, not just a
    # description of what went wrong. Both None on a genuinely first
    # attempt -- nothing to preserve yet, so that prompt is unchanged from
    # a plain first-attempt call. See write_candidate_tool's docstring.
    previous_code: str | None = None
    previous_error: str | None = None


@dataclass
class WriteResult:
    # "no_variation": the response was byte-identical to the anchor (see
    # write_candidate_tool's exact-repeat guard) -- distinct from "failed"
    # (broken/rejected content) precisely because the content here is NOT
    # broken, it's just not new. staging_path stays None either way (an
    # identical candidate is never re-staged; the original staged copy from
    # the attempt it repeats is still on disk and already has a real test
    # result).
    status: Literal["staged", "failed", "no_variation"]
    staging_path: Path | None = None
    # Invariant: status == "staged" implies tool_name is not None -- see
    # _validate_candidate. Stays Optional in the type because a "failed"
    # result (no candidate ever became stageable) has no name to report;
    # that is a different, expected case, not the gap this field once had.
    tool_name: str | None = None
    attempts: int = 0
    error: str | None = None
    validation_notes: list[str] = field(default_factory=list)


SYSTEM_PROMPT = """You are Kratos's tool-writing assistant. You generate a SINGLE new tool \
implementation for Kratos's security-investigation agent, matching the exact structural \
convention already used throughout agent/tools.py.

CONVENTION (match exactly):
    from kratos.agent.tools import register_tool
    from typing import Any
    from pathlib import Path

    @register_tool(
        name="<tool_name>",
        description="<one paragraph: what it checks, when it's relevant>",
        parameters={
            "<arg_name>": {"type": "<str|int|path|...>", "description": "<...>", "default": <value, or omit if required>},
        },
    )
    def tool_<tool_name>(<python signature matching the parameters above>) -> dict[str, Any]:
        ...
        return {...}

REAL INVOCATION CONTRACT (how arguments actually arrive at runtime -- read this carefully):
Your tool is called by agent/loop.py::execute_tool_call, which passes arguments straight from
the agent's parsed tool-call JSON with NO type coercion in between:

    call_args = dict(args or {})
    if "data_dir" in tool.parameters and "data_dir" not in call_args:
        call_args["data_dir"] = data_dir
    ...
    result = tool.handler(**call_args)

JSON has no Path type. Every "path"-typed argument arrives as a plain `str` (or `None` if
optional and omitted), never as an already-constructed `pathlib.Path`. Every existing
hand-written tool in agent/tools.py that takes a path-like argument follows the same
convention: annotate the parameter as `Path` (or `str | Path | None` if optional) for
readability, but ALWAYS explicitly re-wrap it with `Path(...)` at the point of use -- never
call a Path-only method (`.read_text()`, `.exists()`, `/` joins, etc.) directly on the parameter
as received. Real precedent, from agent/tools.py's tool_parse_auth_log:

    def tool_parse_auth_log(
        data_dir: Path,
        log_path: str | Path | None = None,
        source: str = "auto",
    ) -> dict[str, Any]:
        resolved_log_path = Path(log_path) if log_path else None
        events_out, stats_out, stats = _parse_auth_log_file(Path(data_dir), resolved_log_path, source)
        return {"events_file": str(events_out), "stats_file": str(stats_out), "stats": stats}

Follow this pattern for any path-like argument your tool takes: convert with `Path(...)` before
using any Path-only method. Do not assume the caller already converted it for you.

TARGET-FACING TOOLS (reaching the MONITORED device, not Kratos's own host, over SSH):
Some goals are about data that only exists on the SEPARATE device Kratos monitors -- users,
processes, open files, config, logs living on that machine -- not anything already collected
into a local JSON/XML file under data_dir. For a goal like this, do NOT invent a local-file data
source under data_dir; that data is not there. Instead, import the ssh_remote MODULE (not
individual names from it -- this matters, see below) and call one of its two fixed-command
functions:

    from kratos.adapters import ssh_remote

    def tool_<name>() -> dict[str, Any]:
        result = ssh_remote.run_remote_command("cat /etc/group | grep '^sudo:'")
        if not result.ok:
            return {"status": "error", "observation": f"command failed: {(result.stderr or result.stdout).strip()}"}
        # ... parse result.stdout into your return shape ...
        return {"status": "ok", "target": ssh_remote.target_label(), ...}

`run_remote_command(command)` runs one command string on the target over SSH; `run_remote_script
(script)` runs a multi-line script via `bash -s` (use this if you need more than one command).
Both return an SSHResult (`.ok`, `.returncode`, `.stdout`, `.stderr`) -- never raise on a failed
command, so always check `.ok` before trusting `.stdout`. The command/script string itself MUST
be fixed at write time (a literal you write, optionally with fixed flags) -- never build it from
a caller-supplied argument; that would turn this into a generic remote-command executor, which
Kratos never allows regardless of how the tool is framed (see agent/tools.py's run_linux_command
and docs/DESIGN.md's "Execution boundary" section for the full reasoning).
IMPORTANT -- import the MODULE (`from kratos.adapters import ssh_remote`), never individual names
(`from kratos.adapters.ssh_remote import run_remote_command`): the human-authored test harness
that will judge this code needs to mock the SSH layer (the sandbox that tests it has no network
access at all, by design), and mocking only works reliably against the module-qualified call
shown above -- a bare imported name breaks that.

PARTIAL FAILURES INSIDE A LOOP (do not silently shrink the result set):
If your tool iterates over multiple items (ports, users, processes, files, ...) and a per-item
sub-step can independently fail, come back empty, or be unidentifiable for just ONE item (e.g. a
listening socket's owning process isn't visible without elevated privileges, or one user's
crontab can't be read), do NOT simply skip that item and omit it from the result. For a
security-investigation tool, a silently-shrunk result set is worse than an incomplete one -- it
can hide exactly the entry an investigator most needs to see (an unattributed listening port is a
more suspicious finding than an attributed one, not a less interesting one). Always include the
item, with the failed/unresolved sub-fields set to `None` (or a short "error"/"unknown" marker
string), so the caller can see it was present but not fully resolved. Only omit an item entirely
when it genuinely isn't in the source data at all -- never because one piece of enrichment about
it failed.

PRIVILEGE & ERROR VISIBILITY (target-facing tools -- the #1 real cause of a tool that PASSES its
sandbox test but then FAILS silently on the live target):
The sandbox that tests your code MOCKS the SSH layer with fake output, so a command that would be
DENIED on the real target (permission denied, exit 1) still "works" in the test. Two rules keep a
candidate from passing the test yet breaking live:

1. Many system files and logs are readable ONLY by root, and the SSH user Kratos connects as is a
   NORMAL, UNPRIVILEGED user (not root). Reading them with a plain command silently fails on the
   real target. Concrete real failures this has caused: `cat /etc/sudoers` (mode 0440, root-only --
   exit 1 for a normal user), `cat /etc/shadow` (root-only), and privileged journald entries
   (hidden from a normal user with no error). Do NOT reach for the privileged path. Prefer a
   NON-PRIVILEGED alternative that returns the SAME information for an ordinary user:
     - to find who has sudo:            `getent group sudo`   (NOT `cat /etc/sudoers`)
     - for recent logins / who is on:   `last`, `who`, `lastlog`   (NOT privileged auth logs)
     - for listening sockets/processes: `ss -tlnp`, `ps aux`   (owner fields may be blank without
       privilege -- that's expected; include the item anyway per PARTIAL FAILURES above)
   ONLY if the data genuinely has no unprivileged source, use `sudo -n <command>` EXPLICITLY (the
   `-n` means "never prompt for a password" -- it either works via passwordless sudo or fails fast
   and cleanly, instead of hanging waiting for a password that will never come). Never assume the
   SSH user is root; never assume interactive sudo is available.

2. NEVER suppress stderr in a way that hides the real error. Do NOT append a blanket `2>/dev/null`
   to a command whose failure you then report -- when that command fails on the live target, the
   ONLY diagnostic (the permission-denied / not-found message) is exactly what you just threw away,
   so the tool reports an EMPTY error ("command failed:" with nothing after it), which is strictly
   worse than surfacing the raw stderr. Always check `result.ok` and include
   `result.stderr` (falling back to `result.stdout`) in your error return, e.g.:
     if not result.ok:
         return {"status": "error", "observation": f"command failed: {(result.stderr or result.stdout).strip()}"}

RULES:
- Output ONLY the Python source code for this one tool -- no markdown fences, no commentary \
before or after, no explanation. If you do use fences, put ONLY code inside them.
- When iterating over multiple items, never let a failed/missing per-item sub-step remove that \
item from the result entirely -- see PARTIAL FAILURES INSIDE A LOOP above.
- Do NOT read a root-only file/log with a plain (non-sudo) command -- the SSH user is unprivileged. \
Prefer an unprivileged equivalent (`getent group sudo`, `last`, `who`, `ss`, `ps`); use `sudo -n` \
explicitly only when root is genuinely unavoidable. See PRIVILEGE & ERROR VISIBILITY above.
- Do NOT append a blanket `2>/dev/null` (or otherwise discard stderr) on a command whose failure \
you then report -- surface the real `result.stderr`/`result.stdout` in your error return. An empty \
error message is worse than the raw stderr. See PRIVILEGE & ERROR VISIBILITY above.
- Do NOT write a test. A human-authored test file is given to you below so you know the exact \
interface (tool name, handler argument names, return shape) you must implement -- match it \
exactly, since that test is what your code will be judged against later.
- Do NOT add documentation beyond the `description` field and short inline comments where the \
reasoning genuinely isn't obvious from the code.
- Import only from Python's standard library or kratos's existing modules \
(kratos.agent.tools, kratos.adapters.*) -- do not invent third-party dependencies.
- Any path-like argument must be accepted as it actually arrives (`str`, or `str | Path | None` \
if optional) and explicitly converted with `Path(...)` before any Path-only method is called on \
it -- never type a parameter as bare `Path` and call `.read_text()`/`.exists()`/etc. directly on \
the value as received. See REAL INVOCATION CONTRACT above.
- The function must not perform network access, subprocess calls, or file writes of its own \
EXCEPT via ssh_remote.run_remote_command/run_remote_script as described above for a genuinely \
target-facing goal -- this tool will later run in a sandbox with no real network access, and the \
human-authored test harness is expected to mock the SSH layer for exactly that reason. Do not \
add any OTHER network access, subprocess call, or file write beyond that one documented path.
"""


def _minimal_change_instruction() -> str:
    return (
        "STRICT REQUIREMENT FOR THIS RESPONSE: output the COMPLETE file again, but change ONLY "
        "what is directly necessary to fix the SPECIFIC error shown above. Every line that is "
        "not directly responsible for that error must be copied over EXACTLY as it appears in "
        "your previous attempt -- same imports, same variable names, same return dict keys, same "
        "overall structure and approach. Do NOT rename variables, change data structures, alter "
        "the return shape, reorganize the code, or write a fresh implementation from scratch. "
        "This is a targeted bugfix applied on top of your own previous code, not a rewrite -- a "
        "correct response here looks almost identical to your previous attempt, with a small, "
        "localized diff addressing only the error shown."
    )


def _build_retry_section(previous_code: str, previous_error: str, rejected_before_testing: bool) -> str:
    label = (
        "YOUR PREVIOUS ATTEMPT (rejected before any testing even ran -- it did not parse, or did "
        "not match the required @register_tool(...) shape)"
        if rejected_before_testing else
        "YOUR PREVIOUS ATTEMPT (this code WAS staged and actually tested in the sandbox -- it "
        "ran, but the test failed)"
    )
    return (
        f"{label}:\n```python\n{previous_code}\n```\n\n"
        f"THE SPECIFIC ERROR from that attempt:\n{previous_error}\n\n"
        f"{_minimal_change_instruction()}\n"
    )


def _build_user_prompt(
    request: WriteRequest,
    previous_code: str | None,
    previous_error: str | None,
    rejected_before_testing: bool,
) -> str:
    test_source = request.test_file.read_text(encoding="utf-8")
    parts = [
        f"GOAL:\n{request.goal}\n",
        f"HUMAN-AUTHORED TEST FILE this tool must satisfy ({request.test_file.name}):\n"
        f"```python\n{test_source}\n```\n",
    ]
    if request.extra_context:
        parts.append(f"ADDITIONAL CONTEXT:\n{request.extra_context}\n")
    if previous_code and previous_error:
        parts.append(_build_retry_section(previous_code, previous_error, rejected_before_testing))
    return "\n".join(parts)


def _extract_code(raw: str) -> str:
    fence_match = _CODE_FENCE_RE.search(raw)
    if fence_match:
        return fence_match.group(1).strip()
    return raw.strip()


def _find_register_tool_call(tree: ast.AST) -> ast.Call | None:
    """
    Walks the SAME parse tree ast.parse() already produced (no second,
    separate parsing mechanism -- this and tool-name resolution both work
    off one ast.parse() call) looking for a function decorated with
    @register_tool(...), and returns that decorator's Call node.
    """
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if isinstance(func, ast.Name) and func.id == "register_tool":
                return dec
            if isinstance(func, ast.Attribute) and func.attr == "register_tool":
                return dec
    return None


def _resolve_literal_tool_name(call: ast.Call) -> str | None:
    """
    Extracts register_tool's `name` argument IF it is statically
    resolvable: a plain string literal, passed either as the keyword
    `name=...` (the convention this module's own prompt template teaches)
    or as the first positional argument (register_tool's real signature --
    see agent/tools.py -- makes `name` the first positional-or-keyword
    parameter, so that is an equally valid call). Anything else -- an
    f-string, a variable reference, a function call, a module-level
    constant referenced by name -- genuinely cannot be resolved without
    EXECUTING the code, which Part A never does by design (only Part B's
    sandbox ever executes candidate code). Returns None in that case.
    """
    for kw in call.keywords:
        if kw.arg == "name":
            value = kw.value
            return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None
    if call.args:
        first = call.args[0]
        return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
    return None


def _validate_candidate(code: str) -> tuple[list[str], str | None]:
    """
    Sanity checks only (Part A's job) -- not correctness, not behavior.
    Returns (problems, tool_name): problems is empty and tool_name is a real
    str exactly when the candidate is fit to stage -- there is no path that
    returns an empty problems list alongside tool_name=None; see
    write_candidate_tool's own assertion of this invariant right before it
    stages anything.

    Deliberately narrow beyond that: parses as Python, matches the
    @register_tool(...) registration shape this codebase's tools all use,
    AND that call's `name` argument is a literal string Part D can safely
    use as a registry key later. This last check closes a real, previously-
    open gap: the old (regex-only, "@register_tool(" present anywhere")
    check would happily stage `@register_tool(description=..., parameters=...)`
    with no `name` at all, or `@register_tool(name=some_dynamic_expr, ...)`
    -- both valid Python, both matching the loose regex, both guaranteed to
    either raise a TypeError the moment register_tool's decorator actually
    runs (missing required `name`) or leave Part D with no static way to
    know what registry key to use. Whether the candidate's LOGIC actually
    works is still entirely Part B's job, not this one's.
    """
    problems: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        problems.append(f"SyntaxError: {e}")
        return problems, None  # no point checking decorator shape on unparseable code

    call = _find_register_tool_call(tree)
    if call is None:
        problems.append(
            "No @register_tool(...) decorator usage found -- doesn't match the existing "
            "tool-registration convention used throughout agent/tools.py."
        )
        return problems, None

    tool_name = _resolve_literal_tool_name(call)
    if tool_name is None:
        problems.append(
            "@register_tool(...)'s `name` argument is missing or is not a literal string "
            "constant (e.g. an f-string, a variable, or a function call). The tool's name must "
            "be statically determinable from the source alone, exactly like every hand-written "
            "tool in agent/tools.py -- use a plain string literal, e.g. name=\"my_tool_name\"."
        )
        return problems, None

    return problems, tool_name


def _stage(code: str, staging_dir: Path, tool_hint: str) -> Path:
    staging_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9_]+", "_", tool_hint.lower()).strip("_")[:40] or "candidate"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # timestamp + short uuid: safe against both same-second concurrent writes
    # and repeated runs of the same goal overwriting a prior candidate.
    filename = f"{slug}_{ts}_{uuid.uuid4().hex[:8]}.py"
    out_path = staging_dir / filename
    out_path.write_text(code, encoding="utf-8")
    return out_path


def write_candidate_tool(
    request: WriteRequest,
    staging_dir: Path = DEFAULT_STAGING_DIR,
    max_attempts: int = MAX_WRITE_ATTEMPTS,
    outer_attempt_label: str | None = None,
) -> WriteResult:
    """
    Runs the WRITE step only. Prompts the configured LLM backend (via
    kratos.llm_interface.agent_chat -- the same plumbing agent/loop.py uses,
    same LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND config) for a
    candidate tool implementation, sanity-checks it, and stages it to disk
    on success.

    Retries up to max_attempts on EITHER a sanity-check failure (bad syntax
    or wrong registration shape) OR a retry response that diverges too far
    from the immediately-preceding attempt to count as a targeted fix (see
    MIN_RETRY_SIMILARITY_RATIO) -- there is still no test-EXECUTION feedback
    loop here (that's Part B/D); this only concerns the SHAPE of what comes
    back, not whether its logic is correct. A vague/ambiguous goal still
    gets staged as long as what comes back parses and is shaped like a
    tool -- judging whether the result is actually CORRECT is explicitly
    not this function's job.

    Retry framing: if request.previous_code/previous_error are
    set (the orchestrator is retrying after a real sandbox test failure),
    the similarity guard below is ANCHORED to that exact code for this
    call's entire duration -- it is never reassigned, even across this
    call's own internal sanity-retries. This is deliberate, not an
    oversight: an earlier version of this function updated the anchor to
    whatever the most recently REJECTED sub-attempt was, which meant a
    rejected rewrite silently became the new baseline every subsequent
    response was compared against -- a targeted fix on the ORIGINAL
    (real, sandbox-tested) code could then itself get flagged as "too
    different", simply because it didn't resemble the intervening rejected
    rewrite. Caught by this module's own scripted sanity test before ever
    reaching a real LLM. What's actually DISPLAYED as "your previous
    attempt" in the prompt is a separate variable that DOES update after an
    ordinary sanity-check rejection (so the model sees and fixes its own
    latest concrete mistake, e.g. a new syntax error) -- but after a
    similarity-guard rejection specifically, the display is reset back to
    the anchor, redirecting the model to edit the real code again instead
    of building further on a rewrite that was just refused.

    Returns a WriteResult carrying the staging PATH, never the code inline,
    so Part B can pick the candidate up by path without this function's
    caller needing to shuttle source text around.

    outer_attempt_label (display only, no effect on control flow): an
    optional pre-formatted string like "outer attempt 2/3" from the caller
    (run_self_write_loop), folded into this function's own progress
    messages below. This function's OWN attempt/max_attempts always
    restarts from 1 on every fresh call -- it's Part A's own internal
    write-retry budget, distinct from Part D's outer sandbox-test retry
    budget -- so without this label, two genuinely different outer
    attempts both print "(attempt 1/3)" and look identical even though a
    retry happened between them. None (the default) preserves the plain
    message shape for any caller that doesn't pass one (e.g.
    scripts/dev/run_self_write_count_failed_ssh_attempts.py).
    """
    if not request.test_file.exists():
        return WriteResult(status="failed", error=f"test_file does not exist: {request.test_file}")

    # Fixed for this whole call -- see docstring. None on a genuine first
    # attempt (nothing to anchor to; the similarity guard simply never
    # fires in that case, since it's gated on anchor_code is not None).
    anchor_code = request.previous_code
    anchor_error = request.previous_error
    anchor_rejected_before_testing = False  # an orchestrator-supplied anchor always means "ran, but failed"

    # What's shown in the prompt for the NEXT sub-attempt -- starts equal to
    # the anchor, but can diverge from it (see docstring) after an ordinary
    # sanity-check rejection.
    display_code = anchor_code
    display_error = anchor_error
    rejected_before_testing = anchor_rejected_before_testing
    last_problems: list[str] = []

    for attempt in range(1, max_attempts + 1):
        # See outer_attempt_label's own docstring note above for why this is
        # NOT just f"attempt {attempt}/{max_attempts}" when a label is given.
        attempt_desc = (
            f"{outer_attempt_label}, write sub-attempt {attempt}/{max_attempts}"
            if outer_attempt_label
            else f"attempt {attempt}/{max_attempts}"
        )
        user_prompt = _build_user_prompt(request, display_code, display_error, rejected_before_testing)
        raw = agent_chat(system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, max_tokens=MAX_TOKENS)

        if raw is None:
            _console.render_error(_console.get_stderr_console(), "Evo-loop: LLM backend unavailable, aborting write step.")
            return WriteResult(status="failed", attempts=attempt, error="LLM backend unavailable (agent_chat returned None).")

        code = _extract_code(raw)
        problems, tool_name = _validate_candidate(code)
        was_similarity_rejection = False

        # Exact-repeat guard: the OPPOSITE extreme from the similarity guard
        # below (zero difference, not too much difference) -- a 5-attempt
        # diagnostic run once produced attempts 2-5 that were byte-for-byte
        # identical, despite each being shown fresh, correct failing-test
        # context. This is a distinct failure mode from a rewrite: the
        # model isn't varying its output AT ALL, so re-staging and
        # re-sandbox-testing an identical candidate would just reproduce a
        # result Part B already produced, burning a real sandbox run (and,
        # at the orchestrator level, a real LLM call) for zero new
        # information. Checked BEFORE the similarity guard since an exact
        # match trivially satisfies that guard's threshold anyway (ratio=1.0)
        # -- this is the more specific, more useful diagnosis to surface.
        # Gated the same way as the similarity guard: only meaningful when
        # there's a real anchor (not attempt 1) and the response is
        # otherwise valid (an already-broken repeat is still just broken,
        # nothing new to report there).
        if not problems and anchor_code is not None and code == anchor_code:
            _console.render_note(
                _console.get_stderr_console(),
                f"Evo-loop: {attempt_desc} is BYTE-IDENTICAL to the anchor -- no "
                "variation despite fresh failing-test context. Stopping this write step immediately "
                "rather than silently consuming another attempt on a known repeat.",
            )
            return WriteResult(status="no_variation", tool_name=tool_name, attempts=attempt)

        # Structural minimal-change guard: only applicable when there IS an
        # anchor to compare against (a genuine orchestrator-level retry, not
        # attempt 1) and the response otherwise passed sanity checks -- a
        # response that's already broken doesn't need a second, redundant
        # complaint. ALWAYS compares against anchor_code, never display_code.
        if not problems and anchor_code is not None:
            similarity = difflib.SequenceMatcher(
                a=anchor_code.splitlines(), b=code.splitlines(), autojunk=False
            ).ratio()
            if similarity < MIN_RETRY_SIMILARITY_RATIO:
                was_similarity_rejection = True
                diff_text = "\n".join(difflib.unified_diff(
                    anchor_code.splitlines(), code.splitlines(),
                    fromfile="your_previous_attempt.py", tofile="this_response.py", lineterm="",
                ))
                problems = [
                    f"This response is too different from your previous attempt to be a targeted "
                    f"fix (line similarity={similarity:.0%}, minimum required="
                    f"{MIN_RETRY_SIMILARITY_RATIO:.0%}). You were told to make the smallest "
                    f"possible change -- instead large parts of the file were rewritten. Diff of "
                    f"what changed:\n{diff_text}\n"
                    "Revert everything not directly related to fixing the specific error, and "
                    "resubmit."
                ]

        if not problems:
            assert tool_name is not None, (
                "invariant violated: _validate_candidate returned no problems but tool_name=None "
                "-- staging would hand Part D an unnamed candidate; refusing to proceed silently."
            )
            staging_path = _stage(code, staging_dir, request.goal)
            _console.render_note(
                _console.get_stderr_console(),
                f"Evo-loop: staged candidate '{tool_name}' ({attempt_desc}) -> {staging_path}",
            )
            return WriteResult(status="staged", staging_path=staging_path, tool_name=tool_name, attempts=attempt)

        last_problems = problems
        if was_similarity_rejection:
            # Redirect back to the real anchor -- do NOT adopt the rejected
            # rewrite as the new "previous attempt" (see docstring). Show
            # BOTH the original bug (anchor_error) and the rejection reason,
            # not one replacing the other: an earlier version of this
            # branch overwrote anchor_error with JUST the similarity
            # complaint, so the next sub-attempt was told "you changed too
            # much" without being re-shown WHAT bug it still needed to fix
            # -- which produced cosmetic edits (a ternary collapse, a
            # typing-annotation tweak) that cleared the similarity bar
            # without ever touching the actual reported error.
            display_code = anchor_code
            display_error = (
                f"{anchor_error}\n\n"
                "YOUR MOST RECENT RESPONSE WAS ALSO REJECTED, for a SEPARATE reason (this does "
                "NOT replace the error above -- you still need to fix that too):\n"
                + "\n".join(f"- {p}" for p in problems)
            )
            rejected_before_testing = anchor_rejected_before_testing
        else:
            display_code = code
            display_error = "\n".join(f"- {p}" for p in problems)
            rejected_before_testing = True
        _console.render_error(
            _console.get_stderr_console(),
            f"Evo-loop: {attempt_desc} failed sanity check: {display_error}",
        )

    return WriteResult(
        status="failed",
        attempts=max_attempts,
        error=f"Could not produce syntactically valid, correctly-shaped code after {max_attempts} attempts.",
        validation_notes=last_problems,
    )
