"""Reproduction on a copy, in the sandbox, with the dangerous call replaced (E.7b §3.7).

For a **Python**, **self-contained** slice of a class Kratos ships a recorder for, this writes --
**by code, from the class's recorder list, never by a model** -- a pytest harness that, inside
`agent/self_test.py`'s no-network Incus sandbox:

1. unpacks a copy of the root's source (embedded in the harness, so nothing extra is pushed),
2. puts Kratos's code-owned framework **fakes** first on `sys.path` (the real Flask/FastAPI are
   not installed in the sandbox),
3. **replaces every dangerous call of the class with a recorder** -- the real call is never run,
   even in the sandbox,
4. calls the handler through the fake with one inert **canary** value in every request field,
5. passes iff the canary reached the recorder.

The copy lives under `data_dir/.review-work/<run>/`, 0700/0600, emptied in a `finally`, and swept
at the next review start if a crash left it. One sandbox run at a time across Kratos
(`sandbox_lock`). No Incus, or `review.sandbox_reproduction=false` -> reproduction is OFF and the
lead is `needs_validation` ("reproduction is off on this computer"), never a silent confirm.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any, Callable

from kratos.review import classes as C
from kratos.review import sandbox_lock
from kratos.review.slice import Index, Slice
from kratos.review.verdict import (R_NOT_ATTEMPTED, R_NOT_REPRODUCED, R_OFF, R_REPRODUCED, Repro)

# Classes whose recorders are module-level or class-method callables the harness can replace
# cleanly. sql (needs a fake cursor) and noauth (no dangerous call) are never reproduced -- they
# are confirmed by a direct rule or checked by a person only.
REPRODUCIBLE: frozenset[str] = frozenset({"exec", "deserialise", "path", "template", "upload"})
WORK_DIRNAME = ".review-work"
MARKER = "__REVIEW_REPRO__"

Runner = Callable[[Path, Path], Any]       # (candidate_path, harness_path) -> SandboxTestResult


def incus_available() -> bool:
    return shutil.which("incus") is not None


def reproduction_enabled(data_dir: Path | str) -> bool:
    from kratos.review import settings as RS
    return bool(RS.get(RS.SANDBOX_REPRODUCTION, data_dir)) and incus_available()


# --------------------------------------------------------------------------- self-contained check
def _stdlib() -> frozenset[str]:
    import sys
    return frozenset(getattr(sys, "stdlib_module_names", frozenset()))


def self_contained(sl: Slice, idx: Index) -> tuple[bool, str]:
    """Every import on the reachable path must be the stdlib, a name inside the root, or a
    framework Kratos ships a fake for. Returns (ok, reason naming the first import that isn't)."""
    from kratos.review.fakes import FAKE_MODULES
    std = _stdlib()
    for rel in sl.touched:
        mod = idx.modules.get(rel)
        if mod is None:
            return False, f"not reproduced: {rel} was not parsed"
        for qualified in mod.imports.values():
            top = qualified.split(".")[0]
            if top in std or top in FAKE_MODULES:
                continue
            if idx.resolve_module(qualified) is not None or any(
                    idx.resolve_module(".".join(qualified.split(".")[:i])) is not None
                    for i in range(1, qualified.count(".") + 1)):
                continue
            if top in {m.split(".")[0] for m in idx.by_name}:
                continue
            return False, f"not reproduced: it needs {top!r}, which the sandbox can't provide"
    return True, ""


# --------------------------------------------------------------------------- the harness (code-authored)
def _call_name(sl: Slice) -> str:
    for c in sl.calls:
        if c.cls == sl.cls:
            return c.qualified[2:] if c.qualified.startswith("*.") else c.qualified
    return C.get(sl.cls).label


def _sources_for(sl: Slice, idx: Index) -> dict[str, str]:
    """Every .py file of the root, so intra-root imports resolve when the handler is imported."""
    return {rel: mod.text for rel, mod in idx.modules.items()}


def _canary(cls: str, token: str) -> str:
    """The value driven in. For `path`, an attack-shaped canary (a directory traversal) so a
    reproduction confirms EXPLOITABILITY (the traversal survives to `open`), not mere reachability
    -- a basename/allow-list sanitiser strips the `../` and the reproduction correctly fails.
    Other classes use the plain token (reaching an exec/deserialise sink with request data is the
    weakness; the value isn't neutralised by being quoted)."""
    return f"../../../{token}" if cls == "path" else token


def build_harness(sl: Slice, idx: Index, canary: str, *, token: str = "") -> str:
    """The pytest harness source. Code-authored in full: the model never writes any of it."""
    wc = C.get(sl.cls)
    payload = {
        "sources": {rel: base64.b64encode(text.encode("utf-8", "surrogatepass")).decode("ascii")
                    for rel, text in _sources_for(sl, idx).items()},
        "surface_rel": sl.rel, "surface_func": sl.function, "canary": canary,
        "token": token or canary, "cls": sl.cls,
        "recorders": list(wc.recorders), "call_name": _call_name(sl),
    }
    blob = base64.b64encode(json.dumps(payload).encode("ascii")).decode("ascii")
    return _HARNESS_TEMPLATE.replace("__PAYLOAD_B64__", blob)


# The harness runs INSIDE the sandbox. It must not import kratos.review (only the fakes dir); it
# uses kratos.review.fakes.FAKES_DIR for the fake-framework path (kratos is on PYTHONPATH there).
_HARNESS_TEMPLATE = r'''
import asyncio, base64, importlib, inspect, json, sys, tempfile
from pathlib import Path

_P = json.loads(base64.b64decode("__PAYLOAD_B64__").decode("ascii"))
CANARY = _P["canary"]
TOKEN = _P.get("token") or CANARY
CLS = _P.get("cls") or ""
_RECORDED = []


class _Inert:
    """A permissive stand-in the recorder returns, so handler code after the dangerous call
    (reading .stdout, indexing, iterating) does not crash and abort the reproduction."""
    def __getattr__(self, name): return _Inert()
    def __call__(self, *a, **k): return _Inert()
    def __getitem__(self, k): return _Inert()
    def __iter__(self): return iter(())
    def __int__(self): return 0
    def __str__(self): return ""
    def __bytes__(self): return b""
    def __bool__(self): return False
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _recorder(*a, **k):
    _RECORDED.append((a, k))
    return _Inert()


def _flatten(x, out):
    try:
        out.append(str(x))
    except Exception:
        pass
    if isinstance(x, dict):
        for v in x.values():
            _flatten(v, out)
    elif isinstance(x, (list, tuple, set)):
        for v in x:
            _flatten(v, out)


def _canary_seen():
    parts = []
    for a, k in _RECORDED:
        _flatten(a, parts); _flatten(k, parts)
    if CLS == "path":
        # exploitable iff the traversal SURVIVED to the call (a basename/allow-list strips ../).
        return any(TOKEN in p and "../" in p for p in parts)
    return any(TOKEN in p for p in parts)


def _unpack():
    d = Path(tempfile.mkdtemp(prefix="review-copy-"))
    for rel, b64 in _P["sources"].items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(base64.b64decode(b64))
    return d


def _patch_module_recorder(target, restores):
    """Replace a module-level (or class-method) dangerous call with the recorder, recording how to
    put the original back (so pytest's own file I/O after the test isn't left talking to a
    recorder). NOT used for `builtins:*` -- patching builtins.exec/eval would break the import
    machinery itself, so those are injected into each root module's own namespace instead."""
    mod_name, _, attr = target.partition(":")
    if mod_name == "builtins":
        return
    try:
        mod = importlib.import_module(mod_name)
    except Exception:
        return
    if "." in attr:
        cls_name, meth = attr.split(".", 1)
        obj = getattr(mod, cls_name, None)
    else:
        obj, meth = mod, attr
    if obj is None or not hasattr(obj, meth):
        return
    restores.append((obj, meth, getattr(obj, meth)))
    setattr(obj, meth, _recorder)


def _patch_builtins_in_root(root, attrs, restores):
    """A handler's bare `exec(...)`/`eval(...)` resolves via its MODULE globals before builtins,
    so the recorder is injected into every already-imported root module's namespace. builtins
    itself is never touched (the import system needs the real exec)."""
    root = str(root)
    for mod in list(sys.modules.values()):
        f = getattr(mod, "__file__", None)
        if f and str(f).startswith(root):
            for attr in attrs:
                restores.append((mod, attr, getattr(mod, attr, _MISSING)))
                setattr(mod, attr, _recorder)


_MISSING = object()


def _restore(restores):
    """Put every patched callable back, so pytest's teardown (cacheprovider, etc.) uses real I/O
    -- a recorder left on `open`/`io.open` otherwise crashes pytest and the PASS reads as a fail."""
    for obj, attr, original in restores:
        try:
            if original is _MISSING:
                delattr(obj, attr)
            else:
                setattr(obj, attr, original)
        except Exception:
            pass


def _canary_request():
    try:
        import flask
        flask.set_canary(CANARY)
        req = flask.request
    except Exception:
        req = None
    try:
        import pydantic
        pydantic.set_canary(CANARY)
    except Exception:
        pass
    try:
        import starlette.requests as _sr
        _sr.request = _sr.Request(CANARY)
    except Exception:
        pass
    return req


def _get_handler(root):
    from kratos.review.fakes import FAKES_DIR
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(FAKES_DIR))
    req = _canary_request()
    name = _P["surface_func"]
    modname = _P["surface_rel"][:-3].replace("/", ".")
    mod = importlib.import_module(modname)           # real exec runs the module body
    # Patch AFTER import: module-level dangerous calls on their own modules, and builtins
    # exec/eval into each root module's namespace (never into builtins -- that breaks import).
    restores = []
    builtin_attrs = [t.split(":", 1)[1] for t in _P["recorders"] if t.split(":", 1)[0] == "builtins"]
    for t in _P["recorders"]:
        _patch_module_recorder(t, restores)
    if builtin_attrs:
        _patch_builtins_in_root(root, builtin_attrs, restores)
    if "." in name:
        cls_name, meth = name.split(".", 1)
        cls = getattr(mod, cls_name)
        try:
            inst = cls()
        except Exception:
            inst = cls.__new__(cls)
        return getattr(inst, meth), req, restores
    return getattr(mod, name), req, restores


def _invoke(handler, req):
    try:
        sig = inspect.signature(handler)
        kwargs = {}
        for p in sig.parameters.values():
            if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                continue
            if p.name in ("self", "cls"):
                continue
            kwargs[p.name] = req if p.name in ("request", "req", "environ", "scope") and req is not None else CANARY
    except (TypeError, ValueError):
        kwargs = {}
    result = handler(**kwargs)
    if inspect.iscoroutine(result):
        asyncio.run(result)


def test_reproduce():
    reason = "the canary did not reach the dangerous call"
    try:
        root = _unpack()
        handler, req, restores = _get_handler(root)
    except Exception as e:                       # import of a third-party dependency, etc.
        reason = "not reproduced: " + type(e).__name__ + ": " + str(e)[:160]
        print(MARKER_LINE({"reproduced": False, "reason": reason}))
        import pytest; pytest.fail(reason)
        return
    try:
        _invoke(handler, req)
    except Exception as e:                        # the handler may raise after the dangerous call
        reason = "handler raised " + type(e).__name__
    finally:
        _restore(restores)                        # put real I/O back before pytest teardown
    if _canary_seen():
        print(MARKER_LINE({"reproduced": True, "call": _P["call_name"]}))
        return
    print(MARKER_LINE({"reproduced": False, "reason": reason}))
    import pytest; pytest.fail(reason)


def MARKER_LINE(d):
    return "__REVIEW_REPRO__ " + json.dumps(d)
'''


# --------------------------------------------------------------------------- running it
def _review_work(data_dir: Path | str) -> Path:
    return Path(data_dir) / WORK_DIRNAME


def sweep(data_dir: Path | str) -> None:
    """Remove any `.review-work` a crash left (swept at the next review start). Never backed up."""
    work = _review_work(data_dir)
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)


def _parse_marker(text: str) -> dict[str, Any] | None:
    for line in reversed((text or "").splitlines()):
        line = line.strip()
        if line.startswith(MARKER):
            try:
                return json.loads(line[len(MARKER):].strip())
            except ValueError:
                return None
    return None


def _default_runner() -> Runner:
    def run(candidate: Path, harness: Path) -> Any:
        from kratos.agent.self_test import run_sandbox_test
        return run_sandbox_test(candidate, harness)
    return run


def reproduce(sl: Slice, idx: Index, *, data_dir: Path | str, run_id: str, enabled: bool,
              runner: Runner | None = None) -> Repro:
    """Attempt to reproduce one slice. Returns a `verdict.Repro` (facts only). The real
    dangerous call is never executed -- the recorder replaces it."""
    if not enabled:
        return Repro(status=R_OFF)
    if sl.language != "python" or sl.cls not in REPRODUCIBLE:
        return Repro(status=R_NOT_ATTEMPTED)
    ok, reason = self_contained(sl, idx)
    if not ok:
        return Repro(status=R_NOT_REPRODUCED, reason=reason)

    import secrets as _secrets
    token = "KRATOSCANARY_" + _secrets.token_hex(8)
    canary = _canary(sl.cls, token)
    work = _review_work(data_dir) / run_id / sl.id
    try:
        work.mkdir(parents=True, exist_ok=True)
        os.chmod(_review_work(data_dir), stat.S_IRWXU)
        candidate = work / "candidate.py"
        harness = work / "harness.py"
        candidate.write_text("# review reproduction placeholder (logic is in the harness)\n")
        harness.write_text(build_harness(sl, idx, canary, token=token))
        for p in (candidate, harness):
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        runner = runner or _default_runner()
        with sandbox_lock.hold():
            result = runner(candidate, harness)
        return _result_to_repro(result, sl)
    finally:
        shutil.rmtree(_review_work(data_dir) / run_id, ignore_errors=True)


def _result_to_repro(result: Any, sl: Slice) -> Repro:
    if getattr(result, "infra_error", None):
        return Repro(status=R_NOT_REPRODUCED,
                     reason="reproduction could not run (the sandbox was unavailable)")
    if getattr(result, "timed_out", False):
        return Repro(status=R_NOT_REPRODUCED, reason="not reproduced: sandbox timeout")
    marker = _parse_marker(getattr(result, "stdout", "") or "") or \
        _parse_marker(getattr(result, "stderr", "") or "")
    if getattr(result, "passed", False) and (marker is None or marker.get("reproduced")):
        call = (marker or {}).get("call") or _call_name(sl)
        return Repro(status=R_REPRODUCED, evidence=f"the canary reached {call}() in the sandbox")
    reason = (marker or {}).get("reason") or "the canary did not reach the dangerous call"
    return Repro(status=R_NOT_REPRODUCED, reason=str(reason)[:300])


# --------------------------------------------------------------------------- fix re-check
def fix_recheck(sl: Slice, idx: Index, fix_added: str, *, data_dir: Path | str, run_id: str,
                enabled: bool, runner: Runner | None = None) -> str:
    """For a reproduced finding: apply the model's added lines to the scratch copy's surface
    function and re-run the same harness. 'checked' when the canary no longer reaches the call,
    'not_confirmed' when it still does, 'not_checked' when the patch can't be applied cleanly or
    reproduction is off. Nothing is written to the machine."""
    if not enabled:
        return "not_checked"
    patched = _apply_added(sl, idx, fix_added)
    if patched is None:
        return "not_checked"
    idx2, sl2 = patched
    repro = reproduce(sl2, idx2, data_dir=data_dir, run_id=f"{run_id}-fix", enabled=enabled, runner=runner)
    if repro.status == R_REPRODUCED:
        return "not_confirmed"              # the canary still reaches the call -> fix didn't work
    if repro.status == R_NOT_REPRODUCED and "canary did not reach" in (repro.reason or ""):
        return "checked"
    return "not_checked"


def _apply_added(sl: Slice, idx: Index, fix_added: str) -> tuple[Index, Slice] | None:
    """A conservative in-memory patch: the model's added lines must stay inside the slice's
    surface function; we replace that function's body-bearing lines with the added lines. A
    patch that can't be placed inside the slice returns None ('fix not checked')."""
    import ast
    from kratos.review.slice import build_index
    added = [ln for ln in (fix_added or "").splitlines() if ln.strip()]
    if not added:
        return None
    mod = idx.modules.get(sl.rel)
    if mod is None or sl.function not in mod.functions:
        return None
    start, end = sl.span
    lines = mod.text.splitlines()
    if start < 1 or end > len(lines):
        return None
    # Replace the function's lines with the added lines; must still parse.
    new_lines = lines[:start - 1] + added + lines[end:]
    new_text = "\n".join(new_lines)
    try:
        ast.parse(new_text)
    except SyntaxError:
        return None
    files = {rel: m.text for rel, m in idx.modules.items()}
    files[sl.rel] = new_text
    idx2 = build_index(files)
    if sl.rel not in idx2.modules or sl.function not in idx2.modules[sl.rel].functions:
        return None
    fn = idx2.modules[sl.rel].functions[sl.function]
    from kratos.review.slice import _span
    sl2 = Slice(root=sl.root, rel=sl.rel, function=sl.function, cls=sl.cls, span=_span(fn),
                surface_kind=sl.surface_kind, methods=sl.methods, route=sl.route,
                segments=[(sl.rel, *_span(fn))], calls=sl.calls, touched=sl.touched, imports=sl.imports,
                text=new_text, sha256=sl.sha256 + "-fix", context_sha256=sl.context_sha256, language="python")
    return idx2, sl2
