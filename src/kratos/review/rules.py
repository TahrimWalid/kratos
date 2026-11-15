"""Direct rules over the AST (E.7b §3.6, step 2).

A ``direct`` match is the only thing that can make a lead ``confirmed`` without a sandbox
reproduction, and a ``direct`` finding of an execution-like class on an internet-exposed
process can be **high** -- so this analysis is deliberately CONSERVATIVE, for precision:

- it is **intraprocedural** -- the request value and the dangerous call must be in the **same
  function** (a flow through a helper is for reproduction, not a direct rule);
- the value may travel only through **assignments, indexing/attribute access, and string
  building** (`+`, `%`, an f-string, ``.format``, ``str.join``, ``.encode``/``.decode``). Any
  **other call** on the value -- ``shlex.quote(x)``, ``int(x)``, ``secure_filename(x)``, an
  unknown helper -- **breaks the chain**: Kratos doesn't recognise it, so the rule does not
  match and the lead falls to ``needs_validation`` (the verifier may name the check);
- for a shell command the dangerous argument must reach a **shell context** (``os.system``,
  ``shell=True``, ...); a list-form ``subprocess`` call is not a direct shell-injection match;
- for SQL the request value must be in the **query string**, not the parameters.

No model text is read here. The result is a ``verdict.RuleMatch`` with code-owned evidence
(the callable and line number), never a severity.
"""
from __future__ import annotations

import ast

from kratos.review import classes as C
from kratos.review import slice as SL
from kratos.review.slice import Module
from kratos.review.verdict import RuleMatch

# A request parameter by these names is a request object itself (Django `request`, a WSGI
# `environ`, an ASGI `scope`), on top of the module-level `request` aliases the slicer found.
REQUEST_PARAM_NAMES = frozenset({"request", "req", "environ", "scope"})
# String operations that keep attacker control (building, not sanitising).
STRING_METHODS = frozenset({"format", "join", "encode", "decode"})
# Shell callables that always run a shell; others need shell=True.
ALWAYS_SHELL = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                          "commands.getoutput", "commands.getstatusoutput"})


# Modules whose module-level `request` IS the per-request object, so `flask.request.args`
# (the common `import flask` style, not only `from flask import request`) is a request source.
REQUEST_MODULES = frozenset({"flask", "quart", "bottle"})


def request_roots(mod: Module, fn: ast.AST) -> frozenset[str]:
    roots = set(mod.request_names)
    args = fn.args
    for a in (list(getattr(args, "posonlyargs", [])) + list(args.args) + list(args.kwonlyargs)):
        if a.arg in REQUEST_PARAM_NAMES:
            roots.add(a.arg)
    return frozenset(roots)


def request_modules(mod: Module) -> frozenset[str]:
    """Local names bound to a framework module whose `.request` is the request object
    (`import flask` -> {"flask"}; `import flask as f` -> {"f"})."""
    return frozenset(alias for alias, q in mod.imports.items() if q in REQUEST_MODULES)


def _is_request_expr(node: ast.AST, roots: frozenset[str], req_modules: frozenset[str] = frozenset()) -> bool:
    """A read off a request object: `request`, `request.args`, `request.form['x']`,
    `request.args.get('x')`, `environ['PATH_INFO']`, and the module-dotted `flask.request...`."""
    if isinstance(node, ast.Name):
        return node.id in roots
    if isinstance(node, ast.Attribute):
        if node.attr == "request" and isinstance(node.value, ast.Name) and node.value.id in req_modules:
            return True            # flask.request
        return _is_request_expr(node.value, roots, req_modules)
    if isinstance(node, ast.Subscript):
        return _is_request_expr(node.value, roots, req_modules)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _is_request_expr(node.func.value, roots, req_modules)
    return False


def _is_tainted(node: ast.AST, tainted: frozenset[str], roots: frozenset[str],
                req_modules: frozenset[str] = frozenset()) -> bool:
    if _is_request_expr(node, roots, req_modules):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _is_tainted(node.value, tainted, roots, req_modules)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return (_is_tainted(node.left, tainted, roots, req_modules)
                or _is_tainted(node.right, tainted, roots, req_modules))
    if isinstance(node, ast.JoinedStr):
        return any(_is_tainted(v.value, tainted, roots, req_modules) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.FormattedValue):
        return _is_tainted(node.value, tainted, roots, req_modules)
    if isinstance(node, ast.Starred):
        return _is_tainted(node.value, tainted, roots, req_modules)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return any(_is_tainted(e, tainted, roots, req_modules) for e in node.elts)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in STRING_METHODS:
            # "{}".format(x), sep.join(parts), x.encode() -- string building keeps taint.
            return (_is_tainted(func.value, tainted, roots, req_modules)
                    or any(_is_tainted(a, tainted, roots, req_modules) for a in node.args))
        if isinstance(func, ast.Attribute) and _is_request_expr(func.value, roots, req_modules):
            return True            # request.args.get('x')
        return False               # any other call is unrecognised -> breaks the chain
    return False


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [n for e in node.elts for n in _targets(e)]
    if isinstance(node, ast.Starred):
        return _targets(node.value)
    return []


def taints(mod: Module, fn: ast.AST, roots: frozenset[str],
           req_modules: frozenset[str] = frozenset()) -> frozenset[str]:
    """Local names holding a request-derived value, by a fixpoint over the function's
    assignments using the string-building taint rule above."""
    tainted: set[str] = set()
    # Collect assignment-like bindings once; iterate to a fixpoint (assignments can appear
    # before the names they read in source order; walk order is not source order).
    binds: list[tuple[ast.AST, list[str]]] = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign):
            binds.append((n.value, [t for tgt in n.targets for t in _targets(tgt)]))
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            binds.append((n.value, _targets(n.target)))
        elif isinstance(n, ast.AugAssign):
            binds.append((n.value, _targets(n.target)))        # x += tainted
        elif isinstance(n, ast.NamedExpr):
            binds.append((n.value, _targets(n.target)))
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            binds.append((n.iter, _targets(n.target)))         # for x in request.args.getlist(...)
    for _ in range(len(binds) + 1):
        changed = False
        for value, names in binds:
            if names and _is_tainted(value, frozenset(tainted), roots, req_modules) and not set(names) <= tainted:
                tainted.update(names)
                changed = True
        if not changed:
            break
    return frozenset(tainted)


def _shell_context(qualified: str, call: ast.Call) -> bool:
    if qualified in ALWAYS_SHELL:
        return True
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _dangerous_args(cls: str, qualified: str, call: ast.Call) -> list[ast.AST]:
    """The argument expressions that carry the dangerous value for this class."""
    if cls == "exec":
        if qualified in ("builtins.eval", "builtins.exec", "builtins.compile"):
            return call.args[:1]
        if _shell_context(qualified, call):
            return call.args[:1]        # the command string
        return []                       # list-form subprocess with no shell is not a direct match
    if cls == "sql":
        return call.args[:1]            # the query string; parameters (arg1+) are not a direct match
    # deserialise, template, path, upload: the first positional carries the value.
    return call.args[:1]


def direct(idx: SL.Index, sl: SL.Slice) -> RuleMatch:
    """Does a request value reach this slice's dangerous call inside the surface function,
    through string building only, with no check Kratos recognises?"""
    mod = idx.modules.get(sl.rel)
    if mod is None or sl.function not in mod.functions:
        return RuleMatch(matched=False)
    fn = mod.functions[sl.function]

    if sl.cls == "noauth":
        verbs = "/".join(m.upper() for m in sl.methods if m != "*") or "state-changing"
        return RuleMatch(matched=True,
                         evidence=f"a {verbs} route with no login check Kratos can see on its path")

    roots = request_roots(mod, fn)
    req_modules = request_modules(mod)
    tnt = taints(mod, fn, roots, req_modules)
    for call, qualified, c in SL.sink_calls(mod, fn):
        if c != sl.cls:
            continue
        for arg in _dangerous_args(sl.cls, qualified, call):
            if _is_tainted(arg, tnt, roots, req_modules):
                name = qualified[2:] if qualified.startswith("*.") else qualified
                return RuleMatch(matched=True,
                                 evidence=f"a request value reaches {name}() at line {call.lineno} "
                                          "through string building, with no check Kratos recognises")
    return RuleMatch(matched=False)
