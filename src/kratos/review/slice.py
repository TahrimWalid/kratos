"""Python slicer (E.7b §3.3): the statements the network can reach, not the repository.

Runs on Kratos, in memory, over the source a person agreed to read (E.7a's `review` read).
Nothing here imports, compiles or runs the machine's code: only `ast.parse`.

1. **Index** every `.py` file of the root: its imports (alias -> qualified name), its
   functions and methods, and the module name(s) it can be imported as.
2. **Surfaces** -- the network's way in, from a closed pattern set: Flask / FastAPI /
   Starlette route decorators (``@x.route``, ``@x.get`` ...), Django ``urlpatterns``,
   class-based views' HTTP methods, bare WSGI ``application(environ, start_response)``
   and ASGI ``app(scope, receive, send)``.
3. From each surface, follow calls into functions **inside the root**, up to
   ``review.slice_depth`` deep, and find the **dangerous calls** of the closed classes
   (kratos.review.classes). One slice per (surface, class): the surface, the functions on the
   path to each dangerous call, and the touched files' import lines.

Each slice records its file, line span, function, class, the call sites, a **slice sha256**
(over its source text only -- unrelated edits elsewhere leave it unchanged) and a **context
sha256** (over every touched file's hash, the web-server decision for the root and its
lockfiles -- any of those changing means "review it again").
"""
from __future__ import annotations

import ast
import hashlib
import json
import posixpath
from dataclasses import dataclass, field
from typing import Any, Iterable

from kratos.review import classes as C

HTTP_VERBS = ("get", "post", "put", "delete", "patch", "head", "options")
MUTATING = frozenset({"post", "put", "delete", "patch"})
ROUTE_DECORATORS = frozenset({"route", "api_route", "websocket", *HTTP_VERBS})
VIEW_BASES = ("View", "MethodView", "APIView", "TemplateView", "FormView", "GenericAPIView", "HTTPEndpoint",
              "Resource")
URL_FUNCS = frozenset({"path", "re_path", "url"})
AUTH_DECORATORS = frozenset({"login_required", "permission_required", "user_passes_test", "requires_auth",
                             "auth_required", "jwt_required", "token_required", "admin_required", "roles_required",
                             "roles_accepted", "staff_member_required", "superuser_required", "fresh_login_required",
                             "requires_login", "authenticated", "require_login", "basic_auth_required",
                             "auth.login_required", "csrf_protect"})
AUTH_NAMES = frozenset({"current_user", "session", "authorization", "is_authenticated", "check_auth", "authenticate",
                        "verify_token", "get_current_user", "require_auth", "login_required", "abort_if_not_logged",
                        "verify_password", "check_password", "has_permission", "is_admin", "g.user"})
BUILTIN_SINKS = frozenset({"open", "eval", "exec"})
LOCKFILES = ("requirements.txt", "poetry.lock", "pipfile.lock", "uv.lock", "package-lock.json", "yarn.lock",
             "pnpm-lock.yaml", "composer.lock", "go.sum", "go.mod", "gemfile.lock", "cargo.lock")


# --------------------------------------------------------------------------- index
@dataclass
class Module:
    rel: str
    text: str
    tree: ast.Module
    names: tuple[str, ...]                     # dotted names it can be imported as
    imports: dict[str, str]                    # local alias -> qualified ("subprocess.run", "app.helpers")
    functions: dict[str, ast.AST]              # "f" and "Class.method" -> node
    import_lines: list[tuple[int, int]]        # top-level import statements' spans
    request_names: frozenset[str]              # names bound to flask/werkzeug/starlette `request`

    def lines(self, start: int, end: int) -> list[str]:
        return self.text.splitlines()[start - 1:end]


@dataclass
class Index:
    modules: dict[str, Module]                 # rel -> module
    by_name: dict[str, str]                    # dotted module name -> rel
    not_parsed: dict[str, str] = field(default_factory=dict)   # rel -> reason

    def resolve_module(self, dotted: str) -> Module | None:
        rel = self.by_name.get(dotted)
        return self.modules.get(rel) if rel else None


def _module_names(rel: str) -> tuple[str, ...]:
    """`app/views.py` -> ("app.views", "views"); `pkg/__init__.py` -> ("pkg",). Every suffix,
    so a module imported relative to any folder on sys.path resolves."""
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return tuple(".".join(parts[i:]) for i in range(len(parts)) if parts[i:])


def _package_of(rel: str) -> str:
    parts = rel[:-3].split("/")
    return ".".join(parts[:-1])


def _imports(tree: ast.Module, rel: str) -> tuple[dict[str, str], list[tuple[int, int]]]:
    out: dict[str, str] = {}
    spans: list[tuple[int, int]] = []
    pkg = _package_of(rel)
    for node in tree.body:
        if isinstance(node, ast.Import):
            spans.append((node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno))
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    out[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            spans.append((node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno))
            base = node.module or ""
            if node.level:
                up = pkg.split(".") if pkg else []
                up = up[:len(up) - (node.level - 1)] if node.level > 1 else up
                base = ".".join([*up, base] if base else up)
            for a in node.names:
                if a.name == "*":
                    continue
                out[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
    return out, spans


def _functions(tree: ast.Module) -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[f"{node.name}.{sub.name}"] = sub
    return out


def build_index(files: dict[str, str]) -> Index:
    """`files`: relpath -> decoded text (only `.py`)."""
    modules: dict[str, Module] = {}
    by_name: dict[str, str] = {}
    not_parsed: dict[str, str] = {}
    for rel in sorted(files):
        if not rel.endswith(".py"):
            continue
        text = files[rel]
        try:
            tree = ast.parse(text, filename="<review>")
        except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
            not_parsed[rel] = f"not parsed: {type(e).__name__}"
            continue
        imports, spans = _imports(tree, rel)
        req = frozenset(a for a, q in imports.items()
                        if q in ("flask.request", "werkzeug.wrappers.request", "starlette.requests.request",
                                 "bottle.request", "quart.request", "flask.globals.request"))
        mod = Module(rel, text, tree, _module_names(rel), imports, _functions(tree), spans, req)
        modules[rel] = mod
        for n in mod.names:
            by_name.setdefault(n, rel)
    return Index(modules, by_name, not_parsed)


# --------------------------------------------------------------------------- names
def dotted(node: ast.AST) -> str | None:
    """`a.b.c` -> "a.b.c" for a pure attribute chain on a name, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def qualify(mod: Module, func: ast.AST, local_names: frozenset[str] = frozenset()) -> str | None:
    """The fully qualified name a call's callee refers to through the module's imports;
    `*.method` for a method on something Kratos can't type."""
    d = dotted(func)
    if d is None:
        if isinstance(func, ast.Attribute):
            return f"*.{func.attr}"
        return None
    head, _, rest = d.partition(".")
    if head in mod.imports and head not in local_names:
        q = mod.imports[head]
        return f"{q}.{rest}" if rest else q
    if not rest and head in BUILTIN_SINKS and head not in mod.functions and head not in local_names:
        return f"builtins.{head}"
    if rest:
        return f"*.{d.rsplit('.', 1)[1]}"
    return d


def _locals(fn: ast.AST) -> frozenset[str]:
    names = {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)} if hasattr(fn, "args") else set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            names.add(n.id)
    return frozenset(names)


# --------------------------------------------------------------------------- surfaces
@dataclass(frozen=True)
class Surface:
    rel: str
    function: str                  # "f" or "Class.method"
    kind: str                      # flask | fastapi | django | wsgi | asgi | view
    methods: tuple[str, ...]       # lower-case verbs; ("*",) when unknown
    path: str                      # the route pattern when given ("" otherwise)


def _decorator_route(dec: ast.AST) -> tuple[str, tuple[str, ...], str] | None:
    call = dec if isinstance(dec, ast.Call) else None
    func = call.func if call else dec
    if not isinstance(func, ast.Attribute) or func.attr not in ROUTE_DECORATORS:
        return None
    path = ""
    if call and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        path = call.args[0].value
    if func.attr in HTTP_VERBS:
        return "fastapi" if func.attr != "route" else "flask", (func.attr,), path
    methods: tuple[str, ...] = ("get",)
    for kw in (call.keywords if call else []):
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            ms = [e.value.lower() for e in kw.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            methods = tuple(ms) or ("get",)
    if func.attr == "websocket":
        methods = ("*",)
    return "flask", methods, path


def _decorator_names(fn: ast.AST) -> set[str]:
    out = set()
    for dec in getattr(fn, "decorator_list", []):
        node = dec.func if isinstance(dec, ast.Call) else dec
        d = dotted(node)
        if d:
            out.add(d)
            out.add(d.rsplit(".", 1)[-1])
    return out


def _depends_auth(fn: ast.AST) -> bool:
    """FastAPI: a parameter defaulting to Depends(<something about auth/users>)."""
    defaults = list(getattr(fn.args, "defaults", [])) + [d for d in getattr(fn.args, "kw_defaults", []) if d]
    for d in defaults:
        if isinstance(d, ast.Call) and (dotted(d.func) or "").endswith(("Depends", "Security")):
            text = ast.dump(d).lower()
            if any(w in text for w in ("auth", "user", "token", "login", "permission", "admin", "security", "oauth")):
                return True
    return False


def surfaces(idx: Index) -> list[Surface]:
    out: list[Surface] = []
    seen: set[tuple[str, str]] = set()

    def add(s: Surface) -> None:
        if (s.rel, s.function) not in seen:
            seen.add((s.rel, s.function))
            out.append(s)

    for rel, mod in idx.modules.items():
        for name, fn in mod.functions.items():
            for dec in getattr(fn, "decorator_list", []):
                r = _decorator_route(dec)
                if r:
                    add(Surface(rel, name, r[0], r[1], r[2]))
                    break
            if "." not in name:
                params = [a.arg for a in fn.args.args]
                if name == "application" and len(params) == 2:
                    add(Surface(rel, name, "wsgi", ("*",), ""))
                elif name in ("app", "application") and len(params) == 3 and isinstance(fn, ast.AsyncFunctionDef):
                    add(Surface(rel, name, "asgi", ("*",), ""))
        for node in mod.tree.body:
            if isinstance(node, ast.ClassDef):
                bases = {(dotted(b) or "").rsplit(".", 1)[-1] for b in node.bases}
                if bases & set(VIEW_BASES):
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name in HTTP_VERBS:
                            add(Surface(rel, f"{node.name}.{sub.name}", "view", (sub.name,), ""))
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "urlpatterns"
                                                    for t in node.targets):
                for call in ast.walk(node.value):
                    if not (isinstance(call, ast.Call) and (dotted(call.func) or "").rsplit(".", 1)[-1] in URL_FUNCS):
                        continue
                    if len(call.args) < 2:
                        continue
                    target = _resolve_ref(idx, mod, call.args[1])
                    if target:
                        pat = call.args[0].value if isinstance(call.args[0], ast.Constant) else ""
                        add(Surface(target[0], target[1], "django", _django_methods(idx, target), str(pat)))
    return out


def _django_methods(idx: Index, target: tuple[str, str]) -> tuple[str, ...]:
    fn = idx.modules[target[0]].functions.get(target[1])
    names = _decorator_names(fn) if fn is not None else set()
    if "require_POST" in names:
        return ("post",)
    if "require_GET" in names or "require_safe" in names:
        return ("get",)
    return ("*",)


def _resolve_ref(idx: Index, mod: Module, node: ast.AST) -> tuple[str, str] | None:
    """A function reference (`views.f`, `f`, `View.as_view()`) -> (rel, function name) inside the root."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
        node = node.func.value
    d = dotted(node)
    if not d:
        return None
    if d in mod.functions:
        return mod.rel, d
    head, _, rest = d.partition(".")
    q = mod.imports.get(head)
    if q is None:
        return None
    full = f"{q}.{rest}" if rest else q
    return _resolve_qualified(idx, full)


def _resolve_qualified(idx: Index, full: str) -> tuple[str, str] | None:
    """`app.helpers.run` -> (rel of app/helpers.py, "run"); also `pkg.mod.Class` -> its class (first method)."""
    parts = full.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        m = idx.resolve_module(".".join(parts[:cut]))
        if m is None:
            continue
        name = ".".join(parts[cut:])
        if name in m.functions:
            return m.rel, name
        if any(k.startswith(name + ".") for k in m.functions):
            return m.rel, name
        return None
    return None


# --------------------------------------------------------------------------- calls and sinks
@dataclass(frozen=True)
class CallSite:
    rel: str
    function: str
    line: int
    qualified: str
    cls: str


def _callee(idx: Index, mod: Module, fn_name: str, call: ast.Call) -> tuple[str, str] | None:
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in mod.functions:
            return mod.rel, func.id
        q = mod.imports.get(func.id)
        return _resolve_qualified(idx, q) if q else None
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in ("self", "cls") and "." in fn_name:
            cname = fn_name.split(".", 1)[0]
            key = f"{cname}.{func.attr}"
            return (mod.rel, key) if key in mod.functions else None
        d = dotted(func)
        if d:
            head, _, rest = d.partition(".")
            q = mod.imports.get(head)
            if q is not None:
                return _resolve_qualified(idx, f"{q}.{rest}")
    return None


def _from_request_files(node: ast.AST, mod: Module, fn: ast.AST) -> bool:
    """Is `node` (a `.save` receiver) an uploaded file -- `request.files[...]`, or a name assigned from it?"""
    def is_files(n: ast.AST) -> bool:
        d = dotted(n.value) if isinstance(n, ast.Subscript) else None
        if d is None and isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("get", "getlist"):
            d = dotted(n.func.value)
        return bool(d and (d.endswith(".files") or d.endswith(".FILES")))
    if is_files(node):
        return True
    if isinstance(node, ast.Name):
        for a in ast.walk(fn):
            if isinstance(a, ast.Assign) and any(isinstance(t, ast.Name) and t.id == node.id for t in a.targets):
                if is_files(a.value):
                    return True
            if isinstance(a, (ast.For, ast.comprehension)) and isinstance(a.target, ast.Name) and \
                    a.target.id == node.id:
                it = a.iter
                if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute):
                    it = it.func.value
                d = dotted(it) or ""
                if d.endswith(".files") or d.endswith(".FILES") or "getlist" in ast.dump(a.iter):
                    return True
    return False


def sinks_in(mod: Module, fn_name: str, fn: ast.AST) -> list[CallSite]:
    out: list[CallSite] = []
    local = _locals(fn)
    for call in ast.walk(fn):
        if not isinstance(call, ast.Call):
            continue
        q = qualify(mod, call.func, local - set(mod.imports))
        if q is None:
            continue
        if q.startswith("*."):
            # A method on a receiver Kratos can't type is taken only in its receiver shape,
            # so "*.save" doesn't mean every save() and "*.execute()" needs an argument. These
            # must NOT fall through to class_for_sink (the class sink tables list them too).
            cls = C.METHOD_SINKS.get(q[2:])
            if cls == "upload" and not _from_request_files(call.func.value, mod, fn):
                cls = None
            elif cls == "sql" and not call.args:
                cls = None
        else:
            cls = C.class_for_sink(q)
        if cls:
            out.append(CallSite(mod.rel, fn_name, call.lineno, q, cls))
    return out


# --------------------------------------------------------------------------- slices
@dataclass
class Slice:
    root: str
    rel: str                         # the surface's file
    function: str                    # the surface function
    cls: str
    span: tuple[int, int]            # the surface function's lines
    surface_kind: str
    methods: tuple[str, ...]
    route: str
    segments: list[tuple[str, int, int]]   # (rel, start, end) of every piece sent
    calls: list[CallSite]
    touched: tuple[str, ...]         # files the slice's path touches
    imports: frozenset[str]          # top-level modules imported by the touched files
    text: str                        # what the model is sent: numbered source lines
    sha256: str                      # over the source text only
    context_sha256: str = ""
    part: int = 0                    # >0 when split by function
    drift: bool = False
    exposure: str = "unknown"        # internet | network | local | not_running | unknown
    served: str = "imported"         # executed | served | imported
    language: str = "python"
    nbytes: int = 0

    @property
    def id(self) -> str:
        return self.sha256[:16]

    def entity(self) -> str:
        return f"{self.rel}:{self.function}:{self.cls}"


@dataclass
class SliceStats:
    root_bytes: int = 0
    python_files: int = 0
    sliced_bytes: int = 0
    surfaces: int = 0
    too_large: int = 0
    not_parsed: dict[str, str] = field(default_factory=dict)
    other_language: dict[str, int] = field(default_factory=dict)    # extension -> files not sliced


def _span(node: ast.AST) -> tuple[int, int]:
    start = min([node.lineno, *[d.lineno for d in getattr(node, "decorator_list", [])]])
    return start, int(getattr(node, "end_lineno", node.lineno) or node.lineno)


def _numbered(rel: str, mod: Module, start: int, end: int) -> str:
    head = f"# file {json.dumps(rel, ensure_ascii=True)} lines {start}-{end}"
    body = [f"{n:>5}| {line}" for n, line in zip(range(start, end + 1), mod.lines(start, end))]
    return "\n".join([head, *body])


def _reach(idx: Index, start: tuple[str, str], depth: int) -> dict[tuple[str, str], tuple[str, str] | None]:
    """BFS over calls inside the root: node -> parent (None for the start)."""
    parent: dict[tuple[str, str], tuple[str, str] | None] = {start: None}
    frontier = [start]
    for _ in range(depth):
        nxt = []
        for key in frontier:
            mod = idx.modules[key[0]]
            fn = mod.functions.get(key[1])
            if fn is None:
                continue
            for call in ast.walk(fn):
                if isinstance(call, ast.Call):
                    tgt = _callee(idx, mod, key[1], call)
                    if tgt and tgt not in parent and tgt[1] in idx.modules[tgt[0]].functions:
                        parent[tgt] = key
                        nxt.append(tgt)
        frontier = nxt
    return parent


def _path_to(parent: dict, node: tuple[str, str]) -> list[tuple[str, str]]:
    out = []
    while node is not None:
        out.append(node)
        node = parent[node]
    return list(reversed(out))


def has_auth(mod: Module, fn: ast.AST) -> bool:
    if _decorator_names(fn) & AUTH_DECORATORS or _depends_auth(fn):
        return True
    for n in ast.walk(fn):
        d = dotted(n) if isinstance(n, (ast.Name, ast.Attribute)) else None
        if d and (d in AUTH_NAMES or d.rsplit(".", 1)[-1] in AUTH_NAMES):
            return True
        if isinstance(n, ast.Call):
            cd = dotted(n.func) or ""
            if cd.endswith("abort") and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value in (401, 403):
                return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.lower() in ("authorization", "x-api-key"):
            return True
    return False


def _hash(parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()


def context_hash(touched: Iterable[str], file_hashes: dict[str, str], serving: str, lockfiles: dict[str, str]) -> str:
    items = [f"f:{r}={file_hashes.get(r, '')}" for r in sorted(set(touched))]
    items.append(f"serving:{serving}")
    items.extend(f"lock:{k}={v}" for k, v in sorted(lockfiles.items()))
    return _hash(items)


def lockfile_hashes(file_hashes: dict[str, str]) -> dict[str, str]:
    return {r: h for r, h in file_hashes.items() if posixpath.basename(r).lower() in LOCKFILES
            or (posixpath.basename(r).lower().startswith("requirements") and r.endswith(".txt"))}


def slice_root(root: str, files: dict[str, str], *, file_hashes: dict[str, str], serving: str = "",
               depth: int = 4, max_slice_bytes: int = 64 * 1024, all_sizes: dict[str, int] | None = None,
               index: Index | None = None) -> tuple[list[Slice], SliceStats, Index]:
    """Slices of one root's Python source. `files`: relpath -> text of the source read;
    `file_hashes`: relpath -> sha256 from E.7a's inventory (the context hash);
    `all_sizes`: relpath -> size of EVERY inventory file (the reduction's denominator)."""
    idx = index or build_index(files)
    stats = SliceStats(not_parsed=dict(idx.not_parsed))
    stats.root_bytes = sum((all_sizes or {r: len(t.encode("utf-8", "replace")) for r, t in files.items()}).values())
    stats.python_files = len(idx.modules)
    locks = lockfile_hashes(file_hashes)
    out: list[Slice] = []
    surf = surfaces(idx)
    stats.surfaces = len(surf)
    for s in surf:
        mod = idx.modules[s.rel]
        fn = mod.functions[s.function]
        parent = _reach(idx, (s.rel, s.function), depth)
        by_cls: dict[str, list[CallSite]] = {}
        for key in parent:
            kmod = idx.modules[key[0]]
            kfn = kmod.functions.get(key[1])
            if kfn is None:
                continue
            for cs in sinks_in(kmod, key[1], kfn):
                by_cls.setdefault(cs.cls, []).append(cs)
        if (set(s.methods) & MUTATING) and not has_auth(mod, fn):
            by_cls.setdefault("noauth", [])
        for cls, calls in by_cls.items():
            keys: list[tuple[str, str]] = [(s.rel, s.function)]
            for cs in calls:
                for k in _path_to(parent, (cs.rel, cs.function)):
                    if k not in keys:
                        keys.append(k)
            out.extend(_make(root, idx, s, cls, calls, keys, file_hashes, serving, locks, max_slice_bytes, stats))
    stats.sliced_bytes = sum(sl.nbytes for sl in out)
    return out, stats, idx


def _make(root: str, idx: Index, s: Surface, cls: str, calls: list[CallSite], keys: list[tuple[str, str]],
          file_hashes: dict[str, str], serving: str, locks: dict[str, str], max_bytes: int,
          stats: SliceStats) -> list[Slice]:
    mod = idx.modules[s.rel]
    fn = mod.functions[s.function]
    span = _span(fn)
    touched = tuple(dict.fromkeys(k[0] for k in keys))
    pieces: list[tuple[str, int, int]] = []
    for rel in touched:
        for a, b in idx.modules[rel].import_lines:
            pieces.append((rel, a, b))
    funcs = [(k[0], *_span(idx.modules[k[0]].functions[k[1]])) for k in keys]
    imports = frozenset(q.split(".")[0] for rel in touched for q in idx.modules[rel].imports.values())
    ctx = context_hash(touched, file_hashes, serving, locks)

    def build(segs: list[tuple[str, int, int]], part: int) -> Slice:
        src = [line for rel, a, b in segs for line in idx.modules[rel].lines(a, b)]
        text = "\n".join(_numbered(rel, idx.modules[rel], a, b) for rel, a, b in segs)
        sha = _hash([cls, *src])
        return Slice(root=root, rel=s.rel, function=s.function, cls=cls, span=span, surface_kind=s.kind,
                     methods=s.methods, route=s.path, segments=segs, calls=list(calls), touched=touched,
                     imports=imports, text=text, sha256=sha, context_sha256=ctx, part=part,
                     nbytes=len(text.encode("utf-8", "replace")))

    whole = build(_merge(pieces + funcs), 0)
    if whole.nbytes <= max_bytes:
        return [whole]
    out = []
    for n, f in enumerate(funcs, 1):
        part = build(_merge([p for p in pieces if p[0] == f[0]] + [f]), n)
        if part.nbytes > max_bytes:
            stats.too_large += 1
            continue
        out.append(part)
    return out


def _merge(segs: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Sorted per file, overlapping/adjacent spans merged; files in first-seen order."""
    order: list[str] = []
    by: dict[str, list[tuple[int, int]]] = {}
    for rel, a, b in segs:
        if rel not in by:
            order.append(rel)
            by[rel] = []
        by[rel].append((a, b))
    out = []
    for rel in order:
        spans = sorted(by[rel])
        cur = list(spans[0])
        for a, b in spans[1:]:
            if a <= cur[1] + 1:
                cur[1] = max(cur[1], b)
            else:
                out.append((rel, cur[0], cur[1]))
                cur = [a, b]
        out.append((rel, cur[0], cur[1]))
    return out


def spans_of(sl: Slice) -> dict[str, list[tuple[int, int]]]:
    out: dict[str, list[tuple[int, int]]] = {}
    for rel, a, b in sl.segments:
        out.setdefault(rel, []).append((a, b))
    return out


def as_record(sl: Slice) -> dict[str, Any]:
    """What is stored about a slice (never its text)."""
    return {"rel": sl.rel, "function": sl.function, "cls": sl.cls, "span": list(sl.span),
            "segments": [list(x) for x in sl.segments], "sha256": sl.sha256, "context_sha256": sl.context_sha256,
            "part": sl.part, "drift": sl.drift, "exposure": sl.exposure, "served": sl.served,
            "language": sl.language, "nbytes": sl.nbytes, "methods": list(sl.methods),
            "calls": [{"rel": c.rel, "function": c.function, "line": c.line, "call": c.qualified} for c in sl.calls]}
