"""Web-server configurations -> what is served, and what runs when requested (E.7a §3.1, §3.5).

A closed subset of nginx and Apache httpd, parsed from the raw files the `code_roots_facts`
read fetched (never by running the server):

- nginx: ``root``, ``alias``, ``location`` (``=``, ``^~``, prefix, ``~``, ``~*``, nested),
  ``include`` (depth 5, cycles detected), ``fastcgi_pass`` / ``proxy_pass`` / ``uwsgi_pass``
  / ``scgi_pass``, ``deny all``, ``return 403|404|444``, ``internal``, ``server_name``,
  ``listen``;
- Apache: ``DocumentRoot``, ``Alias``, ``ScriptAlias``, ``<Directory>``, ``<Files>`` /
  ``<FilesMatch>``, ``<Location>``, ``Require all denied`` / ``Deny from all``,
  ``SetHandler`` / ``AddHandler`` / ``AddType`` for PHP and CGI, ``Options ExecCGI``,
  ``Include`` / ``IncludeOptional``, ``<IfModule>`` (its body counts), mod_php loaded;
- PHP-FPM pools: ``chdir`` and ``listen``.

Anything Kratos can't evaluate counts as SERVED -- the safe direction: a file is only
called "not served" when a rule Kratos understands says so. A ``root`` built from a
variable is never guessed ("root uses a variable: add it by path").
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

MAX_INCLUDE_DEPTH = 5
MAX_INCLUDES = 200
EXEC_EXTS = (".php", ".phtml", ".phar", ".php5", ".php7", ".php8", ".pht", ".cgi", ".pl")
PHP_EXTS = (".php", ".phtml", ".phar", ".php5", ".php7", ".php8", ".pht")
CGI_EXTS = (".cgi", ".pl")
# Files nginx/Apache include that never say where code lives.
_HARMLESS_INCLUDES = ("fastcgi_params", "fastcgi.conf", "mime.types", "proxy_params", "uwsgi_params",
                      "scgi_params", "koi-utf", "koi-win", "win-utf")
NGINX_PREFIX = "/etc/nginx"


@dataclass
class Location:
    modifier: str                     # "", "=", "^~", "~", "~*", "@"
    pattern: str
    root: str | None = None
    alias: str | None = None
    denied: bool = False
    backend: str | None = None        # fastcgi_pass / proxy_pass / uwsgi_pass target
    backend_kind: str | None = None   # fastcgi | proxy | uwsgi | scgi
    children: list["Location"] = field(default_factory=list)
    rx: Any = None
    rx_failed: bool = False


@dataclass
class Site:
    kind: str                          # nginx | apache
    source: str                        # the config file
    names: list[str] = field(default_factory=list)
    listen: list[str] = field(default_factory=list)
    root: str | None = None
    locations: list[Location] = field(default_factory=list)
    # apache
    aliases: list[tuple[str, str, bool]] = field(default_factory=list)   # (uri prefix, folder, cgi)
    directories: list[list[Any]] = field(default_factory=list)
    #                [folder, granted True/denied False/None, php handler, exec cgi]
    php_global: bool = False
    files_denied: list[Any] = field(default_factory=list)
    variable_roots: list[str] = field(default_factory=list)


@dataclass
class Config:
    sites: list[Site] = field(default_factory=list)
    pools: list[dict[str, str]] = field(default_factory=list)       # {name, chdir, listen, source}
    notes: list[str] = field(default_factory=list)                   # "config partly read: ..."
    files_used: list[str] = field(default_factory=list)

    def served_roots(self) -> list[dict[str, Any]]:
        """Every folder some site serves: {path, how, site, backend}."""
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def add(path: str | None, how: str, site: Site, backend: str | None = None) -> None:
            if not path or "$" in path:
                return
            p = posixpath.normpath(path)
            if (p, how) in seen:
                return
            seen.add((p, how))
            out.append({"path": p, "how": how, "site": ", ".join(site.names[:3]) or site.source,
                        "source": site.source, "backend": backend, "kind": site.kind})

        for s in self.sites:
            if s.kind == "nginx":
                add(s.root, "nginx root", s)
                stack = list(s.locations)
                while stack:
                    loc = stack.pop()
                    add(loc.root, "nginx root", s, loc.backend)
                    add(loc.alias, "nginx alias", s, loc.backend)
                    stack.extend(loc.children)
            else:
                add(s.root, "Apache DocumentRoot", s)
                for _uri, folder, cgi in s.aliases:
                    add(folder, "Apache ScriptAlias" if cgi else "Apache Alias", s)
        return out

    def backends(self) -> list[dict[str, str]]:
        """Where sites pass requests: {site, kind, target} (to link a site to its process)."""
        out = []
        for s in self.sites:
            stack = list(s.locations)
            while stack:
                loc = stack.pop()
                if loc.backend:
                    out.append({"site": ", ".join(s.names[:3]) or s.source, "kind": loc.backend_kind or "",
                                "target": loc.backend, "root": loc.root or loc.alias or s.root or ""})
                stack.extend(loc.children)
        return out


# --------------------------------------------------------------------------- nginx
_TOKEN = re.compile(r"""\s*(?:(#[^\n]*)|("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|([{};])|([^\s{};"'#]+))""", re.S)


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.group(1):
            continue
        tok = m.group(2) or m.group(3)
        if tok:
            out.append(tok[1:-1].replace('\\"', '"').replace("\\'", "'"))
        elif m.group(4):
            out.append(m.group(4))
        elif m.group(5):
            out.append(m.group(5))
    return out


def _parse_block(toks: list[str], pos: int) -> tuple[list[tuple[str, list[str], Any]], int]:
    """[(name, args, children or None)] until a closing brace."""
    out: list[tuple[str, list[str], Any]] = []
    cur: list[str] = []
    while pos < len(toks):
        t = toks[pos]
        pos += 1
        if t == ";":
            if cur:
                out.append((cur[0], cur[1:], None))
            cur = []
        elif t == "{":
            kids, pos = _parse_block(toks, pos)
            out.append((cur[0] if cur else "", cur[1:], kids))
            cur = []
        elif t == "}":
            return out, pos
        else:
            cur.append(t)
    return out, pos


class _Loader:
    def __init__(self, files: dict[str, str], prefix: str, notes: list[str]):
        self.files, self.prefix, self.notes = files, prefix, notes
        self.count = 0
        self.used: list[str] = []

    def resolve(self, pattern: str) -> list[str]:
        p = pattern if pattern.startswith("/") else posixpath.join(self.prefix, pattern)
        if any(c in p for c in "*?["):
            return sorted(k for k in self.files if fnmatch.fnmatchcase(k, p))
        return [p] if p in self.files else []

    def load(self, path: str, stack: tuple[str, ...]) -> list[tuple[str, list[str], Any]]:
        if path in stack:
            self.notes.append(f"config partly read: include cycle at {path}")
            return []
        if len(stack) > MAX_INCLUDE_DEPTH:
            self.notes.append(f"config partly read: includes nested deeper than {MAX_INCLUDE_DEPTH} at {path}")
            return []
        self.count += 1
        if self.count > MAX_INCLUDES:
            if self.count == MAX_INCLUDES + 1:
                self.notes.append(f"config partly read: more than {MAX_INCLUDES} included files")
            return []
        self.used.append(path)
        tree, _ = _parse_block(_tokens(self.files.get(path, "")), 0)
        return self.expand(tree, stack + (path,))

    def expand(self, tree: list[tuple[str, list[str], Any]], stack: tuple[str, ...]) -> list[tuple[str, list[str], Any]]:
        out: list[tuple[str, list[str], Any]] = []
        for name, args, kids in tree:
            if name == "include" and args and kids is None:
                hits = self.resolve(args[0])
                if not hits and not args[0].rsplit("/", 1)[-1].startswith(_HARMLESS_INCLUDES):
                    self.notes.append(f"config partly read: include {args[0]} not read")
                for h in hits:
                    out.extend(self.load(h, stack))
            elif kids is not None:
                out.append((name, args, self.expand(kids, stack)))
            else:
                out.append((name, args, None))
        return out


def _location(args: list[str], kids: list[tuple[str, list[str], Any]], site: Site) -> Location:
    if len(args) >= 2 and args[0] in ("=", "^~", "~", "~*"):
        mod, pat = args[0], args[1]
    elif args and args[0].startswith("@"):
        mod, pat = "@", args[0]
    elif args and args[0][:1] == "~":
        mod, pat = ("~*", args[0][2:]) if args[0].startswith("~*") else ("~", args[0][1:])
    else:
        mod, pat = "", args[0] if args else "/"
    loc = Location(mod, pat)
    if mod in ("~", "~*"):
        try:
            loc.rx = re.compile(pat, re.I if mod == "~*" else 0)
        except re.error:
            loc.rx_failed = True
    for name, a, k in kids:
        if k is not None and name == "location":
            loc.children.append(_location(a, k, site))
        elif name == "root" and a:
            if "$" in a[0]:
                site.variable_roots.append(a[0])
            else:
                loc.root = a[0]
        elif name == "alias" and a:
            if "$" in a[0]:
                site.variable_roots.append(a[0])
            else:
                loc.alias = a[0]
        elif name == "deny" and a and a[0] == "all" or name == "internal" or (
                name == "return" and a and a[0] in ("403", "404", "444")):
            loc.denied = True
        elif name in ("fastcgi_pass", "proxy_pass", "uwsgi_pass", "scgi_pass") and a:
            loc.backend, loc.backend_kind = a[0], name.split("_", 1)[0]
    return loc


def parse_nginx(files: dict[str, str], cfg: Config) -> None:
    loader = _Loader(files, NGINX_PREFIX, cfg.notes)
    main = f"{NGINX_PREFIX}/nginx.conf"
    starts = [main] if main in files else sorted(k for k in files if k.startswith(NGINX_PREFIX + "/sites-enabled/")
                                                  or k.startswith(NGINX_PREFIX + "/conf.d/"))
    tree: list[tuple[str, list[str], Any]] = []
    for st in starts:
        tree.extend(loader.load(st, ()))
    cfg.files_used.extend(loader.used)

    def servers(items: list[tuple[str, list[str], Any]], src: str) -> None:
        for name, args, kids in items:
            if kids is None:
                continue
            if name == "server":
                site = Site("nginx", src)
                for n, a, k in kids:
                    if k is None and n == "server_name":
                        site.names.extend(a)
                    elif k is None and n == "listen" and a:
                        site.listen.append(a[0])
                    elif k is None and n == "root" and a:
                        if "$" in a[0]:
                            site.variable_roots.append(a[0])
                        else:
                            site.root = a[0]
                    elif k is not None and n == "location":
                        site.locations.append(_location(a, k, site))
                cfg.sites.append(site)
            elif name in ("http", "stream", "events") or name == "":
                servers(kids, src)

    servers(tree, main if main in files else (starts[0] if starts else ""))


def _select(locs: list[Location], uri: str) -> Location | None:
    """nginx's location choice for `uri` among one level of locations."""
    best: Location | None = None
    for loc in locs:
        if loc.modifier == "=" and uri == loc.pattern:
            return loc
    for loc in locs:
        if loc.modifier in ("", "^~") and uri.startswith(loc.pattern):
            if best is None or len(loc.pattern) > len(best.pattern):
                best = loc
    if best is not None and best.modifier == "^~":
        return best
    for loc in locs:
        if loc.modifier in ("~", "~*"):
            if loc.rx_failed:
                return loc             # can't evaluate: assume it applies (safe direction)
            if loc.rx is not None and loc.rx.search(uri):
                return loc
    return best


def _nginx_decide(site: Site, root_path: str, rel: str) -> dict[str, Any] | None:
    """For a file `rel` under folder `root_path`: how this site treats it, or None when the
    site doesn't serve that folder."""
    abs_path = posixpath.join(root_path, rel)
    candidates: list[tuple[str, Location | None]] = []
    if site.root and (abs_path + "/").startswith(site.root.rstrip("/") + "/"):
        candidates.append(("/" + posixpath.relpath(abs_path, site.root), None))
    stack: list[Location] = list(site.locations)
    while stack:
        loc = stack.pop()
        if loc.alias and (abs_path + "/").startswith(loc.alias.rstrip("/") + "/") and loc.modifier in ("", "^~"):
            sub = posixpath.relpath(abs_path, loc.alias)
            candidates.append((loc.pattern.rstrip("/") + "/" + ("" if sub == "." else sub), loc))
        if loc.root and (abs_path + "/").startswith(loc.root.rstrip("/") + "/"):
            candidates.append(("/" + posixpath.relpath(abs_path, loc.root), loc))
        stack.extend(loc.children)
    if not candidates:
        return None
    for uri, _origin in candidates:
        level: list[Location] = site.locations
        chosen: Location | None = None
        while True:
            pick = _select(level, uri)
            if pick is None:
                break
            chosen = pick
            if not pick.children:
                break
            level = pick.children
        eff_root = None
        if chosen is not None:
            eff_root = chosen.alias or chosen.root
        eff_root = eff_root or site.root
        if chosen is not None and chosen.alias:
            if not (abs_path + "/").startswith(chosen.alias.rstrip("/") + "/"):
                continue
        elif eff_root and not (abs_path + "/").startswith(eff_root.rstrip("/") + "/"):
            continue
        if chosen is not None and chosen.denied:
            return {"served": False, "executed": False, "how": f"denied by an nginx location ({chosen.pattern})"}
        if chosen is not None and chosen.backend_kind == "fastcgi":
            return {"served": True, "executed": rel.lower().endswith(EXEC_EXTS) or chosen.rx_failed,
                    "how": f"passed to FastCGI ({chosen.backend}) when requested"}
        if chosen is not None and chosen.backend:
            return {"served": False, "executed": False, "how": f"requests go to {chosen.backend}"}
        return {"served": True, "executed": False, "how": "served as a static file by nginx"}
    return None


# --------------------------------------------------------------------------- Apache
_SECTION_OPEN = re.compile(r"^<\s*([A-Za-z]+)\s*([^>]*)>\s*$")
_SECTION_CLOSE = re.compile(r"^</\s*([A-Za-z]+)\s*>\s*$")


def _apache_args(text: str) -> list[str]:
    out, cur, q = [], "", None
    for ch in text:
        if q:
            if ch == q:
                q = None
            else:
                cur += ch
        elif ch in "\"'":
            q = ch
        elif ch.isspace():
            if cur:
                out.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def _apache_lines(files: dict[str, str], path: str, stack: tuple[str, ...], notes: list[str],
                  prefix: str, used: list[str]) -> list[str]:
    if path in stack or len(stack) > MAX_INCLUDE_DEPTH:
        notes.append(f"config partly read: include cycle or depth at {path}")
        return []
    used.append(path)
    out: list[str] = []
    text = files.get(path, "").replace("\\\n", " ")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(Include|IncludeOptional)\s+(.+)$", line, re.I)
        if m:
            pat = _apache_args(m.group(2))[0] if _apache_args(m.group(2)) else ""
            full = pat if pat.startswith("/") else posixpath.join(prefix, pat)
            hits = sorted(k for k in files if fnmatch.fnmatchcase(k, full)) if any(c in full for c in "*?[") else (
                [full] if full in files else [])
            if not hits and m.group(1).lower() == "include":
                notes.append(f"config partly read: include {pat} not read")
            for h in hits:
                out.extend(_apache_lines(files, h, stack + (path,), notes, prefix, used))
            continue
        out.append(line)
    return out


def parse_apache(files: dict[str, str], cfg: Config) -> None:
    for main, prefix in (("/etc/apache2/apache2.conf", "/etc/apache2"), ("/etc/httpd/conf/httpd.conf", "/etc/httpd")):
        if main not in files:
            continue
        used: list[str] = []
        lines = _apache_lines(files, main, (), cfg.notes, prefix, used)
        cfg.files_used.extend(used)
        mod_php = any(k.startswith(prefix + "/mods-enabled/php") and k.endswith(".load") for k in files) or any(
            re.match(r"^LoadModule\s+php", ln, re.I) for ln in lines)
        server = Site("apache", main)
        server.php_global = False
        stack: list[tuple[str, str]] = []
        site = server
        dirs: list[list[Any]] = []
        vhosts: list[Site] = []
        for line in lines:
            mo = _SECTION_OPEN.match(line)
            mc = _SECTION_CLOSE.match(line)
            if mo:
                kind, arg = mo.group(1).lower(), " ".join(_apache_args(mo.group(2)))
                stack.append((kind, arg))
                if kind == "virtualhost":
                    site = Site("apache", main)
                    site.listen.append(arg)
                    vhosts.append(site)
                    cfg.sites.append(site)
                elif kind == "directory":
                    d = [arg.rstrip("/") or "/", None, False, False]
                    dirs.append(d)
                    site.directories.append(d)
                continue
            if mc:
                if stack:
                    kind, _arg = stack.pop()
                    if kind == "virtualhost":
                        site = server
                    elif kind == "directory" and dirs:
                        dirs.pop()
                continue
            words = _apache_args(line)
            if not words:
                continue
            name, args = words[0].lower(), words[1:]
            cur_dir = dirs[-1] if dirs and stack and stack[-1][0] == "directory" else None
            in_files = bool(stack) and stack[-1][0] in ("files", "filesmatch")
            files_arg = stack[-1][1] if in_files else ""
            if name == "servername" and args:
                site.names.append(args[0])
            elif name == "serveralias":
                site.names.extend(args)
            elif name == "documentroot" and args:
                if "$" in args[0] or "%{" in args[0]:
                    site.variable_roots.append(args[0])
                else:
                    site.root = args[0].rstrip("/") or "/"
            elif name in ("alias", "scriptalias") and len(args) >= 2:
                site.aliases.append((args[0], args[1].rstrip("/"), name == "scriptalias"))
            elif name == "require" and args[:2] == ["all", "denied"] or name == "deny" and args[:2] == ["from", "all"]:
                if in_files:
                    try:
                        site.files_denied.append(re.compile(files_arg) if stack[-1][0] == "filesmatch"
                                                 else re.compile("^" + fnmatch.translate(files_arg)))
                    except re.error:
                        pass
                elif cur_dir is not None:
                    cur_dir[1] = False
            elif name == "require" and args[:2] == ["all", "granted"] or name == "allow" and args[:2] == ["from", "all"]:
                if cur_dir is not None and not in_files:
                    cur_dir[1] = True
            elif name in ("sethandler", "addhandler", "addtype") and args:
                val = " ".join(args).lower()
                php = "php" in val or ("proxy:" in val and "fcgi" in val)
                cgi = "cgi-script" in val
                if php:
                    if cur_dir is not None:
                        cur_dir[2] = True
                    else:
                        site.php_global = True
                if cgi and cur_dir is not None:
                    cur_dir[3] = True
            elif name == "options" and any("execcgi" in a.lower() for a in args) and cur_dir is not None:
                cur_dir[3] = True
        if mod_php:
            server.php_global = True
        # server-level rules apply to every virtual host, wherever they appear in the files
        for vh in vhosts:
            vh.directories = list(server.directories) + vh.directories
            vh.files_denied = list(server.files_denied) + vh.files_denied
            vh.php_global = vh.php_global or server.php_global
        if server.root or server.aliases:
            cfg.sites.append(server)


def _apache_decide(site: Site, root_path: str, rel: str) -> dict[str, Any] | None:
    abs_path = posixpath.join(root_path, rel)
    base = posixpath.basename(abs_path)
    served_by = None
    cgi_alias = False
    if site.root and (abs_path + "/").startswith(site.root.rstrip("/") + "/"):
        served_by = site.root
    for _uri, folder, cgi in site.aliases:
        if (abs_path + "/").startswith(folder.rstrip("/") + "/"):
            served_by, cgi_alias = folder, cgi_alias or cgi
    if served_by is None:
        return None
    if any(rx.search(base) for rx in site.files_denied):
        return {"served": False, "executed": False, "how": "denied by an Apache <Files> rule"}
    granted: bool | None = None
    php = site.php_global
    cgi = cgi_alias
    best = -1
    for folder, g, ph, ex in site.directories:
        f = folder.rstrip("/") or "/"
        if f == "/" or (abs_path + "/").startswith(f + "/"):
            if len(f) >= best and g is not None:
                granted, best = g, len(f)
            php = php or ph
            cgi = cgi or ex
    if granted is False:
        return {"served": False, "executed": False, "how": "denied by an Apache <Directory> rule"}
    executed = (php and rel.lower().endswith(PHP_EXTS)) or (cgi and (cgi_alias or rel.lower().endswith(CGI_EXTS)))
    return {"served": True, "executed": bool(executed),
            "how": "run as a CGI program when requested" if cgi_alias else (
                "run by PHP when requested" if executed else "served as a static file by Apache")}


# --------------------------------------------------------------------------- PHP-FPM
def parse_pools(files: dict[str, str], cfg: Config) -> None:
    for path, text in sorted(files.items()):
        if "fpm" not in path or not path.endswith(".conf"):
            continue
        pool = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in ";#":
                continue
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                pool = {"name": m.group(1), "chdir": "", "listen": "", "source": path}
                if pool["name"] != "global":
                    cfg.pools.append(pool)
                continue
            key, _, val = line.partition("=")
            if pool is not None and key.strip() in ("chdir", "listen"):
                pool[key.strip()] = val.strip().strip('"')


# --------------------------------------------------------------------------- one call
def parse(configs: dict[str, dict[str, Any]]) -> Config:
    """Configs as the facts read returned ({path: {status, text, real}}) -> Config."""
    files = {p: c["text"] for p, c in configs.items() if c.get("status") == "ok" and isinstance(c.get("text"), str)}
    cfg = Config()
    for p, c in configs.items():
        if c.get("status") in ("too_large", "capped", "budget", "unreadable"):
            cfg.notes.append(f"config partly read: {p} {c['status'].replace('_', ' ')}")
    parse_nginx(files, cfg)
    parse_apache(files, cfg)
    parse_pools(files, cfg)
    for s in cfg.sites:
        for v in s.variable_roots:
            cfg.notes.append(f"root uses a variable ({v}): add the folder by path")
    return cfg


def decide(cfg: Config, root_path: str, rel: str) -> dict[str, Any]:
    """How the machine's web servers treat file `rel` of folder `root_path`:
    {served, executed, how}. Not under any site: served False, "not served directly"."""
    verdicts = []
    for s in cfg.sites:
        v = _nginx_decide(s, root_path, rel) if s.kind == "nginx" else _apache_decide(s, root_path, rel)
        if v is not None:
            verdicts.append(v)
    if not verdicts:
        return {"served": False, "executed": False, "how": "not served directly by a web server Kratos read"}
    executed = [v for v in verdicts if v["executed"]]
    if executed:
        return executed[0]
    served = [v for v in verdicts if v["served"]]
    return served[0] if served else verdicts[0]


def root_is_served(cfg: Config, root_path: str) -> bool:
    rp = root_path.rstrip("/")
    for r in cfg.served_roots():
        p = r["path"].rstrip("/")
        if rp == p or rp.startswith(p + "/") or p.startswith(rp + "/"):
            return True
    return False


# --------------------------------------------------------------------------- saved form
def _loc_json(loc: Location) -> dict[str, Any]:
    return {"m": loc.modifier, "p": loc.pattern, "root": loc.root, "alias": loc.alias, "denied": loc.denied,
            "backend": loc.backend, "bk": loc.backend_kind, "children": [_loc_json(c) for c in loc.children]}


def _loc_from(d: dict[str, Any]) -> Location:
    loc = Location(str(d.get("m") or ""), str(d.get("p") or "/"), d.get("root"), d.get("alias"),
                   bool(d.get("denied")), d.get("backend"), d.get("bk"),
                   [_loc_from(c) for c in d.get("children") or [] if isinstance(c, dict)])
    if loc.modifier in ("~", "~*"):
        try:
            loc.rx = re.compile(loc.pattern, re.I if loc.modifier == "~*" else 0)
        except re.error:
            loc.rx_failed = True
    return loc


def to_json(cfg: Config) -> dict[str, Any]:
    """The parsed configuration -- Kratos's own structure, not the raw config text."""
    return {"sites": [{"kind": s.kind, "source": s.source, "names": s.names[:20], "listen": s.listen[:20],
                       "root": s.root, "locations": [_loc_json(x) for x in s.locations],
                       "aliases": [list(a) for a in s.aliases], "directories": [list(d) for d in s.directories],
                       "php_global": s.php_global, "files_denied": [rx.pattern for rx in s.files_denied],
                       "variable_roots": s.variable_roots[:20]} for s in cfg.sites],
            "pools": cfg.pools, "notes": cfg.notes[:50], "files_used": cfg.files_used[:300]}


def from_json(d: dict[str, Any] | None) -> Config:
    cfg = Config()
    for s in (d or {}).get("sites") or []:
        if not isinstance(s, dict):
            continue
        site = Site(str(s.get("kind") or "nginx"), str(s.get("source") or ""), list(s.get("names") or []),
                    list(s.get("listen") or []), s.get("root"),
                    [_loc_from(x) for x in s.get("locations") or [] if isinstance(x, dict)],
                    [tuple(a) for a in s.get("aliases") or [] if isinstance(a, list) and len(a) == 3],
                    [list(x) for x in s.get("directories") or [] if isinstance(x, list) and len(x) == 4],
                    bool(s.get("php_global")), [], list(s.get("variable_roots") or []))
        for pat in s.get("files_denied") or []:
            try:
                site.files_denied.append(re.compile(str(pat)))
            except re.error:
                continue
        cfg.sites.append(site)
    cfg.pools = [p for p in (d or {}).get("pools") or [] if isinstance(p, dict)]
    cfg.notes = [str(n) for n in (d or {}).get("notes") or []]
    return cfg
