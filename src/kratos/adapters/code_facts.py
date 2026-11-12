"""The deployed-code reads (E.7a): where code is served from, what a confirmed root holds,
and the contents of a closed set of its files.

Read-only. Three reads, each two ways that print the SAME records, one parser each:

- ``code_roots_facts`` -- the web-server, PHP-FPM and systemd configurations from closed
  path lists (nginx, Apache/httpd, PHP-FPM pools; systemd units that set
  ``WorkingDirectory=``). Raw config text travels base64 and is parsed on Kratos
  (kratos.code.webconf); a private key or htpasswd file is never read.
- ``code_inventory`` -- a bounded walk of ONE confirmed root: per file the path relative
  to the root, size, mode, owner, mtime, inode, link count, SHA-256 and, in a git
  checkout, the git blob id; symlinks are listed with their target text and never
  followed; another filesystem is never entered; dependency folders (node_modules,
  vendor, .venv, venv, __pycache__) are skipped and counted, except the metadata file
  that says what is installed in them. The repository's own ``.git`` files are listed
  (never their contents here). The sub-agent also reads the repository itself
  (kratos.code.gitread, stdlib) and prints the drift records; over SSH Kratos fetches the
  raw ``.git`` files with ``code_read`` and runs the same code on its side.
- ``code_read`` -- the contents of named files of a root's latest inventory, for one
  closed purpose: ``deps`` (lockfiles and installed-package metadata), ``secrets`` (text
  files to scan for secrets), ``git`` (the repository's own files and .gitignore /
  .gitattributes), ``review`` (source files for a person-started AI review, E.7b). A
  private-key file is never read for any purpose.

Nothing runs from the machine's code: no ``git``, no package manager, no interpreter.
Every SSH script is fixed text; the only values in it are numbers, constants from this
file, and base64 (the root, the paths). Paths travel as base64 inside the script on
standard input, never on a command line. Over SSH everything runs AS THE SSH USER; the
sub-agent reads as root, every file opened relative to its parent's descriptor without
following a symbolic link.

Standard library only: this file ships in the sub-agent bundle.
"""
from __future__ import annotations

import base64
import binascii
import glob
import hashlib
import os
import re
import stat
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:  # in the agent bundle: sibling modules
    from . import gitread  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover -- exercised by whichever layout is running
    try:
        from kratos.code import gitread
    except ImportError:  # run directly
        import gitread  # type: ignore[no-redef]

# --------------------------------------------------------------------------- caps
MAX_FILES = 50000
MAX_DEPTH = 20
DEFAULT_SECONDS = 240
MAX_HASH_BYTES = 64 * 1024 * 1024            # a bigger file is listed, not hashed ("too_large")
MAX_GIT_LISTED = 100000
MAX_DRIFT_RECORDS = 5000
SKIP_COUNT_MAX = 200000                      # files counted inside a skipped folder, at most
ROOTS_OUTPUT_CAP = 8 * 1024 * 1024
INVENTORY_OUTPUT_CAP = 32 * 1024 * 1024
READ_OUTPUT_CAP = 200 * 1024 * 1024
CONFIG_FILE_MAX = 256 * 1024
CONFIG_TOTAL_MAX = 4 * 1024 * 1024
CONFIG_MAX_FILES = 300
MAX_UNIT_LINES = 2000
MAX_ROOT_BYTES = 1024
MAX_READ_PATHS = 25000
DEFAULT_READ_MB = 64
PAGE_BYTES = 6 * 1024 * 1024                 # one agent reply must fit in a protocol frame (8 MiB)
AGENT_READ_MB = 5                            # content per agent code_read reply (base64 grows it by 4/3)

SKIP_DIRS: Tuple[str, ...] = ("node_modules", "vendor", ".venv", "venv", "__pycache__")
# What is installed in a skipped folder: npm's hidden lockfile, Composer's installed list,
# and each Python distribution's METADATA (name and version lines only are parsed on Kratos).
SKIP_META = {
    "node_modules": (".package-lock.json",),
    "vendor": ("composer/installed.json",),
    ".venv": ("lib/python*/site-packages/*.dist-info/METADATA",),
    "venv": ("lib/python*/site-packages/*.dist-info/METADATA",),
    "__pycache__": (),
}
# Files of the repository's own git directory that are listed (and may be read for `git`).
GIT_LISTED_TOP = ("HEAD", "config", "index", "packed-refs", "commondir", "info/exclude", "objects/info/alternates")
_GIT_REL_OK = re.compile(r"^(HEAD|config|index|packed-refs|commondir|info/exclude|objects/info/alternates|"
                         r"sharedindex\.[0-9a-f]{40,64}|refs/[A-Za-z0-9._/+@-]{1,240}|"
                         r"objects/pack/pack-[0-9a-f]{40,64}\.(idx|pack)|objects/[0-9a-f]{2}/[0-9a-f]{38,62}|"
                         r"worktrees/[A-Za-z0-9._-]{1,128}/(HEAD|index|commondir|gitdir))$")

# --------------------------------------------------------------------------- code_read purposes
PURPOSES = ("deps", "secrets", "git", "review")
LOCKFILES = ("requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "package-lock.json", "yarn.lock",
             "pnpm-lock.yaml", "composer.lock", "go.mod", "go.sum", "Gemfile.lock", "Cargo.lock",
             ".package-lock.json", "installed.json", "METADATA")
_REQUIREMENTS = re.compile(r"^requirements[A-Za-z0-9._-]*\.txt$")
DEPS_MAX_BYTES = 5 * 1024 * 1024
SECRETS_MAX_BYTES = 256 * 1024
REVIEW_MAX_BYTES = 1024 * 1024
GIT_MAX_FILE_BYTES = 512 * 1024 * 1024
SECRET_EXTS = (".py", ".php", ".phtml", ".inc", ".js", ".mjs", ".cjs", ".ts", ".rb", ".go", ".java", ".cs", ".pl",
               ".sh", ".env", ".ini", ".cfg", ".conf", ".config", ".json", ".yml", ".yaml", ".toml", ".xml",
               ".properties", ".txt", ".sql", ".html", ".htm", ".tpl", ".twig", ".erb", ".jsp", ".asp", ".aspx")
SECRET_NAMES = (".env", ".env.local", ".env.production", ".env.development", ".env.staging", "wp-config.php",
                "settings.py", "local_settings.py", "config.php", "database.yml", "secrets.yml", "Dockerfile",
                "docker-compose.yml", "docker-compose.yaml", ".npmrc", ".pypirc", "credentials")
# Every review extension any build may slice (E.7b); core narrows it further.
REVIEW_EXTS = (".py", ".php", ".js", ".mjs", ".ts")
# Never read for any purpose: private keys and keystores (reported by name only).
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx", ".gpg", ".asc", ".der")
KEY_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk")


# --------------------------------------------------------------------------- which folders may be roots
ROOT_RE = re.compile(r"^/[A-Za-z0-9._@+,=:~ /-]{1,1023}$")
NEVER_EXACT = ("/", "/home", "/var", "/usr/local", "/mnt", "/media")
NEVER_UNDER = ("/etc", "/root", "/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/sbin", "/lib", "/lib32",
               "/lib64", "/libx32", "/tmp", "/var/tmp", "/var/lib/docker", "/var/lib/containerd",
               "/var/lib/containers", "/var/log", "/var/cache", "/var/spool", "/var/mail", "/var/lib/dpkg",
               "/var/lib/rpm", "/var/lib/apt", "/snap", "/lost+found")
USR_ALLOWED = ("/usr/share/nginx/html",)
_USR_LOCAL_SYSTEM = ("bin", "sbin", "lib", "lib64", "include", "share", "etc", "man", "src", "games")
_CRED_DIRS = (".ssh", ".gnupg", ".aws", ".azure", ".kube", ".password-store", ".docker", ".gcloud")


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def never_reason(path: str) -> Optional[str]:
    """Why `path` is never offered, checked or read as a code root, else None. The same
    list on Kratos and on the agent."""
    p = path.rstrip("/") or "/"
    if p in NEVER_EXACT:
        return "too broad a folder to treat as one app"
    for base in NEVER_UNDER:
        if _under(p, base):
            return f"inside {base}, which Kratos never treats as code"
    if any(part in _CRED_DIRS for part in p.split("/")):
        return "a credential folder, which Kratos never reads"
    if _under(p, "/usr"):
        if any(_under(p, a) for a in USR_ALLOWED):
            return None
        parts = p.split("/")
        if len(parts) >= 4 and parts[2] == "local" and parts[3] not in _USR_LOCAL_SYSTEM:
            return None
        return "inside /usr (system software), which Kratos never treats as code"
    return None


def shape_reason(path: str) -> Optional[str]:
    if not isinstance(path, str) or not ROOT_RE.match(path):
        return "an absolute folder path made of letters, digits and ._@+,=:~ /- only"
    if "//" in path or path.endswith("/") or any(p in (".", "..") for p in path.split("/")[1:]):
        return "a plain absolute path (no //, . or .., no trailing /)"
    return None


class RequestError(ValueError):
    """A request that is not allowed (shape or purpose)."""


# --------------------------------------------------------------------------- names
_SAFE = re.compile(rb"^[A-Za-z0-9._/+@,=:~-]+$")


def enc(raw: bytes) -> Tuple[str, str]:
    """('n', plain) for a name of safe bytes, else ('b', base64) -- never a tab or newline."""
    if raw and _SAFE.match(raw):
        return "n", raw.decode("ascii")
    return "b", base64.b64encode(raw).decode("ascii")


def dec(flag: str, text: str) -> Optional[bytes]:
    if flag == "n":
        return text.encode("ascii", "replace") if text else None
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None


def is_key_file(name: bytes) -> bool:
    low = os.fsdecode(name.rsplit(b"/", 1)[-1]).lower()
    return low.endswith(KEY_SUFFIXES) or low in KEY_NAMES or low.startswith(tuple(k + "." for k in KEY_NAMES))


def check_root(raw: bytes) -> bytes:
    if not isinstance(raw, bytes) or not raw.startswith(b"/") or raw == b"/":
        raise RequestError("the root must be an absolute folder other than /")
    if len(raw) > MAX_ROOT_BYTES or b"\x00" in raw or b"\n" in raw or b"\t" in raw:
        raise RequestError("the root has a character Kratos won't send")
    if raw.endswith(b"/") or any(p in (b"", b".", b"..") for p in raw.split(b"/")[1:]):
        raise RequestError("the root must be a plain absolute path")
    text = raw.decode("utf-8", "replace")
    why = shape_reason(text) or never_reason(text)
    if why:
        raise RequestError(f"not a folder Kratos reads as code: {why}")
    return raw


def check_rel(raw: bytes) -> bytes:
    if not isinstance(raw, bytes) or not raw or raw.startswith(b"/") or b"\x00" in raw or len(raw) > 4096:
        raise RequestError("each path must be relative to the root")
    if any(p in (b"", b".", b"..") for p in raw.split(b"/")):
        raise RequestError("each path must be a plain relative path")
    return raw


def decode_b64(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or len(value) > 8192:
        raise RequestError(f"{what} must be a base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise RequestError(f"{what} must be valid base64") from None


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def purpose_allows(purpose: str, rel: bytes, size: Optional[int]) -> Optional[str]:
    """None when `purpose` may read `rel` (a path relative to the root), else why not.
    The same rule on Kratos and on the agent."""
    name = os.fsdecode(rel.rsplit(b"/", 1)[-1])
    text = os.fsdecode(rel)
    if is_key_file(rel):
        return "a private-key file is never read"
    if purpose == "deps":
        ok = (name in LOCKFILES or bool(_REQUIREMENTS.match(name))) and (
            name != "METADATA" or ".dist-info/" in text) and (
            name != "installed.json" or text.endswith("composer/installed.json")) and (
            name != ".package-lock.json" or text.endswith("node_modules/.package-lock.json"))
        cap = DEPS_MAX_BYTES
    elif purpose == "secrets":
        ok = name in SECRET_NAMES or name.lower().endswith(SECRET_EXTS) or name.startswith(".env")
        cap = SECRETS_MAX_BYTES
    elif purpose == "git":
        ok = name in (".gitignore", ".gitattributes") or (text.startswith(".git/") and bool(_GIT_REL_OK.match(text[5:])))
        cap = GIT_MAX_FILE_BYTES if text.startswith(".git/") else 256 * 1024
    elif purpose == "review":
        ok = name.lower().endswith(REVIEW_EXTS)
        cap = REVIEW_MAX_BYTES
    else:
        return "unknown purpose"
    if not ok:
        return f"not a file the {purpose} read may open"
    if size is not None and size > cap:
        return "too_large"
    return None


# =========================================================================== code_roots_facts
CONFIG_GLOBS: Tuple[str, ...] = (
    "/etc/nginx/nginx.conf", "/etc/nginx/*.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
    "/etc/nginx/snippets/*.conf", "/etc/nginx/default.d/*.conf",
    "/etc/apache2/apache2.conf", "/etc/apache2/ports.conf", "/etc/apache2/sites-enabled/*",
    "/etc/apache2/conf-enabled/*.conf", "/etc/apache2/mods-enabled/*.conf", "/etc/apache2/mods-enabled/*.load",
    "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf", "/etc/httpd/conf.modules.d/*.conf",
    "/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.d/*.conf", "/etc/php*/php-fpm.d/*.conf",
)
CONFIG_REAL_DIRS: Tuple[str, ...] = ("/etc/nginx/", "/etc/apache2/", "/etc/httpd/", "/etc/php/", "/etc/php-fpm.d/")
_CONFIG_SKIP = re.compile(r"(\.key|\.pem|\.crt|\.csr|\.p12|\.pfx|htpasswd[^/]*)$", re.IGNORECASE)
UNIT_GLOBS: Tuple[str, ...] = ("/etc/systemd/system/*.service", "/etc/systemd/system/*.service.d/*.conf",
                               "/run/systemd/system/*.service", "/lib/systemd/system/*.service",
                               "/usr/lib/systemd/system/*.service")
_UNIT_KEYS = re.compile(r"^\s*(WorkingDirectory|ExecStart|User|RootDirectory)=")
_UNIT_PATH = re.compile(r"^/[A-Za-z0-9._@:+/-]{1,512}$")

_ROOTS_SH = r"""
LC_ALL=C; export LC_ALL
printf 'M\tnow\t%s\n' "$(date +%s)"
printf 'M\tuid\t%s\n' "$(id -u)"
kr_b64() { base64 | tr -d '\n'; }
N=0; BYTES=0; SEEN='
'
kr_conf() {
  _p=$1
  case "$SEEN" in *"
$_p
"*) return ;; esac
  SEEN="$SEEN$_p
"
  [ -e "$_p" ] || [ -L "$_p" ] || return 0
  _e=$(printf '%s' "$_p" | kr_b64)
  if printf '%s\n' "$_p" | grep -Eiq '(\.key|\.pem|\.crt|\.csr|\.p12|\.pfx|htpasswd[^/]*)$'; then
    printf 'C\t%s\tskipped\t-\t-\t-\n' "$_e"; return 0
  fi
  _real=$_p
  if [ -L "$_p" ]; then
    _real=$(readlink -f -- "$_p" 2>/dev/null)
    case "$_real" in
      @REALDIRS@) ;;
      *) printf 'C\t%s\toutside\t-\t-\t-\n' "$_e"; return 0 ;;
    esac
  fi
  if [ ! -f "$_real" ] || [ -L "$_real" ]; then printf 'C\t%s\tnot_regular\t-\t-\t-\n' "$_e"; return 0; fi
  _sz=$(stat -c %s -- "$_real" 2>/dev/null)
  if [ -z "$_sz" ] || [ ! -r "$_real" ]; then printf 'C\t%s\tunreadable\t-\t-\t-\n' "$_e"; return 0; fi
  if [ "$_sz" -gt @FILEMAX@ ]; then printf 'C\t%s\ttoo_large\t%s\t-\t-\n' "$_e" "$_sz"; return 0; fi
  N=$((N + 1))
  if [ "$N" -gt @MAXFILES@ ]; then printf 'C\t%s\tcapped\t%s\t-\t-\n' "$_e" "$_sz"; return 0; fi
  BYTES=$((BYTES + _sz))
  if [ "$BYTES" -gt @TOTALMAX@ ]; then printf 'C\t%s\tbudget\t%s\t-\t-\n' "$_e" "$_sz"; return 0; fi
  printf 'C\t%s\tok\t%s\t%s\t%s\n' "$_e" "$_sz" "$(kr_b64 < "$_real")" "$(printf '%s' "$_real" | kr_b64)"
}
for _f in @CONFIGS@; do
  kr_conf "$_f"
done
_units=$(for _u in @UNITS@; do
  [ -f "$_u" ] && [ ! -L "$_u" ] && [ -r "$_u" ] && printf '%s\n' "$_u"
done | grep -E '^/[A-Za-z0-9._@:+/-]+$')
if [ -n "$_units" ]; then
  printf '%s\n' "$_units" | while IFS= read -r _u; do
    grep -Eq '^[[:space:]]*WorkingDirectory=' "$_u" 2>/dev/null || continue
    grep -E '^[[:space:]]*(WorkingDirectory|ExecStart|User|RootDirectory)=' "$_u" 2>/dev/null | head -n 40 | \
      tr '\t' ' ' | while IFS= read -r _l; do printf 'U\t%s\t%s\n' "$_u" "$_l"; done
  done | head -n @UNITLINES@
fi
"""


def build_roots_script(root: str = "") -> str:
    """The SSH read of the configurations. `root` exists for tests only (a fake tree)."""
    r = root.rstrip("/")
    configs = " ".join(r + g for g in CONFIG_GLOBS)
    units = " ".join(r + g for g in UNIT_GLOBS)
    real = "|".join(f"{r}{d}*" for d in CONFIG_REAL_DIRS)
    body = (_ROOTS_SH.replace("@CONFIGS@", configs).replace("@UNITS@", units).replace("@REALDIRS@", real)
            .replace("@FILEMAX@", str(CONFIG_FILE_MAX)).replace("@MAXFILES@", str(CONFIG_MAX_FILES))
            .replace("@TOTALMAX@", str(CONFIG_TOTAL_MAX)).replace("@UNITLINES@", str(MAX_UNIT_LINES)))
    return "{\n" + body + "printf 'END\\n'\n} | head -c " + str(ROOTS_OUTPUT_CAP) + "\nexit 0\n"


def _read_plain(path: str, cap: int) -> Optional[bytes]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        return os.read(fd, cap + 1)[:cap + 1]
    finally:
        os.close(fd)


def roots_facts_output(root: str = "") -> Dict[str, Any]:
    """The agent's read of the configurations: the same records build_roots_script prints."""
    r = root.rstrip("/")
    out: List[str] = [f"M\tnow\t{int(time.time())}", f"M\tuid\t{os.getuid()}"]
    seen: Set[str] = set()
    n = total = 0
    for g in CONFIG_GLOBS:
        for p in sorted(glob.glob(r + g)) or ([r + g] if "*" not in g else []):
            if p in seen:
                continue
            seen.add(p)
            if not os.path.lexists(p):
                continue
            e = b64(os.fsencode(p))
            if _CONFIG_SKIP.search(p):
                out.append(f"C\t{e}\tskipped\t-\t-\t-")
                continue
            real = p
            if os.path.islink(p):
                real = os.path.realpath(p)
                if not any(real.startswith(r + d) for d in CONFIG_REAL_DIRS):
                    out.append(f"C\t{e}\toutside\t-\t-\t-")
                    continue
            try:
                st = os.stat(real, follow_symlinks=False)
            except OSError:
                out.append(f"C\t{e}\tunreadable\t-\t-\t-")
                continue
            if not stat.S_ISREG(st.st_mode):
                out.append(f"C\t{e}\tnot_regular\t-\t-\t-")
                continue
            if st.st_size > CONFIG_FILE_MAX:
                out.append(f"C\t{e}\ttoo_large\t{st.st_size}\t-\t-")
                continue
            n += 1
            if n > CONFIG_MAX_FILES:
                out.append(f"C\t{e}\tcapped\t{st.st_size}\t-\t-")
                continue
            total += st.st_size
            if total > CONFIG_TOTAL_MAX:
                out.append(f"C\t{e}\tbudget\t{st.st_size}\t-\t-")
                continue
            data = _read_plain(real, CONFIG_FILE_MAX)
            if data is None:
                out.append(f"C\t{e}\tunreadable\t-\t-\t-")
                continue
            out.append(f"C\t{e}\tok\t{len(data)}\t{b64(data)}\t{b64(os.fsencode(real))}")
    lines: List[str] = []
    for g in UNIT_GLOBS:
        for u in sorted(glob.glob(r + g)):
            if not _UNIT_PATH.match(u) or os.path.islink(u) or not os.path.isfile(u):
                continue
            data = _read_plain(u, 1024 * 1024)
            if data is None:
                continue
            text = data.decode("utf-8", "replace").replace("\t", " ").splitlines()
            if not any(re.match(r"^\s*WorkingDirectory=", ln) for ln in text):
                continue
            lines += [f"U\t{u}\t{ln}" for ln in [x for x in text if _UNIT_KEYS.match(x)][:40]]
    out += lines[:MAX_UNIT_LINES]
    out.append("END")
    return {"stdout": "\n".join(out) + "\n", "returncode": 0}


def parse_roots_facts(stdout: str, root: str = "") -> Dict[str, Any]:
    """{now, uid, configs: {path: {status, size, text, real}}, units: {unit path: [lines]},
    complete}. `root` (tests only) is stripped from every path."""
    r = root.rstrip("/")

    def strip(p: str) -> str:
        return p[len(r):] if r and p.startswith(r) else p

    out: Dict[str, Any] = {"now": None, "uid": None, "configs": {}, "units": {}, "complete": False}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        tag = cols[0]
        if tag == "M" and len(cols) >= 3:
            if cols[1] in ("now", "uid") and cols[2].strip().isdigit():
                out[cols[1]] = int(cols[2])
        elif tag == "C" and len(cols) >= 6:
            raw = dec("b", cols[1])
            if raw is None:
                continue
            path = strip(os.fsdecode(raw))
            item: Dict[str, Any] = {"status": cols[2], "size": int(cols[3]) if cols[3].isdigit() else None,
                                    "text": None, "real": None}
            if cols[2] == "ok":
                data = dec("b", cols[4])
                real = dec("b", cols[5])
                if data is None:
                    item["status"] = "unreadable"
                else:
                    item["text"] = data.decode("utf-8", "replace")
                    item["real"] = strip(os.fsdecode(real)) if real else path
            out["configs"][path] = item
        elif tag == "U" and len(cols) >= 3:
            out["units"].setdefault(strip(cols[1]), []).append("\t".join(cols[2:]))
        elif tag == "END":
            out["complete"] = True
    return out


# =========================================================================== code_inventory
_INV_SH = r"""
LC_ALL=C; export LC_ALL
ROOT=$(printf '%s' '@ROOTB64@' | base64 -d 2>/dev/null)
START=$(date +%s)
printf 'M\tnow\t%s\n' "$START"
printf 'M\tuid\t%s\n' "$(id -u)"
if [ -z "$ROOT" ]; then printf 'R\tmissing\t-\t-\t-\t-\n'; exit 0; fi
if [ -L "$ROOT" ]; then printf 'R\tsymlink\t-\t-\t-\t-\n'; exit 0; fi
if [ ! -e "$ROOT" ]; then
  _par=${ROOT%/*}; [ -n "$_par" ] || _par=/
  if [ -d "$_par" ] && { [ ! -r "$_par" ] || [ ! -x "$_par" ]; }; then printf 'R\tunreadable\t-\t-\t-\t-\n'
  else printf 'R\tmissing\t-\t-\t-\t-\n'; fi
  exit 0
fi
if [ ! -d "$ROOT" ]; then printf 'R\tnot_dir\t-\t-\t-\t-\n'; exit 0; fi
_phys=$(cd "$ROOT" 2>/dev/null && pwd -P)
if [ -z "$_phys" ]; then printf 'R\tunreadable\t-\t-\t-\t-\n'; exit 0; fi
if [ "$_phys" != "$ROOT" ]; then printf 'R\tsymlink\t-\t-\t-\t-\n'; exit 0; fi
if [ ! -r "$ROOT" ] || [ ! -x "$ROOT" ]; then printf 'R\tunreadable\t-\t-\t-\t-\n'; exit 0; fi
_rs=$(stat -c '%d	%i	%a	%u' -- "$ROOT" 2>/dev/null)
printf 'R\tok\t%s\n' "$_rs"
cd "$ROOT" || exit 0
FMT=-
GITKIND=none
if [ -d .git ] && [ ! -L .git ]; then
  GITKIND=dir
  FMT=sha1
  if [ -r .git/config ] && grep -Eiq '^[[:space:]]*objectformat[[:space:]]*=[[:space:]]*"?sha256' .git/config 2>/dev/null; then FMT=sha256; fi
elif [ -f .git ] && [ ! -L .git ]; then
  GITKIND=file
  printf 'GF\t%s\n' "$(head -c 4096 .git | base64 | tr -d '\n')"
fi
printf 'M\tgit\t%s\n' "$GITKIND"
printf 'M\tformat\t%s\n' "$FMT"
export FMT START
INNER='
kr_enc() {
  case "$1" in
    *[!A-Za-z0-9._/+@,=:~-]*|"") printf "b\t%s" "$(printf "%s" "$1" | base64 | tr -d "\n")" ;;
    *) printf "n\t%s" "$1" ;;
  esac
}
kr_one() {
  _f=$1; _r=${_f#./}
  if [ -L "$_f" ]; then
    printf "L\t%s\t%s\n" "$(kr_enc "$_r")" "$(kr_enc "$(readlink -- "$_f")")"; return
  fi
  [ -f "$_f" ] || return
  _st=$(stat -c "%s %a %u %Y %i %h" -- "$_f" 2>/dev/null)
  if [ -z "$_st" ]; then printf "F\t%s\t-\t-\t-\t-\t-\t-\t-\t-\tunreadable\n" "$(kr_enc "$_r")"; return; fi
  set -- $_st
  _tab="$1	$2	$3	$4	$5	$6"
  if [ "$6" != 1 ]; then printf "F\t%s\t%s\t-\t-\thardlink\n" "$(kr_enc "$_r")" "$_tab"; return; fi
  if [ ! -r "$_f" ]; then printf "F\t%s\t%s\t-\t-\tunreadable\n" "$(kr_enc "$_r")" "$_tab"; return; fi
  if [ "$1" -gt @HASHMAX@ ]; then printf "F\t%s\t%s\t-\t-\ttoo_large\n" "$(kr_enc "$_r")" "$_tab"; return; fi
  _h=$(sha256sum < "$_f" 2>/dev/null); _h=${_h%% *}
  _b=-
  if [ "$FMT" = sha1 ]; then _b=$( { printf "blob %s\000" "$1"; cat -- "$_f"; } 2>/dev/null | sha1sum); _b=${_b%% *}
  elif [ "$FMT" = sha256 ]; then _b=$( { printf "blob %s\000" "$1"; cat -- "$_f"; } 2>/dev/null | sha256sum); _b=${_b%% *}; fi
  _st2=$(stat -c "%s %a %u %Y %i %h" -- "$_f" 2>/dev/null)
  if [ "$_st2" != "$_st" ] || [ -z "$_h" ]; then printf "F\t%s\t%s\t-\t-\tchanged\n" "$(kr_enc "$_r")" "$_tab"; return; fi
  printf "F\t%s\t%s\t%s\t%s\tok\n" "$(kr_enc "$_r")" "$_tab" "$_h" "$_b"
}
_n=0
for _x in "$@"; do
  _n=$((_n + 1))
  if [ $((_n % 50)) = 0 ] && [ $(( $(date +%s) - START )) -ge @SECONDS@ ]; then printf "T\ttimed_out\t1\n"; exit 0; fi
  kr_one "$_x"
done
'
@PRUNE@
find . -xdev -mindepth 1 -maxdepth @MAXDEPTH@ \( -path ./.git -o \( -type d \( @SKIPNAMES@ \) \) \) -prune -o \( -type f -o -type l \) -exec sh -c "$INNER" kr {} + 2>/dev/null | \
  awk -v max=@MAXFILES@ '$1 == "F" || $1 == "L" { n++; if (n > max) { print "T\tcapped\t1"; exit } } $1 == "T" && $2 == "timed_out" { print; exit } { print }'
if [ -n "$(find . -xdev -mindepth @DEEPER@ -maxdepth @DEEPER@ \( -path ./.git -o \( -type d \( @SKIPNAMES@ \) \) \) -prune -o -print 2>/dev/null | head -n 1)" ]; then
  printf 'T\tdepth_capped\t1\n'
fi
find . -xdev -mindepth 1 -maxdepth @MAXDEPTH@ -path ./.git -prune -o -type d \( @SKIPNAMES@ \) -prune -print 2>/dev/null | \
  grep -E '^\./[A-Za-z0-9._/+@,=:~-]+$' | head -n 2000 | while IFS= read -r _d; do
  _base=${_d##*/}
  _cnt=$(find "$_d" -xdev -type f 2>/dev/null | head -n @SKIPCOUNT@ | wc -l | tr -d ' ')
  printf 'S\tn\t%s\t%s\t%s\n' "${_d#./}" "$_base" "$_cnt"
  case "$_base" in
    node_modules) _metas="$_d/.package-lock.json" ;;
    vendor) _metas="$_d/composer/installed.json" ;;
    .venv|venv) _metas=$(ls -d "$_d"/lib/python*/site-packages/*.dist-info/METADATA 2>/dev/null | head -n 2000) ;;
    *) _metas="" ;;
  esac
  [ -n "$_metas" ] && printf '%s\n' "$_metas" | while IFS= read -r _m; do [ -e "$_m" ] && printf '%s\0' "$_m"; done | \
    xargs -0 sh -c "$INNER" kr 2>/dev/null
done
awk -v r="$ROOT" '$5 != r && index($5, r "/") == 1 { print $5 }' /proc/self/mountinfo 2>/dev/null | head -n 200 | \
  while IFS= read -r _m; do
    _rel=${_m#"$ROOT"/}
    case "$_rel" in *[!A-Za-z0-9._/+@,=:~-]*) continue ;; esac
    printf 'S\tn\t%s\tother_device\t-\n' "$_rel"
  done
if [ "$GITKIND" = dir ]; then
  find .git -xdev -maxdepth 4 \( -path .git/modules -o -path .git/logs -o -path .git/hooks -o -path .git/lfs \) -prune -o -type f -print 2>/dev/null | \
    head -n @GITMAX@ | while IFS= read -r _g; do
      _gr=${_g#.git/}
      case "$_gr" in *[!A-Za-z0-9._/+@,=:~-]*) continue ;; esac
      printf 'G\tn\t%s\t%s\n' "$_gr" "$(stat -c %s -- "$_g" 2>/dev/null || echo -)"
    done
fi
"""


def _skip_names_expr(skip: Tuple[str, ...]) -> str:
    return " -o ".join(f"-name {n}" for n in skip) or "-name ' kratos-none '"


def build_inventory_script(root: bytes, *, max_files: int = MAX_FILES, max_depth: int = MAX_DEPTH,
                           seconds: int = DEFAULT_SECONDS, skip: Tuple[str, ...] = SKIP_DIRS) -> str:
    """The SSH walk of one root (checked raw bytes). Every interpolated value is a number,
    a constant from this file or base64 -- nothing in a path reaches the shell as code."""
    check_root(root)
    for s in skip:
        if s not in SKIP_DIRS:
            raise RequestError("only the known dependency folders can be skipped")
    body = (_INV_SH.replace("@ROOTB64@", b64(root)).replace("@MAXFILES@", str(int(max_files)))
            .replace("@MAXDEPTH@", str(int(max_depth))).replace("@DEEPER@", str(int(max_depth) + 1))
            .replace("@SECONDS@", str(int(seconds))).replace("@HASHMAX@", str(MAX_HASH_BYTES))
            .replace("@SKIPCOUNT@", str(SKIP_COUNT_MAX)).replace("@GITMAX@", str(MAX_GIT_LISTED))
            .replace("@SKIPNAMES@", _skip_names_expr(skip)).replace("@PRUNE@", ""))
    return "{\n" + body + "printf 'END\\n'\n} | head -c " + str(INVENTORY_OUTPUT_CAP) + "\nexit 0\n"


# --------------------------------------------------------------------------- the agent's walk
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


def open_root(root: bytes) -> Tuple[Optional[int], str, Optional[os.stat_result]]:
    """(descriptor of the root, status, its stat). Every component opened without following
    a symbolic link."""
    parts = root.split(b"/")[1:]
    try:
        fd = os.open(b"/", _DIR_FLAGS)
    except OSError:
        return None, "unreadable", None
    for i, part in enumerate(parts):
        try:
            st = os.stat(part, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.close(fd)
            return None, "missing", None
        except OSError:
            os.close(fd)
            return None, "unreadable", None
        if stat.S_ISLNK(st.st_mode):
            os.close(fd)
            return None, "symlink", None
        if not stat.S_ISDIR(st.st_mode):
            os.close(fd)
            return None, ("not_dir" if i == len(parts) - 1 else "missing"), None
        try:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
        except OSError:
            os.close(fd)
            return None, "unreadable", None
        os.close(fd)
        fd = nxt
    return fd, "ok", os.fstat(fd)


def _hash_fd(fd: int, size: int, fmt: str) -> Tuple[str, str]:
    h = hashlib.sha256()
    g = hashlib.sha1() if fmt == "sha1" else hashlib.sha256() if fmt == "sha256" else None
    if g is not None:
        g.update(b"blob %d\x00" % size)
    off = 0
    while True:
        chunk = os.pread(fd, 1 << 20, off)
        if not chunk:
            break
        off += len(chunk)
        h.update(chunk)
        if g is not None:
            g.update(chunk)
    if off != size:
        raise OSError("changed")
    return h.hexdigest(), (g.hexdigest() if g is not None else "-")


class Walk:
    """What the agent's walk saw, for git drift on the agent."""

    def __init__(self) -> None:
        self.files: Dict[bytes, Tuple[int, str, int]] = {}   # rel -> (git mode, blob, size)
        self.ignores: Dict[bytes, bytes] = {}                # rel of a .gitignore -> its text
        self.attrs: Dict[bytes, bytes] = {}
        self.skipped: List[bytes] = []
        self.capped = False
        self.timed_out = False
        self.depth_capped = False


def _stat_tab(st: os.stat_result) -> str:
    return (f"{st.st_size}\t{oct(st.st_mode & 0o7777)[2:]}\t{st.st_uid}\t{int(st.st_mtime)}\t{st.st_ino}\t"
            f"{st.st_nlink}")


def _file_record(dfd: int, name: bytes, rel: bytes, fmt: str, out: List[str], walk: Walk) -> None:
    f, e = enc(rel)
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except OSError:
        out.append(f"F\t{f}\t{e}\t-\t-\t-\t-\t-\t-\t-\t-\tunreadable")
        return
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(name, dir_fd=dfd)
        except OSError:
            target = b""
        tf, te = enc(target)
        out.append(f"L\t{f}\t{e}\t{tf}\t{te}")
        walk.files[rel] = (gitread.MODE_LINK, gitread.blob_id(target, fmt) if fmt in ("sha1", "sha256") else "-", 0)
        return
    if not stat.S_ISREG(st.st_mode):
        return
    tab = _stat_tab(st)
    if st.st_nlink != 1:
        out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\thardlink")
        return
    if st.st_size > MAX_HASH_BYTES:
        out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\ttoo_large")
        return
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dfd)
    except OSError:
        out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\tunreadable")
        return
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\tchanged")
            return
        try:
            sha, blob = _hash_fd(fd, st.st_size, fmt)
        except OSError:
            out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\tchanged")
            return
        after = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if _stat_tab(after) != tab:
            out.append(f"F\t{f}\t{e}\t{tab}\t-\t-\tchanged")
            return
        out.append(f"F\t{f}\t{e}\t{tab}\t{sha}\t{blob}\tok")
        walk.files[rel] = (gitread.work_mode(st.st_mode, False), blob, st.st_size)
        base = rel.rsplit(b"/", 1)[-1]
        if base in (b".gitignore", b".gitattributes") and st.st_size <= gitread.MAX_IGNORE_BYTES and (
                len(walk.ignores) + len(walk.attrs)) < gitread.MAX_IGNORE_FILES:
            data = os.pread(fd, st.st_size, 0)
            (walk.ignores if base == b".gitignore" else walk.attrs)[rel] = data
    finally:
        os.close(fd)


def _count_files(dfd: int, cap: int, root_dev: int) -> int:
    n = 0
    stack = [dfd]
    opened: List[int] = []
    try:
        while stack and n < cap:
            d = stack.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for ent in entries:
                try:
                    st = os.stat(ent.name, dir_fd=d, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    n += 1
                elif stat.S_ISDIR(st.st_mode) and st.st_dev == root_dev:
                    try:
                        c = os.open(ent.name, _DIR_FLAGS, dir_fd=d)
                    except OSError:
                        continue
                    opened.append(c)
                    stack.append(c)
    finally:
        for c in opened:
            try:
                os.close(c)
            except OSError:
                pass
    return min(n, cap)


def _meta_paths(dfd: int, base: str) -> List[Tuple[int, bytes, bytes]]:
    """(parent fd, file name, path relative to the skipped folder) of its metadata files.
    Each folder opened without following links; the caller closes the fds."""
    out: List[Tuple[int, bytes, bytes]] = []
    if base == "node_modules":
        out.append((os.dup(dfd), b".package-lock.json", b".package-lock.json"))
    elif base == "vendor":
        try:
            c = os.open(b"composer", _DIR_FLAGS, dir_fd=dfd)
            out.append((c, b"installed.json", b"composer/installed.json"))
        except OSError:
            pass
    elif base in (".venv", "venv"):
        try:
            lib = os.open(b"lib", _DIR_FLAGS, dir_fd=dfd)
        except OSError:
            return out
        try:
            for py in sorted(e.name for e in os.scandir(lib) if e.name.startswith("python")):
                try:
                    pyd = os.open(py, _DIR_FLAGS, dir_fd=lib)
                    sp = os.open("site-packages", _DIR_FLAGS, dir_fd=pyd)
                    os.close(pyd)
                except OSError:
                    continue
                try:
                    for di in sorted(e.name for e in os.scandir(sp) if e.name.endswith(".dist-info")):
                        try:
                            dd = os.open(di, _DIR_FLAGS, dir_fd=sp)
                        except OSError:
                            continue
                        out.append((dd, b"METADATA", os.fsencode(f"lib/{py}/site-packages/{di}/METADATA")))
                        if len(out) >= 2000:
                            break
                finally:
                    os.close(sp)
        finally:
            os.close(lib)
    return out


def _mounts_under(root: bytes) -> List[bytes]:
    out: List[bytes] = []
    try:
        with open("/proc/self/mountinfo", "rb") as fh:
            for line in fh.read(4 * 1024 * 1024).split(b"\n"):
                cols = line.split(b" ")
                if len(cols) > 4:
                    mp = cols[4].replace(b"\\040", b" ")
                    if mp != root and mp.startswith(root + b"/"):
                        out.append(mp[len(root) + 1:])
    except OSError:
        pass
    return sorted(out)[:200]


def inventory_output(root: bytes, *, max_files: int = MAX_FILES, max_depth: int = MAX_DEPTH,
                     seconds: float = DEFAULT_SECONDS, skip: Tuple[str, ...] = SKIP_DIRS, git: bool = True,
                     max_pack_bytes: int = 512 * 1024 * 1024) -> Dict[str, Any]:
    """The agent's walk: the records build_inventory_script prints, plus (with `git`) the
    drift records the agent computes from the repository's own files."""
    check_root(root)
    start = time.monotonic()
    out: List[str] = [f"M\tnow\t{int(time.time())}", f"M\tuid\t{os.getuid()}"]
    rfd, status, rst = open_root(root)
    if rfd is None or rst is None:
        out.append(f"R\t{status}\t-\t-\t-\t-")
        out.append("END")
        return {"stdout": "\n".join(out) + "\n", "returncode": 0, "walk": None}
    walk = Walk()
    try:
        out.append(f"R\tok\t{rst.st_dev}\t{rst.st_ino}\t{oct(rst.st_mode & 0o7777)[2:]}\t{rst.st_uid}")
        fmt, gitkind = "-", "none"
        try:
            gst = os.stat(b".git", dir_fd=rfd, follow_symlinks=False)
        except OSError:
            gst = None
        if gst is not None and stat.S_ISDIR(gst.st_mode):
            gitkind, fmt = "dir", "sha1"
            try:
                gfd = os.open(b".git", _DIR_FLAGS, dir_fd=rfd)
                cfd = os.open(b"config", _FILE_FLAGS, dir_fd=gfd)
                os.close(gfd)
                try:
                    cfg = gitread.parse_config(os.read(cfd, 1024 * 1024))
                finally:
                    os.close(cfd)
                if (cfg.get("extensions.objectformat") or "").lower() == "sha256":
                    fmt = "sha256"
            except OSError:
                pass
        elif gst is not None and stat.S_ISREG(gst.st_mode):
            gitkind = "file"
            try:
                fd = os.open(b".git", _FILE_FLAGS, dir_fd=rfd)
                try:
                    out.append(f"GF\t{b64(os.read(fd, 4096))}")
                finally:
                    os.close(fd)
            except OSError:
                pass
        out.append(f"M\tgit\t{gitkind}")
        out.append(f"M\tformat\t{fmt}")
        listed = 0
        skipped: List[Tuple[int, bytes, str]] = []
        stack: List[Tuple[int, bytes, int]] = [(os.dup(rfd), b"", 0)]
        while stack:
            dfd, rel_dir, depth = stack.pop()
            try:
                try:
                    names = sorted(e.name for e in os.scandir(dfd))
                except OSError:
                    continue
                for name in names:
                    bname = os.fsencode(name)
                    rel = rel_dir + bname if not rel_dir else rel_dir + b"/" + bname
                    if not rel_dir and bname == b".git":
                        continue
                    try:
                        st = os.stat(bname, dir_fd=dfd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if st.st_dev != rst.st_dev:
                            continue                 # reported from mountinfo, as over SSH
                        if name in skip:
                            try:
                                c = os.open(bname, _DIR_FLAGS, dir_fd=dfd)
                            except OSError:
                                continue
                            skipped.append((c, rel, name))
                            continue
                        if depth + 1 >= max_depth:
                            try:            # only content beyond the limit counts (as find -mindepth does)
                                c = os.open(bname, _DIR_FLAGS, dir_fd=dfd)
                                try:
                                    walk.depth_capped = walk.depth_capped or bool(os.listdir(c))
                                finally:
                                    os.close(c)
                            except OSError:
                                pass
                            continue
                        try:
                            c = os.open(bname, _DIR_FLAGS, dir_fd=dfd)
                        except OSError:
                            continue
                        stack.append((c, rel, depth + 1))
                        continue
                    if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                        continue
                    listed += 1
                    if listed > max_files:
                        walk.capped = True
                        break
                    if listed % 50 == 0 and time.monotonic() - start >= seconds:
                        walk.timed_out = True
                        break
                    _file_record(dfd, bname, rel, fmt, out, walk)
            finally:
                os.close(dfd)
            if walk.capped or walk.timed_out:
                break
        for fd, _r, _n in [x for x in stack]:
            try:
                os.close(fd)
            except OSError:
                pass
        if walk.capped:
            out.append("T\tcapped\t1")
        if walk.timed_out:
            out.append("T\ttimed_out\t1")
        if walk.depth_capped:
            out.append("T\tdepth_capped\t1")
        for c, rel, name in sorted(skipped, key=lambda x: x[1]):
            try:
                if _SAFE.match(rel):
                    out.append(f"S\tn\t{rel.decode()}\t{name}\t{_count_files(c, SKIP_COUNT_MAX, rst.st_dev)}")
                    walk.skipped.append(rel)
                    for mfd, mname, mrel in _meta_paths(c, name):
                        try:
                            try:
                                os.stat(mname, dir_fd=mfd, follow_symlinks=False)
                            except OSError:
                                continue
                            _file_record(mfd, mname, rel + b"/" + mrel, fmt, out, walk)
                        finally:
                            os.close(mfd)
            finally:
                os.close(c)
        for m in _mounts_under(root):
            if _SAFE.match(m):
                out.append(f"S\tn\t{m.decode()}\tother_device\t-")
                walk.skipped.append(m)
        if gitkind == "dir":
            out += _git_listing(rfd)
            if git:
                out += agent_git_records(root, rfd, fmt, walk, max_files=max_files, max_pack_bytes=max_pack_bytes)
    finally:
        os.close(rfd)
    out.append("END")
    return {"stdout": "\n".join(out) + "\n", "returncode": 0, "walk": walk}


def _git_listing(rfd: int) -> List[str]:
    out: List[str] = []
    try:
        gfd = os.open(b".git", _DIR_FLAGS, dir_fd=rfd)
    except OSError:
        return out
    stack: List[Tuple[int, str, int]] = [(gfd, "", 0)]
    try:
        while stack and len(out) < MAX_GIT_LISTED:
            dfd, rel_dir, depth = stack.pop()
            try:
                for e in sorted(os.scandir(dfd), key=lambda x: x.name):
                    rel = f"{rel_dir}{e.name}"
                    try:
                        st = os.stat(e.name, dir_fd=dfd, follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if rel in ("modules", "logs", "hooks", "lfs") or depth >= 3:
                            continue
                        try:
                            stack.append((os.open(e.name, _DIR_FLAGS, dir_fd=dfd), rel + "/", depth + 1))
                        except OSError:
                            continue
                    elif stat.S_ISREG(st.st_mode) and _SAFE.match(os.fsencode(rel)):
                        out.append(f"G\tn\t{rel}\t{st.st_size}")
                        if len(out) >= MAX_GIT_LISTED:
                            break
            finally:
                os.close(dfd)
    finally:
        for dfd, _r, _d in stack:
            try:
                os.close(dfd)
            except OSError:
                pass
    return out


# --------------------------------------------------------------------------- git drift (both sides)
def _clean(text: Any) -> str:
    return re.sub(r"[\t\r\n]+", " ", str(text))[:300]


def git_records(info: Dict[str, Any], drift: Optional[Dict[str, Any]]) -> List[str]:
    """The git part of an inventory as records -- printed by the agent, and built on Kratos
    from fetched files over SSH, so one parser reads both."""
    out: List[str] = []
    head = info.get("head") or {}
    out.append("GH\t{}\t{}\t{}\t{}\t{}".format(info.get("format") or "-", _clean(head.get("ref") or "-"),
                                               head.get("commit") or "-", 1 if head.get("detached") else 0,
                                               1 if head.get("unborn") else 0))
    for g in info.get("gaps") or []:
        out.append(f"GR\thead\t{_clean(g)}")
    if info.get("index_reason"):
        out.append(f"GR\tindex\t{_clean(info['index_reason'])}")
    if info.get("tree_reason"):
        out.append(f"GR\ttree\t{_clean(info['tree_reason'])}")
    idx = info.get("index") or {}
    if idx:
        out.append(f"GX\tindex_version\t{idx.get('version') or '-'}")
        out.append(f"GX\tsplit\t{1 if idx.get('split') else 0}")
        out.append(f"GX\tentries\t{len(idx.get('entries') or {})}")
        out.append(f"GX\tsparse_dirs\t{len(idx.get('sparse_dirs') or [])}")
        for p in (idx.get("conflicts") or [])[:100]:
            f, e = enc(os.fsencode(p))
            out.append(f"GC\t{f}\t{e}")
    if info.get("tree") is not None:
        out.append(f"GX\ttree_entries\t{len(info['tree'])}")
    if drift is not None:
        n = 0
        for cls, path, detail in drift["entries"]:
            if cls == "ignored":
                continue
            n += 1
            if n > MAX_DRIFT_RECORDS:
                out.append("GX\tdrift_capped\t1")
                break
            f, e = enc(os.fsencode(path))
            out.append(f"D\t{cls}\t{f}\t{e}\t{_clean(detail) or '-'}")
        for cls, c in sorted(drift["counts"].items()):
            out.append(f"GN\t{cls}\t{c}")
        for cls, path, _d in drift["entries"]:
            if cls == "ignored":
                f, e = enc(os.fsencode(path))
                out.append(f"DI\t{f}\t{e}")
    return out


def compute_git(source: gitread.Source, work: Dict[str, Tuple[int, str]], ignores: Dict[str, str],
                attrs: Dict[str, str], skipped: List[str], *, complete_walk: bool, max_files: int,
                max_pack_bytes: int) -> List[str]:
    """Read the repository and compare it with the walk -- the same on the agent and on
    Kratos. `ignores`/`attrs`: {path of a .gitignore/.gitattributes: text}."""
    try:
        info = gitread.read_repo(source, max_entries=max_files, max_pack_bytes=max_pack_bytes)
    except gitread.GitError as e:
        return [f"GR\thead\t{_clean(e)}"]
    if info.get("worktree"):
        return git_records(info, None) + ["GR\tindex\tcore.worktree points elsewhere: drift not compared"]
    idx = info.get("index")
    if idx is None:
        return git_records(info, None)
    ig = gitread.Ignore()
    for rel, text in sorted(ignores.items()):
        base = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        ig.add(base, text)
    excl = None
    try:
        excl = source.read("info/exclude", 256 * 1024)
    except gitread.GitError:
        excl = None
    if excl:
        ig.add_exclude(excl.decode("utf-8", "replace"))
    rules = []
    for rel, text in sorted(attrs.items()):
        base = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        rules += [(base, r) for r in gitread.filter_rules(text, base)]
    skip = tuple(s.rstrip("/") + "/" for s in skipped)

    def covered(p: str) -> bool:
        return complete_walk and not p.startswith(skip)

    def filtered(p: str) -> bool:
        return any(p.startswith(b) and r.rx.match(p[len(b):]) for b, r in rules)

    d = gitread.drift(work, idx["entries"], info.get("tree"), ig, covered=covered, filtered=filtered,
                      sparse_dirs=idx.get("sparse_dirs") or (), conflicts=idx.get("conflicts") or ())
    tracked_skipped = sum(1 for p in idx["entries"] if p.startswith(skip))
    recs = git_records(info, d)
    if tracked_skipped:
        recs.append(f"GX\ttracked_in_skipped\t{tracked_skipped}")
    return recs


def _agent_lister(path: str) -> Optional[List[str]]:
    try:
        fd = os.open(path, _DIR_FLAGS)
    except OSError:
        return None
    try:
        return sorted(e.name for e in os.scandir(fd))
    except OSError:
        return None
    finally:
        os.close(fd)


def agent_git_records(root: bytes, rfd: int, fmt: str, walk: Walk, *, max_files: int,
                      max_pack_bytes: int) -> List[str]:
    """On the agent: read the root's .git through the hardened opener, compare."""
    try:
        from . import hostfiles  # type: ignore[attr-defined]
    except ImportError:  # pragma: no cover
        try:
            from kratos.logsources import hostfiles
        except ImportError:
            import hostfiles  # type: ignore[no-redef]

    def opener(path: str) -> Tuple[int, Any]:
        return hostfiles.open_log_file(path)

    src = gitread.FileSource(os.fsdecode(root) + "/.git", opener, _agent_lister)
    try:
        work = {os.fsdecode(k): (v[0], v[1]) for k, v in walk.files.items()}
        ig = {os.fsdecode(k): v.decode("utf-8", "replace") for k, v in walk.ignores.items()}
        at = {os.fsdecode(k): v.decode("utf-8", "replace") for k, v in walk.attrs.items()}
        return compute_git(src, work, ig, at, [os.fsdecode(s) for s in walk.skipped],
                           complete_walk=not (walk.capped or walk.timed_out), max_files=max_files,
                           max_pack_bytes=max_pack_bytes)
    finally:
        src.close()


# --------------------------------------------------------------------------- the inventory parser
def parse_inventory(stdout: str) -> Dict[str, Any]:
    """{now, uid, root: {status, dev, ino, mode, uid}, git, format, gitfile, files: {rel:
    {...}}, links: {rel: target}, skipped: [{path, reason, count}], gitfiles: {rel: size},
    totals, git_state: {head, reasons, counts, drift: [...], conflicts, ignored}, complete}."""
    out: Dict[str, Any] = {"now": None, "uid": None, "root": {"status": None}, "git": "none", "format": None,
                           "gitfile": None, "files": {}, "links": {}, "skipped": [], "gitfiles": {}, "totals": {},
                           "git_state": None, "complete": False}
    gs: Dict[str, Any] = {"head": None, "reasons": {}, "extra": {}, "counts": {}, "drift": [], "conflicts": [],
                          "ignored": []}
    have_git = False
    for line in stdout.split("\n"):
        cols = line.split("\t")
        tag = cols[0]
        if tag == "M" and len(cols) >= 3:
            key, val = cols[1], cols[2]
            if key in ("now", "uid") and val.strip().isdigit():
                out[key] = int(val)
            elif key == "git" and val in ("none", "dir", "file"):
                out["git"] = val
            elif key == "format":
                out["format"] = val if val in ("sha1", "sha256") else None
        elif tag == "R" and len(cols) >= 2:
            r: Dict[str, Any] = {"status": cols[1]}
            if cols[1] == "ok" and len(cols) >= 6:
                for k, v in zip(("dev", "ino", "mode", "uid"), cols[2:6]):
                    r[k] = int(v) if v.isdigit() else v
            out["root"] = r
        elif tag == "GF" and len(cols) >= 2:
            raw = dec("b", cols[1])
            out["gitfile"] = raw.decode("utf-8", "replace") if raw is not None else None
        elif tag == "F" and len(cols) >= 12:
            raw = dec(cols[1], cols[2])
            if raw is None:
                continue
            rel = os.fsdecode(raw)

            def num(v: str) -> Optional[int]:
                return int(v) if v.isdigit() else None
            out["files"][rel] = {"size": num(cols[3]), "mode": cols[4] if cols[4] != "-" else None,
                                 "uid": num(cols[5]), "mtime": num(cols[6]), "ino": num(cols[7]),
                                 "nlink": num(cols[8]), "sha256": cols[9] if len(cols[9]) == 64 else None,
                                 "blob": cols[10] if cols[10] != "-" else None, "status": cols[11].strip(),
                                 "encoded": cols[1] == "b"}
        elif tag == "L" and len(cols) >= 5:
            raw = dec(cols[1], cols[2])
            tgt = dec(cols[3], cols[4])
            if raw is not None:
                out["links"][os.fsdecode(raw)] = os.fsdecode(tgt or b"")
        elif tag == "S" and len(cols) >= 5:
            raw = dec(cols[1], cols[2])
            if raw is not None:
                out["skipped"].append({"path": os.fsdecode(raw), "reason": cols[3],
                                       "count": int(cols[4]) if cols[4].strip().isdigit() else None})
        elif tag == "G" and len(cols) >= 4:
            raw = dec(cols[1], cols[2])
            if raw is not None:
                out["gitfiles"][os.fsdecode(raw)] = int(cols[3]) if cols[3].strip().isdigit() else None
        elif tag == "T" and len(cols) >= 3:
            out["totals"][cols[1]] = cols[2].strip()
        elif tag == "GH" and len(cols) >= 6:
            have_git = True
            gs["head"] = {"format": cols[1], "ref": None if cols[2] == "-" else cols[2],
                          "commit": None if cols[3] == "-" else cols[3], "detached": cols[4] == "1",
                          "unborn": cols[5].strip() == "1"}
        elif tag == "GR" and len(cols) >= 3:
            have_git = True
            gs["reasons"][cols[1]] = cols[2]
        elif tag == "GX" and len(cols) >= 3:
            gs["extra"][cols[1]] = cols[2].strip()
        elif tag == "GN" and len(cols) >= 3 and cols[2].strip().isdigit():
            gs["counts"][cols[1]] = int(cols[2])
        elif tag == "GC" and len(cols) >= 3:
            raw = dec(cols[1], cols[2])
            if raw is not None:
                gs["conflicts"].append(os.fsdecode(raw))
        elif tag == "D" and len(cols) >= 5:
            raw = dec(cols[2], cols[3])
            if raw is not None:
                gs["drift"].append({"class": cols[1], "path": os.fsdecode(raw),
                                    "detail": "" if cols[4].strip() == "-" else cols[4].strip()})
        elif tag == "DI" and len(cols) >= 3:
            raw = dec(cols[1], cols[2])
            if raw is not None:
                gs["ignored"].append(os.fsdecode(raw))
        elif tag == "END":
            out["complete"] = True
    if have_git:
        out["git_state"] = gs
    if any(out["totals"].get(k) == "1" for k in ("capped", "timed_out", "depth_capped")) or out["totals"].get(
            "long_lines"):
        out["complete"] = False
    return out


def paginate(stdout: str, page_bytes: int = PAGE_BYTES) -> List[str]:
    """Split an inventory's lines into pages of at most `page_bytes`; each page but the last
    ends with ``P more``, the last with ``P last``. A single line longer than a page is
    dropped and counted (``T long_lines``) -- it can't be sent."""
    pages: List[str] = []
    cur: List[str] = []
    size = 0
    dropped = 0
    for line in stdout.split("\n"):
        if not line:
            continue
        n = len(line.encode("utf-8", "surrogateescape")) + 1
        if n > page_bytes - 64:
            dropped += 1
            continue
        if size + n > page_bytes - 64 and cur:
            pages.append("\n".join(cur + ["P\tmore"]) + "\n")
            cur, size = [], 0
        cur.append(line)
        size += n
    if dropped:
        cur.insert(0, f"T\tlong_lines\t{dropped}")
    pages.append("\n".join(cur + ["P\tlast"]) + "\n")
    return pages


# =========================================================================== code_read
_READ_SH = r"""
LC_ALL=C; export LC_ALL
ROOT=$(printf '%s' '@ROOTB64@' | base64 -d 2>/dev/null)
printf 'M\tnow\t%s\n' "$(date +%s)"
printf 'M\tuid\t%s\n' "$(id -u)"
if [ -z "$ROOT" ] || [ -L "$ROOT" ] || [ ! -d "$ROOT" ]; then printf 'R\tmissing\n'; exit 0; fi
_phys=$(cd "$ROOT" 2>/dev/null && pwd -P)
if [ "$_phys" != "$ROOT" ]; then printf 'R\tsymlink\n'; exit 0; fi
printf 'R\tok\n'
cd "$ROOT" || exit 0
USED=0
printf '%s' '@PATHS@' | base64 -d 2>/dev/null | tr '\0' '\n' | awk '{ print NR - 1 "\t" $0 }' | \
while IFS="$(printf '\t')" read -r _i _p; do
  [ -n "$_p" ] || continue
  if [ -L "$_p" ]; then printf 'B\t%s\tlink\t-\t-\t-\n' "$_i"; continue; fi
  _d=${_p%/*}
  if [ "$_d" != "$_p" ]; then
    _real=$(cd "./$_d" 2>/dev/null && pwd -P)
    if [ "$_real" != "$ROOT/$_d" ]; then printf 'B\t%s\tlink\t-\t-\t-\n' "$_i"; continue; fi
  fi
  if [ ! -e "$_p" ]; then printf 'B\t%s\tmissing\t-\t-\t-\n' "$_i"; continue; fi
  if [ ! -f "$_p" ]; then printf 'B\t%s\tnot_regular\t-\t-\t-\n' "$_i"; continue; fi
  _st=$(stat -c '%s %i %h %Y' -- "$_p" 2>/dev/null)
  if [ -z "$_st" ] || [ ! -r "$_p" ]; then printf 'B\t%s\tunreadable\t-\t-\t-\n' "$_i"; continue; fi
  set -- $_st
  if [ "$3" != 1 ]; then printf 'B\t%s\thardlink\t%s\t-\t-\n' "$_i" "$1"; continue; fi
  _cap=@SMALLCAP@
  case "$_p" in .git/*) _cap=@GITCAP@ ;; esac
  @PURPOSECAP@
  if [ "$1" -gt "$_cap" ]; then printf 'B\t%s\ttoo_large\t%s\t-\t-\n' "$_i" "$1"; continue; fi
  if [ $((USED + $1)) -gt @BUDGET@ ]; then printf 'B\t%s\tbudget\t%s\t-\t-\n' "$_i" "$1"; continue; fi
  @BINARY@
  USED=$((USED + $1))
  _h=$(sha256sum < "$_p" 2>/dev/null); _h=${_h%% *}
  _c=$(base64 < "$_p" 2>/dev/null | tr -d '\n')
  _st2=$(stat -c '%s %i %h %Y' -- "$_p" 2>/dev/null)
  if [ "$_st2" != "$_st" ]; then printf 'B\t%s\tchanged\t%s\t-\t-\n' "$_i" "$1"; continue; fi
  printf 'B\t%s\tok\t%s\t%s\t%s\n' "$_i" "$1" "$_h" "$_c"
done
"""
_BINARY_SH = ('if [ "$(head -c 8192 -- "$_p" 2>/dev/null | tr -d -c \'\\000\' | wc -c | tr -d \' \')" != 0 ]; then '
              'printf \'B\\t%s\\tbinary\\t%s\\t-\\t-\\n\' "$_i" "$1"; continue; fi')


def _cap_for(purpose: str) -> int:
    return {"deps": DEPS_MAX_BYTES, "secrets": SECRETS_MAX_BYTES, "git": 256 * 1024,
            "review": REVIEW_MAX_BYTES}[purpose]


def check_read_request(purpose: str, paths: List[bytes]) -> None:
    if purpose not in PURPOSES:
        raise RequestError("unknown purpose")
    if not paths or len(paths) > MAX_READ_PATHS:
        raise RequestError(f"1-{MAX_READ_PATHS} paths")
    for p in paths:
        check_rel(p)
        if b"\n" in p:
            raise RequestError("a path with a newline is never read")
        why = purpose_allows(purpose, p, None)
        if why is not None:
            raise RequestError(why)


def build_read_script(root: bytes, purpose: str, paths: List[bytes], *, budget_bytes: int) -> str:
    """The SSH content read. The paths (relative to the root, from its latest inventory)
    travel NUL-separated, base64, inside this script on stdin."""
    check_root(root)
    check_read_request(purpose, paths)
    blob = b64(b"\x00".join(paths))
    body = (_READ_SH.replace("@ROOTB64@", b64(root)).replace("@PATHS@", blob)
            .replace("@SMALLCAP@", str(_cap_for(purpose))).replace("@GITCAP@", str(GIT_MAX_FILE_BYTES))
            .replace("@BUDGET@", str(int(budget_bytes)))
            .replace("@PURPOSECAP@", "")
            .replace("@BINARY@", _BINARY_SH if purpose in ("secrets", "review", "deps") else ""))
    return "{\n" + body + "printf 'END\\n'\n} | head -c " + str(READ_OUTPUT_CAP) + "\nexit 0\n"


def read_output(root: bytes, purpose: str, paths: List[bytes], *, budget_bytes: int,
                listed: Callable[[bytes, bytes], Optional[int]] = lambda r, p: 0) -> Dict[str, Any]:
    """The agent's content read: the same records. `listed(root, rel)` -> the size this
    agent's own inventory of `root` recorded for `rel`, or None when it never listed it
    (then the file is refused: "not_listed")."""
    check_root(root)
    check_read_request(purpose, paths)
    out: List[str] = [f"M\tnow\t{int(time.time())}", f"M\tuid\t{os.getuid()}"]
    rfd, status, _rst = open_root(root)
    if rfd is None:
        out += ["R\tmissing" if status != "symlink" else "R\tsymlink", "END"]
        return {"stdout": "\n".join(out) + "\n", "returncode": 0}
    used = 0
    try:
        out.append("R\tok")
        for i, rel in enumerate(paths):
            if listed(root, rel) is None:
                out.append(f"B\t{i}\tnot_listed\t-\t-\t-")
                continue
            parts = rel.split(b"/")
            dfd = os.dup(rfd)
            bad = None
            for part in parts[:-1]:
                try:
                    nxt = os.open(part, _DIR_FLAGS, dir_fd=dfd)
                except OSError as e:
                    bad = "link" if getattr(e, "errno", 0) in (40, 20) else "missing"
                    break
                os.close(dfd)
                dfd = nxt
            if bad is not None:
                os.close(dfd)
                out.append(f"B\t{i}\t{bad}\t-\t-\t-")
                continue
            try:
                try:
                    lst = os.stat(parts[-1], dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError:
                    out.append(f"B\t{i}\tmissing\t-\t-\t-")
                    continue
                except OSError:
                    out.append(f"B\t{i}\tunreadable\t-\t-\t-")
                    continue
                if stat.S_ISLNK(lst.st_mode):
                    out.append(f"B\t{i}\tlink\t-\t-\t-")
                    continue
                if not stat.S_ISREG(lst.st_mode):
                    out.append(f"B\t{i}\tnot_regular\t-\t-\t-")
                    continue
                if lst.st_nlink != 1:
                    out.append(f"B\t{i}\thardlink\t{lst.st_size}\t-\t-")
                    continue
                cap = GIT_MAX_FILE_BYTES if rel.startswith(b".git/") else _cap_for(purpose)
                if lst.st_size > cap:
                    out.append(f"B\t{i}\ttoo_large\t{lst.st_size}\t-\t-")
                    continue
                if used + lst.st_size > budget_bytes:
                    out.append(f"B\t{i}\tbudget\t{lst.st_size}\t-\t-")
                    continue
                try:
                    fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=dfd)
                except OSError:
                    out.append(f"B\t{i}\tunreadable\t-\t-\t-")
                    continue
                try:
                    fst = os.fstat(fd)
                    if (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino) or not stat.S_ISREG(fst.st_mode):
                        out.append(f"B\t{i}\tchanged\t{lst.st_size}\t-\t-")
                        continue
                    data = b""
                    off = 0
                    while off < fst.st_size:
                        chunk = os.pread(fd, min(1 << 20, fst.st_size - off), off)
                        if not chunk:
                            break
                        data += chunk
                        off += len(chunk)
                finally:
                    os.close(fd)
                if len(data) != lst.st_size:
                    out.append(f"B\t{i}\tchanged\t{lst.st_size}\t-\t-")
                    continue
                if purpose in ("secrets", "review", "deps") and b"\x00" in data[:8192]:
                    out.append(f"B\t{i}\tbinary\t{lst.st_size}\t-\t-")
                    continue
                used += len(data)
                out.append(f"B\t{i}\tok\t{len(data)}\t{hashlib.sha256(data).hexdigest()}\t{b64(data)}")
            finally:
                os.close(dfd)
    finally:
        os.close(rfd)
    out.append("END")
    return {"stdout": "\n".join(out) + "\n", "returncode": 0}


def parse_read(stdout: str, count: int) -> Dict[str, Any]:
    """{root_status, files: {idx: {status, size, sha256, data}}, complete}. Content is kept
    in memory only; the caller never stores it."""
    out: Dict[str, Any] = {"root_status": None, "uid": None, "files": {}, "complete": False}
    for line in stdout.split("\n"):
        cols = line.split("\t")
        if cols[0] == "R" and len(cols) >= 2:
            out["root_status"] = cols[1].strip()
        elif cols[0] == "M" and len(cols) >= 3 and cols[1] == "uid" and cols[2].strip().isdigit():
            out["uid"] = int(cols[2])
        elif cols[0] == "B" and len(cols) >= 6 and cols[1].isdigit():
            i = int(cols[1])
            if i >= count:
                continue
            item: Dict[str, Any] = {"status": cols[2], "size": int(cols[3]) if cols[3].isdigit() else None,
                                    "sha256": None, "data": None}
            if cols[2] == "ok":
                data = dec("b", cols[5].strip()) if cols[5].strip() else b""
                if data is None or hashlib.sha256(data).hexdigest() != cols[4]:
                    item["status"] = "changed"
                else:
                    item["data"] = data
                    item["sha256"] = cols[4]
            out["files"][i] = item
        elif cols[0] == "END":
            out["complete"] = True
    return out
