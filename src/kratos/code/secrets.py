"""Secrets in deployed code and config (E.7a §3.8) -- reported by kind and location, never
by value.

A closed set of patterns (the shapes ``kratos.privacy.secrets`` removes from model text,
plus credential-file shapes): private-key blocks, AWS / Google / GitHub / GitLab / Slack /
OpenAI-style keys, JSON web tokens, passwords in URLs, ``password = "..."`` / ``api_key:
...`` assignments, ``wp-config.php``'s ``DB_PASSWORD``, Django's ``SECRET_KEY``, secret
keys in a ``.env`` file. A private-key FILE (``*.pem``, ``id_rsa``, ...) is reported by its
name and never read.

Each hit is (file, line, kind, fingerprint). The fingerprint is HMAC-SHA-256 of the value
under a per-install key (``data_dir/code-keys/fingerprint.key``, 0600, never leaves this
computer), first 8 hex -- so a person sees "the same secret in two places" without seeing
it. The value itself is discarded the moment the fingerprint is computed: it is never
stored, logged, shown, exported or sent to a model (tests/test_code_secrets_never_stored.py
greps every output for planted values).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets as _rand
from dataclasses import dataclass
from pathlib import Path

from kratos.adapters import code_facts as CF

KEY_FILE = "code-keys/fingerprint.key"
MAX_HITS_PER_FILE = 20
MAX_LINE_CHARS = 4000
_PLACEHOLDER = re.compile(
    r"^(?:|x+|\*+|\.+|-+|null|none|nil|true|false|changeme|change_me|password|secret|example|test|dummy|"
    r"your[_-]?\w*|<[^>]*>|\$\{[^}]*\}|\$[A-Za-z_]\w*|%\(?\w*\)?s|\{\{[^}]*\}\}|os\.environ.*|getenv.*|env\(.*)$",
    re.IGNORECASE)
_KEYS = (r"password|passwd|pwd|secret|secret_key|token|auth_token|access_token|api_key|apikey|api_secret|"
         r"client_secret|private_key|aws_secret_access_key|db_password|database_password")

# (kind, compiled pattern with a group named "v" for the value)
PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("private key block", re.compile(r"(?P<v>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)")),
    ("AWS access key id", re.compile(r"\b(?P<v>(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b")),
    ("Google API key", re.compile(r"\b(?P<v>AIza[0-9A-Za-z_-]{35})\b")),
    ("GitHub token", re.compile(r"\b(?P<v>gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("GitLab token", re.compile(r"\b(?P<v>glpat-[A-Za-z0-9_-]{20,})\b")),
    ("Slack token", re.compile(r"\b(?P<v>xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("API secret key (sk-...)", re.compile(r"\b(?P<v>sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,})\b")),
    ("JSON web token", re.compile(r"\b(?P<v>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")),
    ("password in a URL", re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^/\s:@'\"]{1,64}:(?P<v>[^@\s/'\"]{3,128})@[\w.-]+")),
    ("WordPress database password", re.compile(r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](?P<v>[^'\"]*)['\"]")),
    ("Django SECRET_KEY", re.compile(r"^\s*SECRET_KEY\s*=\s*['\"](?P<v>[^'\"]{8,})['\"]")),
    ("secret assignment", re.compile(
        rf"""(?<![\w.])['"]?(?:{_KEYS})['"]?\s*(?::|=>|=)\s*(?P<q>['"])(?P<v>[^'"\n]{{6,256}})(?P=q)""",
        re.IGNORECASE)),
)
_ENV_LINE = re.compile(rf"^\s*(?:export\s+)?[A-Z0-9_]*(?:{_KEYS.upper()})[A-Z0-9_]*\s*=\s*(?P<v>.+?)\s*$")


@dataclass(frozen=True)
class Hit:
    rel: str
    line: int
    kind: str
    fingerprint: str      # 8 hex, keyed; "" for a file reported by name only


def _key(data_dir: Path) -> bytes:
    """The per-install fingerprint key, made once (0600). Never sent anywhere."""
    p = Path(data_dir) / KEY_FILE
    try:
        return p.read_bytes()
    except FileNotFoundError:
        pass
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    key = _rand.token_bytes(32)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return p.read_bytes()
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def fingerprint(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()[:8]


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return v


def scan_text(rel: str, data: bytes, key: bytes) -> list[Hit]:
    """Secret-shaped values in one file's text. Only (line, kind, fingerprint) leave this
    function; the matched value is never returned."""
    name = rel.rsplit("/", 1)[-1]
    is_env = name == ".env" or name.startswith(".env.")
    out: list[Hit] = []
    seen: set[tuple[int, str, str]] = set()
    text = data.decode("utf-8", "replace")
    for n, line in enumerate(text.splitlines(), 1):
        if len(out) >= MAX_HITS_PER_FILE:
            break
        line = line[:MAX_LINE_CHARS]
        found: list[tuple[str, str]] = []
        for kind, rx in PATTERNS:
            for m in rx.finditer(line):
                found.append((kind, m.group("v")))
        if is_env and not line.lstrip().startswith("#"):
            m = _ENV_LINE.match(line)
            if m:
                found.append((".env secret", _strip_quotes(m.group("v"))))
        for kind, value in found:
            if kind != "private key block" and _PLACEHOLDER.match(value.strip()):
                continue
            fp = fingerprint(key, value)
            del value
            if (n, kind, fp) in seen:
                continue
            seen.add((n, kind, fp))
            out.append(Hit(rel, n, kind, fp))
    return out


def key_files(inventory_files: dict[str, dict]) -> list[Hit]:
    """Private-key files reported by NAME (never read)."""
    return [Hit(rel, 0, "private-key file (by name; not read)", "") for rel in sorted(inventory_files)
            if CF.is_key_file(os.fsencode(rel))]


MAX_FILES = 3000                 # per folder: tiny files can fit any byte budget, but each read costs
_CONFIG_EXTS = (".env", ".ini", ".cfg", ".conf", ".config", ".json", ".yml", ".yaml", ".toml", ".xml", ".properties")


def _priority(rel: str) -> tuple[int, str]:
    name = rel.rsplit("/", 1)[-1]
    if name in CF.SECRET_NAMES or name.startswith(".env"):
        return 0, rel
    if name.lower().endswith(_CONFIG_EXTS):
        return 1, rel
    return 2, rel


def candidates(inventory_files: dict[str, dict], max_files: int = MAX_FILES) -> tuple[list[str], int]:
    """(files to scan, how many text-shaped files were skipped). Minified bundles over 1 MiB,
    anything over the secrets size cap, and past `max_files` per folder (credential and config
    files first) are not scanned -- counted."""
    want: list[str] = []
    skipped = 0
    for rel, f in sorted(inventory_files.items()):
        if f.get("status") != "ok":
            continue
        size = int(f.get("size") or 0)
        why = CF.purpose_allows("secrets", os.fsencode(rel), None)
        if why is not None:
            continue
        if size > CF.SECRETS_MAX_BYTES or (rel.endswith((".min.js", ".bundle.js")) and size > 1024 * 1024):
            skipped += 1
            continue
        want.append(rel)
    want.sort(key=_priority)
    if len(want) > max_files:
        skipped += len(want) - max_files
        want = want[:max_files]
    return want, skipped
