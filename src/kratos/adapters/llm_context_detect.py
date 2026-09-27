"""
Best-effort context-window DETECTION for a model behind an OpenAI-compatible
(or native) endpoint. Powers the model-setup UI and the detect-once-and-save
autofill (adapters/llm_context_autofill.py): Kratos asks what context a model
supports so it can save a real number instead of guessing.

Designed to scale across providers WITHOUT per-provider code. Providers differ
in three ways, and each is handled generically:

  * WHERE the number lives -- tried in order: the model list
    (`{base}/models`), the single-model page (`{base}/models/{id}`), the same
    page one path level up (`{parent}/models/{id}` -- e.g. Gemini's native
    `/v1beta/models/{id}` sits above its OpenAI-compatible `/v1beta/openai`),
    and a server-info page (`{root}/info`, e.g. Hugging Face TGI).
  * WHAT it's called -- every reply is searched (nested objects included) for a
    number under any accepted "context size" field name (`_CONTEXT_FIELDS`),
    compared after lowercasing and dropping `_`/`-`, so `inputTokenLimit` and
    `input_token_limit` are the same. OUTPUT-limit names are deliberately not in
    the list. Supporting a new provider is normally one name added there.
  * HOW the key is sent -- the user's key goes out as `Authorization: Bearer`,
    `x-api-key` and `x-goog-api-key` at once, only ever to the endpoint the user
    configured.

Local Ollama is the one special case kept: its info needs a POST and it has a
real loaded-vs-max distinction (`num_ctx` at load time vs the architecture max).

If the provider reports nothing, a PUBLIC CATALOG (OpenRouter's keyless model
list) is consulted by model name. That number is the model's published maximum,
not this provider's limit, so it is marked `authority="catalog"`, never treated
as a hard ceiling, and the UI says the provider may allow less.

Two numbers, because they mean different things:

  * `max_context` -- the HARD ceiling this endpoint enforces. Exceeding it WILL
    be rejected, so the UI treats "above max" as unacceptable. Only set when the
    endpoint itself reported it.
  * `loaded_context` -- what's currently served (Ollama's `num_ctx`), or the
    catalog's published figure. The sensible default, NOT a ceiling.

Everything here is on-demand only (called from the settings flow or when a model
is added/switched), never during an investigation. Every probe is bounded by a
short timeout and fails soft: a wrong guess about where the number lives just
moves on to the next place. An undetectable endpoint is a normal outcome.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from kratos.utils.redact import redact_secrets

_DEFAULT_TIMEOUT = 4  # seconds per probe -- detection is interactive, must not hang the UI
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

# Accepted "context size" field names, NORMALIZED (lowercase, no `_`/`-`), in
# preference order when a reply carries several. Output limits
# (max_completion_tokens, outputTokenLimit, max_output_tokens, max_tokens) are
# intentionally absent: they are not the context window.
_CONTEXT_FIELDS: tuple[str, ...] = (
    "contextlength",        # OpenRouter, Together, Fireworks, LM Studio, many OpenAI-compatible hosts
    "contextwindow",        # Groq and others
    "maxmodellen",          # vLLM
    "maxcontextlength",     # Mistral and others
    "maxcontexttokens",
    "maxtotaltokens",       # Hugging Face TGI /info (prompt + answer: the true window, so it outranks input-only)
    "inputtokenlimit",      # Google Gemini (native API)
    "maxinputtokens",       # Anthropic-style / TGI max_input_tokens
    "maxsequencelength",
    "maxseqlen",
    "contextsize",
    "nctx",                 # llama.cpp server
)
_FIELD_RANK = {name: i for i, name in enumerate(_CONTEXT_FIELDS)}

# Public, keyless model catalog used only as a fallback when the provider itself
# reports nothing. Fetched at most once per process.
_CATALOG_URL = "https://openrouter.ai/api/v1/models"
_catalog_cache: list[dict] | None = None


@dataclass
class DetectedContext:
    max_context: int | None        # hard ceiling this endpoint enforces; None if not reported
    loaded_context: int | None     # currently served (Ollama) or catalog's published figure
    source: str                    # "ollama" | "provider" | "catalog" | "none"
    detail: str                    # short human-readable hint for the UI
    error: str | None = None       # a redacted probe error, when one is worth surfacing
    authority: str | None = None   # "provider" | "catalog" -- how much to trust it; None if undetected

    @property
    def detectable(self) -> bool:
        return self.max_context is not None or self.loaded_context is not None

    @property
    def value(self) -> int | None:
        """The number to save/prefill: what's actually served when known, else the max."""
        return self.loaded_context or self.max_context


def _root(base_url: str) -> str:
    """Native (non-OpenAI) endpoints live at the server root, not under /v1 --
    e.g. Ollama's /api/* and TGI's /info. Strip a trailing /v1 (and any slash)."""
    u = base_url.rstrip("/")
    if u.endswith("/v1"):
        u = u[: -len("/v1")]
    return u


def _parent(base_url: str) -> str | None:
    """The base URL one path level up (`.../v1beta/openai` -> `.../v1beta`), or
    None when there's no path left to strip."""
    p = urlparse(base_url.rstrip("/"))
    path = p.path.rstrip("/")
    if "/" not in path.strip("/"):
        return None
    return f"{p.scheme}://{p.netloc}{path.rsplit('/', 1)[0]}"


def _host_is_local(base_url: str) -> bool:
    host = (urlparse(base_url).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.startswith("127.")


def _norm_key(key: str) -> str:
    return re.sub(r"[_\-]", "", str(key)).lower()


def _norm_model(model_id: str) -> str:
    """Comparable model id: lowercase, no `models/` prefix, no `:variant` suffix."""
    m = str(model_id).strip().lower()
    if m.startswith("models/"):
        m = m[len("models/"):]
    return m.split(":", 1)[0]


def find_context_field(obj, _depth: int = 0) -> tuple[int, str] | None:
    """Search a JSON reply (breadth-first, so top-level fields beat nested ones)
    for the best-ranked accepted context field holding a positive number.
    Returns (value, original_field_name) or None."""
    best: tuple[int, int, int, str] | None = None  # (depth, rank, value, name)
    frontier = [(obj, 0)]
    while frontier:
        node, depth = frontier.pop(0)
        if depth > 4:
            continue
        if isinstance(node, dict):
            for k, v in node.items():
                rank = _FIELD_RANK.get(_norm_key(k))
                if rank is not None and isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                    cand = (depth, rank, int(v), str(k))
                    if best is None or cand[:2] < best[:2]:
                        best = cand
                elif isinstance(v, (dict, list)):
                    frontier.append((v, depth + 1))
        elif isinstance(node, list):
            frontier.extend((item, depth + 1) for item in node)
    return (best[2], best[3]) if best else None


def _find_model_entry(data: list, model: str) -> dict | None:
    """Match `model` in a model list: exact id first, then ignoring a `models/`
    prefix / `:variant` suffix, then by the last path segment (`vendor/model`)."""
    target = _norm_model(model)
    entries = [e for e in data if isinstance(e, dict)]
    for e in entries:
        if e.get("id") == model:
            return e
    for e in entries:
        if _norm_model(e.get("id", "")) == target:
            return e
    tail = target.split("/")[-1]
    for e in entries:
        if _norm_model(e.get("id", "")).split("/")[-1] == tail:
            return e
    return None


def _auth_header_styles(api_key: str) -> list[dict[str, str]]:
    """The common ways providers take a key, tried ONE AT A TIME -- sending them
    together fails on some providers (Google reads a Bearer header as an OAuth
    token and rejects the whole request)."""
    if not api_key:
        return [{}]
    return [{"Authorization": f"Bearer {api_key}"}, {"x-api-key": api_key}, {"x-goog-api-key": api_key}]


def _get_json(url: str, api_key: str, timeout: int):
    """GET a JSON page, trying the next key style only when the key was refused
    (401/403) -- any other status means the page isn't there, so stop."""
    for headers in _auth_header_styles(api_key):
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code not in (401, 403):
            return None
    return None


def _provider_hit(win: int, field: str, url: str) -> DetectedContext:
    host = urlparse(url).netloc or url
    return DetectedContext(max_context=win, loaded_context=win, source="provider",
                           detail=f"{host} reports {win:,} ({field})", authority="provider")


def _try_model_list(base_url: str, api_key: str, model: str, timeout: int) -> DetectedContext | None:
    url = f"{base_url.rstrip('/')}/models"
    body = _get_json(url, api_key, timeout)
    if not isinstance(body, dict):
        return None
    entry = _find_model_entry(body.get("data") or body.get("models") or [], model)
    hit = find_context_field(entry) if entry else None
    return _provider_hit(hit[0], hit[1], url) if hit else None


def _try_json_page(url: str, api_key: str, timeout: int) -> DetectedContext | None:
    body = _get_json(url, api_key, timeout)
    hit = find_context_field(body) if isinstance(body, (dict, list)) else None
    return _provider_hit(hit[0], hit[1], url) if hit else None


def _first_context_length_key(model_info: dict) -> int | None:
    """Ollama /api/show returns model_info with an architecture-scoped key like
    'qwen3.context_length' -- scan for any '*.context_length' rather than guess
    the architecture name."""
    for k, v in model_info.items():
        if k.endswith(".context_length") and isinstance(v, (int, float)) and v > 0:
            return int(v)
    return None


def _try_ollama(root: str, model: str, timeout: int) -> DetectedContext | None:
    """Ollama native API: /api/show for the model's architecture max, /api/ps
    for what it's currently loaded at (num_ctx). Local; no auth."""
    max_ctx: int | None = None
    loaded: int | None = None
    show = requests.post(f"{root}/api/show", json={"name": model}, timeout=timeout)
    if show.status_code != 200:
        return None
    info = show.json().get("model_info") or {}
    max_ctx = _first_context_length_key(info)
    try:
        ps = requests.get(f"{root}/api/ps", timeout=timeout)
        if ps.status_code == 200:
            for m in ps.json().get("models", []):
                if model in (m.get("name", ""), m.get("model", "")):
                    cl = m.get("context_length")
                    if isinstance(cl, (int, float)) and cl > 0:
                        loaded = int(cl)
                    break
    except requests.RequestException:
        pass  # /api/ps is a bonus (current load); its absence isn't fatal
    if max_ctx is None and loaded is None:
        return None
    if loaded is not None and max_ctx is not None and loaded < max_ctx:
        detail = f"Ollama: loaded at {loaded:,}, model supports up to {max_ctx:,}"
    elif max_ctx is not None:
        detail = f"Ollama: model supports up to {max_ctx:,}"
    else:
        detail = f"Ollama: currently loaded at {loaded:,}"
    return DetectedContext(max_context=max_ctx, loaded_context=loaded, source="ollama",
                           detail=detail, authority="provider")


def _load_catalog(timeout: int) -> list[dict]:
    global _catalog_cache
    if _catalog_cache is None:
        resp = requests.get(_CATALOG_URL, timeout=timeout)
        _catalog_cache = (resp.json().get("data") or []) if resp.status_code == 200 else []
    return _catalog_cache


def _try_catalog(model: str, timeout: int) -> DetectedContext | None:
    """The model's PUBLISHED window from a public catalog, by name. Not this
    provider's limit -- so no hard ceiling (max_context stays None)."""
    entry = _find_model_entry(_load_catalog(timeout), model)
    hit = find_context_field(entry) if entry else None
    if not hit:
        return None
    win = hit[0]
    return DetectedContext(
        max_context=None, loaded_context=win, source="catalog", authority="catalog",
        detail=(f"public catalog: {win:,} for {entry.get('id')} — the model's published max; "
                "this provider may allow less"),
    )


def detect_context_window(base_url: str, api_key: str = "", model: str = "",
                          timeout: int = _DEFAULT_TIMEOUT, use_catalog: bool = True) -> DetectedContext:
    """Probe the endpoint for `model`'s real context window, falling back to the
    public catalog. Returns a DetectedContext; `.detectable` is False
    (source='none') when nothing could be read, at which point the UI asks the
    user to enter the number manually. Never raises."""
    base_url = (base_url or "").strip()
    model = (model or "").strip()
    if not base_url or not model:
        return DetectedContext(None, None, "none", "no endpoint/model to probe")

    root = _root(base_url)
    parent = _parent(base_url)
    last_err: str | None = None

    probes = []
    if _host_is_local(base_url) or ":11434" in base_url:
        probes.append(lambda: _try_ollama(root, model, timeout))
    probes.append(lambda: _try_model_list(base_url, api_key, model, timeout))
    probes.append(lambda: _try_json_page(f"{base_url.rstrip('/')}/models/{model}", api_key, timeout))
    if parent:
        probes.append(lambda: _try_json_page(f"{parent}/models/{model}", api_key, timeout))
    probes.append(lambda: _try_json_page(f"{root}/info", api_key, timeout))
    # The catalog describes public cloud models; a local server's model name
    # (e.g. an Ollama tag) would at best match a different deployment's figure.
    if use_catalog and not _host_is_local(base_url):
        probes.append(lambda: _try_catalog(model, timeout))

    for probe in probes:
        try:
            result = probe()
            if result is not None and result.detectable:
                return result
        except requests.RequestException as e:
            last_err = redact_secrets(str(e), api_key) if api_key else str(e)
        except (ValueError, KeyError, TypeError, AttributeError):
            pass  # unexpected JSON shape -- treat as "the number isn't here"

    return DetectedContext(
        None, None, "none",
        "couldn't read the context window from this endpoint or the public catalog -- enter it manually",
        error=last_err,
    )
