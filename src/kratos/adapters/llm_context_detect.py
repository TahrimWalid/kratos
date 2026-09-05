"""
Best-effort context-window DETECTION for a model behind an OpenAI-compatible
(or native) endpoint. Powers the model-setup UI: when a user pastes a base URL
+ key + model string, Kratos asks the serving framework what context the model
actually supports, so the UI can pre-fill a real number instead of a guess and
warn sensibly when the user edits it.

Two distinct numbers, because they mean different things (see the model-setup
design discussion):

  * `max_context` -- the HARD ceiling. The architecture's max (Ollama), the
    server's `--max-model-len` (vLLM), TGI's `max_total_tokens`, or a cloud
    provider's published `context_length`. Exceeding this WILL be rejected by
    the backend, so the UI treats "above max" as unacceptable.
  * `loaded_context` -- what the server is CURRENTLY serving at (only Ollama
    distinguishes this: `num_ctx` at load time, which can be < the arch max on
    a modest rig and raised on a beefy one). It's the sensible default, but NOT
    a ceiling -- the user may set higher (up to `max_context`) if they reload
    their server bigger, so the UI treats "above loaded but below max" as a soft
    heads-up, not an error.

Everything here is on-demand only (called from the settings flow), never at
import or during an investigation. Every provider probe is bounded by a short
timeout and fails soft: a provider that isn't the right one, is unreachable, or
returns an unexpected shape yields no number rather than raising -- an
undetectable endpoint (a bare OpenAI-compatible API that doesn't expose context)
is a normal outcome, and the UI then asks the user to enter it manually.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from kratos.utils.redact import redact_secrets

_DEFAULT_TIMEOUT = 4  # seconds per probe -- detection is interactive, must not hang the UI
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@dataclass
class DetectedContext:
    max_context: int | None        # hard ceiling; None if not detectable
    loaded_context: int | None     # server's current runtime setting (Ollama); None if N/A
    source: str                    # "ollama" | "vllm" | "openrouter" | "openai" | "tgi" | "none"
    detail: str                    # short human-readable hint for the UI
    error: str | None = None       # a redacted probe error, when one is worth surfacing

    @property
    def detectable(self) -> bool:
        return self.max_context is not None or self.loaded_context is not None


def _root(base_url: str) -> str:
    """Native (non-OpenAI) endpoints live at the server root, not under /v1 --
    e.g. Ollama's /api/* and TGI's /info. Strip a trailing /v1 (and any slash)."""
    u = base_url.rstrip("/")
    if u.endswith("/v1"):
        u = u[: -len("/v1")]
    return u


def _host_is_local(base_url: str) -> bool:
    host = (urlparse(base_url).hostname or "").lower()
    return host in _LOCAL_HOSTS or host.startswith("127.")


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
    return DetectedContext(max_context=max_ctx, loaded_context=loaded, source="ollama", detail=detail)


def _find_model_entry(data: list, model: str) -> dict | None:
    for entry in data:
        if isinstance(entry, dict) and entry.get("id") == model:
            return entry
    # tolerate provider-prefixed ids (e.g. "vendor/model") vs a bare model string
    for entry in data:
        if isinstance(entry, dict) and str(entry.get("id", "")).split("/")[-1] == model.split("/")[-1]:
            return entry
    return None


def _try_models_endpoint(base_url: str, api_key: str, model: str, timeout: int) -> DetectedContext | None:
    """The OpenAI-compatible /models list. Different frameworks expose the
    window under different keys: OpenRouter -> 'context_length'; vLLM ->
    'max_model_len'; some -> 'max_context_length'. All are the HARD ceiling
    (there's no separate 'loaded' concept for a served endpoint), so loaded=max."""
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    resp = requests.get(f"{base_url.rstrip('/')}/models", headers=headers, timeout=timeout)
    if resp.status_code != 200:
        return None
    data = resp.json().get("data") or []
    entry = _find_model_entry(data, model)
    if entry is None:
        return None
    for key, source in (("context_length", "openrouter"), ("max_model_len", "vllm"),
                        ("max_context_length", "openai"), ("context_window", "openai")):
        val = entry.get(key)
        if isinstance(val, (int, float)) and val > 0:
            win = int(val)
            return DetectedContext(max_context=win, loaded_context=win, source=source,
                                   detail=f"{source}: {win:,} ({key})")
    return None


def _try_tgi(root: str, timeout: int) -> DetectedContext | None:
    """Hugging Face TGI exposes /info with max_total_tokens (the server's hard
    prompt+generation budget) and max_input_tokens."""
    resp = requests.get(f"{root}/info", timeout=timeout)
    if resp.status_code != 200:
        return None
    info = resp.json()
    win = info.get("max_total_tokens") or info.get("max_input_tokens")
    if isinstance(win, (int, float)) and win > 0:
        win = int(win)
        return DetectedContext(max_context=win, loaded_context=win, source="tgi",
                               detail=f"TGI: {win:,} max_total_tokens")
    return None


def detect_context_window(base_url: str, api_key: str = "", model: str = "",
                          timeout: int = _DEFAULT_TIMEOUT) -> DetectedContext:
    """Probe the endpoint for `model`'s real context window. Returns a
    DetectedContext; `.detectable` is False (source='none') when nothing could
    be read -- a normal outcome for a bare OpenAI-compatible endpoint, at which
    point the UI asks the user to enter the number manually. Never raises."""
    base_url = (base_url or "").strip()
    model = (model or "").strip()
    if not base_url or not model:
        return DetectedContext(None, None, "none", "no endpoint/model to probe")

    root = _root(base_url)
    is_local = _host_is_local(base_url)
    last_err: str | None = None

    # Order probes by what the endpoint most likely is, but every path fails
    # soft, so trying a wrong one just moves on: local -> Ollama first; then the
    # OpenAI-compatible /models list (OpenRouter/vLLM/generic); then TGI's /info.
    probes = []
    if is_local or ":11434" in base_url:
        probes.append(lambda: _try_ollama(root, model, timeout))
    probes.append(lambda: _try_models_endpoint(base_url, api_key, model, timeout))
    probes.append(lambda: _try_tgi(root, timeout))

    for probe in probes:
        try:
            result = probe()
            if result is not None and result.detectable:
                return result
        except requests.RequestException as e:
            last_err = redact_secrets(str(e), api_key) if api_key else str(e)
        except (ValueError, KeyError, TypeError):
            pass  # unexpected JSON shape -- treat as "this isn't the right provider"

    return DetectedContext(
        None, None, "none",
        "couldn't read the context window from this endpoint -- enter it manually",
        error=last_err,
    )
