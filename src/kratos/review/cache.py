"""The review cache (E.7b §3.10): unchanged code is never reviewed twice, and the cache is
per Kratos -- the same deployed code on five machines is reviewed once, each machine getting
its own findings with its own exposure.

The cache key is the slice sha256 + the context sha256 + the class + ``REVIEW_LOGIC_VERSION``.
A verdict Kratos reached by **code** (a reproduction, a direct rule, or a code-made
needs_validation) is **model-independent**: its key carries no model id, so switching the
review model does not re-run it. A verdict that depended on the **verifier** (a ``rejected``,
or a ``needs_validation`` where a rule matched but the verifier named a check) also keys on the
**hunter and verifier model ids**, so changing the model re-reviews it. A ``needs_validation``
that exists only because **reproduction is off** is not cached at all, so turning Incus on
re-evaluates it.

Any change to the rules, templates, fakes or prompts bumps ``REVIEW_LOGIC_VERSION`` and
invalidates every cached verdict; a change on the slice's path (another file, the web-server
config, a lockfile) changes the context sha and does the same for that slice. ``--fresh``
ignores the cache for one run.
"""
from __future__ import annotations

import hashlib
from typing import Any
from pathlib import Path

from kratos.review import store as ST
from kratos.review.verdict import Verdict

# Bump on any change to rules.py, classes.py templates/recorders, fakes/, or the hunt/verify/fix
# prompts. A cached verdict stands only on an exact match of this plus the slice and context.
REVIEW_LOGIC_VERSION = "1"


def _h(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()


def code_key(slice_sha: str, context_sha: str, cls: str) -> str:
    """The key for a code-made verdict -- no model id."""
    return _h("review", REVIEW_LOGIC_VERSION, cls, slice_sha, context_sha, "code")


def model_key(slice_sha: str, context_sha: str, cls: str, hunter_model: str, verifier_model: str) -> str:
    """The key for a verifier-derived verdict -- also the hunter and verifier model ids."""
    return _h("review", REVIEW_LOGIC_VERSION, cls, slice_sha, context_sha, "model",
              hunter_model or "", verifier_model or "")


def is_model_derived(v: Verdict) -> bool:
    return bool(v.from_verifier)


def should_cache(v: Verdict) -> bool:
    """A needs_validation that is only 'reproduction is off' is not cached (so enabling Incus
    re-evaluates it); everything else is."""
    return not v.repro_off


def key_for(v: Verdict, slice_sha: str, context_sha: str, cls: str, hunter_model: str,
            verifier_model: str) -> str:
    if is_model_derived(v):
        return model_key(slice_sha, context_sha, cls, hunter_model, verifier_model)
    return code_key(slice_sha, context_sha, cls)


def lookup(data_dir: Path | str, slice_sha: str, context_sha: str, cls: str, *, hunter_model: str,
           verifier_model: str) -> dict[str, Any] | None:
    """A cached verdict for this slice, if any. A code-made verdict (stored under the
    code key) is reused regardless of the current model; otherwise a verifier-derived verdict
    is reused only for the same models."""
    row = ST.get_verdict(data_dir, code_key(slice_sha, context_sha, cls))
    if row is not None:
        return row
    return ST.get_verdict(data_dir, model_key(slice_sha, context_sha, cls, hunter_model, verifier_model))


def store_verdict(data_dir: Path | str, v: Verdict, *, slice_sha: str, context_sha: str, cls: str,
                  hunter_model: str, verifier_model: str, fix_words: str = "", fix_added: str = "",
                  fix_check: str = "") -> str | None:
    """Cache a verdict and return its key, or None when the verdict is not cached (repro-off)."""
    if not should_cache(v):
        return None
    key = key_for(v, slice_sha, context_sha, cls, hunter_model, verifier_model)
    ST.put_verdict(data_dir, cache_key=key, slice_sha=slice_sha, context_sha=context_sha, cls=cls,
                   logic_version=REVIEW_LOGIC_VERSION, hunter_model=(hunter_model if is_model_derived(v) else ""),
                   verifier_model=(verifier_model if is_model_derived(v) else ""), verdict=v.kind,
                   strength=v.strength, evidence=v.evidence, question=v.question, fix_words=fix_words,
                   fix_added=fix_added, fix_check=fix_check)
    return key
