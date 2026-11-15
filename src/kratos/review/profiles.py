"""The review model profile (E.7b gate answer 1): a review uses only a **saved** profile
(`/model`), never the active model by default. This resolves a profile by name (its model),
refuses anything not saved, and states plainly where the code goes -- a hosted service outside
the network, or a model on the person's own network -- for the consent screen and REVIEW-003.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import paths
from kratos.adapters import llm_profiles
from kratos.llm_config import is_local_base_url

HOSTED, LOCAL = "hosted", "local"
_DEST_TEXT = {HOSTED: "a hosted service outside your network", LOCAL: "a model on your own network"}


class UnknownProfile(ValueError):
    """A name that is not a saved profile; a review never falls back to the active model."""


@dataclass(frozen=True)
class ReviewProfile:
    name: str                 # the model name is the profile's name
    model: str
    base_url: str
    api_key: str
    local: bool

    @property
    def destination(self) -> str:
        return LOCAL if self.local else HOSTED

    @property
    def destination_text(self) -> str:
        return _DEST_TEXT[self.destination]


def _env_path(env_path: Path | None) -> Path:
    return env_path if env_path is not None else paths.env_file()


def saved_names(*, env_path: Path | None = None) -> list[str]:
    candidates, _ = llm_profiles.list_candidate_profiles(_env_path(env_path))
    return [p.model for p in candidates]


def resolve(name: str, *, env_path: Path | None = None) -> ReviewProfile:
    """The saved profile whose model is `name`. Raises UnknownProfile (with the saved names)
    for an empty or unsaved name -- never the active model."""
    want = (name or "").strip()
    names = saved_names(env_path=env_path)
    if not want:
        raise UnknownProfile(
            "pick a saved model profile for this review (nothing is sent to the active model by "
            f"default). Saved profiles: {', '.join(names) if names else '(none -- add one in /model)'}")
    candidates, _ = llm_profiles.list_candidate_profiles(_env_path(env_path))
    for p in candidates:
        if p.model == want:
            base = (p.values.get("LLM_BASE_URL") or "").strip()
            return ReviewProfile(name=p.model, model=p.model, base_url=base,
                                 api_key=(p.values.get("LLM_API_KEY") or "").strip(),
                                 local=bool(is_local_base_url(base)))
    raise UnknownProfile(
        f"{want!r} is not a saved profile. Use a saved profile (`/model`): "
        f"{', '.join(names) if names else '(none -- add one in /model)'}")


def consent_line(hunter: ReviewProfile, verifier: ReviewProfile | None, mask_mode: str) -> str:
    """The one line every plan and REVIEW-003 shows: where the code goes, the profile, the
    masking mode, and that secrets are always removed."""
    v = verifier or hunter
    vtext = "" if v.name == hunter.name else f"; the verifier uses {v.name} ({v.destination_text})"
    return (f"Code slices go to {hunter.name} ({hunter.destination_text}){vtext}. "
            f"Masking: {mask_mode}. Secrets are always removed before anything is sent.")


def as_dict(p: ReviewProfile) -> dict[str, Any]:
    return {"name": p.name, "model": p.model, "destination": p.destination, "local": p.local}
