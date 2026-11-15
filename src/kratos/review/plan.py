"""Prepare a review locally, then describe exactly what a send would cost and disclose (E.7b
§3.2). Nothing here sends anything to a model.

A **prepare**:
1. reads the root's source through E.7a's ``review`` purpose (a person-started read; refused for
   any tool/schedule/MCP/chat/model step by ``code.reads.read_for_review`` itself);
2. slices it **in memory on Kratos** (kratos.review.slice), enriches each slice with drift (E.7a
   CODE-001/002), served kind and the serving process's exposure (D.3), and whether it imports a
   package with an open CODE-003 advisory;
3. ranks and caps the slices, looks each up in the per-Kratos verdict cache, and builds the
   hunter batches and a cost estimate from the real batches;
4. returns a :class:`Plan` held in memory for ``review.plan_ttl_minutes``: the consent summary
   (profile, destination, masking, exact slices and bytes, estimate, cached count, reproduction
   on/off), everything ``run.start_review`` needs, and the file hashes to re-check at send.

Only an explicit yes (``run.start_review``) sends. At send time every slice's file hash is
re-checked against what was read; a slice whose file changed is dropped ("changed since you
agreed").
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.review import cache as CACHE
from kratos.review import cost as COST
from kratos.review import deps as DEPS
from kratos.review import exposure as EXP
from kratos.review import hunt as HUNT
from kratos.review import rank as RANK
from kratos.review import settings as RS
from kratos.review import slice as SL
from kratos.review.profiles import ReviewProfile, consent_line

# Surface kinds that mean the slice's code is executed to serve a request (vs. imported).
_EXECUTED_KINDS = frozenset({"flask", "fastapi", "django", "view"})
_DRIFT_STATUSES = frozenset({"untracked", "modified", "mode_change", "staged", "deleted"})


class PlanError(ValueError):
    """A prepare that can't proceed (unconfirmed root, unreachable machine, nothing to review)."""


@dataclass
class Plan:
    plan_id: str
    machine: str
    target_key: str
    root: str
    root_id: int
    profile: ReviewProfile
    verifier: ReviewProfile | None
    mask_mode: str
    reproduction: bool                      # sandbox reproduction available this run
    index: SL.Index                         # for the direct rules and reproduction (never stored)
    to_review: list[SL.Slice]               # not cached, within the cap -- these are sent
    cached: list[dict[str, Any]]            # {slice, verdict_row} reused free
    batches: list[HUNT.Batch]
    estimate: COST.Estimate
    stats: SL.SliceStats
    file_hashes: dict[str, str]             # rel -> sha256 as read (the send-time recheck)
    reachability: list[DEPS.Reachability]
    read_info: dict[str, Any]
    logic_version: str
    created_at: float
    ttl_seconds: int
    dropped_by_cap: int = 0
    changed_since_read: int = 0
    counts: dict[str, Any] = field(default_factory=dict)

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    def expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at

    def consent_summary(self) -> dict[str, Any]:
        n_send = len(self.to_review)
        bytes_send = sum(sl.nbytes for sl in self.to_review)
        return {
            "plan_id": self.plan_id, "machine": self.machine, "root": self.root,
            "profile": self.profile.name, "destination": self.profile.destination,
            "destination_text": self.profile.destination_text,
            "verifier_profile": (self.verifier.name if self.verifier else self.profile.name),
            "mask_mode": self.mask_mode, "line": consent_line(self.profile, self.verifier, self.mask_mode),
            "slices_to_send": n_send, "bytes_to_send": bytes_send,
            "slices_cached": len(self.cached), "dropped_by_cap": self.dropped_by_cap,
            "reproduction": self.reproduction, "estimate_usd": self.estimate.usd,
            "priced": self.estimate.priced, "est_calls": self.estimate.calls, "est_tokens": self.estimate.tokens,
            "reduction": self.reduction(), "incomplete_languages": dict(self.stats.other_language),
            "too_large": self.stats.too_large, "not_parsed": dict(self.stats.not_parsed),
        }

    def reduction(self) -> float:
        """Bytes in the root / bytes sliced (the 10-100x the spec expects)."""
        sliced = self.stats.sliced_bytes or 1
        return round(self.stats.root_bytes / sliced, 1) if self.stats.root_bytes else 0.0


# --------------------------------------------------------------------------- the in-memory plan registry
_PLANS: dict[str, Plan] = {}


def _reap(now: float) -> None:
    for pid in [p for p, pl in _PLANS.items() if pl.expired(now)]:
        _PLANS.pop(pid, None)


def put_plan(plan: Plan) -> None:
    _reap(time.time())
    _PLANS[plan.plan_id] = plan


def get_plan(plan_id: str, *, now: float | None = None) -> Plan | None:
    now = time.time() if now is None else now
    _reap(now)
    plan = _PLANS.get(plan_id)
    if plan is not None and plan.expired(now):
        _PLANS.pop(plan_id, None)
        return None
    return plan


def drop_plan(plan_id: str) -> None:
    _PLANS.pop(plan_id, None)


# --------------------------------------------------------------------------- building a plan
def _decode(data: Any) -> str:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("utf-8", "replace")
    return str(data or "")


def _serving_token(cfg: Any, root: str) -> str:
    """A stable string for the root's serving decision, folded into the context hash so a
    web-server config change that changes what's served re-reviews the slices on that path."""
    try:
        from kratos.code import webconf as W
        served = W.root_is_served(cfg, root) if cfg is not None else False
        return f"served={1 if served else 0}:{SL._hash([str(W.to_json(cfg))]) if cfg is not None else ''}"
    except Exception:  # noqa: BLE001
        return ""


def _advisory_imports(open_advisories: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for hit in open_advisories:
        out |= DEPS._import_names(str(hit.get("package") or "")) | DEPS._advisory_modules(hit)
    return out


def build_plan(data_dir: Path | str, *, machine: str, target_key: str, root: str, root_id: int,
               files: dict[str, dict[str, Any]], read_info: dict[str, Any], file_hashes: dict[str, str],
               all_sizes: dict[str, int], git_status: dict[str, str], serving_cfg: Any,
               open_advisories: list[dict[str, Any]], local_addresses: list[str], root_serving: list[dict[str, Any]],
               profile: ReviewProfile, verifier: ReviewProfile | None, mask_mode: str, reproduction: bool,
               window_tokens: int, fresh: bool = False, now: float | None = None) -> Plan:
    """Slice the read source, enrich, rank, cache-split, batch and estimate. `files` is
    E.7a's read result ({rel: {status, data, sha256}}); only the OK text files are sliced."""
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    text_files = {rel: _decode(v.get("data")) for rel, v in files.items()
                  if v.get("status") == "ok" and rel.endswith(".py") and v.get("data") is not None}
    serving = _serving_token(serving_cfg, root)
    depth = int(RS.get(RS.SLICE_DEPTH, data_dir))
    max_slice_bytes = int(RS.get(RS.MAX_SLICE_BYTES, data_dir))
    slices, stats, index = SL.slice_root(root, text_files, file_hashes=file_hashes, serving=serving,
                                          depth=depth, max_slice_bytes=max_slice_bytes, all_sizes=all_sizes)
    # count the non-Python source the review didn't slice (the review-extra gap, REVIEW-003).
    for rel in all_sizes:
        ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
        if ext in ("php", "js", "mjs", "ts"):
            stats.other_language[ext] = stats.other_language.get(ext, 0) + 1

    advisory_imports = _advisory_imports(open_advisories)
    exposure = EXP.root_exposure(root_serving, local_addresses)
    for sl in slices:
        sl.drift = git_status.get(sl.rel, "") in _DRIFT_STATUSES
        sl.served = "executed" if sl.surface_kind in _EXECUTED_KINDS else "served"
        sl.exposure = exposure
        sl.advisory = bool({n.lower() for n in sl.imports} & advisory_imports)

    max_slices = int(RS.get(RS.MAX_SLICES, data_dir))
    kept, dropped = RANK.select(slices, max_slices)

    hunter_model = profile.model
    verifier_model = (verifier or profile).model
    to_review: list[SL.Slice] = []
    cached: list[dict[str, Any]] = []
    for sl in kept:
        row = None if fresh else CACHE.lookup(data_dir, sl.sha256, sl.context_sha256, sl.cls,
                                              hunter_model=hunter_model, verifier_model=verifier_model)
        if row is not None:
            cached.append({"slice": sl, "verdict": row})
        else:
            to_review.append(sl)

    plan_id = uuid.uuid4().hex[:16]
    batches = HUNT.build_batches(to_review, run_id=plan_id, window_tokens=window_tokens)
    lead_factor = float(RS.get(RS.LEAD_FACTOR, data_dir))
    max_leads = int(RS.get(RS.MAX_LEADS, data_dir))
    rate = _profile_rate(profile, data_dir)
    avg_tokens = int(sum(HUNT.approx_tokens(sl.text) for sl in to_review) / len(to_review)) if to_review else 0
    est = COST.estimate([b.approx_input_tokens for b in batches], len(to_review), avg_tokens,
                        lead_factor=lead_factor, rate=rate, max_leads=max_leads)
    reachability = DEPS.reachability(open_advisories, slices)

    ttl = int(RS.get(RS.PLAN_TTL_MINUTES, data_dir)) * 60
    plan = Plan(plan_id=plan_id, machine=machine, target_key=target_key, root=root, root_id=root_id,
                profile=profile, verifier=verifier, mask_mode=mask_mode, reproduction=reproduction,
                index=index, to_review=to_review, cached=cached, batches=batches, estimate=est, stats=stats,
                file_hashes=dict(file_hashes), reachability=reachability, read_info=read_info,
                logic_version=CACHE.REVIEW_LOGIC_VERSION, created_at=now, ttl_seconds=ttl,
                dropped_by_cap=dropped)
    put_plan(plan)
    return plan


def _profile_rate(profile: ReviewProfile, data_dir: Path | str) -> tuple[float, float] | None:
    """The input/output per-1M-token rate for a profile's model, or None (local/unpriced)."""
    if profile.local:
        return None
    try:
        from kratos.budget.pricing import rate_for
        return rate_for(profile.model, Path(data_dir))
    except Exception:  # noqa: BLE001
        return None


def recheck_hashes(plan: Plan, current_hashes: dict[str, str]) -> tuple[list[SL.Slice], int]:
    """At send time: keep only slices whose every touched file still matches the hash read;
    drop the rest ("changed since you agreed"). Returns (kept, dropped)."""
    kept: list[SL.Slice] = []
    dropped = 0
    for sl in plan.to_review:
        if all(current_hashes.get(rel) == plan.file_hashes.get(rel) for rel in sl.touched):
            kept.append(sl)
        else:
            dropped += 1
    return kept, dropped
