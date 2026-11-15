"""The hunters (E.7b §3.6): one tool-less model call per batch of slices (grouped by class,
each batch within half the endpoint's context window), slices framed as data and masked. The
reply is a list of leads -- never a verdict or a severity. Every lead is validated (its file was
sent in that batch, its line inside a sent span), duplicates by (file, line, class) are merged,
and leads are capped per call and per run; what was dropped is counted for REVIEW-003.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from kratos.review import modelcall
from kratos.review import prompts as P
from kratos.review.profiles import ReviewProfile
from kratos.review.slice import Slice

FALLBACK_WINDOW_TOKENS = 32000
HUNTER_MAX_TOKENS = 1024
# review.call(system_prompt, user_prompt, *, stage, cls) -> reply text
Caller = Callable[..., str]


def approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


@dataclass
class Batch:
    cls: str
    slices: list[Slice]
    call_id: str
    user_prompt: str
    approx_input_tokens: int
    allowed_files: set[str]
    spans: dict[str, list[tuple[int, int]]]


@dataclass
class HuntResult:
    leads: list[P.Lead] = field(default_factory=list)
    drops: dict[str, int] = field(default_factory=lambda: {"outside": 0, "over_cap_call": 0, "over_cap_run": 0})
    calls: int = 0


def _framed_slice(sl: Slice, run_id: str, call_id: str) -> str:
    from kratos.privacy.secrets import redact
    from kratos.untrusted import frame_text
    clean, _ = redact(sl.text)                      # secrets removed in EVERY mode, before anything is sent
    return frame_text(clean, kind="code", run_id=run_id, call_id=call_id)


def _allowed_and_spans(slices: list[Slice]) -> tuple[set[str], dict[str, list[tuple[int, int]]]]:
    allowed: set[str] = set()
    spans: dict[str, list[tuple[int, int]]] = {}
    for sl in slices:
        for rel, a, b in sl.segments:
            allowed.add(rel)
            spans.setdefault(rel, []).append((a, b))
    return allowed, spans


def build_batches(slices: list[Slice], *, run_id: str, window_tokens: int) -> list[Batch]:
    """Group slices per class into calls that each use at most half the context window."""
    half = max(1000, int(window_tokens) // 2)
    by_cls: dict[str, list[Slice]] = {}
    for sl in slices:
        by_cls.setdefault(sl.cls, []).append(sl)
    out: list[Batch] = []
    n = 0
    for cls, sls in by_cls.items():
        cur: list[Slice] = []
        cur_frames: list[str] = []
        cur_tokens = 0
        for sl in sls:
            frame = _framed_slice(sl, run_id, sl.id)
            t = approx_tokens(frame)
            if cur and cur_tokens + t > half:
                out.append(_batch(cls, cur, cur_frames, run_id, n))
                n += 1
                cur, cur_frames, cur_tokens = [], [], 0
            cur.append(sl)
            cur_frames.append(frame)
            cur_tokens += t
        if cur:
            out.append(_batch(cls, cur, cur_frames, run_id, n))
            n += 1
    return out


def _batch(cls: str, slices: list[Slice], frames: list[str], run_id: str, n: int) -> Batch:
    user = P.hunter_user_prompt(cls, "\n\n".join(frames))
    allowed, spans = _allowed_and_spans(slices)
    return Batch(cls, list(slices), f"{run_id}-hunt-{n}", user, approx_tokens(user), allowed, spans)


def _slice_for(batch: Batch, file: str, line: int) -> Slice | None:
    """The slice in this batch the lead points at: one whose surface function span contains the
    line in that file if possible, else one whose segments cover it, else the first."""
    best: Slice | None = None
    for sl in batch.slices:
        covers = any(rel == file and a <= line <= b for rel, a, b in sl.segments)
        if not covers:
            continue
        if sl.rel == file and sl.span[0] <= line <= sl.span[1]:
            return sl
        best = best or sl
    return best or (batch.slices[0] if batch.slices else None)


def _default_caller(profile: ReviewProfile) -> Caller:
    def call(system_prompt: str, user_prompt: str, *, stage: str, cls: str) -> str:
        return modelcall.call_model(profile, system_prompt, user_prompt, max_tokens=HUNTER_MAX_TOKENS,
                                    stage=stage, cls=cls)
    return call


def hunt(profile: ReviewProfile, batches: list[Batch], *, max_leads_per_call: int, max_leads: int,
         call: Caller | None = None) -> HuntResult:
    call = call or _default_caller(profile)
    res = HuntResult()
    seen: set[tuple[str, int, str]] = set()
    for b in batches:
        reply = call(P.SYSTEM_HUNTER, b.user_prompt, stage="hunter", cls=b.cls)
        res.calls += 1
        parsed, drops = P.parse_leads(reply, allowed_files=b.allowed_files, spans=b.spans,
                                      batch_class=b.cls, max_per_call=max_leads_per_call)
        res.drops["outside"] += drops["outside"]
        res.drops["over_cap_call"] += drops["over_cap"]
        for item in parsed:
            key = (item["file"], item["line"], item["class"])
            if key in seen:
                continue
            seen.add(key)
            if len(res.leads) >= max_leads:
                res.drops["over_cap_run"] += 1
                continue
            sl = _slice_for(b, item["file"], item["line"])
            res.leads.append(P.Lead(file=item["file"], line=item["line"], cls=item["class"],
                                    reason=item["reason"], slice_sha=(sl.sha256 if sl else "")))
    return res
