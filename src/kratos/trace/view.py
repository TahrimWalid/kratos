"""A run record as text: `kratos trace show`, `kratos trace list` and the TUI `/trace`.

Every line is plain text cleaned by `untrusted.for_display` (A.4): a tool result can
hold anything a monitored machine wrote, and the viewer never lets it reach a
terminal raw. The file itself keeps the original bytes.
"""
from __future__ import annotations

from typing import Any

from kratos import untrusted
from kratos.trace.store import TraceInfo


def _d(value: Any, max_len: int | None = 160) -> str:
    return untrusted.for_display(value, max_len=max_len)


def _secs(ms: Any) -> str:
    if ms is None:
        return "still running"
    ms = float(ms)
    return f"{ms:.0f} ms" if ms < 1000 else f"{ms / 1000:.1f} s"


def _money(x: Any) -> str:
    try:
        v = float(x or 0)
    except (TypeError, ValueError):
        return "?"
    return f"${v:.4f}"


def _tokens(n: Any) -> str:
    try:
        return f"{int(n or 0):,}"
    except (TypeError, ValueError):
        return "?"


def _when(iso: Any) -> str:
    text = str(iso or "")
    return text.replace("T", " ")[:19] + (" UTC" if text else "")


def header_lines(info: TraceInfo) -> list[str]:
    d = info.data or {}
    t = d.get("totals") or {}
    parts = [f"Run {_d(info.trace_id, 40)}", _d(d.get("kind") or "?", 30)]
    if d.get("name") and d.get("name") != d.get("kind"):
        parts.append(_d(d.get("name"), 60))
    if d.get("source"):
        parts.append(f"started from {_d(d.get('source'), 20)}")
    if d.get("target"):
        parts.append(f"machine {_d(d.get('target'), 80)}")
    lines = [" · ".join(parts)]
    status = _d(d.get("status") or "?", 40)
    if info.partial:
        status += " (unfinished: the run ended before writing its record -- this is the last saved copy)"
    lines.append(f"{_when(d.get('started'))} · {_secs(t.get('duration_ms'))} · {status}")
    if d.get("parent_run_id"):
        lines.append(f"Part of run {_d(d.get('parent_run_id'), 40)}")
    if d.get("session_id"):
        lines.append(f"Session {_d(d.get('session_id'), 40)}")
    lines.append(
        f"Model calls {t.get('model_calls', 0)} · tokens {_tokens(t.get('prompt_tokens'))} in / "
        f"{_tokens(t.get('completion_tokens'))} out · cost {_money(t.get('cost_usd'))} · "
        f"tool calls {t.get('tool_calls', 0)} · checks {t.get('collection_checks', 0)} · guards {t.get('guards', 0)}")
    return lines


def _span_line(s: dict[str, Any]) -> str:
    a = s.get("attrs") or {}
    kind, name, status = s.get("kind"), _d(s.get("name"), 80), _d(s.get("status"), 30)
    dur = _secs(s.get("duration_ms"))
    if kind == "model_call":
        txt = (f"model {_d(a.get('model'), 60)}{' (local)' if a.get('local') else ''} · "
               f"{_tokens(a.get('prompt_tokens'))} in / {_tokens(a.get('completion_tokens'))} out · "
               f"{_money(a.get('cost_usd'))} · {dur} · {status}")
        if a.get("error"):
            txt += f" · {_d(a.get('error'), 120)}"
        return txt
    if kind == "tool_call":
        if a.get("skipped"):
            return f"tool {name} · skipped · {_d(a.get('detail'), 120)}"
        txt = f"tool {name} · {dur} · {status}"
        if a.get("approval_asked"):
            txt += f" · approval {_d(a.get('approval_answer'), 20)}"
        if a.get("rewrites"):
            txt += f" · {_d('; '.join(map(str, a.get('rewrites'))), 120)}"
        res = a.get("result")
        if isinstance(res, dict) and res.get("truncated"):
            txt += f" · result {int(res.get('bytes') or 0):,} bytes (kept the start + sha256)"
        if a.get("error"):
            txt += f" · {_d(a.get('error'), 120)}"
        return txt
    if kind == "collection_check":
        how = a.get("source") or "?"
        txt = f"check {name} · {_d(how, 20)}"
        if a.get("transport"):
            txt += f" over {_d(a.get('transport'), 10)}"
        if how == "ran":
            txt += f" · {dur}"
        txt += f" · {_d(a.get('outcome') or status, 20)}"
        if a.get("still_running_at_start_budget"):
            txt += " · still running when the model started" + (", finished later" if a.get("settled_later") else "")
        if a.get("summary"):
            txt += f" · {_d(a.get('summary'), 100)}"
        return txt
    if kind == "guard":
        act = "sent the answer back" if a.get("action") == "rejected" else "added a NOTE"
        txt = f"guard {name} · {act}"
        if a.get("correction"):
            txt += f" · {_d(a.get('correction'), 140)}"
        return txt
    if kind == "answer":
        ids = a.get("block_finding_ids") or []
        txt = ("answer · Kratos's findings block: " + (_d(", ".join(map(str, ids)), 200) if ids else "none")
               + f" · NOTEs {a.get('note_count', 0)} · the model's text {int(a.get('model_text_chars') or 0):,} chars")
        if a.get("serious_left_out_of_analysis"):
            txt += " · left out of the analysis: " + _d(", ".join(map(str, a["serious_left_out_of_analysis"])), 120)
        return txt
    if kind == "child_run":
        return f"started run {_d(a.get('child_trace_id'), 40)} ({name})"
    if kind == "run":
        return f"{_d(a.get('run_kind') or name, 40)} · {dur} · {status}"
    return f"{_d(kind, 20)} {name} · {dur} · {status}"


def tree_lines(info: TraceInfo, *, max_lines: int | None = None) -> list[str]:
    d = info.data or {}
    spans = [s for s in d.get("spans") or [] if isinstance(s, dict)]
    if not spans:
        return ["(no steps recorded)"]
    root_id = spans[0].get("id")
    children: dict[Any, list[dict[str, Any]]] = {}
    for s in spans[1:]:
        children.setdefault(s.get("parent_id") or root_id, []).append(s)
    for kids in children.values():
        kids.sort(key=lambda s: str(s.get("start") or ""))
    lines: list[str] = []

    def walk(pid: Any, prefix: str) -> None:
        kids = children.get(pid, [])
        for n, s in enumerate(kids):
            last = n == len(kids) - 1
            lines.append(f"{prefix}{'└ ' if last else '├ '}{_span_line(s)}")
            walk(s.get("id"), prefix + ("  " if last else "│ "))

    walk(root_id, "")
    if max_lines is not None and len(lines) > max_lines:
        extra = len(lines) - max_lines
        lines = lines[:max_lines] + [f"… and {extra} more (kratos trace show {info.trace_id})"]
    return lines


def show_lines(info: TraceInfo, *, children: list[TraceInfo] | None = None) -> list[str]:
    if info.data is None:
        return [f"Run {_d(info.trace_id, 40)}: could not read {_d(str(info.path), 200)} ({_d(info.error, 200)})"]
    out = header_lines(info) + [""] + tree_lines(info)
    if children:
        out.append("")
        out.append("Runs started inside this one:")
        for c in children:
            cd = c.data or {}
            out.append(f"  {_d(c.trace_id, 40)} · {_d(cd.get('kind'), 20)} · {_d(cd.get('status'), 30)}"
                       f" · kratos trace show {_d(c.trace_id, 40)}")
    out.append("")
    out.append(f"File: {_d(str(info.path), 300)}")
    return out


def list_line(info: TraceInfo) -> str:
    d = info.data or {}
    t = d.get("totals") or {}
    if info.data is None:
        return f"{_d(info.trace_id[:12], 12)}  (unreadable: {_d(info.error, 80)})"
    status = _d(d.get("status") or "?", 24) + (" (unfinished)" if info.partial else "")
    return (f"{_d(info.trace_id[:12], 12)}  {_when(d.get('started'))}  {_d(d.get('kind') or '?', 13):13s} "
            f"{_d(d.get('target') or '-', 24):24s} {status:28s} {t.get('model_calls', 0):>3} model / "
            f"{t.get('tool_calls', 0):>3} tool · {_money(t.get('cost_usd'))}")
