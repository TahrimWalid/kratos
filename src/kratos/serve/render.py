"""An investigation's answer as Markdown for a chat client (docs/phaseB/B.3 §3.10, §3.11).

The answer contract holds: Kratos's findings block, then its NOTEs, then the model's
analysis -- in that order, none dropped or reworded. Markdown is a display that fetches
images and makes links clickable, so each part goes out by the rule for what it is:

* the findings block and the NOTEs are Kratos's own text, but they quote machine text
  (titles, accounts, file names): each line goes out verbatim in an inline code span --
  the same characters the TUI shows, nothing rendered, and it wraps in a chat window;
* the model's analysis is prose: `untrusted.for_markdown` -- formatting kept, images
  removed, links and bare addresses defanged unless their host is on `serve.link_hosts`,
  raw HTML escaped, code blocks re-fenced;
* each recommended command is a fenced block under a Kratos-written label saying where it
  came from (Kratos's template, or written by the model) with the A.4 warnings above it.

Progress lines go to the client's reasoning channel and are Kratos-written only.
"""
from __future__ import annotations

from typing import Any, Iterable

from kratos import untrusted


def _split_answer(final_answer: str, parts: dict[str, str] | None) -> tuple[str, str, str] | None:
    """(block, notes, analysis) when the run reported its parts and they add up to the
    final answer exactly; None otherwise (then the whole answer is treated as prose)."""
    if not isinstance(parts, dict):
        return None
    block, notes, analysis = (str(parts.get(k) or "") for k in ("block", "notes", "analysis"))
    if block + notes + analysis != final_answer:
        return None
    return block, notes, analysis


def _kratos_lines(text: str, *, quote: bool = False) -> str:
    """Kratos's own text that quotes machine values, line by line: each line's characters
    exactly as the TUI shows them, inside an inline code span (nothing in it renders, and
    unlike a code block it wraps in a chat window). A "- item" line stays a list item;
    `quote` puts each paragraph (a NOTE) in a block quote."""
    out: list[str] = []
    for para in [p for p in text.split("\n\n") if p.strip()]:
        lines = []
        for line in para.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("- "):
                lines.append("- " + untrusted.md_code(stripped[2:]))
            else:
                lines.append(untrusted.md_code(stripped) + "  ")
        chunk = "\n".join(lines)
        out.append("\n".join("> " + x for x in chunk.split("\n")) if quote else chunk)
    return "\n\n".join(out)


def command_markdown(cmd: dict[str, Any]) -> str:
    """One recommended command: a Kratos-written label, the A.4 flags, the command in a
    fenced block. Nothing here is ever run by Kratos."""
    source = str(cmd.get("source") or "")
    run_on = "Kratos's own machine" if str(cmd.get("run_on") or "") in ("kratos", "local", "host") else "the target"
    if source == "template":
        label = f"Suggested command (Kratos's template {untrusted.md_code(cmd.get('template') or '')}, run on {run_on})"
    elif source == "withheld":
        label = "Kratos did not build this command"
    else:
        label = f"Suggested command (written by the model -- check it before running, on {run_on})"
    lines = [f"**{label}**"]
    for flag in cmd.get("flags") or []:
        reason = flag.get("reason") if isinstance(flag, dict) else str(flag)
        lines.append(f"> ⚠ {untrusted.md_code(reason, max_len=200)}")
    explanation = str(cmd.get("explanation") or "").strip()
    if explanation:
        lines.append(untrusted.for_markdown(explanation.replace("\n", " ")))
    command = str(cmd.get("command") or "").strip()
    if command:
        lines.append(untrusted.md_block(command, info="sh"))
    return "\n\n".join(lines)


def answer_markdown(final_answer: str, parts: dict[str, str] | None = None,
                    recommended_commands: Iterable[dict[str, Any]] | None = None,
                    *, link_hosts: Any = ()) -> str:
    """The checked answer, as the chat client shows it."""
    out: list[str] = []
    split = _split_answer(final_answer or "", parts)
    if split is None:
        out.append(untrusted.for_markdown(final_answer or "", link_hosts=link_hosts))
    else:
        block, notes, analysis = split
        if block.strip():
            out.append(_kratos_lines(block))
        if notes.strip():
            out.append(_kratos_lines(notes, quote=True))
        if analysis.strip():
            out.append(untrusted.for_markdown(analysis.strip("\n"), link_hosts=link_hosts))
    cmds = [c for c in (recommended_commands or []) if isinstance(c, dict)]
    if cmds:
        out.append("**Suggested commands** -- Kratos never runs these; you decide.")
        out.extend(command_markdown(c) for c in cmds)
    return "\n\n".join(p for p in out if p)


def chat_markdown(reply: str, *, link_hosts: Any = ()) -> str:
    """A plain chat reply from the model (no investigation ran)."""
    return untrusted.for_markdown(reply or "", link_hosts=link_hosts)


def kratos_text_markdown(text: str) -> str:
    """Kratos-written text that quotes machine values (a /findings list, /help): one code block."""
    return untrusted.md_block(text)


def kratos_note_markdown(text: str) -> str:
    """A short Kratos-written message (a refusal, a limit): inert, and it wraps."""
    return _kratos_lines(text)


def progress_markdown(line: str) -> str:
    """A progress line for the reasoning channel. Kratos-written; still escaped, since the
    client renders reasoning as Markdown too."""
    return untrusted.for_markdown(untrusted.for_display(line, max_len=300).replace("\n", " ")) + "\n"
