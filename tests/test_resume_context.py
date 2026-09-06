"""
Resume-context substance: a LIGHT resume must retain the conversation's content
(Kratos's replies), not just the user's goals — otherwise a [l] resume (and the
follow-up chat memory built on the same shape) forgets what was discussed.
"""
from __future__ import annotations

import json
from pathlib import Path

from kratos.cli.repl import _build_light_resume_context, _final_reply_from_transcript


def test_final_reply_reads_last_final_answer(tmp_path):
    ref = tmp_path / "t.json"
    ref.write_text(json.dumps([{"tool": "run_nmap_scan"}, {"final_answer": "the answer"}]), encoding="utf-8")
    assert _final_reply_from_transcript(str(ref)) == "the answer"
    assert _final_reply_from_transcript(None) is None
    assert _final_reply_from_transcript(str(tmp_path / "missing.json")) is None


def test_light_resume_includes_kratos_replies(tmp_path):
    ref = tmp_path / "t1.json"
    ref.write_text(json.dumps([{"final_answer": "I found a brute force from 10.0.0.9."}]), encoding="utf-8")
    history = [{"goal": "check ssh logins", "status": "chat_reply", "transcript_ref": str(ref)}]

    ctx = _build_light_resume_context(history)
    assert "check ssh logins" in ctx
    assert "brute force from 10.0.0.9" in ctx  # the SUBSTANCE is retained, not just the goal


def test_light_resume_trims_long_replies(tmp_path):
    ref = tmp_path / "t.json"
    ref.write_text(json.dumps([{"final_answer": "X" * 900}]), encoding="utf-8")
    history = [{"goal": "g", "transcript_ref": str(ref)}]
    ctx = _build_light_resume_context(history)
    assert "…" in ctx                       # trimmed
    assert ctx.count("X") <= 400             # not the full 900


def test_light_resume_falls_back_when_no_transcript():
    ctx = _build_light_resume_context([{"goal": "g", "status": "chat_reply", "transcript_ref": None}])
    assert "g" in ctx and "no saved reply" in ctx
