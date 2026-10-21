"""Committed recordings hold lab data only (docs/phaseB/B.4 §5.3): the hygiene scan runs
over every recording under evals/replay/recordings/, and over the whole evals/ tree for
anything key- or token-shaped."""
from __future__ import annotations

import json
import re
from pathlib import Path

from evals import replay

EVALS = Path(__file__).resolve().parents[1] / "evals"
RECORDINGS = EVALS / "replay" / "recordings"


def test_every_committed_recording_passes_the_hygiene_scan():
    files = sorted(RECORDINGS.glob("*.json")) if RECORDINGS.is_dir() else []
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        assert replay.scan_recording(rec) == [], f"{f.name}: {replay.scan_recording(rec)}"


def test_nothing_under_evals_is_key_or_token_shaped():
    key_pats = [re.compile(p) for p in (r"AIza[0-9A-Za-z_\-]{30,}", r"sk-[A-Za-z0-9]{20,}",
                                        r"gh[pousr]_[A-Za-z0-9]{20,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]
    # recordings and data only: .py source legitimately holds key-shaped test fixtures
    for f in EVALS.rglob("*"):
        if not f.is_file() or f.suffix in (".py", ".pyc") or "__pycache__" in f.parts:
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        for pat in key_pats:
            assert not pat.search(text), f"{f.relative_to(EVALS)} contains a {pat.pattern!r}-shaped string"


def test_the_scan_rejects_a_planted_recording(tmp_path):
    bad = {"calls": [{"result": {"x": "reached 9.9.9.9 with " + "AIza" + "SyA0123456789abcdefghijklmnopqrstuv"}}]}
    probs = replay.scan_recording(bad)
    assert any("9.9.9.9" in p for p in probs) and any("key" in p.lower() for p in probs)
