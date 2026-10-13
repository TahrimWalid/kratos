"""The sanitized injection corpus for unit tests (A.4 §5.5): payload SHAPES, not working exploits.

The full corpus run against the lab lives outside the repo (~/kratos_eval_artifacts/injection/);
these are the shapes every renderer, envelope and flag test is driven with.
"""
from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

CORPUS: dict[str, str] = json.loads((Path(__file__).parent / "fixtures" / "untrusted" / "corpus.json").read_text("utf-8"))
HUGE = "A" * 65536           # a 64 KB field

_BAD = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def assert_screen_safe(text: str, *, where: str = "") -> None:
    """No escape byte, no control character, no invisible format character in `text`."""
    assert "\x1b" not in text, f"{where}: ESC reached the output: {text!r:.200}"
    assert not _BAD.search(text), f"{where}: a control character reached the output: {text!r:.200}"
    hidden = [c for c in text if unicodedata.category(c) in ("Cf", "Cs")]
    assert not hidden, f"{where}: invisible characters reached the output: {[hex(ord(c)) for c in hidden][:5]}"
