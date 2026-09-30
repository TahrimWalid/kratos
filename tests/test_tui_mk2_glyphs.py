"""Terminal fonts commonly lack glyphs from U+2900 up (supplemental arrows, miscellaneous
math symbols, emoji...): they render as a box, or as colour emoji. Found twice for real (a
Twemoji pause sign, then an hourglass pairing-code marker). The TUI sticks to widely
available symbols."""
from __future__ import annotations

import unicodedata
from pathlib import Path

import kratos.tui_mk2 as tui


def test_tui_source_uses_no_rarely_supported_glyphs():
    found = []
    for path in Path(tui.__file__).parent.rglob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for ch in line:
                if ord(ch) >= 0x2900:
                    found.append(f"{path.name}:{n} {ch!r} {unicodedata.name(ch, '?')}")
    assert not found, "\n".join(found)
