"""Terminal fonts commonly lack glyphs from U+2900 up (supplemental arrows, miscellaneous
math symbols, emoji...) and the emoji-style symbols of U+2300-23FF (stopwatch, hourglass,
pause...): they render as a box, or as colour emoji. Found three times for real (a Twemoji
pause sign, an hourglass pairing-code marker, a stopwatch on the time-window line). The
TUI and the CLI renderer stick to widely available symbols."""
from __future__ import annotations

import unicodedata
from pathlib import Path

import kratos.tui_mk2 as tui


def test_tui_source_uses_no_rarely_supported_glyphs():
    found = []
    from kratos.agent import console

    paths = [*Path(tui.__file__).parent.rglob("*.py"), Path(console.__file__)]
    for path in paths:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for ch in line:
                if ord(ch) >= 0x2900 or 0x2300 <= ord(ch) <= 0x23FF:
                    found.append(f"{path.name}:{n} {ch!r} {unicodedata.name(ch, '?')}")
    assert not found, "\n".join(found)
