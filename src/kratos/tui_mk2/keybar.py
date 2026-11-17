"""One-row key bar for list screens: the few keys people use most, plus `? all keys`.
The full list (every binding still works) opens in an InfoModal."""
from __future__ import annotations

from kratos.untrusted_rich import SafeText as Text
from kratos.tui_mk2 import theme as T


def key_bar(pairs: list[tuple[str, str]]) -> Text:
    t = Text()
    for i, (key, word) in enumerate(pairs):
        if i:
            t.append("   ")
        t.append(key, style=f"bold {T.TEXT_BRIGHT}")
        t.append(" " + word, style=T.TEXT_DIM)
    return t


def all_keys_text(full: str) -> Text:
    return Text(full.replace(" · ", "\n"), style=T.TEXT)
