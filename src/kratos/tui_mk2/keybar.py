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


def title_row(title: str, subject: str = "", summary: str = "", *, note: str = "",
              note_style: str | None = None) -> Text:
    """The one-line title of a list screen (A2): the screen's name in the accent colour,
    what it is about in the data colour, then a short dim summary and an optional note."""
    t = Text(title, style=f"bold {T.ACCENT}")
    if subject:
        t.append(f"   {subject}", style=f"bold {T.DATA}")
    if summary:
        t.append(("   " if not subject else " · ") + summary, style=T.TEXT_DIM)
    if note:
        t.append(" · " + note, style=note_style or T.ATTENTION)
    return t


def plural(n: int, one: str, many: str | None = None) -> str:
    """'1 machine', '3 machines' -- never 'machine(s)'."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def layout_css(screen: str, prefix: str, *, table_max: str = "50%") -> str:
    """The shared list-screen layout (A2): title row, table, a detail pane for the
    selected row, a short log, and a one-line key bar. `prefix` is the screen's id prefix."""
    return f"""
    {screen} {{ padding: 1 2; }}
    {screen} #{prefix}-banner {{ height: auto; max-height: 2; padding: 0 0 1 0; }}
    {screen} DataTable {{ height: auto; max-height: {table_max}; }}
    {screen} #{prefix}-detail {{ height: auto; min-height: 4; max-height: 8; border-top: solid $panel; padding-top: 1; }}
    {screen} #{prefix}-log {{ height: 1fr; min-height: 1; border-top: solid $panel; }}
    {screen} #{prefix}-hints {{ height: 1; background: $panel; padding: 0 1; }}
    """
