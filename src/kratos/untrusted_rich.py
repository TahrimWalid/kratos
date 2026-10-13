"""The Rich-aware half of kratos.untrusted: safe-by-default text, and a backstop at the sink.

Two tools, used together (A.4 §5.3):

* `SafeText` -- a drop-in `rich.text.Text` that runs every string it is given through
  `untrusted.for_display`. A renderer module that imports it instead of Rich's `Text` can
  no longer put an escape sequence or an invisible bidi character on the screen by
  forgetting to clean one field, and a `Text` is never parsed as markup either.
* `Scrubbed` / `scrub_segments` -- the same cleaning applied to the finished output
  segments of ANY renderable. Nothing Kratos writes legitimately contains an ESC byte or a
  control character (colour comes from styles, never from embedded sequences), so this is
  safe to put in front of every sink: the CLI console and the TUI transcript. It is the
  backstop for markup-string and raw-`str` table cells that still carry target text.

Neither changes stored data; both act only on what is about to be drawn.
"""
from __future__ import annotations

from typing import Any, Iterable, Iterator

from rich.console import Console, ConsoleOptions, RenderableType, RenderResult
from rich.measure import Measurement
from rich.panel import Panel
from rich.segment import Segment
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from kratos.untrusted import for_display

__all__ = ["SafeText", "SafePanel", "SafeTable", "SafeSyntax", "Scrubbed", "scrub_segments", "scrubbed"]


class SafeText(Text):
    """`rich.text.Text` whose strings are cleaned with `for_display` on the way in."""

    def __init__(self, text: Any = "", *args: Any, **kwargs: Any) -> None:
        if isinstance(text, str):
            text = for_display(text)
        super().__init__(text, *args, **kwargs)

    def __eq__(self, other: object) -> bool:
        # a SafeText stands in for a str in titles and cells, so it compares like one
        if isinstance(other, str):
            return self.plain == other
        return super().__eq__(other)

    __hash__ = None                                                      # type: ignore[assignment]

    def append(self, text: Any, style: Any = None) -> "SafeText":     # type: ignore[override]
        if isinstance(text, str):
            text = for_display(text)
        return super().append(text, style)                              # type: ignore[return-value]


def _safe(value: Any) -> Any:
    """A `str` becomes a `SafeText` (cleaned, and never parsed as markup); anything else
    -- a renderable, None -- is returned as it is."""
    return SafeText(value) if isinstance(value, str) else value


class SafePanel(Panel):
    """`rich.panel.Panel` whose body, title and subtitle strings are cleaned and not
    parsed as markup."""

    def __init__(self, renderable: Any = "", *args: Any, title: Any = None, subtitle: Any = None,
                 **kwargs: Any) -> None:
        super().__init__(_safe(renderable), *args, title=_safe(title), subtitle=_safe(subtitle), **kwargs)


class SafeTable(Table):
    """`rich.table.Table` whose cells, title and caption strings are cleaned and not parsed
    as markup (a plain `str` cell is otherwise rendered as markup)."""

    def __init__(self, *headers: Any, title: Any = None, caption: Any = None, **kwargs: Any) -> None:
        super().__init__(*headers, title=_safe(title), caption=_safe(caption), **kwargs)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("title", "caption"):
            value = _safe(value)
        super().__setattr__(name, value)

    def add_row(self, *renderables: Any, **kwargs: Any) -> None:             # type: ignore[override]
        super().add_row(*(_safe(r) for r in renderables), **kwargs)


class SafeSyntax(Syntax):
    """`rich.syntax.Syntax` over cleaned code: a command or a source file under review can
    carry a bidi override or an escape sequence like any other text from a machine."""

    def __init__(self, code: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(for_display(code), *args, **kwargs)


def scrub_segments(segments: Iterable[Segment]) -> Iterator[Segment]:
    """The segments with escape sequences, control characters and invisible format
    characters removed or made visible. Control segments (cursor moves a `Live` display
    emits) are left alone: they are Rich's own, not text."""
    for seg in segments:
        if seg.control or not seg.text:
            yield seg
            continue
        cleaned = for_display(seg.text)
        yield seg if cleaned == seg.text else Segment(cleaned, seg.style, seg.control)


class Scrubbed:
    """Wraps a renderable so everything it draws goes through `scrub_segments`."""

    def __init__(self, renderable: RenderableType) -> None:
        self.renderable = renderable

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield from scrub_segments(console.render(self.renderable, options))

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        return Measurement.get(console, options, self.renderable)


def scrubbed(renderable: RenderableType) -> RenderableType:
    """`renderable` wrapped in `Scrubbed` unless it already is."""
    return renderable if isinstance(renderable, Scrubbed) else Scrubbed(renderable)
