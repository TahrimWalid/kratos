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
from rich.segment import Segment
from rich.text import Text

from kratos.untrusted import for_display

__all__ = ["SafeText", "Scrubbed", "scrub_segments", "scrubbed"]


class SafeText(Text):
    """`rich.text.Text` whose strings are cleaned with `for_display` on the way in."""

    def __init__(self, text: Any = "", *args: Any, **kwargs: Any) -> None:
        if isinstance(text, str):
            text = for_display(text)
        super().__init__(text, *args, **kwargs)

    def append(self, text: Any, style: Any = None) -> "SafeText":     # type: ignore[override]
        if isinstance(text, str):
            text = for_display(text)
        return super().append(text, style)                              # type: ignore[return-value]


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
