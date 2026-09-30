"""
Fit a DataTable's rows to the width it actually has.

Textual's DataTable sizes every column to its widest cell and scrolls
sideways when the total is wider than the table, so one long cell (a goal, a
status detail) pushes the columns after it off-screen with nothing to show
they're there. `fit_columns` shrinks chosen columns -- in the order given,
each down to its own minimum -- until the row fits, ending shortened cells
with an ellipsis. Only when every listed column is at its minimum does the
table still scroll (a very narrow terminal).
"""
from __future__ import annotations

from typing import Sequence

from rich.cells import cell_len
from rich.text import Text

# DataTable's default cell padding is one column on each side.
_PAD_PER_COLUMN = 2


def _width(cell: Text | str) -> int:
    return cell.cell_len if isinstance(cell, Text) else cell_len(str(cell))


def _clip(cell: Text | str, width: int) -> Text | str:
    if _width(cell) <= width:
        return cell
    text = cell.copy() if isinstance(cell, Text) else Text(str(cell))
    text.truncate(width, overflow="ellipsis")
    return text


def fit_columns(
    rows: Sequence[Sequence[Text | str]],
    available: int,
    shrink: Sequence[tuple[int, int]],
    headers: Sequence[str] = (),
    reserve: int = 2,
) -> list[list[Text | str]]:
    """Return `rows` with the columns in `shrink` ([(column index, minimum
    width), ...], shrunk first to last) cut down so a row fits `available`
    cells. `headers` count toward each column's width; `reserve` leaves room
    for the vertical scrollbar."""
    if not rows:
        return [list(r) for r in rows]
    ncols = max(len(r) for r in rows)
    widths = [0] * ncols
    for i, h in enumerate(headers[:ncols]):
        widths[i] = cell_len(h)
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], _width(cell))
    over = sum(widths) + _PAD_PER_COLUMN * ncols + reserve - max(available, 0)
    caps = list(widths)
    for index, minimum in shrink:
        if over <= 0:
            break
        floor = max(minimum, cell_len(headers[index]) if index < len(headers) else 0)
        give = min(over, max(0, caps[index] - floor))
        caps[index] -= give
        over -= give
    return [[_clip(cell, caps[i]) for i, cell in enumerate(r)] for r in rows]
