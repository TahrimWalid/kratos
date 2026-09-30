"""fit_columns: shrink chosen DataTable columns (in order, down to a floor) so a row fits the
table's width, ending shortened cells with an ellipsis."""
from __future__ import annotations

from rich.text import Text

from kratos.tui_mk2.table_fit import fit_columns


def _widths(rows):
    return [max(len(str(r[i])) for r in rows) for i in range(len(rows[0]))]


def test_already_fits_is_untouched():
    rows = [["a", "bb", "ccc"]]
    assert fit_columns(rows, 80, shrink=[(2, 1)]) == rows


def test_shrinks_the_first_listed_column_first_and_keeps_the_rest():
    rows = [["1", "x" * 30, "y" * 30, "2026-09-29 10:00"]]
    out = fit_columns(rows, 60, shrink=[(2, 5), (1, 5)], reserve=0)
    w = _widths(out)
    assert sum(w) + 2 * len(w) <= 60
    assert w[1] == 30 and str(out[0][2]).endswith("…")       # only the first-listed column gave way
    assert out[0][3] == "2026-09-29 10:00"                      # the right-most column survives whole


def test_moves_on_to_the_next_column_at_the_floor():
    rows = [["x" * 30, "y" * 30]]
    out = fit_columns(rows, 30, shrink=[(1, 10), (0, 8)], reserve=0)
    w = _widths(out)
    assert w[1] == 10 and w[0] < 30 and sum(w) + 4 <= 30


def test_headers_set_a_floor_and_styles_survive():
    rows = [[Text("z" * 40, style="red")]]
    out = fit_columns(rows, 12, shrink=[(0, 1)], headers=("long header",), reserve=0)
    cell = out[0][0]
    assert isinstance(cell, Text) and cell.cell_len == len("long header") and cell.style == "red"


def test_too_narrow_everywhere_stops_at_the_floors():
    rows = [["x" * 20, "y" * 20]]
    out = fit_columns(rows, 5, shrink=[(0, 6), (1, 6)], reserve=0)
    assert _widths(out) == [6, 6]
