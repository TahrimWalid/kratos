"""Textual widgets that never treat a string as markup, and clean it first (A.4 §5.3).

Textual's `Static`/`Label`/`Button`/`Option` parse a `str` as markup, and `DataTable` turns
a `str` cell into `Text.from_markup(...)` -- so a username, a process name or a finding
title that reaches one as a plain string can restyle the screen, hide text or add a link.
These drop-in subclasses make a `str` a `SafeText` (cleaned by `untrusted.for_display`,
never parsed), so a screen that imports them cannot get this wrong by forgetting one field.
`tests/test_untrusted_renderers.py` scans the TUI for direct imports of the plain widgets.

Nothing in the TUI relies on markup inside a string (checked when this was written), so the
only behaviour change is that stray `[...]` in text stays literal.
"""
from __future__ import annotations

from typing import Any

from textual.widgets import Button as _Button
from textual.widgets import DataTable as _DataTable
from textual.widgets import Label as _Label
from textual.widgets import Static as _Static
from textual.widgets.option_list import Option as _Option

from kratos.untrusted_rich import SafeText


def _safe(value: Any) -> Any:
    return SafeText(value) if isinstance(value, str) else value


class SafeStatic(_Static):
    def __init__(self, content: Any = "", *args: Any, **kwargs: Any) -> None:
        kwargs["markup"] = False
        super().__init__(_safe(content), *args, **kwargs)

    def update(self, content: Any = "", *, layout: bool = True) -> None:
        super().update(_safe(content), layout=layout)


class SafeLabel(_Label):
    def __init__(self, content: Any = "", *args: Any, **kwargs: Any) -> None:
        kwargs["markup"] = False
        super().__init__(_safe(content), *args, **kwargs)

    def update(self, content: Any = "", *, layout: bool = True) -> None:
        super().update(_safe(content), layout=layout)


class SafeButton(_Button):
    def __init__(self, label: Any = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(_safe(label), *args, **kwargs)


class SafeOption(_Option):
    def __init__(self, prompt: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(_safe(prompt), *args, **kwargs)


class SafeDataTable(_DataTable):
    """A `DataTable` whose `str` cells and column labels are cleaned and not parsed as markup."""

    def add_column(self, label: Any, *args: Any, **kwargs: Any):            # type: ignore[override]
        return super().add_column(_safe(label), *args, **kwargs)

    def add_columns(self, *labels: Any):                                    # type: ignore[override]
        return [self.add_column(label) for label in labels]

    def add_row(self, *cells: Any, **kwargs: Any):                          # type: ignore[override]
        if isinstance(kwargs.get("label"), str):
            kwargs["label"] = _safe(kwargs["label"])
        return super().add_row(*(_safe(c) for c in cells), **kwargs)

    def add_rows(self, rows: Any):                                          # type: ignore[override]
        return [self.add_row(*row) for row in rows]

    def update_cell(self, row_key: Any, column_key: Any, value: Any, **kwargs: Any) -> None:    # type: ignore[override]
        super().update_cell(row_key, column_key, _safe(value), **kwargs)

    def update_cell_at(self, coordinate: Any, value: Any, **kwargs: Any) -> None:               # type: ignore[override]
        super().update_cell_at(coordinate, _safe(value), **kwargs)
