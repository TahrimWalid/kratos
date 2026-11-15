"""Tiny markupsafe stand-in for reproduction (E.7b §3.7)."""
from __future__ import annotations


class Markup(str):
    def __new__(cls, base="", *a, **k):
        return str.__new__(cls, base)

    def format(self, *a, **k):
        return self


def escape(x):
    return Markup(str(x))


def escape_silent(x):
    return Markup("" if x is None else str(x))
