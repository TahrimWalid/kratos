"""django.views stand-in for reproduction (E.7b §3.7)."""
from __future__ import annotations


class View:
    @classmethod
    def as_view(cls, *a, **k):
        def view(request, *args, **kwargs):
            return cls()
        return view
