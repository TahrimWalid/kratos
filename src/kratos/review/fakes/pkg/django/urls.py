"""django.urls stand-in for reproduction (E.7b §3.7)."""
from __future__ import annotations


def path(route, view=None, *a, **k):
    return (route, view)


def re_path(route, view=None, *a, **k):
    return (route, view)


def url(route, view=None, *a, **k):
    return (route, view)


def include(*a, **k):
    return ()
