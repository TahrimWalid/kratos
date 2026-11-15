"""Tiny jinja2 stand-in for reproduction (E.7b §3.7). `Template` is a dangerous call for the
template class; the harness replaces it with a recorder, so this default never renders."""
from __future__ import annotations


class Template:                       # recorder replaces this for the template class
    def __init__(self, source="", *a, **k):
        self.source = source

    def render(self, *a, **k):
        return str(self.source)


class Environment:
    def __init__(self, *a, **k):
        pass

    def from_string(self, source, *a, **k):   # recorder replaces this for the template class
        return Template(source)

    def get_template(self, name, *a, **k):
        return Template(name)


def escape(x):
    return x
