"""django.shortcuts stand-in for reproduction (E.7b §3.7)."""
from __future__ import annotations

from django.http import HttpResponse


def render(request, template_name, context=None, *a, **k):
    return HttpResponse(template_name)


def redirect(to, *a, **k):
    return HttpResponse(to)


def get_object_or_404(klass, *a, **k):
    return None
