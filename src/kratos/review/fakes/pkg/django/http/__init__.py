"""django.http stand-in for reproduction (E.7b §3.7)."""
from __future__ import annotations


class HttpResponse:
    def __init__(self, content="", *a, **k):
        self.content = content
        self.status_code = 200


class JsonResponse(HttpResponse):
    pass


class HttpResponseRedirect(HttpResponse):
    pass


class HttpResponseBadRequest(HttpResponse):
    pass


class HttpResponseForbidden(HttpResponse):
    status_code = 403
