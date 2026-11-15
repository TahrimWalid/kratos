"""Tiny FastAPI stand-in for reproduction (E.7b §3.7). Route decorators register nothing; a
handler's parameters are filled with the canary by the harness when it calls the function."""
from __future__ import annotations


def _passthrough(*a, **k):
    def deco(fn):
        return fn
    return deco


class _RouterLike:
    def __init__(self, *a, **k):
        pass

    route = get = post = put = delete = patch = api_route = websocket = _passthrough
    middleware = on_event = exception_handler = _passthrough

    def include_router(self, *a, **k):
        return None


class FastAPI(_RouterLike):
    pass


class APIRouter(_RouterLike):
    pass


class Request:
    def __init__(self, *a, **k):
        self._c = ""

    @property
    def query_params(self):
        from flask import _AnyDict  # shares the canary dict shape
        return _AnyDict(self._c)

    @property
    def path_params(self):
        return {"q": self._c}


def Depends(dependency=None, *a, **k):      # a parameter default; the harness fills the param with the canary
    return dependency


def Security(*a, **k):
    return None


def Query(default=None, *a, **k):
    return default


def Body(default=None, *a, **k):
    return default


def Form(default=None, *a, **k):
    return default


def File(default=None, *a, **k):
    return default


class HTTPException(Exception):
    def __init__(self, status_code=400, detail="", *a, **k):
        self.status_code = status_code
        self.detail = detail
