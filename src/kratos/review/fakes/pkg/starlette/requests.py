"""starlette.requests stand-in: `request` is the slicer's taint root for Starlette apps."""
from __future__ import annotations


class _AnyDict:
    def __init__(self, canary):
        self._c = canary

    def __getitem__(self, key):
        return self._c

    def get(self, key, default=None):
        return self._c

    def getlist(self, key):
        return [self._c]


class Request:
    def __init__(self, canary=""):
        self._c = canary

    @property
    def query_params(self):
        return _AnyDict(self._c)

    @property
    def path_params(self):
        return {"q": self._c}

    async def body(self):
        return self._c.encode() if isinstance(self._c, str) else b""

    async def json(self):
        return {"q": self._c}


request = Request("")
