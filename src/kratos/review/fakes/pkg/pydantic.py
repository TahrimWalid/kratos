"""Tiny pydantic stand-in for reproduction (E.7b §3.7): a BaseModel whose attributes all
return the canary set by the harness, so a request-body model still carries taint."""
from __future__ import annotations

_CANARY = ""


def set_canary(value):
    global _CANARY
    _CANARY = value


class BaseModel:
    def __init__(self, *a, **k):
        for key, val in k.items():
            object.__setattr__(self, key, val)

    def __getattr__(self, name):
        return _CANARY

    @classmethod
    def parse_obj(cls, *a, **k):
        return cls()

    def dict(self, *a, **k):
        return {"q": _CANARY}


def Field(default=None, *a, **k):
    return default


class BaseSettings(BaseModel):
    pass
