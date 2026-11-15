"""A tiny code-owned stand-in for Flask, used only inside the reproduction sandbox so a copied
handler can be imported and called with a chosen request. It runs nothing dangerous: the
reproduction harness replaces the real dangerous call with a recorder before the handler runs.

Every ``request`` field returns the one inert canary the harness set, so the review can see
whether that value reaches the dangerous call. The route decorators register nothing.
"""
from __future__ import annotations

_CANARY = ""


def set_canary(value):
    global _CANARY, request
    _CANARY = value
    request = Request(value)


class _AnyDict:
    """A mapping where every key returns the canary (and iteration yields a couple of keys),
    so `request.args['x']`, `request.form.get('y')` and `request.values.getlist('z')` all carry it."""
    def __init__(self, canary):
        self._c = canary

    def __getitem__(self, key):
        return self._c

    def get(self, key, default=None):
        return self._c

    def getlist(self, key):
        return [self._c]

    def __contains__(self, key):
        return True

    def __iter__(self):
        return iter(("q", "name"))

    def keys(self):
        return ["q", "name"]

    def items(self):
        return [("q", self._c), ("name", self._c)]

    def to_dict(self, flat=True):
        return {"q": self._c, "name": self._c}


class _FileStorage:
    def __init__(self, canary):
        self.filename = canary
        self.name = canary
        self.content_type = "application/octet-stream"
        self.stream = None

    def save(self, dst, *a, **k):            # recorder replaces this via werkzeug when the class is upload
        return None

    def read(self, *a, **k):
        return b""


class _Files(_AnyDict):
    def __getitem__(self, key):
        return _FileStorage(self._c)

    def get(self, key, default=None):
        return _FileStorage(self._c)

    def getlist(self, key):
        return [_FileStorage(self._c)]


class Request:
    def __init__(self, canary):
        self.args = _AnyDict(canary)
        self.form = _AnyDict(canary)
        self.values = _AnyDict(canary)
        self.json = {"q": canary, "name": canary}
        self.data = canary.encode() if isinstance(canary, str) else b""
        self.headers = _AnyDict(canary)
        self.cookies = _AnyDict(canary)
        self.files = _Files(canary)
        self.path = canary
        self.full_path = canary
        self.url = canary
        self.method = "POST"
        self.remote_addr = "203.0.113.1"

    def get_json(self, *a, **k):
        return self.json

    def get_data(self, *a, **k):
        return self.data


request = Request(_CANARY)


class _BlueprintLike:
    def __init__(self, *a, **k):
        pass

    def _passthrough(self, *a, **k):
        def deco(fn):
            return fn
        return deco

    route = get = post = put = delete = patch = websocket = _passthrough
    before_request = after_request = errorhandler = _passthrough
    add_url_rule = lambda self, *a, **k: None   # noqa: E731


class Flask(_BlueprintLike):
    def __init__(self, *a, **k):
        self.config = {}


class Blueprint(_BlueprintLike):
    def __init__(self, *a, **k):
        pass


def render_template_string(source, **ctx):   # recorder replaces this for the template class
    return str(source)


def render_template(name, **ctx):
    return str(name)


def send_file(path, *a, **k):                # recorder replaces this for the path class
    return str(path)


def send_from_directory(directory, path, *a, **k):
    return str(path)


def jsonify(*a, **k):
    return {"a": a, "k": k}


def redirect(location, *a, **k):
    return location


def abort(*a, **k):
    raise _Abort(*a)


def make_response(*a, **k):
    return a[0] if a else None


def url_for(*a, **k):
    return "/"


class _Abort(Exception):
    pass


class _G:
    def __getattr__(self, name):
        return None


g = _G()
session = _AnyDict(_CANARY)
current_app = Flask("fake")
