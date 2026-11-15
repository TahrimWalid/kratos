"""werkzeug.utils stand-in. `secure_filename` is a real sanitiser, so a direct rule that sees
it on the path correctly breaks the taint chain -- this fake keeps the same shape so a handler
that uses it still imports (it is a recognised check, so such a slice won't reach reproduction
as a plain upload flow)."""
from __future__ import annotations

import re

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def secure_filename(filename):
    name = _UNSAFE.sub("_", str(filename)).strip("._")
    return name or "file"


def redirect(location, *a, **k):
    return location
