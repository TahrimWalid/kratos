"""Code-owned framework stand-ins for reproduction (E.7b §3.7).

The reproduction sandbox has no network and only a few stdlib-ish packages (pytest, requests);
the real Flask / FastAPI / Starlette / Django are NOT installed there. So when the harness runs
the copied handler, ``import flask`` must resolve to a small, code-owned fake that:

- lets the handler module import and the route decorator register nothing (a pass-through), and
- gives the handler a ``request`` object the harness fills with one inert **canary** value for
  every field, so the review can see whether that value reaches the dangerous call.

**The model never writes any of this.** These files are shipped by Kratos, reviewable, and the
same for every reproduction. The dangerous call itself is replaced by a recorder in the harness
(``reproduce.py``), never by anything here -- these fakes only make the handler callable with a
chosen request.

``FAKE_MODULES`` is the closed set of import names a reproduction may stand in for; an import on
the reachable path outside this set (plus the stdlib and names inside the root) makes the slice
not self-contained -> ``needs_validation``, never a silent reproduction against a missing piece.
"""
from __future__ import annotations

from pathlib import Path

# The directory that holds the fake framework packages, prepended to the sandbox sys.path so
# `import flask` etc. resolve to these, not a real install (there is none in the sandbox).
FAKES_DIR = Path(__file__).resolve().parent / "pkg"

# Import names the reproduction can stand in for. A package imported on the path that isn't here,
# stdlib, or inside the root makes the slice not self-contained.
FAKE_MODULES = frozenset({
    "flask", "werkzeug", "markupsafe", "jinja2", "fastapi", "starlette", "pydantic", "django",
})
