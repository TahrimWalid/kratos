"""Both real listeners must give core a whitelist store.

Found while preparing the execution scenes (2026-10-05): `kratos subagent-serve`
and the TUI's in-process listener built CoreServer without `whitelist_store`, so
core never pushed allowlists, never recorded what an agent allows (the `c` view
in /whitelist), and never delivered a /whitelist run -- every run timed out.
The tests that exercise execution always passed the store themselves."""
from __future__ import annotations

import argparse
from types import SimpleNamespace

from kratos.storage.whitelist_store import WhitelistStore


class _FakeServer:
    seen: dict = {}

    def __init__(self, store, **kwargs):
        _FakeServer.seen = kwargs

    async def serve_forever(self):
        return None

    async def close(self):
        return None


def test_subagent_serve_passes_a_whitelist_store(tmp_path, monkeypatch):
    from kratos.cli import app as cli
    from kratos.subagent import core_server

    monkeypatch.setattr(core_server, "CoreServer", _FakeServer)
    cli.cmd_subagent_serve(argparse.Namespace(data_dir=tmp_path, host="127.0.0.1", port=0))
    store = _FakeServer.seen.get("whitelist_store")
    assert isinstance(store, WhitelistStore) and store.db_path == tmp_path / "kratos.db"


def test_the_tui_listener_passes_a_whitelist_store(tmp_path, monkeypatch):
    from kratos.subagent import core_listener, core_server
    from kratos.tui_mk2.app import KratosTUI

    monkeypatch.setattr(core_server, "CoreServer", _FakeServer)
    monkeypatch.setattr(core_listener, "listener_running", lambda *a, **k: False)
    fake_app = SimpleNamespace(data_dir=tmp_path, _core_listener_inproc=False,
                               run_worker=lambda coro, **kw: coro.close(),
                               _serve_core_listener=lambda server: _noop())
    assert KratosTUI.ensure_core_listener(fake_app) == "in_process"
    store = _FakeServer.seen.get("whitelist_store")
    assert isinstance(store, WhitelistStore) and store.db_path == tmp_path / "kratos.db"


async def _noop():
    return None
