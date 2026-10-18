"""B.2 where the person sees it: /doctor, Settings -> General, `kratos trace show --sent`."""
from __future__ import annotations

import asyncio
import json
from argparse import Namespace

import pytest

pytest.importorskip("requests")

from kratos import kratos_config, llm_interface, settings_store
from kratos.privacy import mode as M
from kratos.run_context import run_scope
from kratos.trace import settings as TS
from kratos.trace import store, view


def test_doctor_says_what_the_model_is_sent(tmp_path, monkeypatch):
    from kratos.agent.doctor import _check_privacy

    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: "https://api.example.com/v1")
    rows = []
    _check_privacy(rows, tmp_path)
    assert rows[0]["check"] == "model privacy" and "masked (standard" in rows[0]["detail"]
    settings_store.set(M.MODE_KEY, "off", data_dir=tmp_path, actor="test")
    rows = []
    _check_privacy(rows, tmp_path)
    assert rows[0]["status"] == "warn" and "not masked" in rows[0]["detail"]
    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: "http://127.0.0.1:11434/v1")
    settings_store.set(M.MODE_KEY, "auto", data_dir=tmp_path, actor="test")
    rows = []
    _check_privacy(rows, tmp_path)
    assert rows[0]["status"] == "info" and "local model" in rows[0]["detail"]


def test_settings_general_lists_the_privacy_rows(tmp_path, monkeypatch):
    from textual.app import App
    from textual.widgets import DataTable

    from kratos.tui_mk2.screens.settings import SettingsScreen

    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: "https://api.example.com/v1")

    class Host(App):
        def on_mount(self):
            self.push_screen(SettingsScreen(session=None, data_dir=tmp_path))

    async def run():
        app = Host()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            table = screen.query_one("#gen-table", DataTable)
            assert table.row_count == len(screen._gen_rows)
            return [str(table.get_cell_at((r, 0))) + " | " + str(table.get_cell_at((r, 1)))
                    for r in range(table.row_count)]

    rows = asyncio.run(run())
    assert any(r.startswith("What the model sees | auto") and "standard" in r for r in rows)
    assert any(r.startswith("Your own model machines | none") for r in rows)


class _Resp:
    def __init__(self, content):
        self._body = {"choices": [{"message": {"content": content}}],
                      "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


@pytest.mark.parametrize("store_prompts", [True, False])
def test_trace_show_sent_shows_the_masked_request(tmp_path, monkeypatch, capsys, store_prompts):
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.cli.data_cmds import cmd_trace

    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("192.0.2.10")
    settings_store.set(TS.STORE_PROMPTS, store_prompts, data_dir=tmp_path, actor="test")
    monkeypatch.setattr(llm_interface, "_running_backend", lambda: "openai_compatible")
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "m")
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", lambda **kw: {
        "findings": [], "count": 0, "staleness_warning": None, "missing_inputs": [], "input_errors": {},
        "inputs_used": {}, "note": "login attempts from 203.0.113.7"})
    replies = [json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}),
               json.dumps({"reasoning": "r", "final_answer": "Nothing serious."})]
    monkeypatch.setattr(llm_interface.requests, "post", lambda *a, **k: _Resp(replies.pop(0)))
    with run_scope("cli"):
        result = agent_loop.run_agent("check 192.0.2.10", tmp_path, max_iters=4)
    info = store.find(tmp_path, result["run_id"])
    lines = "\n".join(view.sent_lines(info)[len(view.header_lines(info)):])   # the requests, not the header
    assert "masked (standard)" in lines and "target ip" in lines
    assert "203.0.113.7" not in lines and "192.0.2.10" not in lines
    if store_prompts:
        assert "[prompt]" in lines and "TARGET_IP_" in lines
    else:
        assert "not kept (trace.store_prompts is off)" in lines
    assert cmd_trace(Namespace(data_dir=str(tmp_path), trace_action="show", run=result["run_id"], json=False,
                               sent=True)) == 0
    assert "model call 1" in capsys.readouterr().out
