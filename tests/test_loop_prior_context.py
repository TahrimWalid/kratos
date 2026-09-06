"""
#2: run_agent can take prior CONVERSATION context so an investigation launched
mid-conversation isn't context-blind. It goes in _Conversation's never-compacted
preamble — so it's injected into the prompt, is backward-compatible when absent,
and survives compaction (never dropped, C7-safe).
"""
from __future__ import annotations

from kratos.agent.loop import (
    _Conversation,
    _bound_prior_context,
    _PRIOR_CONTEXT_RESERVED_TOKENS,
    COMPACTION_KEEP_RECENT_TURNS,
)


def test_bound_prior_context_dropped_on_small_local_window():
    # A local 6144 window can't afford the conversation once the ~4900-token
    # system prompt + working turns are reserved -> dropped, no overflow risk.
    assert _bound_prior_context("You: hi\nKratos: hey", window=6144) is None


def test_bound_prior_context_kept_on_large_cloud_window():
    ctx = "You: is 10.0.0.9 bad?\nKratos: yes, brute force."
    assert _bound_prior_context(ctx, window=262144) == ctx  # plenty of room


def test_bound_prior_context_trimmed_to_budget_keeps_tail():
    window = 262144
    budget_chars = (window - _PRIOR_CONTEXT_RESERVED_TOKENS) * 4
    ctx = "OLDEST_MARKER" + ("x" * (budget_chars + 5000)) + "NEWEST_MARKER"
    out = _bound_prior_context(ctx, window=window)
    assert out is not None
    assert "earlier conversation trimmed" in out
    assert "NEWEST_MARKER" in out          # newest tail kept
    assert "OLDEST_MARKER" not in out       # oldest dropped
    assert len(out) <= budget_chars + 100   # bounded (plus the short marker)


def test_bound_prior_context_empty_is_none():
    assert _bound_prior_context(None, window=262144) is None
    assert _bound_prior_context("   ", window=262144) is None


def test_prior_context_appears_before_goal():
    c = _Conversation("check ssh exposure",
                      prior_context="You: is 10.0.0.9 malicious?\nKratos: yes — a brute-force burst.")
    rendered = c.render()
    assert "Conversation so far" in rendered
    assert "10.0.0.9" in rendered
    # the goal still comes through, after the context
    assert "Investigation goal: check ssh exposure" in rendered
    assert rendered.index("10.0.0.9") < rendered.index("Investigation goal:")


def test_no_prior_context_is_byte_identical_to_before():
    # Backward compatibility: existing callers (CLI, MCP) that pass nothing get
    # the exact old preamble.
    assert _Conversation("g").render() == "Investigation goal: g\n"
    assert _Conversation("g", prior_context="").render() == "Investigation goal: g\n"
    assert _Conversation("g", prior_context="   ").render() == "Investigation goal: g\n"


def test_prior_context_survives_compaction():
    c = _Conversation("investigate", prior_context="EARLIER: found a burst from 10.0.0.9")
    for _ in range(COMPACTION_KEEP_RECENT_TURNS + 3):
        c.add("x" * 500, tool="run_nmap_scan",
              observation={"status": "ok", "result": {"open_ports_total": 1}})
    assert c.maybe_compact(last_context_tokens=10_000, window=1_000) is True  # force a real fold
    # the preamble (prior context + goal) is never folded — still present
    assert "10.0.0.9" in c.render()
    assert "Investigation goal: investigate" in c.render()
