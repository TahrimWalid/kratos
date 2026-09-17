"""
Regression guard for the WRITE step's SYSTEM_PROMPT hardening (A7 chunk 1).

Scripted-only: asserts the privilege / error-visibility guidance is present in
agent/self_write.py's SYSTEM_PROMPT (and its RULES tail), so a future edit
can't silently drop it. The EMPIRICAL check (that the model actually follows
this guidance -- uses `getent group sudo` instead of `cat /etc/sudoers`, and
does not blanket-suppress stderr) is a real LLM run, not something a unit test
can assert; this file just keeps the guidance from vanishing unnoticed.

Root cause this hardening addresses (docs/evoloop_polish_brief.md, 2026-09-07
incident): two evo-loop tools passed sandbox tests then failed live because
they read root-only files without sudo and suppressed stderr, so the live
failure surfaced as an empty error.
"""
from __future__ import annotations

from kratos.agent.self_write import SYSTEM_PROMPT


def test_prompt_warns_about_root_only_files():
    p = SYSTEM_PROMPT
    # The concrete root-only files the incident named.
    assert "/etc/sudoers" in p
    assert "/etc/shadow" in p


def test_prompt_prefers_unprivileged_alternatives():
    p = SYSTEM_PROMPT
    # The specific non-privileged equivalents the brief calls out.
    assert "getent group sudo" in p
    assert "last" in p and "who" in p


def test_prompt_documents_explicit_sudo_n():
    # sudo -n (never-prompt) is the sanctioned fallback ONLY when root is
    # genuinely unavoidable -- so it must be named as the explicit alternative.
    assert "sudo -n" in SYSTEM_PROMPT


def test_prompt_forbids_hiding_stderr():
    p = SYSTEM_PROMPT
    # The exact anti-pattern (blanket 2>/dev/null on a reported command) and
    # the reason an empty error is worse than raw stderr.
    assert "2>/dev/null" in p
    assert "result.stderr" in p


def test_rules_tail_repeats_both_guards():
    # The two new RULES bullets (short, imperative) must both be present -- the
    # section body alone isn't enough; the model keys heavily on the RULES list.
    rules_section = SYSTEM_PROMPT.split("RULES:", 1)[-1]
    assert "root-only file" in rules_section
    assert "2>/dev/null" in rules_section
