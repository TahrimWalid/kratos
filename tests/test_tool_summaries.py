

def test_first_sentence_does_not_stop_at_an_abbreviation():
    """A kept tool's description was cut at '(e.g.' in the /use picker."""
    from kratos.agent.tool_summaries import _first_sentence

    assert _first_sentence("Flags risky ports (e.g. telnet, ftp). Returns a list.") == \
        "Flags risky ports (e.g. telnet, ftp)."
    assert _first_sentence("Counts things, i.e. events. More.") == "Counts things, i.e. events."
