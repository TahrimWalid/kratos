"""The closed list of "worth a look" shapes in a persistence item's own lines.

A shape is a named pattern plus the plain sentence that explains it ("why this
is worth a look: runs a file from a temporary directory"). Shapes never decide
alone above "low" (A.1 §5.3): on their own they raise PERSIST-002 (low), and a
*strong* shape on an item that is also new and unowned raises PERSIST-001 from
medium to high.

Matching is deliberately narrow -- the list is closed, every pattern is
anchored at something an attacker needs (a temporary directory, a decoder, a
pipe into a shell, a network device, a preload) rather than at a word that a
normal maintenance script also uses. The clean-host runs in the Handoff are the
evidence that it does not fire on ordinary machines.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# A path in one of these directories is attacker-shaped wherever it appears.
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")


@dataclass(frozen=True)
class Shape:
    name: str
    why: str                    # "runs a file from a temporary directory"
    pattern: re.Pattern[str]
    strong: bool = True         # strong shapes can raise a new unowned item to high


def _p(text: str) -> re.Pattern[str]:
    return re.compile(text, re.IGNORECASE)


_TEMP = "|".join(re.escape(d) for d in TEMP_DIRS)
# A shell/interpreter reading from a pipe or from standard input.
_SHELL_SINK = r"(ba|z|da|k)?sh\b[^|]*$|\bsh\s+-\S*s|\bpython[0-9.]*\s+-\s*$|\bperl\s+-\s*$"

SHAPES: tuple[Shape, ...] = (
    Shape("runs-from-temp-dir", "runs a file from a temporary directory",
          _p(rf"(^|[\s\"'=:(])({_TEMP})\S*")),
    Shape("runs-from-hidden-dir", "runs a file from a hidden directory",
          _p(r"(^|[\s\"'=:(])/(?:[\w.+-]+/)*\.[\w+-]+/\S+")),
    Shape("decodes-and-runs", "decodes hidden text and runs it",
          _p(r"\b(base64|base32|basenc|uudecode|xxd|openssl\s+enc)\b[^|;&]*[|]\s*(" + _SHELL_SINK + r")"
             r"|\beval\b[^|;&]*\b(base64|xxd)\b"
             r"|\b(python[0-9.]*|perl|ruby|php)\b[^|;&]*\b(b64decode|base64_decode|decode64|MIME::Base64)\b")),
    Shape("downloads-and-runs", "downloads something from the network and runs it",
          _p(r"\b(curl|wget|fetch)\b[^|;&]*[|]\s*(" + _SHELL_SINK + r")"
             r"|\b(curl|wget)\b[^;&]*\s(&&|;)\s*(\./|/tmp/|sh\b|bash\b|chmod\b)")),
    Shape("network-shell", "opens a shell over the network (a reverse shell)",
          _p(r"/dev/(tcp|udp)/|\b(nc|ncat|netcat)\b[^|;&]*\s-\S*e\b|\bsocat\b[^|;&]*\bexec\b"
             r"|\b(ba|z)?sh\s+-\S*i\b[^|;&]*>\s*&|\bmkfifo\b[^|;&]*[|]")),
    Shape("loads-a-library-everywhere", "makes every program load a library",
          _p(r"\bLD_PRELOAD\s*=\S|\bLD_AUDIT\s*=\S|\bLD_LIBRARY_PATH\s*=\S")),
    Shape("makes-itself-undeletable", "makes the file undeletable (chattr +i)",
          _p(r"\bchattr\b[^|;&]*[+]\S*i")),
    Shape("runs-code-from-the-command-line", "runs code written on the command line",
          _p(r"\b(python[0-9.]*|perl|ruby|php|node)\b\s+-\S*(c|e|r)\s+[\"']?.{40}"), strong=False),
    Shape("turns-off-shell-history", "turns off the shell's own history",
          _p(r"\bHISTFILE\s*=\s*(/dev/null|\s*$|\"\"|'')|\bunset\s+HIST\w+|\bset\s+[+]o\s+history"
             r"|\bHISTSIZE\s*=\s*0\b"), strong=False),
    Shape("detaches-itself", "keeps running after the session that started it ends",
          _p(r"\b(nohup|setsid)\b|\bdisown\b"), strong=False),
)

SHAPES_BY_NAME = {s.name: s for s in SHAPES}
STRONG = frozenset(s.name for s in SHAPES if s.strong)


def match(line: str) -> list[Shape]:
    """The shapes one extracted line has, in table order."""
    text = str(line or "")
    return [s for s in SHAPES if s.pattern.search(text)]


def why(names: list[str] | tuple[str, ...]) -> list[str]:
    return [SHAPES_BY_NAME[n].why for n in names if n in SHAPES_BY_NAME]
