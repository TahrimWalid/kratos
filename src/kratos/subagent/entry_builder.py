"""
Turns what a person types in the /whitelist form into an allowlist entry --
the logic behind the UI, kept free of Textual so it can be tested directly.

Two ways to author an entry (docs/subagent_execution_track.md §1):

  - A command with BLANKS, e.g. `fail2ban-client set sshd banip {ip}`. The
    person never picks a validator by hand: each blank's type comes from the
    ceiling position it lands in (a list of allowed values, an IP, a number
    range, or a short word with the ceiling's own pattern). They may only
    narrow it (e.g. tick fewer values).
  - An EXACT command, e.g. `adduser --disabled-password --gecos '' alice`.
    Unless a shipped shape already covers it, the target's own admin must
    list the same line in the target's allow file; `allow_file_snippet`
    produces the copy-paste command for that.

Also matches a command Kratos RECOMMENDED against the entries that are
enabled for a target, so the UI can offer to run it through the same
approval flow (`match_recommendation`).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any

from kratos.subagent import ceiling as C
from kratos.subagent import whitelist as W

_BLANK_RE = re.compile(r"^\{([a-z][a-z0-9_]{0,31})\}$")


class EntryDraftError(ValueError):
    """What the person typed can't become an entry; the message says why in
    plain words."""


@dataclass
class BlankDraft:
    """One `{name}` in the typed command, and what the ceiling allows there."""

    name: str
    position: int
    ceiling_var: C.Var

    @property
    def kind(self) -> str:
        return self.ceiling_var.slot.kind

    def allowed_values(self) -> tuple[str, ...]:
        """For a list-of-values blank: the choices the person may tick."""
        values = self.ceiling_var.slot.values or ()
        deny = {d.lower() for d in self.ceiling_var.deny}
        return tuple(v for v in values if v.lower() not in deny)

    def default_slot(self) -> W.Slot:
        """The widest slot this position allows -- the person can only narrow it."""
        s = self.ceiling_var.slot
        if s.kind == "enum":
            return W.Slot(kind="enum", values=self.allowed_values())
        if s.kind == "ip":
            return W.Slot(kind="ip", ip_deny_private=s.ip_deny_private)
        if s.kind == "int_range":
            return W.Slot(kind="int_range", min_value=s.min_value, max_value=s.max_value)
        return W.Slot(kind="token", pattern=s.pattern, max_length=s.max_length)

    def describe(self) -> str:
        s = self.ceiling_var.slot
        if s.kind == "enum":
            return f"one of: {', '.join(self.allowed_values())}"
        if s.kind == "ip":
            return "a public IP address" if s.ip_deny_private else "an IP address"
        if s.kind == "int_range":
            return f"a whole number from {s.min_value} to {s.max_value}"
        return "a short name (letters, digits, - and _)"


@dataclass
class CommandDraft:
    tokens: list[str]
    shape: C.Shape
    blanks: list[BlankDraft]


def describe_shape(shape: C.Shape) -> str:
    """`fail2ban-client set <word> banip <public IP>` -- one allowed form, in words."""
    parts = [shape.binary]
    for arg in shape.args:
        if isinstance(arg, C.Lit):
            parts.append(arg.value)
        else:
            parts.append("<" + BlankDraft("x", 0, arg).describe() + ">")
    return " ".join(parts)


def allowed_forms(ceiling: C.Ceiling, binary: str | None = None) -> list[str]:
    """Every command form the ceiling allows (optionally for one program),
    excluding target-local exact commands (listed separately)."""
    return [describe_shape(s) for s in ceiling.shapes if not s.local and (binary is None or s.binary == binary)]


def parse_blank_command(text: str) -> list[str]:
    """Split a typed command with `{blank}`s. A leading `sudo` is dropped (the
    agent already runs as the service user)."""
    text = (text or "").strip()
    if not text:
        raise EntryDraftError("Type a command.")
    try:
        tokens = C.normalize_command(shlex.split(text, posix=True))
    except ValueError as e:
        raise EntryDraftError(f"Couldn't read that command: {e}.") from e
    if not tokens:
        raise EntryDraftError("Type a command.")
    names = []
    for t in tokens:
        if "{" in t or "}" in t:
            m = _BLANK_RE.fullmatch(t)
            if not m:
                raise EntryDraftError(
                    f"'{t}': a blank must be a whole word like {{ip}} or {{unit}} (lowercase letters, digits, _)."
                )
            names.append(m.group(1))
    if len(names) != len(set(names)):
        raise EntryDraftError("Each blank needs its own name (e.g. {ip} and {jail}, not {x} twice).")
    if _BLANK_RE.fullmatch(tokens[0]):
        raise EntryDraftError("The program itself can't be a blank.")
    return tokens


def match_shapes(tokens: list[str], ceiling: C.Ceiling) -> list[C.Shape]:
    """Shapes the typed command (with blanks) lines up with."""
    out = []
    for shape in ceiling.shapes:
        if shape.local or len(tokens) != 1 + len(shape.args) or not C._binary_matches(shape, tokens[0]):
            continue
        ok = True
        for tok, arg in zip(tokens[1:], shape.args):
            blank = _BLANK_RE.fullmatch(tok)
            if isinstance(arg, C.Lit):
                ok = not blank and tok == arg.value
            elif not blank:
                ok = C._value_ok(arg, tok)
            if not ok:
                break
        if ok:
            out.append(shape)
    return out


def draft_command(text: str, ceiling: C.Ceiling) -> list[CommandDraft]:
    """All ways the typed command fits the ceiling (usually one). Raises
    EntryDraftError explaining which forms ARE allowed when it fits none."""
    tokens = parse_blank_command(text)
    shapes = match_shapes(tokens, ceiling)
    if not shapes:
        binary = tokens[0].rpartition("/")[2]
        forms = allowed_forms(ceiling, binary)
        if forms:
            raise EntryDraftError(
                f"That isn't an allowed form of '{binary}'. Allowed:\n  " + "\n  ".join(forms)
                + "\nPut a {blank} where a value varies, or add it as an exact command instead."
            )
        raise EntryDraftError(
            f"'{binary}' isn't a program this target's agent will run with blanks. "
            "Add it as an exact command instead -- the target's admin then allows that one line on the target."
        )
    drafts = []
    for shape in shapes:
        blanks = [
            BlankDraft(name=m.group(1), position=i, ceiling_var=shape.args[i - 1])
            for i, tok in enumerate(tokens) if i and (m := _BLANK_RE.fullmatch(tok))
        ]
        drafts.append(CommandDraft(tokens=tokens, shape=shape, blanks=blanks))
    return drafts


def default_texts(shape: C.Shape) -> dict[str, str]:
    """Starting text for the three fields the approval screen shows. The
    person edits them; they're never shown unedited as if authored."""
    return {
        "effect": shape.description,
        "reversibility": ("Reversible -- undo it with the matching opposite action."
                          if shape.reversible else "Not automatically reversible."),
        "blast_radius": "Only the target machine this entry belongs to.",
    }


def allow_file_snippet(line: str) -> str:
    """The command the target's admin runs ON THE TARGET to allow one exact
    command line. Idempotent and permission-correct (the agent ignores the
    file unless it is root-owned and not group/world-writable)."""
    tokens = C.parse_command_line(line)  # validates: no shells/wrappers/shell syntax
    canonical = shlex.join(tokens)
    path = C.LOCAL_ALLOW_FILE
    directory = path.rpartition("/")[0]
    q = shlex.quote
    return (f"sudo install -d -m 755 {q(directory)} && "
            f"(sudo grep -qxF {q(canonical)} {q(path)} 2>/dev/null || echo {q(canonical)} | sudo tee -a {q(path)} >/dev/null) && "
            f"sudo chmod 600 {q(path)}")


def match_recommendation(command: str, rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """If a recommended shell command is exactly one invocation of an enabled
    allowlist entry, return (row, slot_values). Anything with shell syntax,
    pipes or several commands never matches -- only a plain command can be
    run through the sub-agent."""
    try:
        argv = C.normalize_command(shlex.split(command or "", posix=True))
    except ValueError:
        return None
    if not argv or any(m in t for t in argv for m in C._SHELL_META):
        return None
    for row in rows:
        spec: W.ActionSpec = row["spec"]
        tmpl = spec.argv_template
        if len(tmpl) != len(argv):
            continue
        if tmpl[0].rpartition("/")[2] != argv[0].rpartition("/")[2]:
            continue
        values: dict[str, Any] = {}
        ok = True
        for t, a in zip(tmpl[1:], argv[1:]):
            m = W._PLACEHOLDER_RE.fullmatch(t)
            if m is None:
                ok = t == a
            else:
                slot = spec.slots[m.group(1)]
                value: Any = a
                if slot.kind == "int_range":
                    if not re.fullmatch(r"-?\d{1,18}", a):
                        ok = False
                        break
                    value = int(a)
                try:
                    W.validate_slot_value(spec.id, m.group(1), slot, value)
                except W.SlotValueError:
                    ok = False
                values[m.group(1)] = value
            if not ok:
                break
        if ok:
            return row, values
    return None
