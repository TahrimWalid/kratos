"""Turns the model's `recommended_commands` into what the interfaces show.

Each entry becomes one of:

* a **template** command (`source: "template"`): the model named a catalogue id and values;
  code checked them against the evidence and rendered the command. No flags.
* a **recognised** command (`source: "template"`, `recognised: True`): the model wrote the text, but it is
  exactly a template's shape and its values pass the same evidence checks -- shown as the template command.
* a **model** command (`source: "model"`): the model wrote the command text. It carries the
  `flags` found in it and is shown as "written by the model -- check before running".
* a **withheld** entry (`source: "withheld"`): a template the checks refused. The reason is
  the explanation, there is no command to copy.

Entries stay dicts with `command`, `explanation`, `run_on` as before, plus `source`, `flags`
(a list of `{id, reason}`) and, for templates, `template`.
"""
from __future__ import annotations

from typing import Any

from kratos.remediation import catalogue, flags
from kratos.remediation.evidence import Evidence

MAX_COMMANDS = 12
MAX_COMMAND_LEN = 500
MAX_EXPLANATION_LEN = 500
VALID_RUN_ON = ("target", "kratos_host")


def _as_template(command: str, evidence: Evidence) -> tuple[str, str] | None:
    """A command the model wrote that is, line for line, a catalogue template whose values pass the
    evidence checks: (template id, the command code renders). Anything else -- another shape, or a
    value the evidence doesn't support -- stays a model-written command."""
    hit = catalogue.recognise(command)
    if hit is None:
        return None
    tid, values = hit
    if "pid" in values:
        values = {**values, "pid": int(values["pid"])}
    try:
        return tid, catalogue.render_template(tid, values, evidence)
    except catalogue.TemplateError:
        return None


def build_recommendations(raw: Any, evidence: Evidence | None = None) -> list[dict[str, Any]]:
    """The cleaned, bounded list for `raw` (the model's `recommended_commands`); [] for a
    missing or malformed value. Never raises, never executes anything."""
    if not isinstance(raw, list):
        return []
    evidence = evidence or Evidence.empty()
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        explanation = str(item.get("explanation") or "").strip()[:MAX_EXPLANATION_LEN]
        run_on = str(item.get("run_on") or "target").strip().lower()
        if run_on not in VALID_RUN_ON:
            run_on = "target"
        if item.get("template") is not None:
            try:
                command = catalogue.render_template(item.get("template"), item.get("values"), evidence)
            except catalogue.TemplateError as e:
                out.append({"command": "", "explanation": f"{explanation} (Kratos did not build a command: {e})".strip(),
                            "run_on": run_on, "source": "withheld", "flags": [],
                            "template": str(item.get("template"))[:60]})
            else:
                out.append({"command": command, "explanation": explanation, "run_on": run_on,
                            "source": "template", "flags": [], "template": str(item.get("template"))})
        else:
            command = str(item.get("command") or "").strip()
            if not command:
                continue
            command = command[:MAX_COMMAND_LEN]
            recognised = _as_template(command, evidence)
            if recognised is not None:
                tid, built = recognised
                out.append({"command": built, "explanation": explanation, "run_on": run_on, "source": "template",
                            "flags": [], "template": tid, "recognised": True})
                if len(out) >= MAX_COMMANDS:
                    break
                continue
            out.append({"command": command, "explanation": explanation, "run_on": run_on, "source": "model",
                        "flags": [f.as_dict() for f in flags.flag_command(command, evidence)]})
        if len(out) >= MAX_COMMANDS:
            break
    return out
