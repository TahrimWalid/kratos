"""Suggested commands (A.4 §5.4): built from evidence when a template fits, flagged when not.

Kratos never runs a suggested command -- a person copies it and runs it, often as root, on the
monitored machine. That makes the command text the place an injected instruction would do
real harm, so:

* `catalogue` -- a closed list of common fixes. The model names a template and values; CODE
  checks each value against the evidence of this run (an IP that really attacked, an account
  that really appears in a finding, a PID that really was listed) and renders the command.
* `flags` -- a command the model wrote itself is still allowed, but is shown as written by
  the model, with a flag for each risky shape it contains (downloads, a pipe into a shell,
  decoding, command substitution, a host the evidence never mentions, writes to places that
  keep access). A flagged command needs a second confirmation before it is copied.
* `build` -- turns the model's `recommended_commands` into the list the interfaces show.

Display-only: nothing here executes anything, and nothing here is wired to the fix channel.
"""
