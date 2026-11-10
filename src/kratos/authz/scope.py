"""Effective scope: which machines one caller may see (docs/phaseD/D.7 §3.4).

effective scope = the user's scope (machines, plus every current member of each group
in it) ∩ the token's own machine list (B.3). Resolved fresh on every call, so a group
change, a narrowed scope or a narrowed token applies at the next read.

- The owner at the Kratos host (no credential): every machine.
- The owner through a token: the token's machines (empty = the default machine only --
  B.3's meaning, unchanged for existing installs).
- Any other user through a token: their scope, narrowed by the token's machines when the
  token lists any (empty = the whole of their scope).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.target_key import target_key


class ScopeError(Exception):
    """The scope couldn't be worked out (fail closed: the caller refuses)."""


@dataclass(frozen=True)
class Scope:
    every: bool = False
    names: tuple[str, ...] = field(default_factory=tuple)    # display form, in order, deduplicated by machine

    @property
    def machines(self) -> frozenset[str]:
        return frozenset(target_key(n) for n in self.names)

    def allows(self, machine: str | None) -> bool:
        if machine is None:
            return True
        return self.every or target_key(machine) in self.machines


def default_machine() -> str:
    from kratos import kratos_config

    return kratos_config.process_target().rsplit("@", 1)[-1].strip().strip("[]").lower()


def _dedupe(names: list[str]) -> tuple[str, ...]:
    out, seen = [], set()
    for n in names:
        k = target_key(n)
        if n and k and k not in seen:
            seen.add(k)
            out.append(n)
    return tuple(out)


def user_machines(data_dir: Path | str, user: Any) -> tuple[str, ...]:
    """The user's own scope as machine names: machines, then each group's current members."""
    from kratos.fleet import groups as G

    names: list[str] = []
    for entry in user.scopes:
        if entry.startswith("@"):
            try:
                names.extend(G.resolve(data_dir, entry).machines)
            except G.GroupError:
                continue                    # an empty or deleted group gives nothing
        else:
            names.append(entry)
    return _dedupe(names)


def token_row(data_dir: Path | str, token_id: str) -> dict[str, Any] | None:
    from kratos.serve import store as serve_store

    return serve_store.get_token(data_dir, token_id)


def effective(data_dir: Path | str, user: Any, *, token: dict[str, Any] | None = None,
              local: bool = False) -> Scope:
    """`local`: the caller is the owner at the Kratos host with no credential."""
    try:
        if user.is_owner and local and token is None:
            return Scope(every=True)
        token_targets = [str(t).strip().lower() for t in ((token or {}).get("targets") or []) if str(t).strip()]
        if user.is_owner:
            if token is None:
                return Scope(every=True) if local else Scope()
            return Scope(names=_dedupe(token_targets or ([default_machine()] if default_machine() else [])))
        mine = user_machines(data_dir, user)
        if token is not None and token_targets:
            wanted = {target_key(t) for t in token_targets}
            mine = tuple(n for n in mine if target_key(n) in wanted)
        return Scope(names=mine)
    except Exception as e:  # noqa: BLE001 -- fail closed with the reason
        raise ScopeError(f"the scope could not be read ({type(e).__name__})") from e


def scope_allows(names: list[str] | tuple[str, ...], machine: str) -> bool:
    return target_key(machine) in {target_key(n) for n in names}
