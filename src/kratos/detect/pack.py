"""The rule packs Kratos evaluates: the shipped one and any a person imported.

The shipped pack is package data (kratos/detect/packs/sigma-linux-<N>.json, the
highest N). Imported packs live in <data folder>/detect/packs/*.json, written by
`kratos detect import`. Every pack is validated whole by the evaluator's own
validator (kratos.subagent.detect) before use; a pack that fails is refused whole
and listed with the reason -- never partly applied. Nothing here needs pySigma.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from kratos.subagent import detect as D

SHIPPED_PACK_ID = "sigma-linux"
KRATOS_PACK_ID = "kratos-linux"          # Kratos's own rules (scripts/dev/build_kratos_pack.py), Phase C audit
SHIPPED_PACK_IDS = (SHIPPED_PACK_ID, KRATOS_PACK_ID)
IMPORTED_DIR = Path("detect") / "packs"
_SHIPPED_NAME = re.compile(r"^sigma-linux-(\d+)\.json$")
_KRATOS_NAME = re.compile(r"^kratos-linux-(\d+)\.json$")


@dataclass(frozen=True)
class LoadedPack:
    pack: D.Pack
    origin: str                      # shipped | imported
    path: str

    @property
    def pack_id(self) -> str:
        return self.pack.pack_id

    @property
    def version(self) -> int:
        return int(self.pack.version)


@dataclass(frozen=True)
class RefusedPack:
    path: str
    reason: str


@dataclass
class Packs:
    loaded: list[LoadedPack] = field(default_factory=list)
    refused: list[RefusedPack] = field(default_factory=list)

    def rules(self) -> list[tuple[LoadedPack, D.Rule]]:
        return [(lp, r) for lp in self.loaded for r in lp.pack.rules]

    def rule(self, rule_id: str) -> tuple[LoadedPack, D.Rule] | None:
        rid = str(rule_id or "").upper()
        for lp in self.loaded:
            r = lp.pack.by_id.get(rid)
            if r is not None:
                return lp, r
        return None


def _shipped_files(name: "re.Pattern[str]" = _SHIPPED_NAME) -> list[tuple[int, Any]]:
    out = []
    for entry in resources.files("kratos.detect").joinpath("packs").iterdir():
        m = name.match(entry.name)
        if m:
            out.append((int(m.group(1)), entry))
    return sorted(out, key=lambda t: t[0])


@lru_cache(maxsize=1)
def shipped() -> LoadedPack:
    """The shipped Sigma pack (highest version). Raises if it is missing or invalid --
    a broken install, not something to work around."""
    files = _shipped_files()
    if not files:
        raise FileNotFoundError("no shipped detection rule pack (kratos/detect/packs/sigma-linux-*.json)")
    _version, entry = files[-1]
    data = D.parse_pack_bytes(entry.read_bytes())
    return LoadedPack(pack=D.Pack(data), origin="shipped", path=str(entry))


@lru_cache(maxsize=1)
def kratos_pack() -> LoadedPack | None:
    """Kratos's own shipped pack (highest version), or None if this install has none."""
    files = _shipped_files(_KRATOS_NAME)
    if not files:
        return None
    _version, entry = files[-1]
    data = D.parse_pack_bytes(entry.read_bytes())
    return LoadedPack(pack=D.Pack(data), origin="shipped", path=str(entry))


def shipped_all() -> list[LoadedPack]:
    """Every shipped pack: the Sigma pack, then Kratos's own."""
    own = kratos_pack()
    return [shipped()] + ([own] if own is not None else [])


def imported_dir(data_dir: Path | str) -> Path:
    return Path(data_dir) / IMPORTED_DIR


def load(data_dir: Path | str | None) -> Packs:
    """The shipped pack and every valid imported pack. An imported pack that fails
    validation, or reuses a rule id another pack already has, is refused whole."""
    out = Packs(loaded=shipped_all())
    if data_dir is None:
        return out
    folder = imported_dir(data_dir)
    try:
        files = sorted(p for p in folder.glob("*.json") if p.is_file())
    except OSError:
        files = []
    seen = {r.id for lp in out.loaded for r in lp.pack.rules}
    ids = {lp.pack_id for lp in out.loaded}
    for path in files:
        try:
            data = D.parse_pack_bytes(path.read_bytes())
        except (OSError, D.PackError) as e:
            out.refused.append(RefusedPack(str(path), str(e)))
            continue
        pack = D.Pack(data)
        if pack.pack_id in ids:
            out.refused.append(RefusedPack(str(path), f"its pack id {pack.pack_id} is already in use"))
            continue
        clash = sorted({r.id for r in pack.rules} & seen)
        if clash:
            out.refused.append(RefusedPack(str(path), f"rule id(s) already in another pack: {', '.join(clash[:5])}"))
            continue
        ids.add(pack.pack_id)
        seen |= {r.id for r in pack.rules}
        out.loaded.append(LoadedPack(pack=pack, origin="imported", path=str(path)))
    return out


def rule_meta(rule_id: str, data_dir: Path | str | None = None) -> dict[str, Any] | None:
    """A rule's JSON (title, author, source, attack, ...) from the shipped pack, else an
    imported one."""
    found = load(data_dir).rule(rule_id)
    return found[1].meta if found else None


def skipped(pack: LoadedPack) -> list[dict[str, Any]]:
    return list(pack.pack.raw.get("skipped") or [])


def write_imported(data_dir: Path | str, pack: dict[str, Any]) -> Path:
    """Save a compiled pack under the data folder (validated first; atomic replace)."""
    from kratos import paths

    D.validate_pack(pack)
    folder = imported_dir(data_dir)
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / f"{pack['pack_id']}.json"
    paths.write_private_text(dest, json.dumps(pack, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    return dest
