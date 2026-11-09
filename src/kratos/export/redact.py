"""The redacted variant: every text in the bundle passes through B.2's masker with ONE
placeholder map for the whole export (scope ``export:<id>``), so the same account is
``USER_1_xxxx`` in every file. Secrets are always ``[REDACTED]``.

Strict mode: an image's default login (``ubuntu``) and names an attacker only tried are
replaced too. A bundle that spans several machines has no one "machine under
investigation", so every machine's own names and addresses are known values of the same
kind (``HOST_n`` / ``PRIVATE_IP_n``), never the single-machine ``TARGET`` label -- two
machines would otherwise share one label.

The map stays in this Kratos's database (``pseudonym_map``) and is never written into the
bundle: whoever holds the full data can tie a placeholder back, a bundle holder can't.
File names in the bundle are neutral (``0003_persistence.json``) -- the original names
carry machine addresses.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any


class Redactor:
    """Identity for the full variant."""

    active = False
    mode = "off"

    def text(self, s: str) -> str:
        return s

    def machine(self, m: str) -> str:
        return m

    def stats(self) -> dict[str, Any]:
        return {}


class BundleRedactor(Redactor):
    active = True
    mode = "strict"

    def __init__(self, data_dir: Path, export_id: str, machines: list[str]):
        from kratos.privacy.mask import export_masker
        from kratos.privacy.values import KnownValues, gather

        known = KnownValues()
        for m in machines:
            try:
                kv = gather(m, data_dir)
            except Exception:  # noqa: BLE001 -- masking still runs on what the text shows
                kv = KnownValues()
            known.merge(kv)
        # A bundle leaves the team: every name seen in these machines' logs is replaced as a whole
        # word too (the model-facing masker replaces those only where they appear as a name).
        for name in known.seen_names | known.nonexistent:
            known.accounts.setdefault(name, None)
        # every machine's own names and addresses: plain known values, never "the target"
        known.hosts |= known.target_names | {m for m in machines if not _is_ip(m)}
        known.target_names = set()
        known.target_ips = set()
        self._masker = export_masker(export_id=export_id, data_dir=data_dir, values=known)
        self._kinds: Counter[str] = Counter()
        self._secrets = 0
        self._machine_labels: dict[str, str] = {}

    @property
    def tag(self) -> str:
        return self._masker.tag

    def text(self, s: str) -> str:
        if not s:
            return s
        out = self._masker.mask(s)
        self._secrets += max(0, out.count("[REDACTED]") - s.count("[REDACTED]"))
        for label in _labels(out, self.tag):
            self._kinds[re.sub(rf"(?:_\d+)?_{re.escape(self.tag)}$", "", label)] += 1
        return out

    def machine(self, m: str) -> str:
        if m not in self._machine_labels:
            masked = self.text(m)
            if masked == m:       # loopback and other non-identifying names stay readable
                masked = m if m == "loopback" else f"MACHINE_{len(self._machine_labels) + 1}_{self.tag}"
            self._machine_labels[m] = masked
        return self._machine_labels[m]

    def stats(self) -> dict[str, Any]:
        return {"mode": "strict", "placeholder_tag": self.tag,
                "replaced_kinds": dict(sorted(self._kinds.items())),
                "secrets_redacted": self._secrets}


def _is_ip(s: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _labels(text: str, tag: str):
    if not tag:
        return []
    return re.findall(rf"\b[A-Z][A-Z_]*?(?:_\d+)?_{re.escape(tag)}\b", text)


def redactor_for(variant: str, data_dir: Path, export_id: str, machines: list[str]) -> Redactor:
    return BundleRedactor(data_dir, export_id, machines) if variant == "redacted" else Redactor()
