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

    def __init__(self, data_dir: Path, export_id: str, machines: list[str], *, people: tuple[str, ...] = ()):
        from kratos.privacy.mask import export_masker
        from kratos.privacy.values import KnownValues, gather

        known = KnownValues()
        for m in machines:
            try:
                kv = gather(m, data_dir)
            except Exception:  # noqa: BLE001 -- masking still runs on what the text shows
                kv = KnownValues()
            known.merge(kv)
        # The person exporting and this computer's own login are personal data too: the manifest
        # names the exporter, and scanners record their command line (with this login's paths).
        for name in {*people, _this_login()}:
            if name:
                known.accounts.setdefault(name, None)
        # A bundle leaves the team: every name seen in these machines' logs is replaced as a whole
        # word too (the model-facing masker replaces those only where they appear as a name).
        for name in known.seen_names | known.nonexistent:
            known.accounts.setdefault(name, None)
        # every machine's own names and addresses: plain known values, never "the target"
        known.hosts |= known.target_names | {m for m in machines if not _is_ip(m)}
        known.target_names = set()
        known.target_ips = set()
        # Names Kratos knows, also where they are glued to other text by '-', '_' or '/'
        # (a home folder inside a path, a file name): the masker's whole-word pass stops at those.
        from kratos.privacy.vocabulary import fixed_words

        vocab = fixed_words()
        glued = sorted({n for n in (*known.accounts, *known.hosts) if len(n) >= 3 and n.lower() not in vocab},
                       key=len, reverse=True)
        # A name seen in the logs that is also one of Kratos's own words ("admin" -- an attacker
        # tried it): the whole-word pass leaves it alone (it would rewrite Kratos's text), so it
        # is replaced where it IS a value on its own -- a JSON string exactly that name.
        from kratos.privacy.accounts import is_system

        quoted = sorted({n for n in (known.seen_names | known.nonexistent) if n.lower() in vocab and not is_system(n)})
        alt = "|".join(re.escape(n) for n in quoted)
        self._quoted_names = re.compile(r'"(' + alt + r')"') if quoted else None
        # ... and right after "user" in a log line ("Connection closed by invalid user admin <address>")
        self._user_names = re.compile(r"(?i)(?<=\buser[ =])(" + alt + r")\b") if quoted else None
        self._glued_names = (re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in glued) + r")(?![A-Za-z0-9])")
                             if glued else None)
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
        # an address glued to other text (nmap_10.0.0.5_2026...): '_' is a word character, so the
        # masker's word-bounded address pattern skips it
        out = _GLUED_IPV4.sub(lambda m: self._masker.mask(m.group(0)), out)
        if self._glued_names is not None:
            out = self._glued_names.sub(lambda m: self._masker.mask(m.group(0)), out)
        if self._quoted_names is not None:
            out = self._quoted_names.sub(lambda m: '"' + self._label_for_seen(m.group(1)) + '"', out)
            out = self._user_names.sub(lambda m: self._label_for_seen(m.group(1)), out)
        self._secrets += max(0, out.count("[REDACTED]") - s.count("[REDACTED]"))
        for label in _labels(out, self.tag):
            self._kinds[re.sub(rf"(?:_\d+)?_{re.escape(self.tag)}$", "", label)] += 1
        return out

    def _label_for_seen(self, name: str) -> str:
        """The placeholder of a name seen in the logs (the same one its log lines got)."""
        masked = self._masker.mask(f"Invalid user {name} from 192.0.2.1")
        m = re.search(rf"\b([A-Z][A-Z_]*_\d+_{re.escape(self.tag)})\b", masked)
        return m.group(1) if m else name

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


_GLUED_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d])")


def _this_login() -> str:
    import getpass

    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return ""


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


def redactor_for(variant: str, data_dir: Path, export_id: str, machines: list[str], *,
                 people: tuple[str, ...] = ()) -> Redactor:
    return BundleRedactor(data_dir, export_id, machines, people=people) if variant == "redacted" else Redactor()
