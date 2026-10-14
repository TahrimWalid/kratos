"""Judging the persistence inventory -- on Kratos, never on the machine (A.1 §3.2).

Input: one parsed inventory (kratos.adapters.persistence.parse_output) and the
baseline (Kratos's first look). Output: `Signal`s -- what a PERSIST-* finding
will say, already plain-worded and already masked, serialised into the snapshot
the rule engine reads. Nothing here runs a command or reaches a machine.

The three filters, in order of how much noise they remove:

1. **owned by an installed package** -- the main one. An item a package owns, or
   a symlink whose target a package owns (that is what "enabled" looks like for
   a systemd unit), is not reported as new. If the package database could not be
   read at all, Kratos says so and does NOT claim anything is unowned.
2. **in the baseline** -- an item Kratos already saw on its first look is not
   new. A changed item is a new identity (`path#sha256[:12]`), so it reopens a
   decision; an unchanged one keeps it.
3. **shape** -- a closed list of patterns (`shapes.py`) that say "worth a look",
   never a verdict.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from kratos.adapters.persistence import AREA_LABELS, usrmerge_alternates
from kratos.events import redact
from kratos.logsources import attack
from kratos.persist import shapes
from kratos.persist.baseline import Baseline, fingerprint_of, key_identity

MAX_ITEMS_SHOWN = 12            # items named in one finding's evidence
MAX_LINES_PER_ITEM = 4          # excerpt lines shown per item
MAX_EVIDENCE_LINES = 60

AGENT_FIX = "Read this machine through its sub-agent (it reads as root), or run the check as root."

# Which ATT&CK technique an item's area stands for. Set/verified against the
# official v19 data (tests/fixtures/attack_v19_subset.json).
_AREA_ATTACK: dict[str, dict[str, str]] = {
    "cron": attack.CRON, "at": attack.AT, "systemd": attack.SYSTEMD_SERVICE, "ssh": attack.SSH_KEYS,
    "suid": attack.SETUID, "preload": attack.DYNAMIC_LINKER, "kernel": attack.KERNEL_MODULES,
    "shell": attack.SHELL_CONFIG, "pam": attack.PAM, "boot": attack.RC_SCRIPTS, "udev": attack.UDEV,
    "pkg_hooks": attack.INSTALLER_PACKAGES, "misc": attack.EVENT_TRIGGERED,
}
_MASKED_LINK = "/dev/null"
# Kernel taint bits that mean a module was loaded from outside the distribution.
TAINT_BITS: dict[int, str] = {
    0: "a proprietary module is loaded",
    1: "a module was force-loaded",
    6: "a module was force-unloaded by a user",
    12: "an out-of-tree module is loaded",
    13: "an unsigned module is loaded",
}
_SO_RE = re.compile(r"(?<![\w.-])(/\S*\.so(?:\.\d+)*)")
_PAM_EXEC_ARG_RE = re.compile(r"(?<![\w.-])(/\S+)")


@dataclass(frozen=True)
class Signal:
    rule: str
    severity: str
    title: str
    evidence: list[str] = field(default_factory=list)
    recommendation: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    attack: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "title": self.title, "evidence": list(self.evidence),
                "recommendation": list(self.recommendation), "entities": list(self.entities),
                "attack": [dict(a) for a in self.attack]}


def _mask(text: Any) -> str:
    """Credential values out of an excerpt before it is stored or shown."""
    out, _changed = redact.mask(str(text or ""))
    return out


def entity_of(path: str, item: dict[str, Any]) -> str:
    """`path#sha256[:12]` -- a changed item is a new entity (A.1 §3.5)."""
    fp = fingerprint_of(item)
    kind, _, value = fp.partition(":")
    if kind == "sha256":
        return f"{path}#{value[:12]}"
    if kind == "link":
        return f"{path}#->{value}"
    if kind == "lines":
        return f"{path}#{value[:12]}"
    return path


def _area_label(area: str) -> str:
    return AREA_LABELS.get(area, area)


def _attack_for(areas: Iterable[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for area in sorted(set(areas)):
        label = _AREA_ATTACK.get(area)
        if label is not None and label not in out:
            out.append(dict(label))
    return out


class Judgement:
    """One inventory, judged. `signals` is what the snapshot stores."""

    def __init__(self, inv: dict[str, Any], base: Baseline | None, *, areas_known: tuple[str, ...]):
        self.inv = inv
        self.base = base
        self.items: dict[str, dict[str, Any]] = dict(inv.get("items") or {})
        self.ownership_known = bool((inv.get("ownership") or {}).get("source")) and not (inv.get("ownership") or {}).get("error")
        self.new_areas = tuple(a for a in areas_known if base is not None and not base.covers_area(a))
        self.first_look_paths: list[str] = []      # items the baseline could not have seen
        self.gaps: list[str] = []
        self.signals: list[Signal] = []
        self._owner_cache: dict[str, str | None] = {}

    # ---------------------------------------------------------------- ownership
    def _package_of(self, path: str) -> str | None:
        it = self.items.get(path)
        if it is not None and it.get("package"):
            return str(it["package"])
        ref = (self.inv.get("refs") or {}).get(path)
        if ref:
            return str(ref)
        for alt in usrmerge_alternates(path):
            alt_item = self.items.get(alt)
            if alt_item is not None and alt_item.get("package"):
                return str(alt_item["package"])
            alt_ref = (self.inv.get("refs") or {}).get(alt)
            if alt_ref:
                return str(alt_ref)
        return None

    def owner(self, path: str) -> str | None:
        """The package that owns `path`, following a symlink to its target (an
        enabled systemd unit is a symlink to the package's own unit file)."""
        if path in self._owner_cache:
            return self._owner_cache[path]
        self._owner_cache[path] = None          # guard against a symlink loop
        pkg = self._package_of(path)
        if pkg is None:
            it = self.items.get(path) or {}
            link = str(it.get("link") or "")
            if link:
                target = link if link.startswith("/") else os.path.normpath(os.path.join(os.path.dirname(path), link))
                pkg = self._package_of(target) or (self.owner(target) if target != path else None)
        self._owner_cache[path] = pkg
        return pkg

    def masked(self, path: str) -> bool:
        """A unit masked with `systemctl mask` is a link to /dev/null: not persistence."""
        return str((self.items.get(path) or {}).get("link") or "") == _MASKED_LINK

    # ---------------------------------------------------------------- newness
    def is_new(self, path: str, item: dict[str, Any]) -> tuple[bool, str]:
        """(new?, how) against the baseline. Items in an area the baseline never
        covered, or under a location it could not read, are a first look."""
        if self.base is None:
            return False, "first look"
        area = str(item.get("area") or "")
        if area in self.new_areas or self.base.under_a_gap(path):
            self.first_look_paths.append(path)
            return False, "first look at this location"
        known = self.base.items.get(path)
        if known is None:
            return True, "added"
        return (True, "changed") if known != fingerprint_of(item) else (False, "unchanged")

    # ---------------------------------------------------------------- lines
    def shaped_lines(self, item: dict[str, Any]) -> list[tuple[str, list[str]]]:
        """[(line, shape names)] for the lines of one item that have a shape."""
        out = []
        for line in item.get("lines") or []:
            names = [s.name for s in shapes.match(str(line.get("text") or ""))]
            if names:
                out.append((_mask(line.get("text")), names))
        return out

    def _item_line(self, path: str, item: dict[str, Any], note: str = "") -> str:
        bits = [f"{path} ({_area_label(str(item.get('area') or '?'))}"]
        if note:
            bits.append(f", {note}")
        owner, perm = item.get("owner"), item.get("perm")
        if owner:
            bits.append(f", owned by {owner}")
        if perm:
            bits.append(f", mode {perm}")
        if item.get("link"):
            bits.append(f" -> {_mask(item['link'])}")
        bits.append(")")
        return "".join(bits)

    def _excerpt_lines(self, path: str, item: dict[str, Any]) -> list[str]:
        out: list[str] = []
        shaped = self.shaped_lines(item)
        seen: set[str] = set()
        for text, names in shaped[:MAX_LINES_PER_ITEM]:
            out.append(f"    line: {text}")
            for w in shapes.why(names):
                if w not in seen:
                    seen.add(w)
                    out.append(f"    why this is worth a look: {w}")
        if not shaped:
            for line in (item.get("lines") or [])[:MAX_LINES_PER_ITEM]:
                out.append(f"    line: {_mask(line.get('text'))}")
        total = item.get("lines_total")
        if isinstance(total, int) and total > len(item.get("lines") or []):
            out.append(f"    ({total} lines in the file; the rest was not read)")
        return out

    # ---------------------------------------------------------------- the rules
    def _cap(self, lines: list[str]) -> list[str]:
        if len(lines) <= MAX_EVIDENCE_LINES:
            return lines
        return lines[:MAX_EVIDENCE_LINES] + [f"  ... and {len(lines) - MAX_EVIDENCE_LINES} more evidence line(s)"]

    def _say(self, rule: str, severity: str, title: str, lines: list[str], recommendation: list[str],
             entities: list[str], areas: Iterable[str]) -> None:
        self.signals.append(Signal(rule=rule, severity=severity, title=title, evidence=self._cap(lines),
                                   recommendation=recommendation, entities=sorted(set(entities)),
                                   attack=_attack_for(areas)))

    def classify(self) -> dict[str, tuple[dict[str, Any], str]]:
        """Every item that is not owned by a package and not masked: `{path: (item,
        how)}`, where `how` is "added"/"changed" for an item that is new since the
        first look and "" for one that is not. Empty when the package database
        could not be read -- without it Kratos cannot say anything is unowned."""
        out: dict[str, tuple[dict[str, Any], str]] = {}
        if not self.ownership_known:
            return out
        for path, item in self.items.items():
            if self.masked(path) or str(item.get("type") or "").startswith("directory"):
                continue
            if self.owner(path) is not None:
                continue
            new, how = self.is_new(path, item)
            out[path] = (item, how if new else "")
        return out

    def _new_items(self, unowned: dict[str, tuple[dict[str, Any], str]]) -> list[str]:
        """PERSIST-001: a persistence item that is new since the first look and
        belongs to no installed package. Keys, SUID files and the preload file
        have their own rules below."""
        picked: list[tuple[str, dict[str, Any], str]] = []
        for path, (item, how) in sorted(unowned.items()):
            if not how or item.get("suid_bits") or str(item.get("mode") or "") == "keys" or path == "/etc/ld.so.preload":
                continue
            picked.append((path, item, how))
        if not picked:
            return []
        strong = [(p, it) for p, it, _h in picked
                  if any(set(n) & shapes.STRONG for _t, n in self.shaped_lines(it))]
        lines: list[str] = []
        for path, item, how in picked[:MAX_ITEMS_SHOWN]:
            lines.append("  " + self._item_line(path, item, f"{how}, no installed package owns it"))
            lines += self._excerpt_lines(path, item)
        if len(picked) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(picked) - MAX_ITEMS_SHOWN} more")
        areas = {str(it.get("area") or "") for _p, it, _h in picked}
        self._say(
            "PERSIST-001", "high" if strong else "medium",
            f"{len(picked)} place(s) that start programs changed since Kratos first looked"
            + (" -- one of them looks like a backdoor" if strong else ""),
            lines,
            ["Check with whoever administers this machine whether each of these was put there on purpose "
             "(a package install, a configuration-management tool, their own script).",
             "If one was not: keep a copy for evidence, then remove it and look for how it got there "
             "(recent logins, sudo activity, the file's own timestamps).",
             "Accept the finding if they are expected -- Kratos then stops reporting them until they change."],
            [entity_of(p, it) for p, it, _h in picked], areas)
        return [p for p, _it, _h in picked]

    def _shapes_only(self, reported: list[str]) -> None:
        """PERSIST-002: an item whose own lines look like a backdoor, whether or
        not it is new -- "worth a look", never a verdict."""
        hits: list[tuple[str, dict[str, Any], list[tuple[str, list[str]]]]] = []
        for path, item in sorted(self.items.items()):
            if path in reported or self.masked(path):
                continue
            shaped = self.shaped_lines(item)
            if shaped:
                hits.append((path, item, shaped))
        if not hits:
            return
        lines: list[str] = []
        for path, item, shaped in hits[:MAX_ITEMS_SHOWN]:
            owner = self.owner(path)
            lines.append("  " + self._item_line(path, item, f"part of {owner}" if owner else "no package owns it"))
            lines += self._excerpt_lines(path, item)
        if len(hits) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(hits) - MAX_ITEMS_SHOWN} more")
        self._say("PERSIST-002", "low",
                  f"{len(hits)} place(s) that start programs are worth a look",
                  lines,
                  ["Read each line above and decide whether it is something this machine is supposed to do.",
                   "These patterns are also used by normal software, so this is a prompt to look, not a verdict."],
                  [entity_of(p, it) for p, it, _s in hits],
                  {str(it.get("area") or "") for _p, it, _s in hits})

    def _suid(self) -> None:
        """PERSIST-003: a file anyone can run as its owner (SUID/SGID) that no
        installed package ships."""
        if not self.ownership_known:
            return
        hits = [(p, it) for p, it in sorted(self.items.items())
                if it.get("suid_bits") and self.owner(p) is None and not self.masked(p)]
        if not hits:
            return
        lines = []
        for path, item in hits[:MAX_ITEMS_SHOWN]:
            new, how = self.is_new(path, item)
            lines.append("  " + self._item_line(path, item, how if new else "also on the first look"))
            lines += self._excerpt_lines(path, item)
        if len(hits) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(hits) - MAX_ITEMS_SHOWN} more")
        self._say("PERSIST-003", "high",
                  f"{len(hits)} program(s) run with their owner's powers and come from no package",
                  lines,
                  ["A file with the setuid or setgid bit lets any user run it with the file owner's rights -- "
                   "often root. One that no package installed is a common way to keep root access.",
                   "Confirm with the machine's administrator; if it is not expected, keep a copy, then remove the "
                   "setuid bit (`chmod u-s <path>`) and investigate how the file got there."],
                  [entity_of(p, it) for p, it in hits], ["suid"])

    def _paths_in(self, item: dict[str, Any], pattern: re.Pattern[str]) -> list[str]:
        found: list[str] = []
        for line in item.get("lines") or []:
            for m in pattern.finditer(str(line.get("text") or "")):
                if m.group(1) not in found:
                    found.append(m.group(1))
        return found

    def _preload(self) -> None:
        """PERSIST-004: /etc/ld.so.preload is in use, or it names a library no
        package owns. Everything on this machine loads what it lists."""
        item = self.items.get("/etc/ld.so.preload")
        if item is None:
            return
        entries = [str(l.get("text") or "").strip() for l in item.get("lines") or []]
        entries = [e for e in entries if e]
        if not entries:
            return
        lines = ["  /etc/ld.so.preload is not empty -- every program on this machine loads what it lists:"]
        unowned = []
        for entry in entries[:MAX_ITEMS_SHOWN]:
            owner = self.owner(entry) if entry.startswith("/") else None
            if entry.startswith("/") and owner is None and self.ownership_known:
                unowned.append(entry)
            lines.append(f"    {_mask(entry)}" + (f" (part of {owner})" if owner else
                                                  " (no installed package owns it)" if self.ownership_known else ""))
        self._say("PERSIST-004", "high",
                  "Every program on this machine is made to load an extra library",
                  lines,
                  ["/etc/ld.so.preload is almost never used on a normal server. A library listed here runs inside "
                   "every program, which is how a rootkit hides files, processes and logins.",
                   "Treat the machine as possibly compromised until the library is explained: keep a copy of the "
                   "file and the library, check who wrote them and when, and compare with another machine.",
                   "Do not simply delete it before you have a copy -- it is the evidence."],
                  [entity_of("/etc/ld.so.preload", item), *unowned], ["preload"])

    def _kernel(self) -> None:
        """PERSIST-005: the kernel is tainted by a module from outside the
        distribution, or a loaded module no package ships."""
        taint = self.inv.get("taint")
        reasons: list[str] = []
        if isinstance(taint, int) and taint > 0:
            reasons = [why for bit, why in sorted(TAINT_BITS.items()) if taint & (1 << bit)]
        stranger: list[dict[str, Any]] = []
        if self.ownership_known:
            for mod in (self.inv.get("modules") or {}).values():
                if mod.get("path") and not mod.get("package"):
                    stranger.append(mod)
                elif not mod.get("path") and not self.inv.get("module_error"):
                    stranger.append(mod)
        if not reasons and not stranger:
            return
        lines: list[str] = []
        if reasons:
            lines.append(f"  the kernel reports taint {taint}: " + "; ".join(reasons))
        for mod in stranger[:MAX_ITEMS_SHOWN]:
            where = mod.get("path") or "not in this kernel's own module list"
            flag = f", flagged {mod['taint']}" if mod.get("taint") else ""
            lines.append(f"  module '{mod.get('name')}' ({where}{flag}) belongs to no installed package")
        if len(stranger) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(stranger) - MAX_ITEMS_SHOWN} more module(s)")
        entities = [f"{m.get('name')}@{m.get('taint') or '-'}" for m in stranger]
        if reasons:
            entities.append(f"taint:{taint}")
        self._say("PERSIST-005", "medium",
                  "A kernel module from outside this system's packages is loaded",
                  lines,
                  ["A kernel module runs with full control of the machine and can hide anything. Confirm each one "
                   "with the machine's administrator (some are legitimate: drivers, virtualisation, DKMS builds).",
                   "If a module is not expected, treat the machine as possibly compromised and investigate before "
                   "rebooting -- the module list is lost at reboot."],
                  entities, ["kernel"])

    def _keys(self) -> None:
        """PERSIST-006: an SSH key that can log in and was not there on the first
        look, or one whose options make it a backdoor (`command=`, or a root key
        that may be used from anywhere)."""
        keys = [k for k in self.inv.get("keys") or [] if isinstance(k, dict)]
        if not keys:
            return
        known = set(self.base.keys) if self.base is not None else None
        new, risky = [], []
        for k in keys:
            ident = key_identity(k)
            under_gap = self.base is not None and self.base.under_a_gap(str(k.get("path") or ""))
            if known is not None and ident not in known and not under_gap and "ssh" not in self.new_areas:
                new.append(k)
                continue
            opts = str(k.get("options") or "")
            if "command=" in opts.lower() or (str(k.get("user")) == "root" and "from=" not in opts.lower()):
                risky.append(k)

        def describe(k: dict[str, Any]) -> str:
            bits = [f"  {k.get('user') or '?'}: {k.get('type')} {k.get('fingerprint') or 'unreadable key line'}"]
            if k.get("comment"):
                bits.append(f" \"{_mask(k['comment'])}\"")
            bits.append(f" in {k.get('path')} line {k.get('line')}")
            if k.get("options"):
                bits.append(f", options: {_mask(k['options'])}")
            return "".join(bits)

        if new:
            self._say("PERSIST-006", "medium",
                      f"{len(new)} new SSH key(s) can log in to this machine",
                      [describe(k) for k in new[:MAX_ITEMS_SHOWN]]
                      + ([f"  ... and {len(new) - MAX_ITEMS_SHOWN} more"] if len(new) > MAX_ITEMS_SHOWN else []),
                      ["Ask the account's owner whether they added this key. A key added without them knowing is "
                       "how an intruder keeps getting back in, even after a password change.",
                       "If it is not theirs: remove the line from the authorized_keys file shown above and look for "
                       "how it was added (recent logins, sudo activity)."],
                      [key_identity(k) for k in new], ["ssh"])
        if risky:
            self._say("PERSIST-006", "low",
                      f"{len(risky)} SSH key(s) with options worth checking",
                      [describe(k) for k in risky[:MAX_ITEMS_SHOWN]]
                      + ([f"  ... and {len(risky) - MAX_ITEMS_SHOWN} more"] if len(risky) > MAX_ITEMS_SHOWN else []),
                      ["A key with `command=` always runs that one command -- useful for backups, also a quiet way "
                       "back in. A root key with no `from=` can be used from any address.",
                       "Keep the keys you can explain; restrict the rest with `from=` or remove them."],
                      [key_identity(k) for k in risky], ["ssh"])

    def _verify(self) -> None:
        """PERSIST-007: a file an installed package owns, in one of these
        locations, whose CONTENT no longer matches what the package shipped."""
        verify = self.inv.get("verify") or {}
        changed = verify.get("changed") or {}
        if not verify.get("done") or not changed:
            return
        hits = [(p, info) for p, info in sorted(changed.items())
                if p in self.items and info.get("content_changed") and self.owner(p) is not None]
        if not hits:
            return
        config_only = all(info.get("config") for _p, info in hits)
        lines = []
        for path, info in hits[:MAX_ITEMS_SHOWN]:
            item = self.items[path]
            note = "a configuration file its package expects to be edited" if info.get("config") else \
                   "not a configuration file -- its package did not expect this to change"
            lines.append("  " + self._item_line(path, item, f"part of {self.owner(path)}, {note}"))
            lines += self._excerpt_lines(path, item)
        if len(hits) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(hits) - MAX_ITEMS_SHOWN} more")
        lines.append(f"  checked with {verify.get('tool')}")
        self._say("PERSIST-007", "medium" if config_only else "high",
                  f"{len(hits)} file(s) that start programs differ from what their package installed",
                  lines,
                  ["Compare each file with the package's own copy (`apt-get download`/`rpm2cpio`, or another machine "
                   "running the same version) and see what the difference does.",
                   "Local edits are normal in configuration files; a changed program or unit that nobody edited on "
                   "purpose is not -- treat that as possible tampering."],
                  [entity_of(p, self.items[p]) for p, _i in hits],
                  {str(self.items[p].get("area") or "") for p, _i in hits})

    def _pam(self) -> None:
        """PERSIST-008: a PAM module (or a script pam_exec runs) that no installed
        package owns -- PAM decides who may log in."""
        if not self.ownership_known:
            return
        hits: list[tuple[str, str, str]] = []           # (pam file, referenced path, what)
        for path, item in sorted(self.items.items()):
            if str(item.get("area") or "") != "pam" or not item.get("lines"):
                continue
            for line in item.get("lines") or []:
                text = str(line.get("text") or "")
                for mod in _SO_RE.findall(text):
                    if self.owner(mod) is None:
                        hits.append((path, mod, "a login module no package owns"))
                if "pam_exec" in text:
                    for arg in _PAM_EXEC_ARG_RE.findall(text):
                        if arg.endswith(".so"):
                            continue
                        if self.owner(arg) is None:
                            hits.append((path, arg, "a program pam_exec runs at login, owned by no package"))
        if not hits:
            return
        seen: set[tuple[str, str]] = set()
        unique = [(f, p, w) for f, p, w in hits if (f, p) not in seen and not seen.add((f, p))]
        lines = [f"  {f}: {_mask(p)} -- {w}" for f, p, w in unique[:MAX_ITEMS_SHOWN]]
        if len(unique) > MAX_ITEMS_SHOWN:
            lines.append(f"  ... and {len(unique) - MAX_ITEMS_SHOWN} more")
        self._say("PERSIST-008", "high",
                  f"{len(unique)} login (PAM) rule(s) point at software no package installed",
                  lines,
                  ["PAM decides who may log in and what happens when they do. A module or script that no package "
                   "installed can accept a password that was never set, or run anything at every login.",
                   "Keep a copy, confirm with the machine's administrator, and compare /etc/pam.d with another "
                   "machine of the same version."],
                  [f"{f}#{p}" for f, p, _w in unique], ["pam"])

    def _coverage(self) -> list[str]:
        """What this read could not see -- a run note (never decidable)."""
        gaps: list[str] = []
        inv = self.inv
        uid = inv.get("reader_uid")
        root_only = [g for g in inv.get("gaps") or [] if g.get("reason") == "unreadable"]
        if root_only:
            where = ", ".join(sorted({str(g.get("path")) for g in root_only})[:8])
            gaps.append(f"{len(root_only)} location(s) could not be read as this user ({where})"
                        + (f"; the read ran as uid {uid}" if uid else "") + f". {AGENT_FIX}")
        for t in inv.get("truncated") or []:
            gaps.append(f"{t.get('path')} holds {t.get('count')} entries; only the first "
                        f"{'200' if t.get('area') != 'suid' else '500'} were looked at")
        if inv.get("suid_timeouts"):
            gaps.append("the search for setuid programs ran out of time on: "
                        + ", ".join(sorted(set(inv["suid_timeouts"]))[:8]))
        if not self.ownership_known:
            gaps.append("the package database could not be read, so Kratos cannot tell which of these files came "
                        f"from an installed package: {(inv.get('ownership') or {}).get('error') or 'unknown reason'}")
        if inv.get("module_error"):
            gaps.append(str(inv["module_error"]))
        if str(inv.get("container") or "none") != "none":
            gaps.append("this machine shares its kernel with its host (it is a container), so loaded kernel modules "
                        "and the kernel taint flag belong to the host and were not checked here")
        if not inv.get("complete"):
            gaps.append("the read did not finish inside its time budget, so this inventory is partial")
        if inv.get("truncated_output"):
            gaps.append("the read produced more than its output limit, so the end of the inventory is missing")
        for note in inv.get("odd_names") or []:
            gaps.append(f"{note.get('path')} holds a file whose name contains a newline or tab; it was skipped")
        if self.base is None:
            gaps.append("this is Kratos's first look at this machine: everything here is the baseline, so nothing "
                        "can be called new yet")
        elif self.new_areas:
            gaps.append("first look at " + ", ".join(_area_label(a) for a in self.new_areas)
                        + ": items there were added to the baseline, not reported as new")
        self.gaps = gaps
        return gaps

    def run(self) -> None:
        self._coverage()
        unowned = self.classify()
        reported = self._new_items(unowned)
        self._shapes_only(reported)
        self._suid()
        self._preload()
        self._kernel()
        self._keys()
        self._verify()
        self._pam()
        if self.gaps:
            self.signals.append(Signal(
                rule="PERSIST-009", severity="info",
                title="What the persistence check could not see",
                evidence=[f"  {g}" for g in self.gaps],
                recommendation=["A location that was not read is unknown, not clean."]))


def judge(inv: dict[str, Any], base: Baseline | None, *, areas_known: tuple[str, ...]) -> Judgement:
    """Judge one inventory against the baseline. Nothing is written anywhere."""
    j = Judgement(inv, base, areas_known=areas_known)
    j.run()
    return j
