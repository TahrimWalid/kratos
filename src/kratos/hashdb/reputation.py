"""One reputation per file, decided by code from local data (E.4 §3.1, §3.4).

Order, first match wins:

1. ``known_bad`` -- its SHA-256 is in the MalwareBazaar set. Beats everything: a package
   can ship a trojaned file after a supply-chain compromise, so a known-bad file owned by
   a package is still known-bad (with "owned by package X" beside it).
2. ``package_modified`` -- a package owns the path, but the content differs from the
   checksum the package recorded (or A.1's package verification said so).
3. ``package`` -- a package owns it and its content matches the package's checksum.
4. ``known_good`` -- its SHA-1 is in CIRCL hashlookup's filter: "probably known-good".
5. ``unknown`` -- none of the above.

``not_checked`` only when the file couldn't be read (or a needed set is missing) AND
nothing else matched -- a hash the snapshot saw can still make it known-bad.

A reputation is an ANNOTATION. It never lowers any finding (README §1 rule 6): a
known-good `bash` copied setuid into /tmp is the classic backdoor. The only thing it may
suppress is E.4's own HASH-002 (not raised for package / package_modified / known_good,
and not for any file a package owns).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from kratos.adapters.file_facts import apk_q1_to_hex

VERDICTS = ("known_bad", "package_modified", "package", "known_good", "unknown", "not_checked")
LABELS = {
    "known_bad": "known-bad (MalwareBazaar)",
    "package_modified": "changed since its package installed it",
    "package": "from an installed package, unchanged",
    "known_good": "probably known-good (CIRCL set, Bloom filter)",
    "unknown": "unknown",
    "not_checked": "not checked",
}
# Why a file wasn't read, in plain words, with the fix.
REASONS = {
    "missing": ("the file is gone", "nothing to do unless it comes back"),
    "link": ("it is a link (links are not followed)", "the link's target is looked up when it is itself a candidate"),
    "hardlink": ("it is hard-linked (a hard link can point a root reader at another file)",
                 "run the full audit so the package manager verifies its own files"),
    "not_regular": ("it is not a regular file", ""),
    "not_program": ("it is not a program or library", ""),
    "unreadable_ssh": ("only root can read this", "read this machine through its sub-agent (it reads as root)"),
    "unreadable": ("it could not be read", ""),
    "too_large": ("it is too large for this check's byte budget", "raise hashdb.max_run_mb or hashdb.max_file_mb"),
    "time": ("the check's time budget ran out", "raise hashdb.seconds"),
    "refused": ("it is in a credential location, which Kratos never reads", ""),
    "changed": ("it changed while it was being read", "it is read again next time"),
    "not_listed": ("the sub-agent hasn't listed this file in its own reads yet",
                   "it will after its next persistence and running-process reads"),
    "over_cap": ("more candidates than one check looks at", "raise hashdb.max_files"),
    "name": ("its name has bytes that aren't text, so Kratos can't name it exactly", ""),
    "proc_ssh": ("it is the running image of another user's process, which only root can read",
                 "read this machine through its sub-agent (it reads as root)"),
    "read_failed": ("the file read failed", ""),
    "old_agent": ("this machine's sub-agent is too old for this read", "update the agent (`g` in /subagent)"),
}


class KnownBad(Protocol):
    def get(self, sha256: str) -> dict[str, str] | None: ...


class KnownGood(Protocol):
    def __contains__(self, sha1: str) -> bool: ...


@dataclass
class Reputation:
    verdict: str
    sources: list[dict[str, Any]] = field(default_factory=list)   # [{source, detail, date}]
    reason: str = ""            # not_checked: the REASONS key
    note: str = ""              # plain words shown beside the verdict
    package: str | None = None
    known_bad: dict[str, str] | None = None
    packed: bool = False
    high_entropy: bool = False

    @property
    def label(self) -> str:
        return LABELS.get(self.verdict, self.verdict)

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "label": self.label, "sources": list(self.sources), "reason": self.reason,
                "note": self.note, "package": self.package, "known_bad": dict(self.known_bad or {}) or None,
                "packed": self.packed, "high_entropy": self.high_entropy}


def _digest_matches(fact: dict[str, Any], digests: list[dict[str, str]]) -> bool | None:
    """True/False when a package checksum could be compared, None when none could."""
    for d in digests or []:
        algo, value = d.get("algo"), str(d.get("digest") or "").lower()
        ours = None
        if algo == "md5":
            ours = fact.get("md5")
        elif algo == "sha1":
            ours = fact.get("sha1")
        elif algo == "sha256":
            ours = fact.get("sha256")
        elif algo == "apk-q1":
            value = apk_q1_to_hex(str(d.get("digest") or "")) or ""
            ours = fact.get("sha1")
        if ours and value:
            return ours == value
    return None


def decide(fact: dict[str, Any] | None, cand: dict[str, Any], *, known_bad: KnownBad | None,
           known_good: KnownGood | None, entropy_threshold: float, mb_date: str = "", circl_date: str = "",
           not_read: str = "") -> Reputation:
    """The reputation of one candidate from its read (`fact`, None when it wasn't read --
    then `not_read` names the REASONS key) and the local sets (None when not installed)."""
    fact = fact or {}
    ok = fact.get("status") == "ok"
    sha256 = fact.get("sha256") if ok else None
    pkg = fact.get("package") or cand.get("package")
    # 1. known-bad -- on the hash read now, else the hash the snapshot saw
    for h, when in ((sha256, "read now"), (None if sha256 else cand.get("sha256"), "seen by the snapshot")):
        if h and known_bad is not None:
            hit = known_bad.get(h)
            if hit is not None:
                src = {"source": "malwarebazaar", "detail": hit.get("signature") or "", "date": mb_date}
                note = "" if when == "read now" else "hash from the earlier read; the file could not be read again now"
                if pkg:
                    note = (note + "; " if note else "") + (f"owned by package {pkg} -- the package itself may be "
                                                            "compromised; reinstall it from the distribution")
                return Reputation("known_bad", [src], note=note, package=pkg, known_bad=hit)
    if not ok:
        reason = not_read or {"unreadable": "unreadable"}.get(str(fact.get("status") or ""), str(fact.get("status") or
                                                                                                "read_failed"))
        if pkg and cand.get("package_verify") == "changed":
            return Reputation("package_modified", [{"source": "package_verify", "detail": "the package manager's "
                                                    "own check", "date": ""}], package=pkg,
                              note="the package manager says it differs from what it installed")
        if pkg and reason == "hardlink" and cand.get("package_verify") == "unchanged":
            return Reputation("package", [{"source": "package_verify", "detail": "the package manager's own check",
                                           "date": ""}], package=pkg, note="hard-linked, so checked by the package "
                                                                          "manager instead of read")
        return Reputation("not_checked", reason=reason, package=pkg)
    # 2./3. package checksum
    if fact.get("package"):
        match = _digest_matches(fact, fact.get("pkg_digests") or [])
        if match is False or (match is None and cand.get("package_verify") == "changed"):
            return Reputation("package_modified", [{"source": "package", "detail": fact["package"], "date": ""}],
                              package=fact["package"], note="differs from the checksum its package recorded")
        if match is True:
            return Reputation("package", [{"source": "package", "detail": fact["package"], "date": ""}],
                              package=fact["package"])
    # 4. known-good
    packed = bool(fact.get("packers"))
    ent = fact.get("entropy")
    high = isinstance(ent, (int, float)) and ent >= entropy_threshold
    if known_good is not None and fact.get("sha1") and fact["sha1"] in known_good:
        return Reputation("known_good", [{"source": "circl", "detail": "hashlookup Bloom filter", "date": circl_date}],
                          package=pkg, packed=packed, high_entropy=high,
                          note="probably known-good (CIRCL set, Bloom filter) -- a known program in an unusual place "
                               "or with unusual permissions is still a risk")
    # 5. unknown
    sets = []
    if known_good is None:
        sets.append("no known-good set")
    if known_bad is None:
        sets.append("no known-bad set")
    note = f"({' / '.join(sets)})" if sets else ""
    if fact.get("package"):
        note = (f"owned by package {fact['package']}, but its checksum couldn't be compared" +
                (f" {note}" if note else ""))
    return Reputation("unknown", package=pkg, packed=packed, high_entropy=high, note=note)


def short_tag(rep: dict[str, Any]) -> str:
    """The few words the model's digest and lists show ("known-bad (MalwareBazaar)",
    "unknown, packed")."""
    v = str(rep.get("verdict") or "")
    if v == "unknown":
        bits = ["unknown"] + (["packed"] if rep.get("packed") else []) + (["high entropy"] if rep.get("high_entropy")
                                                                            else [])
        return ", ".join(bits)
    if v == "known_good":
        return "probably known-good (CIRCL)"
    return LABELS.get(v, v)
