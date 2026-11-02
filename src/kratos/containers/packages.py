"""Known vulnerabilities in the packages inside RUNNING containers (D.5 §3.5).

Through the machine's sub-agent only: for each distinct running image (at most
``containers.MAX_IMAGES`` per collection), the agent reads its package database through
``/proc/<pid>/root`` of one of its processes, never following a link out of that root,
and prints the host read's own records. Kratos stores each image's list in
``pkg_inventory`` (scope ``image:<id>``, deduplicated by content hash) and matches it
offline exactly like a machine's (``pkgvuln.record.match_image``). No image is pulled, no
registry is contacted.

Findings: PKG-001 per vulnerable package with the subject ``<image>:<package>`` and one
PKG-002 per image (subject ``<image>``) -- the colon keeps them apart from the machine's
own package findings, whose subjects are plain package names -- with the containers
running the image as entities. An image without a package database (distroless, static)
is "not checked", never "no vulnerabilities". The snapshot is
``data_dir/containers/container_packages_<machine>.json``, one per machine.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from kratos.containers import record as _record
from kratos.target_key import target_key
from kratos.utils.timeutil import epoch_to_utc_iso

PATTERN = "container_packages_*.json"
IMAGE_ORIGIN_NOTE = ("Inside container images Kratos can't tell where each package came from (most images remove "
                     "apt's package lists), so a package from another vendor's repository (for example nginx.org's "
                     "nginx) is matched against the distribution's advisories")

Reader = Callable[[], Any]


def snapshot_path(data_dir: Path, target: str) -> Path:
    return Path(data_dir) / _record.FOLDER / f"container_packages_{_record.machine_hash(target)}.json"


def image_ref(name: str, image_id: str) -> str:
    """The image as a person names it, always with a tag or digest (so it has a ':' --
    which is what tells an image-scoped package finding from the machine's own)."""
    ref = str(name or "").strip()
    if not ref or ref.startswith("sha256:"):
        return f"image@{image_id[:19]}" if image_id else "image@unknown"
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last and "@" not in last:
        ref += ":latest"
    return ref


def is_image_subject(subject: Any) -> bool:
    """A package finding's subject names a container image (D.5) -- host package names never
    contain ':' (dpkg, rpm and apk names can't)."""
    return ":" in str(subject or "")


def _default_reader(target: str) -> Reader:
    def read() -> Any:
        from kratos import kratos_config
        from kratos.adapters.ssh_remote import fetch_container_packages

        if _record.is_local(target):
            return {"unsupported": "the packages inside containers on Kratos's own machine are only readable as root",
                    "via": "local"}
        with kratos_config.pinned_target(target):
            return fetch_container_packages()
    return read


def _rename(sig: dict[str, Any], ref: str, image: dict[str, Any], digest: str) -> dict[str, Any]:
    names = sorted(str(n) for n in image.get("containers") or [])
    out = dict(sig)
    out["subject"] = f"{ref}:{sig['subject']}" if sig["rule"] == "PKG-001" else ref
    out["title"] = f"In a container image: {sig['title']}"   # the image's name is machine text: subject/evidence only
    out["entities"] = sorted({*(sig.get("entities") or []), *(f"container:{n}" for n in names)})
    ev = list(sig.get("evidence") or [])
    ev.insert(0, f"Inside container image {ref} ({digest[7:19] or 'id unknown'}), run by container(s) "
                 f"{', '.join(names) or '?'} -- read from a running container's own files, not the registry.")
    out["evidence"] = ev
    rec = [r for r in sig.get("recommendation") or [] if "on the machine" not in r and "Restart the services" not in r]
    rec.append(f"Pull or rebuild a newer {ref} and re-create its container(s) (`docker compose pull && docker compose "
               "up -d` for a Compose project, or `docker pull` then re-create). For an image you build, rebuild it "
               "on an updated base image. Kratos does not run this.")
    out["recommendation"] = rec
    out["image"] = image
    out["image_ref"] = ref
    return out


def run(data_dir: Path, target: str, *, reader: Reader | None = None, now: float | None = None) -> dict[str, Any]:
    """Read, store, match, save. A failed read saves nothing ({"status": "error"})."""
    from kratos.pkgvuln import inventory_store
    from kratos.pkgvuln.record import match_image

    data_dir = Path(data_dir)
    when = time.time() if now is None else now
    containers_doc = _record.load(data_dir, target) or {}
    images_seen: dict[str, dict[str, Any]] = containers_doc.get("images") or {}
    dropped_by_image = _dropped(containers_doc)
    result = (reader or _default_reader(target))()
    gaps: list[str] = []
    signals: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    if isinstance(result, dict) and result.get("unsupported"):
        if containers_doc.get("engines_found") is False:
            return _save(data_dir, target, when, signals, [], checked, complete=True, via=str(result.get("via")),
                         note="no container engine found")
        gaps.append(f"packages inside containers: {result['unsupported']} -- read this machine through its sub-agent "
                    "(it reads as root)")
        return _save(data_dir, target, when, _with_note(signals, gaps), gaps, checked, complete=False,
                     via=str(result.get("via")))
    if not isinstance(result, dict):
        text = (getattr(result, "stderr", "") or "").strip()
        return {"status": "error", "target": target, "observation": " ".join(text.split())[:300] or "the read failed"}
    for what, n in (result.get("truncated") or {}).items():
        gaps.append(f"more running images than one collection reads ({n}); the rest were not checked this time")
    gaps += [f"packages inside containers: {g}" for g in result.get("gaps") or []]
    any_matched = False
    for image_id, item in sorted((result.get("images") or {}).items()):
        image = images_seen.get(image_id) or {"image": "", "digest": "", "containers": [], "ports": []}
        ref = image_ref(image.get("image") or "", image_id)
        status = item.get("status")
        row = {"image": ref, "image_id": image_id, "containers": image.get("containers") or [], "status": status}
        inv = item.get("inventory")
        if status == "no_db":
            row["note"] = "no package database (distroless or static image) -- not checked"
            checked.append(row)
            continue
        if status == "old_rpmdb":
            gaps.append(f"image {ref}: old rpm database format (BerkeleyDB), not read")
            row["note"] = "old rpm database format, not read"
            checked.append(row)
            continue
        if status != "ok" or not isinstance(inv, dict):
            gaps.append(f"image {ref}: its package database could not be read ({status})")
            row["note"] = f"not read ({status})"
            checked.append(row)
            continue
        inv["via"] = result.get("via") or "subagent"
        from kratos.pkgvuln import ecosystems as _eco

        choice = _eco.for_os(inv.get("os") or {})
        stored = inventory_store.save(data_dir, target, inv, family=str(_family_of(inv)),
                                      selector=choice.selector.key if choice.selector else None, now=when,
                                      read={"complete": bool(inv.get("complete")), "image": ref},
                                      scope=inventory_store.image_scope(image_id))
        source_line = (f"Packages read {epoch_to_utc_iso(when)} from a running container of image {ref} "
                       f"({len(inv.get('packages') or [])} installed packages), matched on the Kratos machine")
        m = match_image(data_dir, inv, source_line=source_line)
        any_matched = any_matched or m["matched"]
        gaps += [f"image {ref}: {g}" for g in m["gaps"]]
        row.update({"os": m["os_name"], "packages": m["packages"], "matched": m["matched"],
                    "inventory_id": stored.id,
                    "vulnerable": sum(1 for s in m["signals"] if s["rule"] == "PKG-001")})
        checked.append(row)
        for sig in m["signals"]:
            s = _rename(sig, ref, image, image.get("digest") or image_id)
            s["dropped_ports"] = dropped_by_image.get(image_id, [])
            signals.append(s)
    if any_matched:
        gaps.append(IMAGE_ORIGIN_NOTE)
    complete = bool(result.get("complete")) and not result.get("truncated_output") and not any(
        r.get("status") not in ("ok", "no_db") for r in checked)
    return _save(data_dir, target, when, _with_note(signals, gaps), gaps, checked, complete=complete,
                 via=str(result.get("via") or ""))


def _family_of(inv: dict[str, Any]) -> str:
    managers = inv.get("managers") or {}
    return "deb" if "dpkg" in managers else "rpm" if "rpm" in managers else "apk" if "apk" in managers else ""


def _dropped(doc: dict[str, Any]) -> dict[str, list[list[Any]]]:
    """Per image: published ports the firewall model says the forwarding path drops."""
    by_name: dict[str, list[list[Any]]] = {}
    for p in doc.get("port_checks") or []:
        if (p.get("forward") or {}).get("verdict") == "drop":
            by_name.setdefault(str(p.get("container")), []).append([p.get("host_port"), p.get("proto")])
    out: dict[str, list[list[Any]]] = {}
    for image_id, image in (doc.get("images") or {}).items():
        for n in image.get("containers") or []:
            out.setdefault(image_id, []).extend(by_name.get(str(n), []))
    return out


def _with_note(signals: list[dict[str, Any]], gaps: list[str]) -> list[dict[str, Any]]:
    if not gaps:
        return signals
    return [*signals, {"rule": "CONT-008", "severity": "info", "subject": "",
                       "title": "Part of the check of packages inside containers could not be done",
                       "entities": [], "evidence": [*gaps, "Vulnerabilities in what wasn't checked are unknown, not absent."],
                       "recommendation": ["Read this machine through its sub-agent and keep vulnerability data current "
                                          "(`kratos vulndb-update`)."]}]


def _save(data_dir: Path, target: str, when: float, signals: list[dict[str, Any]], gaps: list[str],
          checked: list[dict[str, Any]], *, complete: bool, via: str, note: str = "") -> dict[str, Any]:
    doc = {"target": target, "checked_at": epoch_to_utc_iso(when), "checked_at_epoch": when, "via": via,
           "complete": complete, "images": checked, "coverage_gaps": gaps, "signals": signals, "note": note,
           "counts": {"images": len(checked), "vulnerable_packages": sum(1 for s in signals if s["rule"] == "PKG-001"),
                      "not_checked": sum(1 for r in checked if r.get("status") != "ok")}}
    path = snapshot_path(data_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    return {**doc, "status": "ok", "file": str(path), "target_key": target_key(target)}


def summary_line(doc: dict[str, Any]) -> str:
    if doc.get("note"):
        return str(doc["note"])
    c = doc.get("counts") or {}
    imgs = int(c.get("images") or 0)
    if not imgs:
        return "no running images read" + ("" if doc.get("complete") else " (see what couldn't be checked)")
    vul = int(c.get("vulnerable_packages") or 0)
    ns = int(c.get("not_checked") or 0)
    parts = [f"{imgs} running image(s) read", f"{vul} vulnerable package(s)" if vul else "no fixable known vulnerability"]
    if ns:
        parts.append(f"{ns} image(s) not checked (no package database, or not readable)")
    return "; ".join(parts)
