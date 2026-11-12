"""Web-shell and malware YARA rules over a confirmed code root (E.7a §3.9, CODE-005).

The same bounded scan `run_yara_scan` does (kratos.adapters.ssh_remote.fetch_yara_scan):
through the sub-agent with the rules on its own box (its scan scope and credential-path
rules apply), or over SSH with the bundled rules (the `yara` binary must be installed on the
machine). Only matches come back (rule, file) -- never the scanned files' contents."""
from __future__ import annotations

from typing import Any, Callable

Scanner = Callable[[str], Any]


def _default(root: str) -> Any:
    from kratos.adapters.ssh_remote import fetch_yara_scan
    from kratos.agent.tools import _load_yara_rules_content

    loaded = _load_yara_rules_content(None)
    if loaded is None:
        return "no bundled YARA rules"
    return fetch_yara_scan(root, loaded[0])


def scan(root: str, scanner: Scanner | None = None) -> tuple[list[dict[str, str]], str]:
    """([{rel, rule}], why the scan didn't run or was partial -- empty when it ran)."""
    try:
        res = (scanner or _default)(root)
    except Exception as e:  # noqa: BLE001 -- a scan failure is a coverage note, never a crash
        return [], f"YARA could not run ({type(e).__name__})"
    if isinstance(res, str):
        return [], res
    if not isinstance(res, list):
        err = " ".join(str(getattr(res, "stderr", "") or "the scan failed").split())[:200]
        if "not found" in err and "yara" in err.lower() or "command not found" in err:
            err = "the yara program is not installed on the machine (install it, or read the machine through its " \
                  "sub-agent)"
        return [], f"YARA not run: {err}"
    out: list[dict[str, str]] = []
    base = root.rstrip("/") + "/"
    for m in res:
        f = str(m.get("file") or m.get("path") or "") if isinstance(m, dict) else ""
        if f.startswith(base):
            out.append({"rel": f[len(base):], "rule": str(m.get("rule") or "")[:120]})
    return out, ""
