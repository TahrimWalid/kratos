"""Every writer of an evidence file records it in the evidence ledger (D.6 §3.1).

The source scan: a module that writes into an evidence folder (it joins an evidence
folder onto the data folder, holds one in a folder constant, or reserves a stamped file)
must call ``evidence.record`` in every function that writes a file -- or the function is
listed below with the reason it writes no evidence. The runtime twin is
``ledger.unrecorded_files`` (``kratos evidence verify``): evidence files with no row.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from kratos.evidence.ledger import EVIDENCE_FOLDERS

SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"
TOP = {f.split("/")[0] for f in EVIDENCE_FOLDERS} | {"results"}

# module:function -> why it writes a file but no evidence (or records it elsewhere)
NOT_EVIDENCE = {
    "pkgvuln/record.py:_write": "a helper; its one caller (_judge) records the file right after",
    "compliance/record.py:_write": "a helper; its caller (run) records each file right after",
    "adapters/vuln_scan.py:_download": "downloads NVD feeds into the vulscan folder, not evidence",
    "adapters/vuln_scan.py:build_cve_csv_from_nvd": "writes the CVE list (vulscan's data), not evidence",
    "adapters/vuln_scan.py:_install_script_files": "installs vulscan's script files, not evidence",
    "trace/recorder.py:_write": "writes the run record and its .partial; finish()/rewrite() record the final file",
    "agent/self_write.py:*": "writes candidate tools into the sandbox staging folder, not evidence",
    "agent/self_write_loop.py:*": "writes kept tools and their metadata, not evidence",
    "cli/app.py:*": "writes the settings file, installer scripts and ATT&CK layers the person asked for -- none "
                    "into an evidence folder",
    "tui_mk2/screens/session.py:*": "writes session transcripts (the sessions folder), not evidence",
    "signing/__init__.py:*": "writes the signing key, not evidence",
    "export/bundle.py:*": "writes the export bundle itself; export/create.py records its manifest",
    "export/archive.py:*": "writes the bundle's .tar.gz; its hash is printed and in the export record",
    "review/sarif.py:write_sarif": "writes a SARIF file to a path the person chose (an export for "
                                   "their own SAST tooling), not an evidence-folder artifact; the review's "
                                   "own snapshot is recorded by review/judge.py:write_snapshot",
}

WRITE_ATTRS = {"write_text", "write_bytes", "write_private_text", "dump"}


def _consts(tree: ast.Module) -> dict[str, str]:
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = node.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out[node.targets[0].id] = v.value
            elif isinstance(v, (ast.Call, ast.BinOp)):
                lits = [n.value for n in ast.walk(v) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
                if lits:
                    out[node.targets[0].id] = "/".join(lits)
    return out


def _is_evidence_writer_module(tree: ast.Module, text: str) -> bool:
    if re.search(r"\breserve\(", text):
        return True
    consts = _consts(tree)
    for name, v in consts.items():
        if re.fullmatch(r"_?[A-Z_]*(DIR|FOLDER)", name) and v.split("/")[0] in TOP:
            return True
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left = ast.unparse(node.left)
            right = node.right
            if "data_dir" in left and isinstance(right, ast.Constant) and isinstance(right.value, str) \
                    and right.value.split("/")[0] in TOP:
                return True
    return False


def _own_calls(fn: ast.AST):
    """The calls in a function's own body (calls inside nested functions belong to them)."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call):
            yield n
        stack.extend(ast.iter_child_nodes(n))


def _mode_arg(node: ast.Call) -> str:
    for a in list(node.args[1:]) + [k.value for k in node.keywords if k.arg == "mode"]:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    return ""


def _is_write(node: ast.Call) -> bool:
    f = node.func
    if isinstance(f, ast.Attribute):
        if f.attr in WRITE_ATTRS or f.attr == "reserve":
            return True
        if f.attr == "replace" and (ast.unparse(f.value) == "os" or "tmp" in ast.unparse(f.value)):
            return True
        if f.attr in ("open", "fdopen") and _mode_arg(node)[:1] in ("w", "a", "x"):
            return True
        if f.attr == "open" and not node.args and any(k.arg == "mode" for k in node.keywords):
            return _mode_arg(node)[:1] in ("w", "a", "x")
    elif isinstance(f, ast.Name):
        if f.id in ("write_private_text", "reserve"):
            return True
        if f.id == "open" and _mode_arg(node)[:1] in ("w", "a", "x"):
            return True
    return False


def _writes(fn: ast.AST) -> bool:
    return any(_is_write(c) for c in _own_calls(fn))


def _records(fn: ast.AST) -> bool:
    for node in _own_calls(fn):
        s = ast.unparse(node.func)
        if s.endswith("evidence.record") or s.endswith("_record_evidence"):
            return True
    return False


def offenders() -> list[str]:
    out = []
    for p in sorted(SRC.rglob("*.py")):
        rel = str(p.relative_to(SRC))
        if rel.startswith("evidence/"):
            continue
        text = p.read_text(encoding="utf-8")
        tree = ast.parse(text)
        if not _is_evidence_writer_module(tree, text) or f"{rel}:*" in NOT_EVIDENCE:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _writes(node) \
                    and not _records(node) and f"{rel}:{node.name}" not in NOT_EVIDENCE:
                out.append(f"{rel}:{node.name}")
    return out


def test_every_evidence_writer_records_into_the_ledger():
    bad = offenders()
    assert not bad, (
        "functions that write a file in a module that writes evidence, without evidence.record(...) -- record "
        "the file after it is complete, or add the function to NOT_EVIDENCE with the reason: " + ", ".join(bad))


def test_the_scan_sees_the_real_writers():
    """The scan is not vacuous: it finds the writers it must, and flags a writer whose
    record call is removed."""
    text = (SRC / "persist/record.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert _is_evidence_writer_module(tree, text)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "run")
    assert _writes(fn) and _records(fn)
    stripped = ast.parse(text.replace("_evidence.record(", "_evidence_not_recorded("))
    fn2 = next(n for n in ast.walk(stripped) if isinstance(n, ast.FunctionDef) and n.name == "run")
    assert _writes(fn2) and not _records(fn2)
    for mod in ("adapters/nmap_scan.py", "adapters/findings_engine.py", "detect/findings.py", "hunt/auto.py",
                "containers/record.py", "agent/tools.py"):
        t = (SRC / mod).read_text(encoding="utf-8")
        assert _is_evidence_writer_module(ast.parse(t), t), mod


def test_not_evidence_entries_are_real():
    for key in NOT_EVIDENCE:
        mod, _, fn = key.partition(":")
        p = SRC / mod
        if not p.exists():
            # export modules are added in a later step of D.6; listed ahead on purpose
            assert mod.startswith("export/"), key
            continue
        if fn != "*":
            tree = ast.parse(p.read_text(encoding="utf-8"))
            assert any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn
                       for n in ast.walk(tree)), key
