"""Where Kratos keeps settings and data (kratos/paths.py), and the pieces that
depend on it: private settings writes, `kratos init`, the vulscan install and
its honest staleness, and run_vuln_scan without a CVE list."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from kratos import paths


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# ---------------------------------------------------------------- layout


def test_this_checkout_keeps_everything_next_to_the_code():
    repo = Path(__file__).resolve().parents[1]
    assert paths.LAYOUT == "checkout"
    assert paths.env_file() == repo / ".env"
    assert paths.default_data_dir() == repo / "data"
    assert paths.kept_tools_dir() == repo / "kept_tools"
    assert paths.sandbox_staging_dir() == repo / "sandbox_staging"
    assert paths.vulscan_dir() == repo / "vulscan"
    assert paths.threat_intel_cache_dir() == repo / "data" / "threat_intel_cache"
    assert paths.harness_dir() == repo / "tests" / "self_write_harnesses"


def test_an_installed_copy_uses_per_user_folders(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_checkout_root", lambda: None)
    monkeypatch.delenv("KRATOS_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    layout, config, state = paths._resolve_layout()
    assert layout == "installed"
    assert config == tmp_path / ".config" / "kratos"
    assert state == tmp_path / ".local" / "share" / "kratos"


def test_xdg_dirs_are_honoured_and_relative_ones_ignored(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_checkout_root", lambda: None)
    monkeypatch.delenv("KRATOS_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", "relative/data")  # the spec says: ignore
    _layout, config, state = paths._resolve_layout()
    assert config == tmp_path / "cfg" / "kratos"
    assert state == tmp_path / ".local" / "share" / "kratos"


def test_kratos_home_puts_settings_and_data_under_one_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("KRATOS_HOME", str(tmp_path / "kh"))
    layout, config, state = paths._resolve_layout()
    assert (layout, config, state) == ("custom", tmp_path / "kh", tmp_path / "kh")


def test_installed_layout_keeps_evolve_harnesses_out_of_the_cwd(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "LAYOUT", "installed")
    monkeypatch.setattr(paths, "STATE_ROOT", tmp_path)
    assert paths.harness_dir() == tmp_path / "evolve_harnesses"


def test_defaults_do_not_depend_on_the_working_directory(monkeypatch, tmp_path):
    before = paths.default_data_dir()
    monkeypatch.chdir(tmp_path)
    from kratos.cli import app

    assert app.DEFAULT_DATA_DIR == before and app.DEFAULT_DATA_DIR.is_absolute()


# ---------------------------------------------------------------- private writes


def test_ensure_private_dir_makes_every_new_level_owner_only(tmp_path):
    target = tmp_path / "a" / "b" / "c"
    paths.ensure_private_dir(target)
    for d in (tmp_path / "a", tmp_path / "a" / "b", target):
        assert _mode(d) == 0o700


def test_ensure_private_dir_leaves_an_existing_folder_alone(tmp_path):
    d = tmp_path / "shared"
    d.mkdir()
    d.chmod(0o755)
    paths.ensure_private_dir(d)
    assert _mode(d) == 0o755


def test_new_settings_file_is_private_and_atomic(tmp_path):
    env = tmp_path / "cfg" / "kratos" / ".env"
    paths.write_private_text(env, "LLM_API_KEY=secret\n")
    assert env.read_text() == "LLM_API_KEY=secret\n"
    assert _mode(env) == 0o600 and _mode(env.parent) == 0o700
    assert [p.name for p in env.parent.iterdir()] == [".env"]  # no temp file left behind


def test_rewriting_keeps_the_existing_mode(tmp_path):
    env = tmp_path / ".env"
    env.write_text("A=1\n")
    env.chmod(0o640)
    paths.write_private_text(env, "A=2\n")
    assert env.read_text() == "A=2\n" and _mode(env) == 0o640


def test_a_symlinked_settings_file_is_written_through(tmp_path):
    real = tmp_path / "real.env"
    real.write_text("A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(real)
    paths.write_private_text(link, "A=2\n")
    assert link.is_symlink() and real.read_text() == "A=2\n"


def test_adding_a_model_creates_the_settings_file_privately(tmp_path):
    from kratos.adapters import llm_profiles

    env = tmp_path / "fresh" / ".env"
    llm_profiles.add_profile(env, {"LLM_BASE_URL": "https://api.example.test/v1", "LLM_API_KEY": "k",
                                   "LLM_MODEL": "m1", "KRATOS_LLM_BACKEND": "openai_compatible"})
    assert _mode(env) == 0o600
    _cands, current = llm_profiles.list_candidate_profiles(env)
    assert current is not None and current.model == "m1"


# ---------------------------------------------------------------- kratos init


@pytest.fixture
def _restore_process_state():
    from kratos import kratos_config as kc

    target, data_dir = kc.get_active_target(), kc.get_active_data_dir()
    yield
    kc.set_active_target(target)
    kc.set_active_data_dir(data_dir)


def test_init_creates_settings_from_the_bundled_template_once(monkeypatch, tmp_path, capsys, _restore_process_state):
    from kratos.cli import app

    env = tmp_path / "cfg" / ".env"
    monkeypatch.setattr(paths, "env_file", lambda: env)
    assert app.main(["--data-dir", str(tmp_path / "data"), "init"]) == 0
    text = env.read_text()
    assert "LLM_BASE_URL" in text and "kratos init" in text
    assert _mode(env) == 0o600
    env.write_text("MINE=1\n")
    assert app.main(["--data-dir", str(tmp_path / "data"), "init"]) == 0
    assert env.read_text() == "MINE=1\n"  # never overwritten
    assert "already exists" in capsys.readouterr().out


def test_template_in_the_package_matches_the_repo_example():
    repo = Path(__file__).resolve().parents[1]
    from importlib.resources import files

    shipped = files("kratos").joinpath("templates/env.example").read_text(encoding="utf-8")
    assert (repo / ".env.example").read_text(encoding="utf-8") == shipped


# ---------------------------------------------------------------- vulscan


NSE = b"-- vulscan.nse\n" + b"description = [[ vulscan ]]\n" * 60


def _csv(newest_year: int) -> bytes:
    rows = [f"CVE-2010-{i};an old vulnerability in some product, padded to a realistic length\n"
            for i in range(20000)]
    rows.append(f"CVE-{newest_year}-1234;newest\n")
    return "".join(rows).encode()


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]


class _Session:
    def __init__(self, files):
        self.files, self.calls = files, []

    def get(self, url, stream=True, timeout=None):
        name = url.rsplit("/", 1)[-1]
        self.calls.append(name)
        body = self.files.get(name)
        return _Resp(200, body) if body is not None else _Resp(404, b"")


def _good_files(year=2013):
    return {"vulscan.nse": NSE, "cve.csv": _csv(year), "COPYING.TXT": b"GPL\n"}


def test_install_vulscan_puts_files_where_nmap_expects_them(tmp_path):
    from kratos.adapters import vuln_scan

    ok, msg = vuln_scan.install_vulscan(tmp_path, session=_Session(_good_files()))
    assert ok, msg
    base = tmp_path / "scripts" / "vulscan"
    assert {p.name for p in base.iterdir()} == {"vulscan.nse", "cve.csv", "COPYING.TXT"}
    assert vuln_scan.vulscan_installed(tmp_path) and "up to 2013" in msg


def test_a_bad_download_changes_nothing(tmp_path):
    from kratos.adapters import vuln_scan

    assert vuln_scan.install_vulscan(tmp_path, session=_Session(_good_files()))[0]
    base = tmp_path / "scripts" / "vulscan"
    before = {p.name: p.read_bytes() for p in base.iterdir()}
    bad = _good_files()
    bad["cve.csv"] = b"<!DOCTYPE html><title>Just a moment...</title>" * 50
    ok, msg = vuln_scan.install_vulscan(tmp_path, force=True, session=_Session(bad))
    assert not ok and "Nothing was changed" in msg
    assert {p.name: p.read_bytes() for p in base.iterdir()} == before  # no temp files, nothing replaced


def test_a_missing_file_upstream_changes_nothing(tmp_path):
    from kratos.adapters import vuln_scan

    files = _good_files()
    del files["COPYING.TXT"]
    ok, msg = vuln_scan.install_vulscan(tmp_path, session=_Session(files))
    assert not ok and "HTTP 404" in msg
    assert not vuln_scan.vulscan_installed(tmp_path)
    assert list((tmp_path / "scripts" / "vulscan").iterdir()) == []


def test_already_installed_is_a_no_op(tmp_path):
    from kratos.adapters import vuln_scan

    vuln_scan.install_vulscan(tmp_path, session=_Session(_good_files()))
    s = _Session(_good_files())
    ok, msg = vuln_scan.install_vulscan(tmp_path, session=s)
    assert ok and "Already installed" in msg and s.calls == []


def test_staleness_is_judged_by_the_newest_cve_not_the_file_date(tmp_path):
    """A freshly copied file from a decade-old snapshot is still stale."""
    from kratos.adapters import vuln_scan

    db = tmp_path / "cve.csv"
    db.write_bytes(_csv(2013))
    status = vuln_scan.check_vulscan_db_staleness(db)
    assert status["age_days"] == 0 and status["newest_cve_year"] == 2013
    assert status["stale"] and "only goes up to 2013" in status["note"]
    from datetime import datetime

    db.write_bytes(_csv(datetime.now().year))
    status = vuln_scan.check_vulscan_db_staleness(db)
    assert not status["stale"] and status["note"] is None


def test_missing_database_says_how_to_install_it(tmp_path):
    from kratos.adapters import vuln_scan

    status = vuln_scan.check_vulscan_db_staleness(tmp_path / "nope.csv")
    assert status["stale"] and "kratos vulscan-install" in status["note"]


def _patch_scan(monkeypatch, tools, installed, newest=2013):
    seen = {}

    def fake_nmap(target, data_dir, use_vulscan=True):
        seen["use_vulscan"] = use_vulscan
        out = Path(data_dir) / "x.xml"
        out.write_text("<nmaprun/>")
        return out

    monkeypatch.setattr(tools, "_vulscan_installed", lambda: installed)
    monkeypatch.setattr(tools, "_run_nmap_vulscan", fake_nmap)
    monkeypatch.setattr(tools, "_parse_vulscan_xml", lambda p: [])
    monkeypatch.setattr(tools, "_parse_nmap_xml_to_dict", lambda p: {"hosts": []})
    monkeypatch.setattr(tools, "_run_nuclei_scan", lambda *a: Path("n.jsonl"))
    monkeypatch.setattr(tools, "_parse_nuclei_jsonl", lambda p: [])
    monkeypatch.setattr(tools, "_network_scan_gap", lambda t: None)
    from kratos.adapters import vuln_scan

    def staleness():
        if not installed:
            return vuln_scan.check_vulscan_db_staleness(Path("/nonexistent/cve.csv"))
        return {"exists": True, "last_updated": "x", "age_days": 0, "newest_cve_year": newest,
                "stale": newest < 2025, "note": "old" if newest < 2025 else None}

    monkeypatch.setattr(tools, "_check_vulscan_db_staleness", staleness)
    return seen


def test_vuln_scan_without_cve_data_still_finds_ports_and_names_the_gap(monkeypatch, tmp_path):
    from kratos.agent import tools

    seen = _patch_scan(monkeypatch, tools, installed=False)
    out = tools.tool_run_vuln_scan(tmp_path, target="198.51.100.7")
    assert seen["use_vulscan"] is False  # plain -sV still runs, so Nuclei gets real ports
    assert "kratos vulscan-install" in " ".join(out["errors"])
    assert "isn't installed" in out["coverage_gap"]


def test_vuln_scan_with_an_old_cve_list_names_the_cutoff(monkeypatch, tmp_path):
    from kratos.agent import tools

    seen = _patch_scan(monkeypatch, tools, installed=True, newest=2013)
    out = tools.tool_run_vuln_scan(tmp_path, target="198.51.100.7")
    assert seen["use_vulscan"] is True
    assert out["database_newest_cve_year"] == 2013
    assert out["coverage_gap"].startswith("CVEs published after 2013")


def test_vuln_scan_with_a_current_cve_list_reports_no_gap(monkeypatch, tmp_path):
    from kratos.agent import tools

    _patch_scan(monkeypatch, tools, installed=True, newest=2099)
    out = tools.tool_run_vuln_scan(tmp_path, target="198.51.100.7")
    assert "coverage_gap" not in out and out["status"] == "ok"


def test_doctor_reports_a_missing_cve_list_with_the_fix(monkeypatch):
    from kratos.adapters import vuln_scan
    from kratos.agent import doctor

    monkeypatch.setattr(vuln_scan, "vulscan_installed", lambda *a: False)
    out: list = []
    doctor._check_vulscan(out)
    assert out[0]["status"] == "warn" and "kratos vulscan-install" in out[0]["fix"]


def test_doctor_points_at_kratos_init_when_there_is_no_settings_file(monkeypatch, tmp_path):
    from kratos import llm_config
    from kratos.agent import doctor

    monkeypatch.setattr(llm_config, "ENV_FILE_PATH", tmp_path / "missing.env")
    out: list = []
    doctor._check_files(out)
    assert out[0]["status"] == "warn" and "kratos init" in out[0]["fix"]
    assert os.fspath(tmp_path / "missing.env") in out[0]["detail"]


def test_doctor_warns_when_the_settings_file_is_readable_by_others(monkeypatch, tmp_path):
    from kratos import llm_config
    from kratos.agent import doctor

    env = tmp_path / ".env"
    env.write_text("LLM_API_KEY=x\n")
    env.chmod(0o664)
    monkeypatch.setattr(llm_config, "ENV_FILE_PATH", env)
    out: list = []
    doctor._check_files(out)
    assert out[0]["status"] == "warn" and out[0]["fix"] == f"chmod 600 {env}"
    env.chmod(0o600)
    out = []
    doctor._check_files(out)
    assert out[0]["status"] == "info"
