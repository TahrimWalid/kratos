"""E.2 `hardening_facts`: one fixed script, the same records under gawk, mawk and BusyBox
awk, closed lists only (nothing outside them is printed), every value typed by the parser,
and the agent's read runs the same script."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from kratos.adapters import hardening as H

from tests._logsources_util import awks  # noqa: E402

AWKS = awks()
TOOLS = ("sh", "sed", "tr", "cat", "head", "stat", "grep", "cut", "wc", "printf", "id", "uname", "tail")


def _busybox() -> str:
    return (os.environ.get("KRATOS_TEST_BUSYBOX") or shutil.which("busybox")
            or str(Path("~/.local/bin/busybox").expanduser()))


def _bindir(base: Path, awk: str) -> Path:
    b = base / f"bin_{awk}"
    b.mkdir(parents=True, exist_ok=True)
    for t in TOOLS:
        src = shutil.which(t)
        if src and not (b / t).exists():
            os.symlink(src, b / t)
    if not (b / "awk").exists():
        os.symlink(_busybox() if awk == "busybox" else shutil.which(awk), b / "awk")
    return b


def _w(root: Path, rel: str, text: str, mode: int = 0o644) -> None:
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)


def make_tree(base: Path) -> Path:
    r = base / "root"
    krel = subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()
    _w(r, "/etc/os-release", 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n')
    for key in H.SYSCTL_KEYS:
        if key.startswith("net.ipv6.conf.default."):
            continue                                  # missing on purpose
        _w(r, "/proc/sys/" + key.replace(".", "/"), "1\n")
    _w(r, "/proc/sys/kernel/randomize_va_space", "2\n")
    _w(r, "/proc/sys/kernel/not_in_the_list", "1\n")            # never printed
    _w(r, "/etc/passwd", "root:x:0:0::/root:/bin/sh\n", 0o644)
    _w(r, "/etc/crontab", "# cron\n", 0o666)
    (r / "etc/cron.d").mkdir(parents=True, exist_ok=True)
    _w(r, "/proc/self/mounts", "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n/dev/sda1 / ext4 rw 0 0\n"
                               "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n")
    _w(r, "/etc/login.defs", "# c\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS\t1\nUMASK 027\nENCRYPT_METHOD YESCRYPT\n"
                             "MAIL_DIR /var/mail\n")
    _w(r, "/etc/pam.d/common-auth",
       "auth [success=1 default=ignore] pam_unix.so nullok file=/etc/secret deny=5 minlen=x\n"
       "auth requisite pam_deny.so\n-auth optional /lib/x86_64-linux-gnu/security/pam_faillock.so authfail deny=4\n"
       "@include common-extra\n")
    _w(r, "/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3 minlen=14\n")
    _w(r, "/etc/security/pwquality.conf", "# x\nminlen = 12\nnot_a_key = 9\n")
    _w(r, "/etc/security/pwquality.conf.d/90.conf", "minlen=16\n")
    _w(r, "/etc/security/faillock.conf", "deny = 3\nunlock_time = 900\n")
    _w(r, "/etc/modprobe.d/cramfs.conf", "install cramfs /bin/false\nblacklist cramfs\n")
    _w(r, "/etc/modprobe.d/usb.conf", "blacklist usb_storage\ninstall udf /usr/bin/true\n")
    _w(r, "/proc/modules", "sctp 1 0 - Live 0x0\n")
    _w(r, f"/lib/modules/{krel}/modules.dep", "kernel/fs/hfs/hfs.ko.zst:\nkernel/net/sctp/sctp.ko:\n"
                                             "kernel/drivers/usb/storage/usb-storage.ko:\n")
    _w(r, "/sys/module/apparmor/parameters/enabled", "Y\n")
    _w(r, "/sys/kernel/security/apparmor/profiles", "/usr/sbin/a (enforce)\n/usr/bin/b (complain)\n")
    _w(r, "/etc/issue.net", "Ubuntu \\r \\m\n")
    _w(r, "/etc/ssh/sshd_config", "Port 22\nMatch User x\n  PasswordAuthentication yes\n")
    _w(r, "/etc/ssh/sshd_config.d/a.conf", "match group y\n")
    _w(r, "/etc/systemd/journald.conf", "[Journal]\n#Storage=auto\nStorage=persistent\n")
    (r / "var/log/journal").mkdir(parents=True, exist_ok=True)
    _w(r, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    _w(r, "/etc/default/ufw", 'DEFAULT_INPUT_POLICY="DROP"\n')
    return r


def run_script(base: Path, root: Path, awk: str) -> str:
    b = _bindir(base, awk)
    out = subprocess.run([str(b / "sh"), "-s"], input=H.build_script("sudo -n", root=str(root)),
                         capture_output=True, text=True, timeout=60, env={"PATH": str(b), "LC_ALL": "C"})
    assert out.returncode == 0, out.stderr
    return out.stdout


def test_script_is_valid_sh_both_ways():
    for sudo in ("sudo -n", ""):
        r = subprocess.run(["sh", "-n"], input=H.build_script(sudo), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("awk", AWKS)
def test_same_records_under_every_awk(tmp_path, awk):
    root = make_tree(tmp_path)
    ref = run_script(tmp_path, root, "gawk") if shutil.which("gawk") else None
    got = run_script(tmp_path, root, awk)
    if ref is not None:
        assert got == ref
    d = H.parse_output(got)
    assert d["complete"] and d["format"] == H.FORMAT
    assert d["os"]["ID"] == "ubuntu" and d["os"]["VERSION_ID"] == "24.04"
    assert d["sysctl"]["kernel.randomize_va_space"] == 2
    assert d["sysctl"]["net.ipv6.conf.default.accept_ra"] == {"absent": "missing"}
    assert d["stat"]["/etc/crontab"]["mode"] == 0o666
    assert d["stat"]["/etc/shadow"] == {"absent": "missing"}
    assert d["mounts"]["/tmp"]["options"] == ["nodev", "noexec", "nosuid", "rw"]
    assert d["mounts"]["/var/tmp"] is None
    assert d["login_defs"] == {"PASS_MAX_DAYS": "99999", "PASS_MIN_DAYS": "1", "UMASK": "027",
                               "ENCRYPT_METHOD": "YESCRYPT"}
    auth = d["pam"]["common-auth"]["lines"]
    assert auth[0]["control"] == "[success=1,default=ignore]" and auth[0]["module"] == "pam_unix.so"
    assert auth[0]["args"] == ["nullok", "deny=5"]               # no path, no non-numeric key value
    assert auth[2]["module"] == "pam_faillock.so" and auth[2]["args"] == ["authfail", "deny=4"]
    assert d["pam_includes"]["common-auth"] == ["common-extra"]
    assert d["sec"]["pwquality"] == {"minlen": "16"} and d["sec"]["faillock"] == {"deny": "3", "unlock_time": "900"}
    m = d["modules"]
    assert m["cramfs"]["install"] == "false" and m["cramfs"]["blacklisted"]
    assert m["usb-storage"]["install"] == "none" and m["usb-storage"]["blacklisted"]   # usb_storage == usb-storage
    assert m["udf"]["install"] == "true"
    assert m["sctp"]["loaded"] and m["hfs"]["shipped"] and m["jffs2"]["shipped"] is False
    assert d["mac"]["apparmor_enabled"] and d["mac"]["apparmor_profiles"] == 2 and d["mac"]["apparmor_enforce"] == 1
    assert d["banners"]["/etc/issue.net"]["os_details"] and d["banners"]["/etc/motd"] is None
    assert d["sshd_match_blocks"] == 2
    assert d["journald"] == {"storage": "persistent", "var_log_journal": "yes"}
    assert d["firewall"]["ufw_enabled"] == "yes" and d["firewall"]["ufw_input_policy"] == "DROP"
    assert d["virt"] == "none"


def test_an_incus_or_lxc_container_is_recognised_without_root(tmp_path):
    """By its user-namespace uid map (a VM has /dev/incus too, so that can't tell)."""
    root = make_tree(tmp_path)
    _w(root, "/proc/self/uid_map", "         0    1000000 1000000000\n")
    assert H.parse_output(run_script(tmp_path, root, AWKS[0]))["virt"] == "container"


def test_nothing_outside_the_closed_lists_is_printed(tmp_path):
    root = make_tree(tmp_path)
    out = run_script(tmp_path, root, "gawk" if shutil.which("gawk") else AWKS[0])
    assert "not_in_the_list" not in out
    assert "/etc/secret" not in out and "MAIL_DIR" not in out and "not_a_key" not in out
    assert "PasswordAuthentication" not in out                # sshd_config content never leaves


def test_sshd_records_count_user_lists_and_never_name_them():
    sample = ("permitrootlogin no\npasswordauthentication yes\nallowusers alice bob\nallowgroups admins\n"
              "ciphers aes256-gcm@openssh.com,aes128-cbc\nport 22\nhostkey /etc/ssh/key\n")
    awk = shutil.which("gawk") or shutil.which("awk")
    out = subprocess.run([awk, "-v", "keys=" + " ".join(H.SSHD_KEYS), "-v", "counts=" + " ".join(H.SSHD_COUNT_KEYS),
                          H.AWK_SSHD], input=sample, capture_output=True, text=True).stdout
    assert "alice" not in out and "admins" not in out and "/etc/ssh/key" not in out
    d = H.parse_output("HFACTS\t1\nSSHDSTATE\tok\n" + out + "END\n")
    assert d["sshd"]["allowusers"] == 2 and d["sshd"]["allowgroups"] == 1 and d["sshd"]["denyusers"] == 0
    assert d["sshd"]["permitrootlogin"] == "no" and d["sshd"]["ciphers"] == "aes256-gcm@openssh.com,aes128-cbc"


def test_hostile_values_become_unexpected_never_carried():
    esc = "\x1b]8;;http://evil\x07x\x1b[2J"
    raw = (f"HFACTS\t1\nSYSCTL\tkernel.randomize_va_space\t2{esc}\nSYSCTL\tkernel.made_up\t1\n"
           f"STAT\t/etc/passwd\t644|0|0|root{esc}|root|regular file\nLDEF\tUMASK\t$(reboot)\n"
           f"SSHD\tbanner\t<script>{esc}\nOS\tPRETTY_NAME={esc}\nTIME\tNTP\t{esc}\nFW\tufw_enabled\t{esc}\n")
    d = H.parse_output(raw)
    assert d["sysctl"]["kernel.randomize_va_space"] == {"unexpected": True}
    assert "kernel.made_up" not in d["sysctl"]
    assert d["stat"]["/etc/passwd"]["user"] == "?"
    assert d["login_defs"]["UMASK"] == {"unexpected": True}
    assert d["sshd"]["banner"] == {"unexpected": True}
    assert "PRETTY_NAME" not in d["os"] and d["time"]["NTP"] == "unexpected" and "ufw_enabled" not in d["firewall"]
    assert not d["complete"]                                  # no END marker: cut off


def test_systemd_units_parsed_from_show_output():
    raw = ("HFACTS\t1\nINIT\tsystemd\nSVCRAW\tId=ssh.service\nSVCRAW\tLoadState=loaded\nSVCRAW\tActiveState=active\n"
           "SVCRAW\tUnitFileState=enabled\nSVCRAW\tId=cups.service\nSVCRAW\tLoadState=not-found\n"
           "SVCRAW\tActiveState=inactive\nSVCRAW\tUnitFileState=\nSVCRAW\tId=evil.service\nSVCRAW\tLoadState=loaded\n"
           "END\n")
    d = H.parse_output(raw)
    assert d["services"]["ssh"] == {"load": "loaded", "enabled": "enabled", "active": "active"}
    assert d["services"]["cups"]["load"] == "not-found" and "evil" not in d["services"]


def test_agent_probe_runs_the_same_script(monkeypatch):
    from kratos.subagent import reads

    seen = {}

    def fake(argv, timeout, cap, stdin_text=None):
        seen.update(argv=argv, stdin=stdin_text, cap=cap)
        return {"status": "ok", "stdout": "HFACTS\t1\nEND\n", "exit_code": 0}

    monkeypatch.setattr(reads, "run_capped", fake)
    out = reads.run_probe("hardening_facts", {})
    assert out["status"] == "ok" and seen["stdin"] == H.build_script(sudo="")
    assert seen["argv"][-1] == "-s" and seen["cap"] == H.OUTPUT_CAP_BYTES + 65536
    assert reads.run_probe("hardening_facts", {"path": "/etc/shadow"})["status"] == "refused"


def test_core_refuses_the_read_to_an_older_agent():
    from kratos.subagent import agent, core_server

    assert core_server.PROBE_MIN_AGENT_VERSION["hardening_facts"] == (0, 13, 0)
    assert core_server.parse_agent_version(agent.AGENT_VERSION) >= (0, 13, 0)


def test_a_vm_with_an_identity_uid_map_is_not_a_container(tmp_path):
    root = make_tree(tmp_path)
    (root / "dev/incus").mkdir(parents=True)
    _w(root, "/proc/self/uid_map", "         0          0 4294967295\n")
    assert H.parse_output(run_script(tmp_path, root, AWKS[0]))["virt"] == "none"


@pytest.mark.parametrize("awk", AWKS)
def test_sysctl_files_closed_keys_last_wins(tmp_path, awk):
    root = make_tree(tmp_path)
    _w(root, "/usr/lib/sysctl.d/10-default.conf", "kernel.randomize_va_space = 1\nkernel/yama/ptrace_scope=1\n")
    _w(root, "/etc/sysctl.d/60-hard.conf", "# x\nkernel.randomize_va_space=2\n-fs.suid_dumpable = 0\nvm.swappiness=10\n"
                                           "net.ipv4.ip_forward = $(id)\n")
    d = H.parse_output(run_script(tmp_path, root, awk))
    assert d["sysctl_conf_read"] and d["sysctl_conf"] == {"kernel.randomize_va_space": 2,
                                                         "kernel.yama.ptrace_scope": 1, "fs.suid_dumpable": 0}


def test_awk_programs_use_no_interval_expressions():
    """mawk 1.3.4-20200120 (Ubuntu 22.04's awk) silently never matches /x{1,6}/ -- found on a
    real VM, where every sysctl-file value was dropped. Patterns use + and length() instead."""
    import re as _re

    for name in dir(H):
        if name.startswith("AWK_"):
            assert not _re.search(r"\{\d*,?\d*\}", getattr(H, name)), name
