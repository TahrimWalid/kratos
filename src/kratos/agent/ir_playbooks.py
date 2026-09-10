"""A6.2 -- incident-response playbooks (RECOMMEND-ONLY).

For a finding (e.g. a HIGH ``CORR-SSH-001``), produce a structured response plan
a HUMAN can follow in their OWN session: ordered steps, the exact commands to
run (each host-attributed and flagged if it changes state), what to verify
afterwards, and when to escalate.

Hard boundaries this module obeys (design doc §5 + INVARIANTS):

* **Recommend only, structurally.** Nothing here dispatches a tool, imports
  ``execute_tool_call``/``run_pipeline``, or calls any tool handler. It returns
  data describing commands; it never runs one. ``tests/test_ir_playbooks.py``
  asserts this by scanning the module's own source.
* **No prompt-injection surface (the single most dangerous edge case, §5).**
  The FIRST slice is CURATED TEMPLATES ONLY -- every command is a static literal
  written here. ``build_response_plan`` reads ONLY the finding's ``id`` and
  ``severity``; it NEVER reads ``evidence`` (which can carry attacker-controlled
  text -- a malicious username in an auth log, the F1 eval) into a command, a
  step, or anything else. An LLM-drafted fallback is deliberately NOT in this
  slice.
* **Host attribution + destructive flagging.** Every command states where it
  runs (``run_on`` -- reusing 19b's convention) and is flagged destructive when
  it changes state, via the same ``agent/loop.py::_STATE_CHANGE_RE`` the
  investigation dispatch already uses. A ``rm``/``systemctl``/``ufw``/user-mod
  command is never presented as routine.
* **No manufactured urgency.** ``info``/``low`` findings get no playbook
  (``build_response_plan`` returns ``None``); the auto-attach surface only asks
  for HIGH/CRITICAL anyway.
* **Distro assumption is stated, not hidden.** Curated commands assume a
  systemd + ufw + fail2ban Linux target; each plan carries that caveat so a
  mismatched target reads it as an assumption, not a confirmed fix (§5 OS/distro
  mismatch, "unverifiable steps").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from kratos.agent.loop import _STATE_CHANGE_RE  # destructive-command detector (a regex, not a dispatcher)

VALID_RUN_ON = ("target", "kratos_host")

# Assumption every curated command makes; surfaced on every curated plan so a
# mismatched target treats it as an assumption to check, not a confirmed fix.
_DISTRO_CAVEAT = (
    "These commands assume a systemd-based Linux target using ufw + fail2ban. "
    "If the target uses a different service manager or firewall, adapt them — "
    "they're recommendations, not confirmed-correct for this host."
)


@dataclass(frozen=True)
class PlaybookCommand:
    """One command a human may run. ``run_on`` says WHERE (never ambiguous).
    ``destructive`` is DERIVED from the command text, not hand-set, so it can
    never disagree with what the command actually does."""

    command: str
    run_on: str = "target"
    explanation: str = ""

    @property
    def destructive(self) -> bool:
        return bool(_STATE_CHANGE_RE.search(self.command))

    @property
    def where(self) -> str:
        return "the target" if self.run_on == "target" else "Kratos's own host"


@dataclass
class PlaybookStep:
    """One ordered step of a response plan: a short title, zero or more commands,
    and an optional note."""

    title: str
    commands: list[PlaybookCommand] = field(default_factory=list)
    note: Optional[str] = None


@dataclass
class ResponsePlan:
    """A per-finding response plan for a human. ``curated`` is True for a
    hand-written template, False for the generic fallback (an uncovered finding).
    ``found_at`` binds the plan to the finding INSTANCE + time so a plan for an
    already-remediated finding is recognizably stale (§5 stale finding)."""

    finding_id: str
    title: str
    severity: str
    steps: list[PlaybookStep]
    verify: list[str]
    escalate: list[str]
    caveats: list[str] = field(default_factory=list)
    curated: bool = True
    found_at: Optional[str] = None

    @property
    def has_destructive(self) -> bool:
        return any(c.destructive for s in self.steps for c in s.commands)


def _c(command: str, run_on: str = "target", explanation: str = "") -> PlaybookCommand:
    return PlaybookCommand(command=command, run_on=run_on, explanation=explanation)


# --------------------------------------------------------------------------- #
# Curated templates, keyed by finding-ID.
# Each entry is STATIC data. No value here is ever derived from a finding's
# evidence -- commands use literal placeholders like <SOURCE_IP> / <USER> that
# the human fills in from what they see, so attacker-controlled evidence text
# can never reach a command position.
# --------------------------------------------------------------------------- #
def _ssh_bruteforce_plan(title: str) -> dict:
    return {
        "title_hint": title,
        "steps": [
            PlaybookStep(
                "Confirm the attempts are still happening",
                [
                    _c("sudo journalctl _COMM=sshd --since '1 hour ago' --no-pager | grep -Ei 'failed|invalid user' | tail -n 40",
                       "target", "See recent failed SSH auth, newest last (read-only)."),
                    _c("ss -tnp | grep ':22'", "target", "See who is currently connected to SSH (read-only)."),
                ],
                "Read-only. Confirm the burst is ongoing before changing anything.",
            ),
            PlaybookStep(
                "Identify the source address(es)",
                [
                    _c("sudo grep -E 'Failed password|Invalid user' /var/log/auth.log | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head",
                       "target", "Rank the IPs behind the failed logins (read-only). Note the top offender as <SOURCE_IP>."),
                ],
                "Fill <SOURCE_IP> in the next step from what THIS command prints — do not trust an IP quoted elsewhere.",
            ),
            PlaybookStep(
                "Block the source and confirm brute-force protection is active",
                [
                    _c("sudo fail2ban-client status sshd", "target", "Check fail2ban is watching SSH and how many IPs it has banned (read-only)."),
                    _c("sudo ufw deny from <SOURCE_IP> to any port 22", "target", "Firewall-block the attacking IP from SSH. CHANGES STATE."),
                    _c("sudo systemctl enable --now fail2ban", "target", "Ensure fail2ban is running and starts on boot. CHANGES STATE."),
                ],
            ),
            PlaybookStep(
                "Harden SSH so guessing can't succeed",
                [
                    _c("sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin'", "target", "Check whether password / root login are allowed (read-only)."),
                    _c("sudo systemctl restart sshd", "target", "Apply SSH config changes after you disable password auth. CHANGES STATE — will drop existing sessions."),
                ],
                "Prefer key-based auth: set 'PasswordAuthentication no' and 'PermitRootLogin no' in sshd_config, then restart.",
            ),
        ],
        "verify": [
            "Re-run the standard audit (/run) and confirm the failed-login burst has stopped.",
            "Confirm <SOURCE_IP> can no longer reach port 22 and fail2ban shows it (or is actively banning).",
        ],
        "escalate": [
            "If ANY login SUCCEEDED from an unknown IP (not just failed attempts), treat this as a possible breach: "
            "preserve the logs, rotate credentials and SSH keys, check for new/modified accounts and cron jobs, and escalate to your incident lead.",
        ],
    }


def _sudo_burst_plan() -> dict:
    return {
        "title_hint": "Privileged (sudo) authentication failures",
        "steps": [
            PlaybookStep(
                "Review the sudo activity around the burst",
                [
                    _c("sudo journalctl _COMM=sudo --since '3 hours ago' --no-pager | tail -n 80", "target", "See recent sudo attempts and who made them (read-only)."),
                    _c("getent group sudo", "target", "List the accounts with sudo rights (read-only)."),
                ],
                "Confirm whether these failures match expected admin activity (a mistyped password) or look unexpected.",
            ),
            PlaybookStep(
                "If the failures are unexpected, contain the account",
                [
                    _c("sudo passwd -l <USER>", "target", "Lock the affected account's password while you investigate. CHANGES STATE."),
                ],
                "Only if you can't attribute the failures to legitimate admin use. Fill <USER> from the review above.",
            ),
        ],
        "verify": [
            "Re-run the standard audit (/run) and confirm no further sudo-failure bursts on the account.",
        ],
        "escalate": [
            "If a sudo attempt SUCCEEDED that no admin can account for, treat as a possible privilege compromise: "
            "review recent commands, new accounts, and persistence (cron/systemd), and escalate.",
        ],
    }


def _integrity_plan() -> dict:
    return {
        "title_hint": "Tracked file(s) changed since baseline",
        "steps": [
            PlaybookStep(
                "Establish what changed and whether it was authorized",
                [
                    _c("sudo journalctl _COMM=sudo --since '24 hours ago' --no-pager | tail -n 80", "target", "Look for admin activity that could explain the change (read-only)."),
                    _c("ls -l --time-style=full-iso <CHANGED_PATH>", "target", "Check the modification time of the changed file (read-only). Fill <CHANGED_PATH> from the finding's evidence."),
                ],
                "Correlate the change time with a known, authorized admin action (update/install/config).",
            ),
            PlaybookStep(
                "If the change is unexplained, look for tampering",
                [
                    _c("ps aux --sort=-%cpu | head -n 20", "target", "Look for unexpected running processes (read-only)."),
                    _c("sudo find / -newer <CHANGED_PATH> -type f 2>/dev/null | grep -vE '^/(proc|sys|run)/' | head -n 40", "target", "Find other files changed around the same time (read-only)."),
                ],
            ),
        ],
        "verify": [
            "Once the change is confirmed legitimate, re-baseline with check_file_integrity so future diffs measure from the new known-good state.",
        ],
        "escalate": [
            "If the change can't be tied to an authorized action, treat as possible tampering or persistence: preserve the file and logs, and escalate before re-baselining.",
        ],
    }


def _open_ports_plan() -> dict:
    return {
        "title_hint": "Open network ports (attack surface)",
        "steps": [
            PlaybookStep(
                "Review each exposed service and confirm it's needed",
                [
                    _c("ss -tlnp", "target", "List every listening TCP port and its owning process (read-only)."),
                ],
                "For each port in the finding's evidence, confirm the service is intentional and needs to be network-reachable.",
            ),
            PlaybookStep(
                "Restrict anything that shouldn't be public",
                [
                    _c("sudo ufw status verbose", "target", "See the current firewall rules (read-only)."),
                    _c("sudo ufw deny <PORT>/tcp", "target", "Block a port that shouldn't be exposed. CHANGES STATE. Fill <PORT> from the review."),
                ],
            ),
        ],
        "verify": [
            "Re-run the standard audit (/run) and confirm only the intended ports remain open.",
        ],
        "escalate": [
            "If an exposed service is one you did not deploy, treat as a possible unauthorized service and investigate its origin before removing it.",
        ],
    }


_TEMPLATES = {
    "CORR-SSH-001": lambda: _ssh_bruteforce_plan("SSH exposed with a failed-login burst — likely brute force"),
    "CORR-001": lambda: _ssh_bruteforce_plan("SSH exposure correlated with a failed-login burst"),
    "CORR-002": _sudo_burst_plan,
    "AUTH-004": _sudo_burst_plan,
    "INTEG-001": _integrity_plan,
    "NET-002": _open_ports_plan,
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _generic_plan() -> dict:
    """Fallback for a HIGH/CRITICAL finding we have no curated template for.
    Deliberately NOT an LLM draft (that's a later slice, §5) — a safe, generic,
    honestly-labeled 'here's the shape of a response' rather than a blank or a
    fabricated-confident answer."""
    return {
        "title_hint": None,
        "steps": [
            PlaybookStep(
                "Preserve evidence before you change anything",
                [_c("sudo journalctl --since '6 hours ago' --no-pager > ~/kratos_incident_$(date +%s).log", "target",
                    "Capture recent logs to a file before remediation. Writes a file on the target.")],
                "Keep a copy of the relevant logs so you can investigate even after you act.",
            ),
            PlaybookStep(
                "Investigate the specifics in the finding's evidence",
                [],
                "Use the finding's evidence (below the plan) to guide read-only inspection — confirm the "
                "pattern, its source, and its scope — before applying any state-changing fix.",
            ),
            PlaybookStep(
                "Contain, then remediate — only once you understand it",
                [],
                "Isolate the affected service/account first if it looks active, then apply the narrowest fix that resolves it.",
            ),
        ],
        "verify": [
            "Re-run the standard audit (/run) and confirm the finding no longer fires.",
        ],
        "escalate": [
            "If you can't explain the finding or it looks like an active compromise, preserve state and escalate to your incident lead before remediating.",
        ],
    }


def has_playbook(finding_id: str) -> bool:
    """Whether a CURATED template exists for this finding-ID (a generic fallback
    always exists for high/critical, so this is specifically about curation)."""
    return finding_id in _TEMPLATES


def build_response_plan(finding: dict, *, found_at: Optional[str] = None) -> Optional[ResponsePlan]:
    """Build a recommend-only response plan for a finding, or None.

    Reads ONLY ``finding['id']`` and ``finding['severity']`` -- never
    ``evidence`` (the injection boundary, §5). ``info``/``low`` findings return
    None (no manufactured urgency). A finding-ID with a curated template gets it;
    an uncovered HIGH/CRITICAL finding gets the generic fallback (``curated=False``).
    """
    fid = str(finding.get("id") or "").strip() or "UNKNOWN"
    severity = str(finding.get("severity") or "info").strip().lower()
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK["medium"]:
        return None

    template_factory = _TEMPLATES.get(fid)
    curated = template_factory is not None
    spec = template_factory() if curated else _generic_plan()

    title = spec.get("title_hint") or str(finding.get("title") or fid)
    caveats = [_DISTRO_CAVEAT]
    if not curated:
        caveats.insert(
            0,
            "No curated playbook exists for this finding yet — this is generic incident-response "
            "guidance, not a step-by-step fix specific to this finding.",
        )
    return ResponsePlan(
        finding_id=fid,
        title=title,
        severity=severity,
        steps=[s for s in spec["steps"] if s.title],
        verify=list(spec["verify"]),
        escalate=list(spec["escalate"]),
        caveats=caveats,
        curated=curated,
        found_at=found_at,
    )
