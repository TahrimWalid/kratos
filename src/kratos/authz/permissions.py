"""The permission table: which role may do which action (docs/phaseD/D.7 §3.3, §5.1).

Three fixed roles, one literal table, no custom roles. An action is named once here and
everywhere else refers to these names; `require()` (kratos.authz.check) refuses any name
it doesn't know, so a typo can never become "allowed".

Admin actions are LOCAL-ONLY (§3.2): even an admin-role user can't do them over the
network -- only the owner at the Kratos host's TUI or CLI can.
"""
from __future__ import annotations

ROLES = ("viewer", "investigator", "admin")

# --- reading (every role) ------------------------------------------------------------
READ = "read"                       # see a machine at all (models list, a run's per-read scope check)
FINDINGS_READ = "findings.read"     # open findings, finding states, reports
CHAT = "chat"                       # a question answered from what Kratos already knows (no investigation)
HUNT = "hunt"                       # search what Kratos holds for an indicator
USAGE_READ = "usage.read"           # today's model use and the limits
SESSIONS_OWN = "sessions.own"       # list and resume one's own sessions

# --- investigating (investigator, admin) ----------------------------------------------
INVESTIGATE = "investigate.start"
FLEET_ASK = "fleet.ask"
RETEST = "retest"
FINDING_DECIDE = "finding.decide"
EXPORT_REDACTED = "export.redacted"

# --- administering (admin role, and only at the Kratos host) ---------------------------
USERS_MANAGE = "users.manage"
TOKENS_MANAGE = "tokens.manage"
CHANNELS_MANAGE = "channels.manage"
SETTINGS_CHANGE = "settings.change"
BUDGET_CHANGE = "budget.change"
ENROL = "enrol"                     # SSH certificates, sub-agent pairing, agent link keys
FIXCHANNEL_CONSENT = "fixchannel.consent"   # whitelist entries and execution consent
EXPORT_FULL = "export.full"
GROUPS_MANAGE = "groups.manage"
ASSETS_MANAGE = "assets.manage"
SCHEDULES_MANAGE = "schedules.manage"     # schedules, triggers, presets
DETECT_MANAGE = "detect.manage"           # rule overrides, live watching
DATA_PRUNE = "data.prune"
AUDIT_READ = "audit.read"
AUDIT_PRUNE = "audit.prune"
KEYS_MANAGE = "keys.manage"               # signing key, sealing keys, TLS keys
TOOLS_MANAGE = "tools.manage"             # evo-loop: write and keep a new tool
SESSIONS_ALL = "sessions.all"             # see every user's sessions (read-only)
LOCAL_RUN = "local.run"                   # anything else done at the Kratos host's TUI/CLI (owner only)

VIEWER = frozenset({READ, FINDINGS_READ, CHAT, HUNT, USAGE_READ, SESSIONS_OWN})
INVESTIGATOR = VIEWER | frozenset({INVESTIGATE, FLEET_ASK, RETEST, FINDING_DECIDE, EXPORT_REDACTED})
ADMIN = INVESTIGATOR | frozenset({
    USERS_MANAGE, TOKENS_MANAGE, CHANNELS_MANAGE, SETTINGS_CHANGE, BUDGET_CHANGE, ENROL, FIXCHANNEL_CONSENT,
    EXPORT_FULL, GROUPS_MANAGE, ASSETS_MANAGE, SCHEDULES_MANAGE, DETECT_MANAGE, DATA_PRUNE, AUDIT_READ,
    AUDIT_PRUNE, KEYS_MANAGE, TOOLS_MANAGE, SESSIONS_ALL, LOCAL_RUN,
})

TABLE: dict[str, frozenset[str]] = {"viewer": VIEWER, "investigator": INVESTIGATOR, "admin": ADMIN}

ACTIONS = frozenset(ADMIN)

# Only the owner at the Kratos host (TUI / CLI) -- never over the network, whatever the role.
LOCAL_ONLY = ADMIN - INVESTIGATOR
LOCAL_INTERFACES = ("tui", "cli")

# Who needs what, in plain words -- the refusal names the role that has it.
_WORDS = {
    READ: "see this machine",
    FINDINGS_READ: "read findings",
    CHAT: "ask Kratos questions",
    HUNT: "hunt",
    USAGE_READ: "see the usage",
    SESSIONS_OWN: "use sessions",
    INVESTIGATE: "start investigations",
    FLEET_ASK: "ask questions about a group of machines",
    RETEST: "re-check findings",
    FINDING_DECIDE: "decide about findings",
    EXPORT_REDACTED: "export incident bundles",
}


def allowed(role: str, action: str) -> bool:
    return action in TABLE.get(role, frozenset())


def role_word(role: str) -> str:
    return {"viewer": "viewers", "investigator": "investigators", "admin": "admins"}.get(role, f"{role!r} users")


def lowest_role_for(action: str) -> str | None:
    for role in ROLES:
        if action in TABLE[role]:
            return role
    return None


def refusal_text(role: str, action: str) -> str:
    """'viewers can't start investigations -- ask the Kratos owner for investigator access'."""
    need = lowest_role_for(action)
    what = _WORDS.get(action, f"do {action!r}")
    if need is None or action in LOCAL_ONLY:
        return f"{role_word(role)} can't {what} -- that is done by the Kratos owner on the Kratos computer"
    return f"{role_word(role)} can't {what} -- ask the Kratos owner for {need} access"
