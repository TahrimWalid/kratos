"""
kratos-mk2 visual identity -- lifted directly from the "Kratos TUI" design
canvas, NOT from agent/console.py's classic-REPL palette (that palette --
ACCENT #5dc9d6 etc. -- is a different, cooler identity; the canvas uses a
warmer, muted terminal look). Keeping mk2's colors in one module means a
future theming pass (or a light-mode variant) touches one file.

Every hex here traces to a real value in the canvas mockups:
  - the near-black card grounds (#0b0b0d / #0e0e10 / #101013),
  - the muted parchment text ramp (#e6e1d8 -> #3f3e3b),
  - KRATOS's oxblood wordmark (#8b1a1a),
  - the three status roles: read-only/safe green (#7f9e79), attention amber
    (#c9962c), and critical red (#ff3b3b).

The grounds, text ramp, and status roles are the shared base across every
theme pack (see PACKS). Only the identity colors -- the chrome ACCENT (tool
names / IPs / links / active tab / focus), the KRATOS wordmark, and the ADMIN
voice -- are re-tinted per pack. The default pack, "kratos-red", uses a warm
brick accent (#cf7259); "kratos-blue" preserves the original tool-blue
(#7fa8bf). CRITICAL never changes, so "red = danger" reads the same in every
theme.
"""
from __future__ import annotations

import os

# --- Grounds / surfaces --------------------------------------------------
BG = "#0b0b0d"            # app background (canvas card ground)
PANEL_BG = "#0e0e10"      # nested panels
INSET_BG = "#101013"      # inset boxes (e.g. recommended-command block)
TITLEBAR_BG = "#141416"   # macOS-style titlebar
BORDER = "#232327"        # hairline borders between regions
BORDER_SOFT = "#1b1b1f"   # even softer dividers

# --- Text ramp (light -> dark) ------------------------------------------
TEXT_BRIGHT = "#e6e1d8"   # emphasised primary text
TEXT = "#cfcac1"          # body text
TEXT_MUTED = "#a8a29a"    # secondary body
TEXT_DIM = "#8c8880"      # labels / key hints
TEXT_FAINT = "#6f6c67"    # captions
TEXT_FAINTER = "#5e5c58"  # column headers / timestamps
TEXT_GHOST = "#4d4b48"    # placeholder-adjacent
TEXT_PLACEHOLDER = "#3f3e3b"  # true placeholder / "type a goal…"

# --- Theme packs: identity colors (chrome accent + brand + admin voice) --
# The grounds + text ramp above and the status roles below are the shared
# "warm muted terminal" base and do NOT change between packs -- a pack only
# re-tints the interactive/identity colors (ACCENT, KRATOS_RED, ADMIN).
#
# CRITICAL (danger red) is deliberately NOT a pack color: it must stay a
# constant, unambiguous alarm regardless of theme, so a red-chromed default
# can't blur "red = danger". The default pack's ACCENT is a warm brick that
# reads red-family but is clearly distinct (muted, orange-leaning) from the
# bright pure-red CRITICAL below.
PACKS: dict[str, dict[str, str]] = {
    "kratos-red": {"label": "Kratos Red (default)", "ACCENT": "#cf7259",
                   "KRATOS_RED": "#8b1a1a", "ADMIN": "#b3968a"},
    "kratos-blue": {"label": "Slate Blue", "ACCENT": "#7fa8bf",
                    "KRATOS_RED": "#8b1a1a", "ADMIN": "#8f9bb0"},
}
DEFAULT_PACK = "kratos-red"


def active_pack_name() -> str:
    """The active theme pack, resolved once at import. Overridable via the
    KRATOS_THEME env var (Phase 2's settings switcher persists a choice and sets
    this env var so a fresh process picks it up); falls back to the red default
    for an unset/unknown value."""
    name = os.environ.get("KRATOS_THEME", "").strip()
    return name if name in PACKS else DEFAULT_PACK


_ACTIVE = PACKS[active_pack_name()]

# --- Brand + roles -------------------------------------------------------
KRATOS_RED = _ACTIVE["KRATOS_RED"]  # the KRATOS wordmark / Kratos's own voice label
ACCENT = _ACTIVE["ACCENT"]          # chrome: tool names, IPs, links, prompts, active tab, focus
ADMIN = _ACTIVE["ADMIN"]            # the Admin/you voice label

SAFE = "#7f9e79"          # read-only / passed / clean / success (green)
ATTENTION = "#c9962c"     # attention / in-progress / decision-needed (amber)
CRITICAL = "#ff3b3b"      # a real HIGH/CRITICAL finding / hard failure -- NOT theme-swappable

# macOS traffic lights (launch / titlebar chrome)
TL_RED = "#ff5f57"
TL_YELLOW = "#febc2e"
TL_GREEN = "#28c840"

SEVERITY_COLOR = {
    "critical": CRITICAL,
    "high": CRITICAL,
    "medium": ATTENTION,
    "low": ATTENTION,
    "info": SAFE,
}

# Textual CSS shared by every mk2 screen. Screens add their own scoped rules;
# these are the app-wide grounds/typography and the reusable role classes.
APP_CSS = f"""
Screen {{
    background: {BG};
    color: {TEXT};
}}

/* Kratos's oxblood wordmark, used on the idle/launch screens */
.kratos-wordmark {{
    color: {KRATOS_RED};
    text-style: bold;
}}

.dim   {{ color: {TEXT_DIM}; }}
.faint {{ color: {TEXT_FAINT}; }}
.muted {{ color: {TEXT_MUTED}; }}

.role-safe      {{ color: {SAFE}; }}
.role-attention {{ color: {ATTENTION}; }}
.role-critical  {{ color: {CRITICAL}; }}
.role-accent    {{ color: {ACCENT}; }}

/* The top identity/status bar (turn 9a header) */
#appheader {{
    height: 1;
    background: {TITLEBAR_BG};
    color: {TEXT_DIM};
    padding: 0 1;
}}

/* The bottom status line (turn 7c footer: session · model · target · ctx) */
#statusfooter {{
    height: 1;
    background: {TITLEBAR_BG};
    color: {TEXT_FAINTER};
    padding: 0 1;
}}

Input {{
    background: {PANEL_BG};
    color: {TEXT_BRIGHT};
    border: none;
    padding: 0 1;
}}
Input:focus {{ border: none; }}

DataTable {{
    background: {BG};
    color: {TEXT};
}}
DataTable > .datatable--header {{
    background: {BG};
    color: {TEXT_FAINTER};
    text-style: bold;
}}
DataTable > .datatable--cursor {{
    background: {BORDER};
    color: {TEXT_BRIGHT};
}}

/* Modal dimming + card */
ModalScreen {{
    align: center middle;
    background: black 60%;
}}
.modal-card {{
    background: {PANEL_BG};
    border: round {BORDER};
    padding: 1 2;
    width: 84;
    max-width: 90%;
    height: auto;
    max-height: 90%;
}}
.modal-title {{
    text-style: bold;
    color: {ACCENT};
    margin-bottom: 1;
}}
"""
