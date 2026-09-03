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
    (#c9962c), and critical red (#ff3b3b),
  - tool-blue (#7fa8bf) for tool names / IPs / links, and the Admin voice
    (#8f9bb0).
"""
from __future__ import annotations

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

# --- Brand + roles -------------------------------------------------------
KRATOS_RED = "#8b1a1a"    # the KRATOS wordmark / Kratos's own voice label
ACCENT = "#7fa8bf"        # tool-blue: tool names, IPs, links, prompts
ADMIN = "#8f9bb0"         # the Admin/you voice label

SAFE = "#7f9e79"          # read-only / passed / clean / success (green)
ATTENTION = "#c9962c"     # attention / in-progress / decision-needed (amber)
CRITICAL = "#ff3b3b"      # a real HIGH/CRITICAL finding / hard failure (red)

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
