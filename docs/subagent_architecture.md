# Kratos Sub-Agent Architecture (v2 — revised after security review)

Status: DECIDED, REVISED. Supersedes the original 2026-07-XX version of this doc.

## What changed from v1, and why

An independent security review of v1 found that its central safety claim did not hold. v1
described cryptographic command signing as "the actual security boundary" against a
compromised/prompt-injected Kratos core. This is incorrect: signing proves a command came from
Kratos's core and wasn't forged or replayed by another device — it does nothing against a core
that is itself manipulated (e.g. via a crafted log line) into legitimately deciding to issue a
bad command. In that scenario the malicious command is validly signed, ACL-permitted, and
malicious, all at once. The review also found the example whitelist actions were not actually
bounded (`apply_config_diff` with an arbitrary path is unbounded write access — e.g. writing to
`authorized_keys` is a full persistent backdoor, achieved through an action the original doc
called "safe"). Full review preserved in project history; this doc incorporates its conclusions
rather than re-litigating them.

## Background — the boundary this modifies

On 2026-07-16, Kratos formalized a permanent architectural boundary: Kratos must never execute or
change state on the monitored target — not even behind approval. This came from a real incident
and was made deliberately non-negotiable, because approval-gating a remediation channel doesn't
remove the risk, it just adds a checkpoint to a capability that shouldn't exist.

v2 resolves the tension between that boundary and real user demand for automated remediation by
splitting the sub-agent into two independent capabilities with very different risk profiles,
rather than reversing the boundary wholesale.

## The two capabilities, kept structurally separate

### 1. Continuous telemetry (always on, read-only, low risk)

The sub-agent, once paired, continuously forwards read-only state — logs, service status, file
hashes, whatever Kratos's existing tools already collect — to Kratos's core on a regular interval,
independent of any investigation being actively run. This is monitoring, not execution, and
carries none of the risk this doc is otherwise concerned with. This capability is always on for
every paired target, regardless of anything below.

This is what allows Kratos to notice the effect of a change on the target — including a
remediation command the human ran themselves in their own session — without needing to have
triggered that change itself, and without the human needing to manually report back "I ran it."
The next telemetry cycle surfaces the new state naturally, the same way Kratos would notice a
change made by an attacker.

### 2. Direct execution (opt-in, off by default, real risk — the thing v1 got wrong)

A separate, explicitly opt-in capability: Kratos's core can send a signed, whitelisted command to
the sub-agent, which executes it on the target. Default state for every newly paired target: OFF.
The user must explicitly enable this per-target (or globally, with per-target override) via its
own dedicated consent screen — not a checkbox folded into general onboarding.

The default (non-opted-in) remediation flow: Kratos detects an issue, proposes a fix, and
generates the exact command or script needed — then hands it to the human to run in their own
session (copy-to-clipboard, or a "run this" action targeting the user's own already-authenticated
terminal, never a Kratos-controlled channel). This reuses the same low-friction pattern already
validated in the target-onboarding/pairing flow. Telemetry (capability 1) picks up the result
automatically on its next cycle.

## Corrected threat model and compensating controls

The actual security boundary against a compromised/injected core is the whitelist (control 3
below) and the human typing EXECUTE — not signing. Signing defends against a different, real
threat (a rogue tailnet device, MITM, command replay) and remains worth having, but must not be
described or relied upon as protection against a manipulated core. This is the load-bearing
correction from the security review; every control below is scoped accordingly.

1. **Tailscale ACL isolation.** Tag the sub-agent device and Kratos's core device distinctly. ACL
   rule restricts the sub-agent's command port to accept connections ONLY from the `kratos-core`
   tag, enforced at the network layer.

2. **Cryptographic command signing.** Defends against: a rogue device on the same tailnet, MITM,
   or replayed commands. Does NOT defend against: a legitimate, signed command issued by a core
   that has been manipulated (e.g. via prompt injection) into deciding to issue something harmful.
   State this distinction explicitly anywhere this control is documented or discussed — v1's error
   was treating this as sufficient against the latter.

3. **Fixed, genuinely narrow action whitelist — this is the real boundary, and it is not optional
   or deferrable.** Every whitelisted action must be narrow and target-constrained:
   * `enable_service(name)` where `name` is drawn from a fixed allowlist, not arbitrary —
     acceptable.
   * Arbitrary-path config writes (`apply_config_diff(path, diff)` with a free-form path) are
     explicitly REJECTED as a design — this is unbounded write access regardless of signing or
     ACLs. If config edits are needed at all, they must be schema-validated edits to a fixed,
     pre-enumerated set of known files, never an arbitrary path. Sensitive paths (`authorized_keys`,
     `sudoers.d/*`, cron, systemd unit files, anything under a user's home `.ssh`) must never be
     reachable through this mechanism, full stop — no whitelist entry may touch them, regardless of
     how the action is framed or parameterized.
   * This whitelist design is required BEFORE direct execution can ship as a real feature, not
     deferred as "separate work" the way v1 treated it. A whitelist is only as strong as its most
     dangerous entry; if any entry allows effectively arbitrary write/execute, the whole control is
     void.

4. **Independent sub-agent-side logging,** unchanged from v1 — every executed command logged
   locally on the target, independent of the core's own logs.

5. **Ephemeral, scoped Tailscale auth keys for setup,** unchanged from v1.

6. **Opt-in consent screen for direct execution** must state the real risk plainly, not in
   reassuring/minimizing language: Kratos can be manipulated by data it reads from the target (e.g.
   a crafted log entry) into proposing a harmful action; enabling this means Kratos can carry that
   action out directly rather than only showing it to the human. Reversible any time via settings,
   not a one-time irreversible choice made before the user has context to evaluate it.

7. **The critical-approval gate (typed EXECUTE) is required in BOTH modes** and is not shortened or
   skipped by opting into direct execution. The toggle changes only what EXECUTE does once confirmed
   — copy the command (opted out) vs. dispatch to the sub-agent (opted in). Same visual treatment,
   same friction, same information disclosed (effect/reversibility/blast-radius), in both cases.
   The effect/reversibility/blast-radius shown on the approval screen must be sourced from the
   trusted whitelist action definition, never LLM-generated — the LLM selects a whitelisted action
   and parameters; the risk disclosure is derived from code, so an injected core cannot pair a
   harmful action with a reassuring false summary.

8. **Known residual risk, not solved by any of the above:** the security review's point 3 stands
   even with informed opt-in consent — a beginner user may not be able to judge whether a specific
   proposed command is subtly malicious, even after enabling direct execution deliberately and
   understanding the general risk in the abstract. Worth considering (not yet designed): flagging in
   the approval screen itself when a proposed action touches an unusually sensitive category, as an
   additional signal — not a replacement for the whitelist's hard constraints, which must hold
   regardless of whether this softer signal is ever built.

**Explicitly corrected from v1:** reversibility of this decision (we can turn off direct-execution
as a feature if it goes wrong) is not the same as reversibility of harm (a bad executed command
against a real user's production server may cause irreversible damage — data loss, persistent
backdoor). Do not treat "we can revisit this" as sufficient justification on its own; weigh the
un-reversible half explicitly when deciding whether direct-execution ships at all, and treat the
whitelist narrowness (control 3) as the actual load-bearing decision, not a formality to fill in
later.

## Kratos-core-side pairing flow (Tailscale account connection + target onboarding)

Unchanged from v1 — see the accompanying design conversation for the full onboarding flow (OAuth
connection, per-target pairing, failure/edge-case states, account-switch handling). This flow now
additionally includes the direct-execution opt-in screen (control 6 above) as a distinct step,
separate from and not bundled into the base pairing flow.

## What this doc does NOT cover (separate, not-yet-designed/built work)

* The sub-agent's own internal implementation (whitelist enforcement, signature verification,
  telemetry forwarding) — none of this exists in code yet; this doc and the accompanying design
  work describe the intended target architecture, not current state.
* Confirmed via direct codebase audit: Kratos currently has no sub-agent, no Tailscale integration,
  and no Textual TUI. The current implementation is a single core process reaching one target over
  SSH, with a Rich + `prompt_toolkit` REPL and a blocking `input()` approval prompt. Nothing in this
  doc is a "fix" to existing code — it's a target design for future implementation.
* The Kratos-core-side UI for both remediation modes — tracked in the accompanying design
  conversation.
* Any changes to the eval suite (C6 and F1–F3) — needs rework once real code exists, specifically
  to test: whitelist enforcement holds under injection attempts, the opted-out (recommend-only)
  path is fully unaffected by injection since it never executes anything, and the opted-in path's
  whitelist genuinely rejects out-of-scope actions even when a plausible-looking malicious proposal
  is generated.

## Action items before any of this ships

* [ ] Update CLAUDE.md to reference this doc (v2) and mark the 2026-07-16 boundary as
      modified-not-reversed: default behavior remains recommend-only; direct execution is an
      explicit, narrow, opt-in exception with its own hard constraints (control 3).
* [ ] Design and build the sub-agent itself: telemetry forwarding first (capability 1, lower risk,
      ships independently), direct-execution whitelist second (capability 2, gated on control 3's
      design actually being narrow — do not ship a whitelist with any arbitrary-path or
      arbitrary-write entry).
* [ ] Design and build the opt-in consent screen (control 6) as its own dedicated UI, not folded
      into general pairing.
* [ ] Rework eval suite C6/F1–F3 per the corrected scope above, once real code exists.
* [ ] Before shipping control 3's whitelist, have it independently reviewed again specifically for
      arbitrary-write/arbitrary-execute entries disguised as narrow actions — this is the exact
      failure mode v1 shipped with undetected until review.
