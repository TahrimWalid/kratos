# Security policy

Kratos is a security tool that reads the machines you point it at, so a flaw in it can
matter more than in most software. Thank you for reporting one privately.

## Reporting a vulnerability

Use GitHub's private reporting: on this repository, open **Security → Report a
vulnerability**. Please don't open a public issue for a security problem.

Include what you found, how to reproduce it, the Kratos version (`kratos --version`) and,
for the sub-agent, the agent version shown in `/subagent`. This is a one-person project:
you will get a reply as soon as possible, and a fix is worked on before anything is made
public.

Especially welcome:

- a way for Kratos to run something on, or change, a monitored machine when the fix
  channel is off, or to run something outside its allowlist when it is on;
- text written on a monitored machine (a log line, a file name, a user name) that
  changes what Kratos does, hides a finding or reaches the terminal as control codes;
- a way around the pinned, encrypted agent link, or an agent accepting data it should
  refuse;
- data leaving the Kratos host that the documentation says doesn't.

## Supported versions

The latest release on PyPI (`kratos-security-assistant`) and the `main` branch. For the
sub-agent, the version the current Kratos installs: update an agent in place with `g` in
`/subagent`.

## How fixes reach you

A fixed vulnerability gets a GitHub Security Advisory on this repository, with a CVE when
one applies. Advisories flow into the public advisory databases (GitHub, OSV, PyPA), so
the tools many people already run warn about an affected install or fork on their own:
`pip-audit`, Dependabot, OSV-Scanner. To hear about them directly, watch this repository
with **Custom → Security alerts**. Then:

- **Kratos:** `pip install -U kratos-security-assistant` (or `git pull` in a checkout);
- **sub-agents:** `g` in `/subagent` for each machine, or re-run its installer.

## Kratos's own dependencies

Every push and every day, CI installs Kratos the way a user does and audits exactly what
was installed against the public advisory data (the `deps-audit` job in
`scripts/ci/jobs.toml`). An advisory is only accepted with its reason written next to
that job. Currently accepted:

- **CVE-2025-69872** (diskcache, no fixed release yet): unsafe pickle in a cache folder.
  Only the optional `sigma` extra brings it in, through pySigma, and the cache is in your
  own folder: someone who can write there can already run code as you.

The sub-agent that runs on monitored machines uses only the Python standard library, so
its exposure is the machine's own Python, which Kratos's package check already covers.

## The SSH certificate authority key

If you turn on SSH certificates (`kratos ssh-ca`), the key that signs Kratos's login
certificates is the **most valuable secret on the Kratos host**: a copy of it can sign a
login certificate for every enrolled machine. The certificates it signs still expire in
minutes and stay bound to this computer's address, but the CA key itself must stay private.

- It lives in `<data folder>/ssh-ca/` (the folder is `0700`, files `0600`) and **never
  leaves this computer** — Kratos never writes it to a monitored machine.
- Protect it with the strongest mode your host supports (`kratos ssh-ca status` shows which
  is in use): **tpm** (sealed to this machine's TPM — a copied file is useless elsewhere),
  **agent** (held in a dedicated ssh-agent, unlocked after a reboot), **token** (a PKCS#11
  device), or **file** (an owner-only file; honest about the trade-off).
- **Back it up** — copy the `ssh-ca/` folder somewhere safe, together with your database
  backup and your agent-link keys. Losing it means re-enrolling every machine. Keep the
  backup private; treat it like the live key.
- Rotate it with `kratos ssh-ca rotate` / `promote`; the retired key is trusted for a week
  so no run fails during the change.

The Python that runs Kratos needs security fixes too. `kratos doctor` (and `/doctor`)
warns 90 days before python.org stops them for your version and after it has; Python 3.10
reaches that point at the end of October 2026. A Python that came with your Linux
distribution keeps getting fixes from the distribution, so for it the doctor only says so.

## The signing key

Kratos's Ed25519 signing key (`<data folder>/signing/`, folder `0700`, key `0600`) signs incident
bundles (`/export`, OpenSSH `SSHSIG`, namespace `kratos-export`), the evidence ledger's daily
checkpoints, and — when you turn it on — webhook messages (`v1a`). It never leaves this computer and
is never used for SSH logins or the agent link.

- A bundle's signature proves the bundle wasn't changed after this key signed it. That is worth
  something only if the person checking knows the key is yours: **give them the fingerprint some
  other way than with the bundle** (`/doctor` → "signing key", or `kratos signing status`).
- Whoever holds a copy of the key can sign bundles as you, and — with write access to `kratos.db` —
  rebuild the evidence ledger's chain. Keep it private.
- **Back it up** with your other keys: a copy is made in `signing/backup/` when the key is created;
  copy the whole `signing/` folder somewhere safe with your database backup.
- `kratos signing rotate` makes a new key and keeps the old public key in `signing/retired/`, so
  bundles and checkpoints signed before the change still verify.

## Users, tokens and the shared Open WebUI secret

Other people reach Kratos only through `kratos serve` (chat and MCP over HTTP), with a
token that belongs to a Kratos user and expires (90 days by default). Everything that
administers Kratos — users, roles, scopes, tokens, channels, settings, budgets,
certificates, keys, the fix channel, full exports — is done only by the owner at the
Kratos computer (TUI or CLI) and is refused over the network for every role, admins and
the owner's own tokens included.

A **gateway token** for a shared Open WebUI has no person of its own: each request must
carry Open WebUI's signed identity (an HS256 JWT made with
`FORWARD_USER_INFO_HEADER_JWT_SECRET`), which Kratos verifies and maps to a Kratos user
the owner created. Unsigned forwarded headers are never trusted. **The gateway token and
its secret together can act as every mapped user**: keep both private, store the secret
only in Open WebUI's environment and Kratos's owner-only `gateway-secrets/` folder. If the
token may have leaked, `kratos tokens rotate` it (the replacement keeps the secret); if the
secret may have leaked, make a new `--gateway` token (it comes with a new secret), update
Open WebUI, and revoke the old token. Every allowed and refused action is in the append-only
audit trail (`kratos audit`).
