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
