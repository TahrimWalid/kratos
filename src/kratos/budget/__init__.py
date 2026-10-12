"""Model spending: a usage ledger, hard caps and a circuit breaker (Phase 0 / 0.4).

Every request to a model goes through one guarded function in
`kratos.llm_interface` (`_metered_call`), which reserves budget before the
request (`guard.before_call`) and records what was actually used after it
(`guard.after_call`). Caps are user settings (`budget.*`, Settings -> Budget),
read fresh on every check. OWASP LLM10:2025 "Unbounded Consumption".

  pricing.py  rate table + the person's corrections
  ledger.py   budget_ledger / budget_state tables, reservations, totals
  limits.py   the budget.* settings and a Limits snapshot
  guard.py    before_call / after_call, BudgetExceeded, the over-cap prompt
  breaker.py  pauses an unattended source that keeps failing or looping
"""
