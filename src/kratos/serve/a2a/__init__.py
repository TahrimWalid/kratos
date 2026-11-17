"""The agent doors of `kratos serve` (docs/phaseE/E.5): A2A 1.0 (an Agent Card and a task
endpoint over HTTP+JSON/REST) and AG-UI (an event stream for one run).

Both are OFF until a person turns them on (`a2a.enabled`, `agui.enabled`), take only
person tokens that carry the `agents` door, and run through the same engines, answer
checks, scopes, budgets and run records as the chat and MCP doors. Neither can reach an
approval, the fix channel or any person-only action: no `INPUT_REQUIRED`, no
`AUTH_REQUIRED`, no push notifications.
"""
