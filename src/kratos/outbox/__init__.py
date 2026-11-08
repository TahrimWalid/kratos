"""D.4 -- the outbox: every message Kratos sends to a receiver goes through here.

A producer (a trigger firing, a scheduled run's report, a live detection alert, a
finding's lifecycle change, the events cursor, a person's test) only ENQUEUES a row in
``kratos.db`` -> ``outbox``; a delivery worker sends it (``outbox.worker``). Rows are
durable (a restart retries what was not delivered), deduplicated per channel by a
stable ``message_id`` (the receiver's idempotency key: a retry carries the same id),
retried on the Standard Webhooks schedule, rendered and redacted before they are
stored, and kept -- delivered and dead alike -- until a person prunes them.

Modules:
  store     tables, enqueue, the worker lease, per-message claims, state moves, prune
  retry     the retry schedule and which failures are permanent
  channels  channel configuration (people-only edits), secrets, the four senders
  formats   kratos JSON, OCSF (pinned), ECS, RFC 5424 -- pure functions
  alerts    the notifier producers call (text alerts to channels by name)
  forward   the findings-change and events-cursor producers
  worker    the delivery loop: lease, due messages, rate caps, outage notices
  health    what /doctor and the status bar show
"""
