"""Persistence checks (phase A.1): judging, on Kratos, the inventory the read returns.

The read itself (both transports, one parser) is kratos.adapters.persistence. Here:
`shapes` (the closed list of "worth a look" patterns), `baseline` (Kratos's first look
at each machine, in kratos.db), `judge` (inventory + baseline -> PERSIST-* findings),
`record` (judge, update the baseline, save the snapshot the findings engine reads) and
`check` (the two collection checks).
"""
