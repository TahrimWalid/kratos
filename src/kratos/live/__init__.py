"""Live-response checks (A.5): what is running right now, judged on Kratos.

The read lives in ``kratos.adapters.live_response`` (it ships in the sub-agent
bundle, stdlib only). This package judges one read on Kratos and saves the result
the rule engine reads:

- ``judge`` -- turn one parsed inventory into LIVE-001..007 signals;
- ``record`` -- read, judge, and save ``data_dir/live/live_response_<time>.json``;
- ``check`` -- the A.0 collection check (``live_response``, quick class).
"""
