"""Run records (docs/phaseB/B.5): one local trace per run, an optional OpenTelemetry copy.

`recorder` builds them (hooks in the model choke point, tool dispatch, collection,
the agent loop's guards and answer, pipelines and scheduled runs); `store` reads
them back; `view` prints them; `otel` exports them when the extra is installed and
the person turned it on."""
from kratos.trace import settings as _settings  # noqa: F401 -- registers trace.* settings
