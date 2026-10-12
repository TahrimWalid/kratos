"""Model prices: the one rate table every cost estimate uses.

Rates are USD per 1M tokens (input, output) -- list prices, approximate; the
provider's bill is the real figure. The built-in table is a starting point; the
person corrects or adds prices in Settings -> Budget (`budget.model_rates`,
stored in `app_settings` so every Kratos process sees the same table).

Cost of one call, in order of preference (docs/phase0/0.4 §3.6):
  1. the provider's own figure, when the response reports one (`usage.cost`);
  2. tokens x this table;
  3. unknown -- no price on file: token caps still apply.
A model served from this machine (local Ollama / llama.cpp) costs 0.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

MODEL_RATES_KEY = "budget.model_rates"

# (input, output) USD per 1M tokens. Approximate list prices.
DEFAULT_RATES: dict[str, tuple[float, float]] = {
    "gemini-3.1-flash-lite": (0.10, 0.40),
    "gemini-3.1-pro-preview": (1.25, 5.00),
}

ESTIMATE_NOTE = "Costs are estimates from list prices — your provider's bill is the real figure."

# Where a ledger row's cost came from.
COST_PROVIDER = "provider"
COST_RATE_TABLE = "rate_table"
COST_UNKNOWN = "unknown"
COST_LOCAL = "local"

_MAX_RATE = 10_000.0   # USD per 1M tokens: far above any real price, catches a typo like 125 vs 1.25 x 100
_MAX_MODELS = 200
_MAX_NAME = 200


def _rate_value(value: Any, model: str) -> float:
    if isinstance(value, bool):
        raise SettingError(f"{model}: a price is a number of dollars per 1M tokens")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise SettingError(f"{model}: a price is a number of dollars per 1M tokens") from None
    if not math.isfinite(number) or number < 0 or number > _MAX_RATE:
        raise SettingError(f"{model}: a price must be between 0 and {_MAX_RATE:,.0f} dollars per 1M tokens")
    return number


def _validate_rates(value: Any) -> dict[str, list[float]]:
    """{model: [input, output]} -- USD per 1M tokens, each 0..10,000."""
    if not isinstance(value, dict):
        raise SettingError("the price table maps a model name to [input, output] dollars per 1M tokens")
    if len(value) > _MAX_MODELS:
        raise SettingError(f"at most {_MAX_MODELS} models in the price table")
    out: dict[str, list[float]] = {}
    for raw_name, pair in value.items():
        name = str(raw_name).strip()
        if not name or len(name) > _MAX_NAME:
            raise SettingError("a model name in the price table is empty or too long")
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise SettingError(f"{name}: give two prices, [input, output] dollars per 1M tokens")
        out[name] = [_rate_value(pair[0], name), _rate_value(pair[1], name)]
    return out


settings_store.register(SettingSpec(
    key=MODEL_RATES_KEY,
    default={k: list(v) for k, v in DEFAULT_RATES.items()},
    validate=_validate_rates,
    doc="Price per 1M tokens (input, output, USD) for each model -- used to estimate costs, not your bill.",
))


def rates(data_dir: Path | None) -> dict[str, tuple[float, float]]:
    """The price table in force (the person's, else the built-in one)."""
    if data_dir is None:
        return dict(DEFAULT_RATES)
    table = settings_store.get(MODEL_RATES_KEY, data_dir=data_dir)
    return {k: (float(v[0]), float(v[1])) for k, v in table.items()}


def set_rate(data_dir: Path, model: str, input_usd: Any, output_usd: Any, *, actor: str) -> None:
    """Add or correct one model's price (a person, from Settings)."""
    table = {k: list(v) for k, v in rates(data_dir).items()}
    table[str(model).strip()] = [input_usd, output_usd]
    settings_store.set(MODEL_RATES_KEY, table, data_dir=data_dir, actor=actor)


def remove_rate(data_dir: Path, model: str, *, actor: str) -> bool:
    table = {k: list(v) for k, v in rates(data_dir).items()}
    if table.pop(str(model).strip(), None) is None:
        return False
    settings_store.set(MODEL_RATES_KEY, table, data_dir=data_dir, actor=actor)
    return True


def rate_for(model: str, data_dir: Path | None) -> tuple[float, float] | None:
    return rates(data_dir).get(model or "")


def tokens_cost(rate: tuple[float, float] | None, prompt_tokens: int, completion_tokens: int) -> float | None:
    if rate is None:
        return None
    return (max(0, prompt_tokens) / 1e6) * rate[0] + (max(0, completion_tokens) / 1e6) * rate[1]


def call_cost(model: str, *, local: bool, prompt_tokens: int, completion_tokens: int,
              reported_cost: float | None, data_dir: Path | None) -> tuple[float | None, str]:
    """(cost_usd, cost_source) for one finished call."""
    if local:
        return 0.0, COST_LOCAL
    if reported_cost is not None and math.isfinite(reported_cost) and reported_cost >= 0:
        return float(reported_cost), COST_PROVIDER
    cost = tokens_cost(rate_for(model, data_dir), prompt_tokens, completion_tokens)
    return (cost, COST_RATE_TABLE) if cost is not None else (None, COST_UNKNOWN)


def reported_cost_from_usage(raw: Any) -> float | None:
    """The provider's own cost figure from a response's `usage` block, if any
    (e.g. OpenRouter's `usage.cost`, USD). Anything else -> None."""
    if not isinstance(raw, dict):
        return None
    value = raw.get("cost")
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None
