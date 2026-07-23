from __future__ import annotations

from typing import TYPE_CHECKING

# Per-model pricing in USD per 1M tokens (input, output)
# Updated: 2026-07
MODEL_PRICING: dict[str, dict[str, float]] = {
    # Anthropic
    "claude-opus-4-8":              {"input": 15.0,  "output": 75.0},
    "claude-sonnet-4-6":            {"input": 3.0,   "output": 15.0},
    "claude-haiku-4-5-20251001":    {"input": 0.8,   "output": 4.0},
    "claude-3-5-sonnet-20241022":   {"input": 3.0,   "output": 15.0},
    "claude-3-5-haiku-20241022":    {"input": 0.8,   "output": 4.0},
    "claude-3-opus-20240229":       {"input": 15.0,  "output": 75.0},
    # OpenAI
    "gpt-4o":                       {"input": 2.5,   "output": 10.0},
    "gpt-4o-mini":                  {"input": 0.15,  "output": 0.60},
    "gpt-4-turbo":                  {"input": 10.0,  "output": 30.0},
    "gpt-3.5-turbo":                {"input": 0.5,   "output": 1.5},
    "o1":                           {"input": 15.0,  "output": 60.0},
    "o1-mini":                      {"input": 3.0,   "output": 12.0},
    "o3-mini":                      {"input": 1.1,   "output": 4.4},
    # Google
    "gemini-1.5-pro":               {"input": 3.5,   "output": 10.5},
    "gemini-1.5-flash":             {"input": 0.075, "output": 0.30},
    "gemini-2.0-flash":             {"input": 0.10,  "output": 0.40},
}

# Fallback pricing for unknown models (conservative estimate)
_FALLBACK_PRICING = {"input": 5.0, "output": 15.0}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return cost in USD for a given model and token counts."""
    pricing = _get_pricing(model)
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return round(input_cost + output_cost, 8)


def _get_pricing(model: str) -> dict[str, float]:
    """Exact match first, then prefix match for versioned model names."""
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    # Prefix match — e.g. "claude-sonnet-4-6-20250101" → "claude-sonnet-4-6"
    for key in MODEL_PRICING:
        if model.startswith(key):
            return MODEL_PRICING[key]
    return _FALLBACK_PRICING


def get_pricing(model: str) -> dict[str, float]:
    return _get_pricing(model)
