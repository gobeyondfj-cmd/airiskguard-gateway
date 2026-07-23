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
    # DeepSeek
    "deepseek-chat":                {"input": 0.14,  "output": 0.28},
    "deepseek-reasoner":            {"input": 0.55,  "output": 2.19},
    # Moonshot
    "moonshot-v1-8k":               {"input": 0.12,  "output": 0.12},
    "moonshot-v1-32k":              {"input": 0.24,  "output": 0.24},
    "moonshot-v1-128k":             {"input": 0.60,  "output": 0.60},
    # GLM (Zhipu AI)
    "glm-4":                        {"input": 0.14,  "output": 0.14},
    "glm-4-flash":                  {"input": 0.01,  "output": 0.01},
    "glm-4-air":                    {"input": 0.07,  "output": 0.07},
    # MiniMax
    "abab6.5s-chat":                {"input": 0.10,  "output": 0.10},
    "abab5.5-chat":                 {"input": 0.015, "output": 0.015},
    # Mistral
    "mistral-large-latest":         {"input": 2.0,   "output": 6.0},
    "mistral-small-latest":         {"input": 0.1,   "output": 0.3},
    "codestral-latest":             {"input": 0.2,   "output": 0.6},
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
