from __future__ import annotations

# Model pricing in USD per 1M tokens (input, output) — refreshed July 2026
MODEL_PRICING: dict[str, dict[str, float]] = {
    # Anthropic — Claude
    "claude-fable-5":              {"input": 10.0,  "output": 50.0},
    "claude-mythos-5":             {"input": 10.0,  "output": 50.0},
    "claude-opus-4-8":             {"input": 5.0,   "output": 25.0},
    "claude-opus-4-7":             {"input": 5.0,   "output": 25.0},
    "claude-sonnet-5":             {"input": 3.0,   "output": 15.0},
    "claude-sonnet-4-6":           {"input": 3.0,   "output": 15.0},
    "claude-haiku-4-5-20251001":   {"input": 1.0,   "output": 5.0},
    "claude-3-5-sonnet-20241022":  {"input": 3.0,   "output": 15.0},
    "claude-3-5-haiku-20241022":   {"input": 0.8,   "output": 4.0},
    "claude-3-opus-20240229":      {"input": 15.0,  "output": 75.0},

    # OpenAI — GPT-5.6 series (July 2026)
    "gpt-5.6-sol":    {"input": 5.0,   "output": 30.0},
    "gpt-5.6-terra":  {"input": 2.5,   "output": 15.0},
    "gpt-5.6-luna":   {"input": 1.0,   "output": 6.0},
    "o3":             {"input": 2.0,   "output": 8.0},
    "gpt-4.1":        {"input": 2.0,   "output": 8.0},
    "gpt-4.1-mini":   {"input": 0.4,   "output": 1.6},
    "gpt-4o":         {"input": 2.5,   "output": 10.0},
    "gpt-4o-mini":    {"input": 0.15,  "output": 0.60},
    "gpt-4-turbo":    {"input": 10.0,  "output": 30.0},

    # DeepSeek — V4 series (July 2026)
    "deepseek-v4-pro":    {"input": 0.27,  "output": 1.10},
    "deepseek-v4-flash":  {"input": 0.30,  "output": 0.50},
    # Legacy aliases (deprecated July 24, 2026)
    "deepseek-chat":      {"input": 0.14,  "output": 0.28},
    "deepseek-reasoner":  {"input": 0.55,  "output": 2.19},

    # Moonshot / Kimi
    "kimi-k3":                   {"input": 1.0,  "output": 3.0},
    "kimi-k2.7-code":            {"input": 0.5,  "output": 1.5},
    "kimi-k2.7-code-highspeed":  {"input": 0.5,  "output": 1.5},
    "kimi-k2.6":                 {"input": 0.3,  "output": 0.9},
    "moonshot-v1-8k":            {"input": 0.12, "output": 0.12},
    "moonshot-v1-32k":           {"input": 0.24, "output": 0.24},
    "moonshot-v1-128k":          {"input": 0.60, "output": 0.60},

    # GLM / Zhipu AI
    "glm-4.5":       {"input": 0.20,  "output": 1.10},
    "glm-4.5-air":   {"input": 0.07,  "output": 0.28},
    "glm-4.5-x":     {"input": 0.14,  "output": 0.55},
    "glm-4.5-airx":  {"input": 0.07,  "output": 0.28},
    "glm-4.5-flash": {"input": 0.0,   "output": 0.0},   # free tier
    "glm-4":         {"input": 0.14,  "output": 0.14},
    "glm-4-flash":   {"input": 0.01,  "output": 0.01},

    # MiniMax
    "MiniMax-M3":              {"input": 1.0,   "output": 4.0},
    "MiniMax-M2.7":            {"input": 0.4,   "output": 1.6},
    "MiniMax-M2.7-highspeed":  {"input": 0.4,   "output": 1.6},
    "MiniMax-M2.5":            {"input": 0.2,   "output": 0.8},
    "MiniMax-M2.5-highspeed":  {"input": 0.2,   "output": 0.8},
    "MiniMax-M2.1":            {"input": 0.15,  "output": 0.60},
    "MiniMax-M2.1-highspeed":  {"input": 0.15,  "output": 0.60},

    # Mistral
    "mistral-large-latest":   {"input": 2.0,  "output": 6.0},
    "mistral-medium-latest":  {"input": 0.4,  "output": 2.0},
    "mistral-small-latest":   {"input": 0.1,  "output": 0.3},
    "ministral-8b-latest":    {"input": 0.1,  "output": 0.1},
    "devstral-medium-latest": {"input": 1.0,  "output": 3.0},
    "codestral-latest":       {"input": 0.2,  "output": 0.6},

    # Google Gemini
    "gemini-3.6-flash":      {"input": 1.5,   "output": 7.5},
    "gemini-3.5-flash":      {"input": 0.15,  "output": 0.60},
    "gemini-3.5-flash-lite": {"input": 0.075, "output": 0.30},
    "gemini-2.5-pro":        {"input": 3.5,   "output": 10.5},
    "gemini-2.5-flash":      {"input": 0.15,  "output": 0.60},
    "gemini-2.5-flash-lite": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro":        {"input": 3.5,   "output": 10.5},
    "gemini-1.5-flash":      {"input": 0.075, "output": 0.30},
    "gemini-2.0-flash":      {"input": 0.10,  "output": 0.40},

    # Azure OpenAI
    "gpt-5":       {"input": 5.0,  "output": 30.0},
    "gpt-5-mini":  {"input": 1.25, "output": 5.0},
    "gpt-5-nano":  {"input": 0.3,  "output": 1.2},
}

_FALLBACK_PRICING = {"input": 5.0, "output": 15.0}


def calculate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Return cost in USD for a given model and token counts."""
    pricing = _get_pricing(model)
    return round(
        (input_tokens / 1_000_000) * pricing["input"] +
        (output_tokens / 1_000_000) * pricing["output"],
        8,
    )


def _get_pricing(model: str) -> dict[str, float]:
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    # Prefix match for versioned names
    for key in MODEL_PRICING:
        if model.startswith(key):
            return MODEL_PRICING[key]
    return _FALLBACK_PRICING


def get_pricing(model: str) -> dict[str, float]:
    return _get_pricing(model)
