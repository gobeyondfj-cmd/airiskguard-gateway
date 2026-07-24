from __future__ import annotations

# Known model versions per provider — used for the model selection UI
# Users can still type in any model ID not listed here
PROVIDER_MODELS: dict[str, list[dict]] = {
    "anthropic": [
        {"id": "claude-opus-4-8",             "label": "Claude Opus 4.8",         "tier": "flagship"},
        {"id": "claude-sonnet-4-6",            "label": "Claude Sonnet 4.6",       "tier": "standard"},
        {"id": "claude-haiku-4-5-20251001",    "label": "Claude Haiku 4.5",        "tier": "fast"},
        {"id": "claude-3-5-sonnet-20241022",   "label": "Claude 3.5 Sonnet",       "tier": "standard"},
        {"id": "claude-3-5-haiku-20241022",    "label": "Claude 3.5 Haiku",        "tier": "fast"},
        {"id": "claude-3-opus-20240229",       "label": "Claude 3 Opus",           "tier": "flagship"},
    ],
    "openai": [
        {"id": "gpt-4o",          "label": "GPT-4o",          "tier": "flagship"},
        {"id": "gpt-4o-mini",     "label": "GPT-4o Mini",     "tier": "fast"},
        {"id": "o1",              "label": "o1",               "tier": "reasoning"},
        {"id": "o1-mini",         "label": "o1 Mini",          "tier": "reasoning"},
        {"id": "o3-mini",         "label": "o3 Mini",          "tier": "reasoning"},
        {"id": "gpt-4-turbo",     "label": "GPT-4 Turbo",     "tier": "standard"},
        {"id": "gpt-3.5-turbo",   "label": "GPT-3.5 Turbo",   "tier": "fast"},
    ],
    "deepseek": [
        {"id": "deepseek-chat",      "label": "DeepSeek Chat",      "tier": "standard"},
        {"id": "deepseek-reasoner",  "label": "DeepSeek Reasoner",  "tier": "reasoning"},
    ],
    "moonshot": [
        {"id": "moonshot-v1-8k",    "label": "Moonshot v1 8K",    "tier": "fast"},
        {"id": "moonshot-v1-32k",   "label": "Moonshot v1 32K",   "tier": "standard"},
        {"id": "moonshot-v1-128k",  "label": "Moonshot v1 128K",  "tier": "flagship"},
    ],
    "glm": [
        {"id": "glm-4",        "label": "GLM-4",        "tier": "flagship"},
        {"id": "glm-4-air",    "label": "GLM-4 Air",    "tier": "standard"},
        {"id": "glm-4-flash",  "label": "GLM-4 Flash",  "tier": "fast"},
    ],
    "minimax": [
        {"id": "abab6.5s-chat",  "label": "ABAB 6.5s",  "tier": "standard"},
        {"id": "abab5.5-chat",   "label": "ABAB 5.5",   "tier": "fast"},
    ],
    "mistral": [
        {"id": "mistral-large-latest",   "label": "Mistral Large",   "tier": "flagship"},
        {"id": "mistral-small-latest",   "label": "Mistral Small",   "tier": "fast"},
        {"id": "codestral-latest",       "label": "Codestral",       "tier": "code"},
    ],
    "google": [
        {"id": "gemini-2.0-flash",  "label": "Gemini 2.0 Flash",  "tier": "fast"},
        {"id": "gemini-1.5-pro",    "label": "Gemini 1.5 Pro",    "tier": "flagship"},
        {"id": "gemini-1.5-flash",  "label": "Gemini 1.5 Flash",  "tier": "fast"},
    ],
    "azure_openai": [
        {"id": "gpt-4o",       "label": "GPT-4o (Azure)",       "tier": "flagship"},
        {"id": "gpt-4o-mini",  "label": "GPT-4o Mini (Azure)",  "tier": "fast"},
        {"id": "gpt-4-turbo",  "label": "GPT-4 Turbo (Azure)",  "tier": "standard"},
    ],
    "ollama": [
        {"id": "llama3.2",    "label": "Llama 3.2",    "tier": "standard"},
        {"id": "llama3.1",    "label": "Llama 3.1",    "tier": "standard"},
        {"id": "mistral",     "label": "Mistral",      "tier": "standard"},
        {"id": "gemma2",      "label": "Gemma 2",      "tier": "standard"},
        {"id": "qwen2.5",     "label": "Qwen 2.5",     "tier": "standard"},
        {"id": "deepseek-r1", "label": "DeepSeek R1",  "tier": "reasoning"},
    ],
}

TIER_COLORS = {
    "flagship":  {"bg": "rgba(124,58,237,0.12)", "border": "rgba(124,58,237,0.3)", "color": "#a78bfa"},
    "standard":  {"bg": "rgba(0,212,255,0.08)",  "border": "rgba(0,212,255,0.2)",  "color": "#00d4ff"},
    "fast":      {"bg": "rgba(74,222,128,0.08)", "border": "rgba(74,222,128,0.2)", "color": "#4ade80"},
    "reasoning": {"bg": "rgba(251,146,60,0.08)", "border": "rgba(251,146,60,0.2)", "color": "#fb923c"},
    "code":      {"bg": "rgba(251,191,36,0.08)", "border": "rgba(251,191,36,0.2)", "color": "#fbbf24"},
}
