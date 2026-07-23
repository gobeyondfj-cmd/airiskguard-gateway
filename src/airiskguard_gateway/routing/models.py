from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class RoutingDestination:
    """A named target endpoint to route traffic to."""
    provider: str               # any provider name from the registry e.g. "deepseek", "ollama"
    model: str
    base_url: str = ""          # override the provider's base_url (optional)
    api_key_env: str = ""       # override the provider's api_key_env (optional)


@dataclass
class RoutingRule:
    """A single rule evaluated in order. First match wins."""
    match: Literal[
        "contains_pii",
        "contains_secrets",
        "contains_financial_data",
        "model_pattern",
        "provider",
        "task_type",
        "complexity",
        "language",
        "always",
    ]
    action: Literal["route_to", "block", "allow"]
    destination: str = ""       # name of RoutingDestination (required when action=route_to)
    model_pattern: str = ""     # glob e.g. "gpt-4*" (only for match=model_pattern)
    provider: str = ""          # e.g. "openai" (only for match=provider)
    task_type: str = ""         # e.g. "simple_qa" (only for match=task_type)
    complexity: str = ""        # "low" | "medium" | "high" (only for match=complexity)
    language: str = ""          # "zh" | "en" | "ja" | "ko" etc. (only for match=language)


@dataclass
class RoutingDecision:
    action: Literal["route_to", "block", "allow"]
    destination: RoutingDestination | None = None
    matched_rule: RoutingRule | None = None
    session_pinned: bool = False    # True if decision came from session store


# Financial data keywords
FINANCIAL_KEYWORDS = frozenset([
    "account number", "account balance", "routing number", "wire transfer",
    "iban", "swift", "brokerage", "portfolio", "trade", "equity", "bond",
    "revenue", "earnings", "ebitda", "p&l", "balance sheet", "income statement",
    "tax return", "tax id", "ein ", "financial statement",
])
