from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class RoutingDestination:
    """A named target endpoint to route traffic to."""
    provider: Literal["anthropic", "openai", "ollama", "azure_openai", "google"]
    model: str
    base_url: str = ""          # override API base URL (required for ollama/private endpoints)
    api_key_env: str = ""       # env var name holding the API key for this destination


@dataclass
class RoutingRule:
    """A single rule evaluated in order. First match wins."""
    match: Literal[
        "contains_pii",
        "contains_secrets",
        "contains_financial_data",
        "model_pattern",
        "always",
    ]
    action: Literal["route_to", "block", "allow"]
    destination: str = ""       # name of RoutingDestination (required when action=route_to)
    model_pattern: str = ""     # glob-style pattern e.g. "gpt-4*" (only for match=model_pattern)


@dataclass
class RoutingDecision:
    action: Literal["route_to", "block", "allow"]
    destination: RoutingDestination | None = None
    matched_rule: RoutingRule | None = None


# Financial data keywords — simple but catches the most common cases
FINANCIAL_KEYWORDS = frozenset([
    "account number", "account balance", "routing number", "wire transfer",
    "iban", "swift", "brokerage", "portfolio", "trade", "equity", "bond",
    "revenue", "earnings", "ebitda", "p&l", "balance sheet", "income statement",
    "tax return", "tax id", "ein ", "financial statement",
])
