from __future__ import annotations

import os
import hashlib
import platform
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from airiskguard_gateway.routing.models import RoutingDestination, RoutingRule


CONFIG_DIR = Path.home() / ".config" / "airiskguard-gateway"
DATA_DIR = Path.home() / ".local" / "share" / "airiskguard-gateway"
RUN_DIR = Path.home() / ".local" / "run"
LOG_DIR = Path.home() / ".local" / "log"


class RoutingConfig(BaseModel):
    rules: list[dict] = Field(default_factory=list)
    destinations: dict[str, dict] = Field(default_factory=dict)

    def parsed_rules(self) -> list[RoutingRule]:
        return [RoutingRule(**r) for r in self.rules]

    def parsed_destinations(self) -> dict[str, RoutingDestination]:
        return {k: RoutingDestination(**v) for k, v in self.destinations.items()}


class PolicyServerConfig(BaseModel):
    url: str = ""
    api_key: str = ""
    sync_interval_seconds: int = 60


class AuditConfig(BaseModel):
    local_path: str = ""
    max_size_mb: int = 100
    ship_to_server: bool = False

    def resolved_path(self) -> Path:
        if self.local_path:
            return Path(self.local_path)
        return DATA_DIR / "audit.jsonl"


class GatewayConfig(BaseModel):
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080

    # Simple top-level actions (the 80/20 config)
    on_secrets_detected: Literal["block", "redact", "log"] = "block"
    on_pii_detected: Literal["block", "redact", "log"] = "redact"

    # Model allowlist
    allowed_models: list[str] = Field(default_factory=lambda: [
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
    ])
    model_allowlist_enabled: bool = True
    on_disallowed_model: Literal["block", "log"] = "block"

    # Smart routing
    routing: RoutingConfig = Field(default_factory=RoutingConfig)

    # Team tier
    policy_server: PolicyServerConfig = Field(default_factory=PolicyServerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: Path | None = None) -> "GatewayConfig":
        config_path = path or (CONFIG_DIR / "config.yaml")
        if config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            return cls.model_validate(data)
        return cls()

    def save(self, path: Path | None = None) -> None:
        config_path = path or (CONFIG_DIR / "config.yaml")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False, sort_keys=False)


def machine_id() -> str:
    raw = platform.node() + str(os.getuid() if hasattr(os, "getuid") else "")
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


DEFAULT_CONFIG_YAML = """\
# AIRiskGuard Gateway configuration
# Docs: https://docs.airiskguard.ai/gateway/config

listen_host: "127.0.0.1"
listen_port: 8080

# What to do when outbound violations are detected
on_secrets_detected: block    # block | redact | log
on_pii_detected: redact       # block | redact | log

# Which models your team is allowed to use
model_allowlist_enabled: true
on_disallowed_model: block
allowed_models:
  - claude-sonnet-4-6
  - claude-haiku-4-5-20251001
  - gpt-4o
  - gpt-4o-mini

# Smart routing — route traffic to different models based on content
# routing:
#   rules:
#     - match: contains_pii
#       action: route_to
#       destination: internal_llm
#     - match: model_pattern
#       model_pattern: "gpt-4*"
#       action: route_to
#       destination: gpt_4o_mini
#   destinations:
#     internal_llm:
#       provider: ollama
#       base_url: http://localhost:11434
#       model: llama3.2
#     gpt_4o_mini:
#       provider: openai
#       model: gpt-4o-mini

# Team tier: connect to a policy server for centralized management
policy_server:
  url: ""
  api_key: ""

audit:
  local_path: ""      # default: ~/.local/share/airiskguard-gateway/audit.jsonl
  ship_to_server: false
"""
