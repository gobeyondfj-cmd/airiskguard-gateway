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


class ProviderConfig(BaseModel):
    """Configuration for a single AI provider."""
    base_url: str
    format: Literal["openai", "anthropic", "ollama"] = "openai"
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    api_key_env: str = ""       # env var name for the API key

    def get_api_key(self) -> str:
        if self.api_key_env:
            return os.environ.get(self.api_key_env, "")
        return ""

    def host(self) -> str:
        """Extract hostname from base_url for intercept matching."""
        url = self.base_url.rstrip("/")
        if "://" in url:
            url = url.split("://", 1)[1]
        return url.split("/")[0]


# Built-in provider definitions — users can override or extend in config.yaml
BUILTIN_PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "format": "anthropic",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "base_url": "https://api.openai.com",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "OPENAI_API_KEY",
    },
    "azure_openai": {
        "base_url": "",           # set base_url in config — varies per deployment
        "format": "openai",
        "auth_header": "api-key",
        "auth_prefix": "",
        "api_key_env": "AZURE_OPENAI_API_KEY",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "GOOGLE_API_KEY",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "DEEPSEEK_API_KEY",
    },
    "moonshot": {
        "base_url": "https://api.moonshot.cn/v1",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "MOONSHOT_API_KEY",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/payi/v1",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "GLM_API_KEY",
    },
    "minimax": {
        "base_url": "https://api.minimax.chat/v1",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "MINIMAX_API_KEY",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "format": "openai",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "api_key_env": "MISTRAL_API_KEY",
    },
    "ollama": {
        "base_url": "http://localhost:11434",
        "format": "ollama",
        "auth_header": "",
        "auth_prefix": "",
        "api_key_env": "",
    },
}


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

    on_secrets_detected: Literal["block", "redact", "log"] = "block"
    on_pii_detected: Literal["block", "redact", "log"] = "redact"

    allowed_models: list[str] = Field(default_factory=lambda: [
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "deepseek-chat",
        "moonshot-v1-8k",
        "glm-4",
    ])
    model_allowlist_enabled: bool = True
    on_disallowed_model: Literal["block", "log"] = "block"

    # Provider registry — built-ins merged with any user overrides
    providers: dict[str, dict] = Field(default_factory=dict)

    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    policy_server: PolicyServerConfig = Field(default_factory=PolicyServerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    log_level: str = "INFO"

    def resolved_providers(self) -> dict[str, ProviderConfig]:
        """Merge built-ins with user-defined providers. User overrides win."""
        merged: dict[str, dict] = {**BUILTIN_PROVIDERS, **self.providers}
        return {k: ProviderConfig(**v) for k, v in merged.items()}

    def intercepted_hosts(self) -> set[str]:
        """All hostnames the proxy should intercept."""
        hosts: set[str] = set()
        for p in self.resolved_providers().values():
            h = p.host()
            if h:
                hosts.add(h)
        return hosts

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

# What to do when sensitive data is detected outbound
on_secrets_detected: block    # block | redact | log
on_pii_detected: redact       # block | redact | log

# Approved model list
model_allowlist_enabled: true
on_disallowed_model: block
allowed_models:
  - claude-sonnet-4-6
  - claude-haiku-4-5-20251001
  - gpt-4o
  - gpt-4o-mini
  - deepseek-chat
  - moonshot-v1-8k

# Provider API keys — set the env vars below, or override base_url per provider
# The gateway reads these to authenticate routed requests.
# Example: DEEPSEEK_API_KEY=sk-xxx in your environment
#
# Built-in providers (no config needed, just set the env var):
#   anthropic   → ANTHROPIC_API_KEY
#   openai      → OPENAI_API_KEY
#   deepseek    → DEEPSEEK_API_KEY   (https://api.deepseek.com)
#   moonshot    → MOONSHOT_API_KEY   (https://api.moonshot.cn/v1)
#   glm         → GLM_API_KEY        (https://open.bigmodel.cn/api/payi/v1)
#   minimax     → MINIMAX_API_KEY    (https://api.minimax.chat/v1)
#   mistral     → MISTRAL_API_KEY    (https://api.mistral.ai/v1)
#   ollama      → no key needed      (http://localhost:11434)
#
# Add a custom provider or override a built-in:
# providers:
#   my_private_llm:
#     base_url: https://llm.internal.company.com/v1
#     format: openai           # openai | anthropic | ollama
#     auth_header: Authorization
#     auth_prefix: "Bearer "
#     api_key_env: MY_LLM_API_KEY

# Smart routing rules — evaluated in order, first match wins
# routing:
#   rules:
#     - match: contains_pii
#       action: route_to
#       destination: local_ollama    # send PII to local model, never leaves machine
#     - match: contains_financial_data
#       action: route_to
#       destination: deepseek_cheap  # financial data → cheaper model
#     - match: model_pattern
#       model_pattern: "gpt-4*"
#       action: route_to
#       destination: gpt_mini        # downgrade expensive models
#   destinations:
#     local_ollama:
#       provider: ollama
#       model: llama3.2
#     deepseek_cheap:
#       provider: deepseek
#       model: deepseek-chat
#     gpt_mini:
#       provider: openai
#       model: gpt-4o-mini

# Team tier
policy_server:
  url: ""
  api_key: ""

audit:
  local_path: ""
  ship_to_server: false
"""
