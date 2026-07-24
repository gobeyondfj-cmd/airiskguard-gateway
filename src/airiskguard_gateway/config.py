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
    api_key: str = ""           # inline key (fallback if env var not set)

    def get_api_key(self) -> str:
        """Env var takes priority over inline key."""
        if self.api_key_env:
            key = os.environ.get(self.api_key_env, "")
            if key:
                return key
        return self.api_key

    def key_status(self) -> tuple[str, str]:
        """Returns (source, masked_key) for display."""
        if self.api_key_env:
            key = os.environ.get(self.api_key_env, "")
            if key:
                return "env", key[:8] + "..."
        if self.api_key:
            return "config", self.api_key[:8] + "..."
        return "missing", ""

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
    sticky_sessions: bool = True
    session_ttl_hours: int = 24

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

    # Gateway authentication
    # Free tier: single shared key — set AIRISKGUARD_GATEWAY_KEY env var or here
    gateway_key: str = ""
    # Team tier: path to a keys file with per-developer keys
    gateway_keys_file: str = ""

    # Inline API keys — alternative to env vars
    # These are merged into the matching provider config at runtime
    api_keys: dict[str, str] = Field(default_factory=dict)

    # Cost limits (0 = disabled, reset monthly)
    overall_limit_usd: float = 0.0
    per_provider_limits: dict[str, float] = Field(default_factory=dict)
    on_limit_reached: str = "block"  # "block" | "alert"

    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    policy_server: PolicyServerConfig = Field(default_factory=PolicyServerConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    log_level: str = "INFO"

    def resolved_providers(self) -> dict[str, ProviderConfig]:
        """Merge built-ins with user-defined providers. User overrides win.
        Inline api_keys are injected into the matching provider config."""
        merged: dict[str, dict] = {**BUILTIN_PROVIDERS, **self.providers}
        result: dict[str, ProviderConfig] = {}
        for name, data in merged.items():
            cfg = ProviderConfig(**data)
            # Inject inline key if provided and no env var key is set
            if name in self.api_keys and self.api_keys[name]:
                cfg = cfg.model_copy(update={"api_key": self.api_keys[name]})
            result[name] = cfg
        return result

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
# Docs: https://github.com/gobeyondfj-cmd/airiskguard-gateway#readme

listen_host: "127.0.0.1"
listen_port: 8080

# Gateway Authentication
# Without this, anyone who can reach the gateway can use it.
#
# Free tier — single shared key for your team:
#   Option 1: env var (recommended)
#     export AIRISKGUARD_GATEWAY_KEY=gw-your-secret-key
#   Option 2: inline here
# gateway_key: gw-your-secret-key
#
# Team tier — per-developer keys (one per line in a text file):
#   gateway_keys_file: /etc/airiskguard/keys.txt
#   Keys file format:
#     key=gw-abc123  name=john@company.com  team=engineering
#     key=gw-xyz789  name=jane@company.com  team=data
#
# Generate a key: airiskguard-gateway keygen

# What to do when sensitive data is detected outbound
on_secrets_detected: block    # block | redact | log
on_pii_detected: redact       # block | redact | log

# Cost limits (0 = no limit, resets on 1st of each month)
# overall_limit_usd: 200.00
# on_limit_reached: block   # block | alert (Slack only)
# per_provider_limits:
#   openai: 50.00
#   anthropic: 100.00
#   deepseek: 20.00

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

# API Keys (real provider keys — only needed on the gateway machine)
# Option 1 (recommended): env vars
#   export ANTHROPIC_API_KEY=sk-ant-...
#   export OPENAI_API_KEY=sk-...
#   export DEEPSEEK_API_KEY=sk-...
# Option 2: inline (env var takes priority)
# api_keys:
#   anthropic: sk-ant-...
#   openai: sk-...
#   deepseek: sk-...

# Smart routing rules
# routing:
#   sticky_sessions: true
#   rules:
#     - match: contains_pii
#       action: route_to
#       destination: local_ollama
#     - match: task_type
#       task_type: simple_qa
#       action: route_to
#       destination: deepseek_cheap
#   destinations:
#     local_ollama:
#       provider: ollama
#       model: llama3.2
#     deepseek_cheap:
#       provider: deepseek
#       model: deepseek-chat

# Team tier
policy_server:
  url: ""
  api_key: ""

audit:
  local_path: ""
  ship_to_server: false
"""
