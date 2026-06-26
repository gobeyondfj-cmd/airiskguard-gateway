from __future__ import annotations

import os
import hashlib
import platform
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


CONFIG_DIR = Path.home() / ".config" / "airiskguard-gateway"
DATA_DIR = Path.home() / ".local" / "share" / "airiskguard-gateway"
RUN_DIR = Path.home() / ".local" / "run"
LOG_DIR = Path.home() / ".local" / "log"


class OutboundPolicy(BaseModel):
    action: Literal["block", "redact", "log"] = "block"
    enabled_checkers: list[str] = ["secrets", "pii"]


class InboundPolicy(BaseModel):
    action: Literal["block", "log"] = "log"
    enabled_checkers: list[str] = ["vuln_code"]


class ModelAllowlist(BaseModel):
    enabled: bool = True
    allowed_models: list[str] = [
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku-20241022",
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
    ]
    action: Literal["block", "log"] = "block"


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
    outbound: OutboundPolicy = Field(default_factory=OutboundPolicy)
    inbound: InboundPolicy = Field(default_factory=InboundPolicy)
    model_allowlist: ModelAllowlist = Field(default_factory=ModelAllowlist)
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
# Full docs: https://docs.airiskguard.ai/gateway/config

listen_host: "127.0.0.1"
listen_port: 8080
log_level: "INFO"

outbound:
  # action: block | redact | log
  action: block
  enabled_checkers:
    - secrets
    - pii

inbound:
  # action: block | log
  # Note: block holds the response; log is non-blocking (scans after stream closes)
  action: log
  enabled_checkers:
    - vuln_code

model_allowlist:
  enabled: true
  action: block
  allowed_models:
    - claude-opus-4-8
    - claude-sonnet-4-6
    - claude-haiku-4-5-20251001
    - claude-3-5-sonnet-20241022
    - claude-3-5-haiku-20241022
    - gpt-4o
    - gpt-4o-mini

# Team tier: connect to a policy server for centralized management
policy_server:
  url: ""
  api_key: ""
  sync_interval_seconds: 60

audit:
  # local_path: leave empty to use default (~/.local/share/airiskguard-gateway/audit.jsonl)
  local_path: ""
  max_size_mb: 100
  ship_to_server: false
"""
