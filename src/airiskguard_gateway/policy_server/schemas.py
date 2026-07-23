from __future__ import annotations

from datetime import datetime, UTC
from typing import Any

from pydantic import BaseModel, Field


# ── Team ─────────────────────────────────────────────────────────────────────

class TeamCreate(BaseModel):
    name: str
    slug: str
    slack_webhook_url: str | None = None


class TeamOut(BaseModel):
    id: str
    name: str
    slug: str
    slack_webhook_url: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── API Keys ──────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: str
    provider: str
    real_key: str | None = None


class ApiKeyOut(BaseModel):
    id: str
    name: str
    provider: str
    created_at: datetime
    is_active: bool
    raw_key: str | None = None  # Only present on creation

    model_config = {"from_attributes": True}


# ── Policies ──────────────────────────────────────────────────────────────────

class PolicyRuleIn(BaseModel):
    rule_id: str
    name: str
    enabled: bool = True
    checker: str
    action: str
    severity_threshold: str = "medium"
    conditions: dict = Field(default_factory=dict)


class PolicyUpdate(BaseModel):
    rules: list[PolicyRuleIn] = Field(default_factory=list)
    model_allowlist: list[str] = Field(default_factory=list)


class PolicyOut(BaseModel):
    id: str
    team_id: str
    version: int
    rules: list[dict]
    model_allowlist: list[str]
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Events ────────────────────────────────────────────────────────────────────

class AuditEventIn(BaseModel):
    event_id: str
    timestamp: str
    machine_id: str
    provider: str
    model: str
    direction: str
    action_taken: str
    findings: list[dict] = Field(default_factory=list)
    request_id: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    latency_ms: int | None = None
    routed_to: str | None = None


class AuditEventOut(BaseModel):
    id: str
    machine_id: str
    provider: str
    model: str
    direction: str
    action_taken: str
    findings_count: int
    timestamp: datetime

    model_config = {"from_attributes": True}


class EventsQuery(BaseModel):
    limit: int = 50
    offset: int = 0
    action: str | None = None
    provider: str | None = None
    since_hours: int = 24
