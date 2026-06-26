from __future__ import annotations

from datetime import datetime, UTC
from typing import Literal

from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    rule_id: str
    name: str
    enabled: bool = True
    checker: str
    action: Literal["block", "redact", "log"]
    severity_threshold: str = "medium"
    conditions: dict = Field(default_factory=dict)


class PolicySet(BaseModel):
    policy_id: str
    team_id: str | None = None
    version: int
    rules: list[PolicyRule] = Field(default_factory=list)
    model_allowlist: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
