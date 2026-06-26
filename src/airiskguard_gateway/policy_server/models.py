from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, UTC

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text,
    func, Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from airiskguard_gateway.policy_server.database import Base


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    slack_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="team", cascade="all, delete-orphan")
    policies: Mapped[list["Policy"]] = relationship(back_populates="team", cascade="all, delete-orphan")
    audit_events: Mapped[list["AuditEventRecord"]] = relationship(back_populates="team", cascade="all, delete-orphan")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Hashed gateway-issued key (for authentication)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The real provider key, stored encrypted (simple XOR with env secret for MVP)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    real_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    team: Mapped["Team"] = relationship(back_populates="api_keys")

    @staticmethod
    def generate() -> tuple[str, str]:
        """Returns (raw_key, key_hash). Store hash, give raw to client."""
        raw = "ag-" + secrets.token_urlsafe(40)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, key_hash

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    rules_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    model_allowlist_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    team: Mapped["Team"] = relationship(back_populates="policies")

    @property
    def rules(self) -> list:
        return json.loads(self.rules_json)

    @property
    def model_allowlist(self) -> list[str]:
        return json.loads(self.model_allowlist_json)


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True)
    machine_id: Mapped[str] = mapped_column(String(32), nullable=False)
    event_json: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    action_taken: Mapped[str] = mapped_column(String(20), nullable=False)
    direction: Mapped[str] = mapped_column(String(10), nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)

    team: Mapped["Team | None"] = relationship(back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_events_team_ts", "team_id", "timestamp"),
        Index("ix_audit_events_action", "action_taken"),
    )
