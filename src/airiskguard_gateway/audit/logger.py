from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import Literal, TYPE_CHECKING

from airiskguard_gateway.models import Finding

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig


class AuditEvent:
    __slots__ = (
        "event_id", "timestamp", "machine_id", "provider", "model",
        "direction", "action_taken", "findings", "request_id",
        "token_count_estimate", "latency_ms",
    )

    def __init__(
        self,
        machine_id: str,
        provider: str,
        model: str,
        direction: Literal["outbound", "inbound"],
        action_taken: Literal["allowed", "blocked", "redacted"],
        findings: list[Finding],
        request_id: str = "",
        token_count_estimate: int | None = None,
        latency_ms: int | None = None,
    ) -> None:
        self.event_id = str(uuid.uuid4())
        self.timestamp = datetime.now(UTC)
        self.machine_id = machine_id
        self.provider = provider
        self.model = model
        self.direction = direction
        self.action_taken = action_taken
        self.findings = findings
        self.request_id = request_id or str(uuid.uuid4())
        self.token_count_estimate = token_count_estimate
        self.latency_ms = latency_ms

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "machine_id": self.machine_id,
            "provider": self.provider,
            "model": self.model,
            "direction": self.direction,
            "action_taken": self.action_taken,
            "findings": [f.to_dict() for f in self.findings],
            "request_id": self.request_id,
            "token_count_estimate": self.token_count_estimate,
            "latency_ms": self.latency_ms,
        }


class AuditLogger:
    def __init__(self, config: "GatewayConfig") -> None:
        self._path = config.audit.resolved_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ship_to_server = config.audit.ship_to_server
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=10_000)

    def log(self, event: AuditEvent) -> None:
        """Write event to local JSONL file. Safe to call from sync or async context."""
        line = json.dumps(event.to_dict()) + "\n"
        # Atomic append via write + flush
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line)

        if self._ship_to_server:
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # Drop oldest by silently discarding; local file always has it

    def tail(self, n: int = 50, since: datetime | None = None) -> list[dict]:
        """Read last n events from local JSONL, optionally filtered by time."""
        if not self._path.exists():
            return []

        lines: list[str] = []
        with open(self._path, encoding="utf-8") as f:
            lines = f.readlines()

        events: list[dict] = []
        for line in reversed(lines):
            try:
                event = json.loads(line.strip())
                if since:
                    ts = datetime.fromisoformat(event["timestamp"].rstrip("Z"))
                    if ts < since:
                        continue
                events.append(event)
                if len(events) >= n:
                    break
            except (json.JSONDecodeError, KeyError):
                continue

        return list(reversed(events))

    def queue(self) -> asyncio.Queue[AuditEvent]:
        return self._queue
