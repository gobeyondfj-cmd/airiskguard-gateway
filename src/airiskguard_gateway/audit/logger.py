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
        "input_tokens", "output_tokens", "cost_usd", "latency_ms",
        "routed_to",
    )

    def __init__(
        self,
        machine_id: str,
        provider: str,
        model: str,
        direction: Literal["outbound", "inbound"],
        action_taken: Literal["allowed", "blocked", "redacted", "routed"],
        findings: list[Finding],
        request_id: str = "",
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        cost_usd: float | None = None,
        latency_ms: int | None = None,
        routed_to: str | None = None,
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
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost_usd = cost_usd
        self.latency_ms = latency_ms
        self.routed_to = routed_to

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "machine_id": self.machine_id,
            "provider": self.provider,
            "model": self.model,
            "direction": self.direction,
            "action_taken": self.action_taken,
            "findings": [f.to_dict() for f in self.findings],
            "request_id": self.request_id,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "routed_to": self.routed_to,
        }


class AuditLogger:
    def __init__(self, config: "GatewayConfig") -> None:
        self._path = config.audit.resolved_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ship_to_server = config.audit.ship_to_server
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=10_000)

    def log(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict()) + "\n"
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line)
        if self._ship_to_server:
            try:
                self._queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def tail(self, n: int = 50, since: datetime | None = None) -> list[dict]:
        if not self._path.exists():
            return []
        with open(self._path, encoding="utf-8") as f:
            lines = f.readlines()
        events: list[dict] = []
        for line in reversed(lines):
            try:
                event = json.loads(line.strip())
                if since:
                    ts_str = event["timestamp"]
                    # Handle both offset-aware and naive ISO strings
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            from datetime import timezone
                            ts = ts.replace(tzinfo=timezone.utc)
                        if ts < since:
                            continue
                    except ValueError:
                        pass
                events.append(event)
                if len(events) >= n:
                    break
            except (json.JSONDecodeError, KeyError):
                continue
        return list(reversed(events))

    def queue(self) -> asyncio.Queue[AuditEvent]:
        return self._queue
