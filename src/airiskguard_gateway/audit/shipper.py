from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from airiskguard_gateway.audit.logger import AuditEvent, AuditLogger
    from airiskguard_gateway.config import GatewayConfig

log = logging.getLogger(__name__)

BATCH_SIZE = 100
BASE_RETRY_DELAY = 2.0
MAX_RETRY_DELAY = 120.0


class AuditShipper:
    """Background asyncio task that ships audit events to the policy server."""

    def __init__(self, config: "GatewayConfig", logger: "AuditLogger") -> None:
        self._url = config.policy_server.url.rstrip("/")
        self._api_key = config.policy_server.api_key
        self._queue = logger.queue()
        self._running = False

    async def run(self) -> None:
        if not self._url:
            return  # Free tier — no policy server configured

        self._running = True
        retry_delay = BASE_RETRY_DELAY

        async with httpx.AsyncClient(timeout=30) as client:
            while self._running:
                batch: list["AuditEvent"] = []
                try:
                    # Collect up to BATCH_SIZE events (non-blocking after first)
                    event = await asyncio.wait_for(self._queue.get(), timeout=5.0)
                    batch.append(event)
                    while len(batch) < BATCH_SIZE:
                        try:
                            batch.append(self._queue.get_nowait())
                        except asyncio.QueueEmpty:
                            break
                except asyncio.TimeoutError:
                    continue

                try:
                    payload = [e.to_dict() for e in batch]
                    resp = await client.post(
                        f"{self._url}/api/v1/events",
                        json=payload,
                        headers={"Authorization": f"Bearer {self._api_key}"},
                    )
                    resp.raise_for_status()
                    retry_delay = BASE_RETRY_DELAY
                except Exception as exc:
                    log.warning("Failed to ship %d audit events: %s. Retrying in %.0fs.", len(batch), exc, retry_delay)
                    # Re-enqueue events (best-effort)
                    for e in batch:
                        try:
                            self._queue.put_nowait(e)
                        except asyncio.QueueFull:
                            break
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)

    def stop(self) -> None:
        self._running = False
