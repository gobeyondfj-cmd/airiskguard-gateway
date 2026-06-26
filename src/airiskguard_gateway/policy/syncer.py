from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig
    from airiskguard_gateway.policy.engine import PolicyEngine
    from airiskguard_gateway.policy.models import PolicySet

log = logging.getLogger(__name__)


class PolicySyncer:
    """Background task that polls the policy server and hot-reloads the local PolicyEngine."""

    def __init__(self, config: "GatewayConfig", engine: "PolicyEngine") -> None:
        self._url = config.policy_server.url.rstrip("/")
        self._api_key = config.policy_server.api_key
        self._interval = config.policy_server.sync_interval_seconds
        self._engine = engine
        self._running = False

    async def run(self) -> None:
        if not self._url:
            return  # Free tier

        self._running = True
        async with httpx.AsyncClient(timeout=10) as client:
            while self._running:
                try:
                    resp = await client.get(
                        f"{self._url}/api/v1/policies/current",
                        headers={"Authorization": f"Bearer {self._api_key}"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    from airiskguard_gateway.policy.models import PolicySet
                    policy = PolicySet.model_validate(data)
                    self._engine.update_policy(policy)
                    log.debug("Policy updated to version %s", policy.version)
                except Exception as exc:
                    log.warning("Policy sync failed: %s", exc)
                await asyncio.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
