from __future__ import annotations

import json
import logging
from datetime import datetime, UTC
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig

log = logging.getLogger(__name__)


class CostLimitChecker:
    """
    Tracks monthly spend from the local audit log and enforces cost limits.

    Limits reset on the 1st of each month (calendar month, UTC).
    Reads the JSONL audit log directly — no database dependency.
    """

    def __init__(self, config: "GatewayConfig") -> None:
        self._config = config
        self._overall_limit = config.overall_limit_usd
        self._provider_limits = config.per_provider_limits
        self._action = config.on_limit_reached  # "block" | "alert"

    def is_configured(self) -> bool:
        return self._overall_limit > 0 or bool(self._provider_limits)

    def check(self, provider: str) -> tuple[bool, str]:
        """
        Returns (allowed, message).
        - allowed=False → request should be blocked (only when action="block")
        - message != "" → limit was hit (in alert mode, request still allowed)
        """
        if not self.is_configured():
            return True, ""

        spend = self._read_monthly_spend()
        alert_msg = ""

        # Overall limit check
        if self._overall_limit > 0:
            total = spend.get("__total__", 0.0)
            if total >= self._overall_limit:
                msg = f"Overall monthly cost limit reached: ${total:.4f} / ${self._overall_limit:.2f}"
                log.warning(msg)
                if self._action == "block":
                    return False, msg
                alert_msg = msg  # alert mode — log but allow

        # Per-provider limit check
        if provider in self._provider_limits:
            provider_spend = spend.get(provider, 0.0)
            limit = self._provider_limits[provider]
            if provider_spend >= limit:
                msg = f"{provider} monthly cost limit reached: ${provider_spend:.4f} / ${limit:.2f}"
                log.warning(msg)
                if self._action == "block":
                    return False, msg
                alert_msg = msg

        return True, alert_msg

    def current_spend(self) -> dict[str, float]:
        """Return current month spend by provider + __total__."""
        return self._read_monthly_spend()

    def limits(self) -> dict:
        return {
            "overall_limit_usd": self._overall_limit,
            "per_provider_limits": self._provider_limits,
            "on_limit_reached": self._action,
        }

    def _read_monthly_spend(self) -> dict[str, float]:
        """Read this calendar month's spend from the local audit JSONL."""
        audit_path = self._config.audit.resolved_path()
        if not audit_path.exists():
            return {"__total__": 0.0}

        now = datetime.now(UTC)
        month_prefix = now.strftime("%Y-%m")

        spend: dict[str, float] = {"__total__": 0.0}

        try:
            with open(audit_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        ts = event.get("timestamp", "")
                        if not ts.startswith(month_prefix):
                            continue
                        cost = float(event.get("cost_usd") or 0)
                        if cost <= 0:
                            continue
                        provider = event.get("provider", "unknown")
                        spend[provider] = spend.get(provider, 0.0) + cost
                        spend["__total__"] = spend["__total__"] + cost
                    except (json.JSONDecodeError, ValueError):
                        continue
        except OSError:
            pass

        return spend
