from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from airiskguard_gateway.models import Finding
from airiskguard_gateway.scanner.outbound.secrets import scan_outbound_secrets, redact_secrets
from airiskguard_gateway.scanner.outbound.pii import scan_outbound_pii

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig


class ScanEngine:
    def __init__(self, config: "GatewayConfig") -> None:
        self._config = config

    async def scan_outbound(self, text: str, location: str = "outbound_request") -> list[Finding]:
        """Scan prompt text before it leaves the machine."""
        return await asyncio.to_thread(self._scan_outbound_sync, text, location)

    async def scan_inbound(self, text: str, location: str = "inbound_response") -> list[Finding]:
        """Scan AI response text (e.g. generated code) after it arrives."""
        return await asyncio.to_thread(self._scan_inbound_sync, text, location)

    def _scan_outbound_sync(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        checkers = self._config.outbound.enabled_checkers

        if "secrets" in checkers:
            findings.extend(scan_outbound_secrets(text, location))
        if "pii" in checkers:
            findings.extend(scan_outbound_pii(text, location))

        return findings

    def _scan_inbound_sync(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        checkers = self._config.inbound.enabled_checkers

        if "vuln_code" in checkers:
            from airiskguard_gateway.scanner.inbound.vuln_code import scan_inbound_vuln_code
            findings.extend(scan_inbound_vuln_code(text, location))

        return findings

    def redact(self, text: str) -> str:
        """Apply all redaction patterns to text (for redact action)."""
        return redact_secrets(text)
