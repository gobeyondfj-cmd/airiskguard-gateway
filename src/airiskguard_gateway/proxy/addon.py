from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

from mitmproxy import http
from mitmproxy.http import HTTPFlow

from airiskguard_gateway.audit.logger import AuditEvent, AuditLogger
from airiskguard_gateway.config import GatewayConfig, machine_id
from airiskguard_gateway.models import PolicyDecision
from airiskguard_gateway.policy.engine import PolicyEngine
from airiskguard_gateway.proxy.provider import (
    Provider,
    detect_provider,
    extract_request_context,
    extract_response_context,
    estimate_tokens,
)
from airiskguard_gateway.scanner.engine import ScanEngine

log = logging.getLogger(__name__)

_AI_HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
}


def _is_ai_request(host: str) -> bool:
    return host in _AI_HOSTS or host.endswith(".openai.azure.com")


class AIRiskGuardAddon:
    """mitmproxy addon that intercepts AI API calls and enforces governance policy."""

    def __init__(self, config: GatewayConfig, logger: AuditLogger, scanner: ScanEngine, policy: PolicyEngine) -> None:
        self._config = config
        self._logger = logger
        self._scanner = scanner
        self._policy = policy
        self._mid = machine_id()
        # Per-flow SSE accumulation buffer: flow.id → list[str]
        self._sse_buffers: dict[str, list[str]] = {}
        self._flow_start_times: dict[str, float] = {}

    def request(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not _is_ai_request(host):
            return

        self._flow_start_times[flow.id] = time.monotonic()

        # Parse request body
        body = self._parse_json(flow.request.content)
        if body is None:
            return

        path = flow.request.path
        request_id = flow.request.headers.get("x-request-id", str(uuid.uuid4()))
        ctx = extract_request_context(host, path, body, request_id)

        # 1. Model allowlist check
        model_decision = self._policy.check_model_allowed(ctx.model)
        if model_decision.action == "block":
            self._kill_flow(flow, model_decision, ctx.provider.value, ctx.model, request_id)
            return

        # 2. Outbound scan (sync call wrapped — mitmproxy addon hooks are sync)
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            findings = loop.run_until_complete(self._scanner.scan_outbound(ctx.prompt_text, f"{host}{path}"))
        except RuntimeError:
            findings = self._scanner._scan_outbound_sync(ctx.prompt_text, f"{host}{path}")

        outbound_decision = self._policy.evaluate_outbound(findings)

        if outbound_decision.action == "block":
            self._kill_flow(flow, outbound_decision, ctx.provider.value, ctx.model, request_id)
            return

        if outbound_decision.action == "redact":
            redacted_text = self._scanner.redact(ctx.prompt_text)
            body_str = flow.request.get_text(strict=False) or ""
            # Simple string replacement — works for most cases
            flow.request.text = body_str.replace(ctx.prompt_text, redacted_text)
            self._log_event(ctx.provider.value, ctx.model, "outbound", "redacted", findings, request_id, estimate_tokens(ctx.prompt_text))
            return

        # Allow — log the clean pass
        if findings:
            self._log_event(ctx.provider.value, ctx.model, "outbound", "allowed", findings, request_id, estimate_tokens(ctx.prompt_text))

    def response(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not _is_ai_request(host):
            return

        content_type = flow.response.headers.get("content-type", "")
        is_streaming = "text/event-stream" in content_type

        if is_streaming:
            # Streaming: accumulate SSE data lines in buffer; scan at stream close
            self._sse_buffers[flow.id] = []
            return

        # Non-streaming: scan the response body now
        body = self._parse_json(flow.response.content)
        if body is None:
            return

        provider = detect_provider(flow.request.pretty_host)
        model = self._parse_json(flow.request.content or b"{}").get("model", "unknown")
        ctx = extract_response_context(provider, model, body, is_streaming=False)

        if not ctx.response_text:
            return

        findings = self._scanner._scan_inbound_sync(ctx.response_text, flow.request.pretty_host)
        decision = self._policy.evaluate_inbound(findings)

        latency = self._get_latency(flow.id)
        if decision.action == "block":
            self._kill_response(flow, decision)
            self._log_event(provider.value, model, "inbound", "blocked", findings,
                            flow.request.headers.get("x-request-id", ""), None, latency)
        elif findings:
            self._log_event(provider.value, model, "inbound", "allowed", findings,
                            flow.request.headers.get("x-request-id", ""), None, latency)

    def response_body_done(self, flow: HTTPFlow) -> None:
        """Called when a streaming response finishes. Scan the assembled buffer."""
        if flow.id not in self._sse_buffers:
            return

        accumulated = "\n".join(self._sse_buffers.pop(flow.id))
        assembled = self._assemble_sse(accumulated)

        if not assembled:
            return

        provider = detect_provider(flow.request.pretty_host)
        model = self._parse_json(flow.request.content or b"{}").get("model", "unknown")

        findings = self._scanner._scan_inbound_sync(assembled, flow.request.pretty_host)
        latency = self._get_latency(flow.id)

        if findings:
            decision = self._policy.evaluate_inbound(findings)
            action_str = "blocked" if decision.action == "block" else "allowed"
            self._log_event(provider.value, model, "inbound", action_str, findings,
                            flow.request.headers.get("x-request-id", ""), None, latency)

    def _kill_flow(self, flow: HTTPFlow, decision: PolicyDecision, provider: str, model: str, request_id: str) -> None:
        findings_data = [f.to_dict() for f in decision.findings]
        body = json.dumps({
            "error": {
                "type": "policy_violation",
                "message": decision.message,
                "findings": findings_data,
            }
        }).encode()
        flow.response = http.Response.make(
            400,
            body,
            {"content-type": "application/json", "x-airiskguard": "blocked"},
        )
        self._log_event(provider, model, "outbound", "blocked", decision.findings, request_id)
        log.info("Blocked request to %s — %s", flow.request.pretty_host, decision.message)

    def _kill_response(self, flow: HTTPFlow, decision: PolicyDecision) -> None:
        body = json.dumps({
            "error": {
                "type": "policy_violation",
                "message": decision.message,
                "findings": [f.to_dict() for f in decision.findings],
            }
        }).encode()
        flow.response = http.Response.make(
            200,  # Return 200 with error body to not break AI tool error handling
            body,
            {"content-type": "application/json", "x-airiskguard": "blocked-inbound"},
        )

    def _log_event(
        self,
        provider: str,
        model: str,
        direction: str,
        action_taken: str,
        findings: list,
        request_id: str,
        tokens: int | None = None,
        latency: int | None = None,
    ) -> None:
        event = AuditEvent(
            machine_id=self._mid,
            provider=provider,
            model=model,
            direction=direction,  # type: ignore
            action_taken=action_taken,  # type: ignore
            findings=findings,
            request_id=request_id,
            token_count_estimate=tokens,
            latency_ms=latency,
        )
        try:
            self._logger.log(event)
        except Exception as exc:
            log.warning("Failed to write audit log: %s", exc)

    def _get_latency(self, flow_id: str) -> int | None:
        start = self._flow_start_times.pop(flow_id, None)
        if start is None:
            return None
        return int((time.monotonic() - start) * 1000)

    @staticmethod
    def _parse_json(content: bytes | None) -> dict[str, Any] | None:
        if not content:
            return {}
        try:
            result = json.loads(content)
            return result if isinstance(result, dict) else None
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _assemble_sse(raw: str) -> str:
        """Extract text content from accumulated SSE data lines."""
        parts: list[str] = []
        for line in raw.splitlines():
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if data_str in ("[DONE]", ""):
                continue
            try:
                chunk = json.loads(data_str)
                # Anthropic streaming: delta.text
                if "delta" in chunk and "text" in chunk.get("delta", {}):
                    parts.append(chunk["delta"]["text"])
                # OpenAI streaming: choices[0].delta.content
                elif choices := chunk.get("choices"):
                    delta = choices[0].get("delta", {})
                    if content := delta.get("content"):
                        parts.append(content)
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
        return "".join(parts)
