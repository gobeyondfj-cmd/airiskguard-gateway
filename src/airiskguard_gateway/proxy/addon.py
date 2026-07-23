from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from mitmproxy import http
from mitmproxy.http import HTTPFlow

from airiskguard_gateway.audit.logger import AuditEvent, AuditLogger
from airiskguard_gateway.config import GatewayConfig, machine_id
from airiskguard_gateway.costs import calculate_cost
from airiskguard_gateway.models import PolicyDecision
from airiskguard_gateway.policy.engine import PolicyEngine
from airiskguard_gateway.proxy.provider import (
    Provider,
    detect_provider,
    extract_request_context,
    extract_response_context,
    estimate_tokens,
)
from airiskguard_gateway.routing.engine import RoutingEngine
from airiskguard_gateway.routing.models import RoutingDestination
from airiskguard_gateway.scanner.engine import ScanEngine

log = logging.getLogger(__name__)

_AI_HOSTS = {
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
}

# Provider base URLs for rewriting routed requests
_PROVIDER_BASE_URLS = {
    "anthropic": "https://api.anthropic.com",
    "openai":    "https://api.openai.com",
    "ollama":    "http://localhost:11434",
    "google":    "https://generativelanguage.googleapis.com",
}


def _is_ai_request(host: str) -> bool:
    return host in _AI_HOSTS or host.endswith(".openai.azure.com")


class AIRiskGuardAddon:
    def __init__(
        self,
        config: GatewayConfig,
        logger: AuditLogger,
        scanner: ScanEngine,
        policy: PolicyEngine,
        router: RoutingEngine,
    ) -> None:
        self._config = config
        self._logger = logger
        self._scanner = scanner
        self._policy = policy
        self._router = router
        self._mid = machine_id()
        self._sse_buffers: dict[str, list[str]] = {}
        self._flow_start_times: dict[str, float] = {}
        self._flow_models: dict[str, str] = {}     # flow.id → model name for response pairing

    def request(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not _is_ai_request(host):
            return

        self._flow_start_times[flow.id] = time.monotonic()
        body = self._parse_json(flow.request.content)
        if body is None:
            return

        path = flow.request.path
        request_id = flow.request.headers.get("x-request-id", str(uuid.uuid4()))
        ctx = extract_request_context(host, path, body, request_id)
        self._flow_models[flow.id] = ctx.model

        # 1. Model allowlist
        model_decision = self._policy.check_model_allowed(ctx.model)
        if model_decision.action == "block":
            self._kill_flow(flow, model_decision, ctx.provider.value, ctx.model, request_id)
            return

        # 2. Outbound scan
        findings = self._scanner._scan_outbound_sync(ctx.prompt_text, f"{host}{path}")
        outbound_decision = self._policy.evaluate_outbound(findings)

        if outbound_decision.action == "block":
            self._kill_flow(flow, outbound_decision, ctx.provider.value, ctx.model, request_id)
            return

        routed_to: str | None = None

        if outbound_decision.action == "redact":
            redacted = self._scanner.redact(ctx.prompt_text)
            body_text = flow.request.get_text(strict=False) or ""
            flow.request.text = body_text.replace(ctx.prompt_text, redacted)
            self._log_event(ctx.provider.value, ctx.model, "outbound", "redacted",
                            findings, request_id, routed_to=None)
            return

        # 3. Routing (after scan — routing can use findings as conditions)
        routing_decision = self._router.evaluate(ctx, findings)

        if routing_decision.action == "block":
            from airiskguard_gateway.models import Category, Finding, Severity
            block_finding = Finding(
                id=str(uuid.uuid4()),
                category=Category.MODEL_POLICY,
                severity=Severity.HIGH,
                title="Request blocked by routing rule",
                description="A routing rule blocked this request.",
                evidence="",
                location="routing",
                remediation="Check your routing configuration.",
            )
            self._kill_flow(
                flow,
                PolicyDecision(action="block", findings=[block_finding], message="Blocked by routing rule."),
                ctx.provider.value, ctx.model, request_id,
            )
            return

        if routing_decision.action == "route_to" and routing_decision.destination:
            dest = routing_decision.destination
            self._rewrite_for_destination(flow, body, dest)
            routed_to = f"{dest.provider}:{dest.model}"
            log.info("Routed %s → %s", ctx.model, routed_to)

        self._log_event(ctx.provider.value, ctx.model, "outbound",
                        "routed" if routed_to else "allowed",
                        findings, request_id, routed_to=routed_to)

    def response(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not _is_ai_request(host):
            return

        content_type = flow.response.headers.get("content-type", "")
        is_streaming = "text/event-stream" in content_type

        if is_streaming:
            self._sse_buffers[flow.id] = []
            return

        body = self._parse_json(flow.response.content)
        if not body:
            return

        provider = detect_provider(flow.request.pretty_host)
        model = self._flow_models.get(flow.id, body.get("model", "unknown"))

        # Extract token usage + calculate cost
        input_tokens, output_tokens = _extract_token_counts(provider, body)
        cost = calculate_cost(model, input_tokens, output_tokens) if input_tokens or output_tokens else None

        ctx = extract_response_context(provider, model, body, is_streaming=False)
        findings = self._scanner._scan_inbound_sync(ctx.response_text, host) if ctx.response_text else []
        latency = self._get_latency(flow.id)

        self._log_event(
            provider.value, model, "inbound", "allowed",
            findings,
            flow.request.headers.get("x-request-id", ""),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            latency_ms=latency,
        )

    def response_body_done(self, flow: HTTPFlow) -> None:
        if flow.id not in self._sse_buffers:
            return

        accumulated = "\n".join(self._sse_buffers.pop(flow.id))
        assembled = self._assemble_sse(accumulated)

        provider = detect_provider(flow.request.pretty_host)
        model = self._flow_models.get(flow.id, "unknown")

        # Extract token usage from SSE (last [DONE] chunk often has usage)
        input_tokens, output_tokens = _extract_sse_token_counts(accumulated, provider)
        cost = calculate_cost(model, input_tokens, output_tokens) if input_tokens or output_tokens else None

        findings = self._scanner._scan_inbound_sync(assembled, flow.request.pretty_host) if assembled else []
        latency = self._get_latency(flow.id)

        self._log_event(
            provider.value, model, "inbound", "allowed",
            findings,
            flow.request.headers.get("x-request-id", ""),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            latency_ms=latency,
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _rewrite_for_destination(self, flow: HTTPFlow, original_body: dict, dest: RoutingDestination) -> None:
        """Rewrite the request URL and body to target a different model/provider."""
        base_url = dest.base_url or _PROVIDER_BASE_URLS.get(dest.provider, "")
        if not base_url:
            return

        # Rewrite URL
        if dest.provider == "ollama":
            flow.request.url = f"{base_url}/api/chat"
        elif dest.provider == "anthropic":
            flow.request.url = f"{base_url}/v1/messages"
        else:
            flow.request.url = f"{base_url}/v1/chat/completions"

        # Rewrite model field in body
        new_body = dict(original_body)
        new_body["model"] = dest.model
        flow.request.content = json.dumps(new_body).encode()

        # Rewrite Authorization header if api_key_env is set
        if dest.api_key_env:
            api_key = os.environ.get(dest.api_key_env, "")
            if api_key:
                if dest.provider == "anthropic":
                    flow.request.headers["x-api-key"] = api_key
                    flow.request.headers.pop("authorization", None)
                else:
                    flow.request.headers["authorization"] = f"Bearer {api_key}"

    def _kill_flow(self, flow: HTTPFlow, decision: PolicyDecision, provider: str, model: str, request_id: str) -> None:
        body = json.dumps({
            "error": {
                "type": "policy_violation",
                "message": decision.message,
                "findings": [f.to_dict() for f in decision.findings],
            }
        }).encode()
        flow.response = http.Response.make(
            400, body, {"content-type": "application/json", "x-airiskguard": "blocked"},
        )
        self._log_event(provider, model, "outbound", "blocked", decision.findings, request_id)

    def _log_event(
        self,
        provider: str,
        model: str,
        direction: str,
        action_taken: str,
        findings: list,
        request_id: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float | None = None,
        latency_ms: int | None = None,
        routed_to: str | None = None,
    ) -> None:
        event = AuditEvent(
            machine_id=self._mid,
            provider=provider,
            model=model,
            direction=direction,       # type: ignore
            action_taken=action_taken, # type: ignore
            findings=findings,
            request_id=request_id,
            input_tokens=input_tokens or None,
            output_tokens=output_tokens or None,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            routed_to=routed_to,
        )
        try:
            self._logger.log(event)
        except Exception as exc:
            log.warning("Failed to write audit log: %s", exc)

    def _get_latency(self, flow_id: str) -> int | None:
        start = self._flow_start_times.pop(flow_id, None)
        return int((time.monotonic() - start) * 1000) if start else None

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
        parts: list[str] = []
        for line in raw.splitlines():
            if not line.startswith("data:"):
                continue
            data_str = line[5:].strip()
            if data_str in ("[DONE]", ""):
                continue
            try:
                chunk = json.loads(data_str)
                if "delta" in chunk and "text" in chunk.get("delta", {}):
                    parts.append(chunk["delta"]["text"])
                elif choices := chunk.get("choices"):
                    delta = choices[0].get("delta", {})
                    if content := delta.get("content"):
                        parts.append(content)
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
        return "".join(parts)


def _extract_token_counts(provider: Provider, body: dict) -> tuple[int, int]:
    """Extract input/output token counts from a non-streaming response body."""
    usage = body.get("usage", {})
    if provider == Provider.ANTHROPIC:
        return usage.get("input_tokens", 0), usage.get("output_tokens", 0)
    elif provider in (Provider.OPENAI, Provider.AZURE_OPENAI):
        return usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)
    return 0, 0


def _extract_sse_token_counts(raw: str, provider: Provider) -> tuple[int, int]:
    """Extract token counts from SSE stream — usually in the final data chunk."""
    for line in reversed(raw.splitlines()):
        if not line.startswith("data:"):
            continue
        data_str = line[5:].strip()
        if data_str in ("[DONE]", ""):
            continue
        try:
            chunk = json.loads(data_str)
            usage = chunk.get("usage", {})
            if provider == Provider.ANTHROPIC:
                inp = usage.get("input_tokens", 0)
                out = usage.get("output_tokens", 0)
            else:
                inp = usage.get("prompt_tokens", 0)
                out = usage.get("completion_tokens", 0)
            if inp or out:
                return inp, out
        except (json.JSONDecodeError, KeyError):
            continue
    return 0, 0
