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
from airiskguard_gateway.config import GatewayConfig, ProviderConfig, machine_id
from airiskguard_gateway.costs import calculate_cost
from airiskguard_gateway.models import Category, Finding, PolicyDecision, Severity
from airiskguard_gateway.policy.engine import PolicyEngine
from airiskguard_gateway.proxy.provider import (
    RequestContext,
    detect_provider_by_host,
    extract_request_context,
    extract_response_text,
    extract_token_counts,
    extract_sse_token_counts,
    get_chat_path,
)
from airiskguard_gateway.routing.engine import RoutingEngine
from airiskguard_gateway.routing.models import RoutingDestination
from airiskguard_gateway.scanner.engine import ScanEngine

log = logging.getLogger(__name__)


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
        self._providers = config.resolved_providers()
        self._intercepted_hosts = config.intercepted_hosts()
        self._sse_buffers: dict[str, list[str]] = {}
        self._flow_start_times: dict[str, float] = {}
        self._flow_contexts: dict[str, RequestContext] = {}

    def request(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self._is_ai_host(host):
            return

        self._flow_start_times[flow.id] = time.monotonic()
        body = self._parse_json(flow.request.content)
        if body is None:
            return

        request_id = flow.request.headers.get("x-request-id", str(uuid.uuid4()))
        ctx = extract_request_context(
            host, flow.request.path, body, request_id, self._providers
        )
        self._flow_contexts[flow.id] = ctx

        # 1. Model allowlist
        model_decision = self._policy.check_model_allowed(ctx.model)
        if model_decision.action == "block":
            self._kill_flow(flow, model_decision, ctx, request_id)
            return

        # 2. Outbound scan
        findings = self._scanner._scan_outbound_sync(ctx.prompt_text, f"{host}{ctx.path}")
        outbound_decision = self._policy.evaluate_outbound(findings)

        if outbound_decision.action == "block":
            self._kill_flow(flow, outbound_decision, ctx, request_id)
            return

        routed_to: str | None = None

        if outbound_decision.action == "redact":
            redacted = self._scanner.redact(ctx.prompt_text)
            body_text = flow.request.get_text(strict=False) or ""
            flow.request.text = body_text.replace(ctx.prompt_text, redacted)
            self._log_event(ctx, "outbound", "redacted", findings, request_id)
            return

        # 3. Routing — pass session ID for stickiness
        session_id = _extract_session_id(body, flow.request.headers)
        routing_decision = self._router.evaluate(ctx, findings, session_id=session_id)

        if routing_decision.action == "block":
            block_finding = Finding(
                id=str(uuid.uuid4()),
                category=Category.MODEL_POLICY,
                severity=Severity.HIGH,
                title="Request blocked by routing rule",
                description="A routing rule blocked this request.",
                evidence="", location="routing",
                remediation="Check your routing configuration.",
            )
            self._kill_flow(
                flow,
                PolicyDecision(action="block", findings=[block_finding], message="Blocked by routing rule."),
                ctx, request_id,
            )
            return

        if routing_decision.action == "route_to" and routing_decision.destination:
            dest = routing_decision.destination
            self._rewrite_for_destination(flow, body, dest)
            routed_to = f"{dest.provider}:{dest.model}"
            log.info("Routed %s → %s%s", ctx.model, routed_to,
                     " [pinned]" if routing_decision.session_pinned else "")

        # Classify content for audit log
        from airiskguard_gateway.routing.classifier import classify
        signals = classify(ctx.prompt_text)

        self._log_event(ctx, "outbound",
                        "routed" if routed_to else "allowed",
                        findings, request_id, routed_to=routed_to,
                        session_id=session_id,
                        task_type=signals.task_type.value,
                        complexity=signals.complexity.value)

    def response(self, flow: HTTPFlow) -> None:
        host = flow.request.pretty_host
        if not self._is_ai_host(host):
            return

        content_type = flow.response.headers.get("content-type", "")
        is_streaming = "text/event-stream" in content_type

        if is_streaming:
            self._sse_buffers[flow.id] = []
            return

        body = self._parse_json(flow.response.content)
        if not body:
            return

        ctx = self._flow_contexts.get(flow.id)
        fmt = ctx.provider_format if ctx else "openai"
        model = (ctx.model if ctx else None) or body.get("model", "unknown")

        input_tokens, output_tokens = extract_token_counts(fmt, body)
        cost = calculate_cost(model, input_tokens, output_tokens) if (input_tokens or output_tokens) else None

        response_text = extract_response_text(fmt, body)
        findings = self._scanner._scan_inbound_sync(response_text, host) if response_text else []
        latency = self._get_latency(flow.id)

        if ctx:
            self._log_event(ctx, "inbound", "allowed", findings,
                            flow.request.headers.get("x-request-id", ""),
                            input_tokens=input_tokens, output_tokens=output_tokens,
                            cost_usd=cost, latency_ms=latency)

    def response_body_done(self, flow: HTTPFlow) -> None:
        if flow.id not in self._sse_buffers:
            return

        accumulated = "\n".join(self._sse_buffers.pop(flow.id))
        assembled = self._assemble_sse(accumulated)

        ctx = self._flow_contexts.get(flow.id)
        fmt = ctx.provider_format if ctx else "openai"
        model = ctx.model if ctx else "unknown"

        input_tokens, output_tokens = extract_sse_token_counts(accumulated, fmt)
        cost = calculate_cost(model, input_tokens, output_tokens) if (input_tokens or output_tokens) else None

        findings = self._scanner._scan_inbound_sync(assembled, flow.request.pretty_host) if assembled else []
        latency = self._get_latency(flow.id)

        if ctx:
            self._log_event(ctx, "inbound", "allowed", findings,
                            flow.request.headers.get("x-request-id", ""),
                            input_tokens=input_tokens, output_tokens=output_tokens,
                            cost_usd=cost, latency_ms=latency)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_ai_host(self, host: str) -> bool:
        return host in self._intercepted_hosts or any(
            host.endswith("." + h) for h in self._intercepted_hosts
        )

    def _rewrite_for_destination(
        self, flow: HTTPFlow, original_body: dict, dest: RoutingDestination
    ) -> None:
        """Rewrite request URL, model field, and auth header for destination."""
        # Look up provider config
        provider_cfg = self._providers.get(dest.provider)
        if not provider_cfg:
            log.warning("Unknown destination provider: %s — skipping rewrite", dest.provider)
            return

        base_url = dest.base_url or provider_cfg.base_url
        if not base_url:
            log.warning("No base_url for provider %s — skipping rewrite", dest.provider)
            return

        base_url = base_url.rstrip("/")
        fmt = provider_cfg.format

        # Rewrite URL
        chat_path = get_chat_path(fmt)
        flow.request.url = f"{base_url}{chat_path}"

        # Rewrite model in body
        new_body = dict(original_body)
        new_body["model"] = dest.model

        # Convert body format if crossing format boundaries
        ctx = self._flow_contexts.get(flow.id)
        if ctx and ctx.provider_format != fmt:
            new_body = _convert_body(new_body, from_fmt=ctx.provider_format, to_fmt=fmt)

        flow.request.content = json.dumps(new_body).encode()
        flow.request.headers["content-length"] = str(len(flow.request.content))

        # Rewrite auth header
        api_key = dest.api_key_env and os.environ.get(dest.api_key_env, "")
        if not api_key:
            api_key = provider_cfg.get_api_key()

        if api_key and provider_cfg.auth_header:
            # Remove old auth headers
            for h in ("authorization", "x-api-key", "api-key"):
                flow.request.headers.pop(h, None)
            value = f"{provider_cfg.auth_prefix}{api_key}".strip()
            flow.request.headers[provider_cfg.auth_header] = value

        # Update host header
        from airiskguard_gateway.config import ProviderConfig as PC
        new_host = PC(base_url=base_url, format=fmt).host()
        if new_host:
            flow.request.headers["host"] = new_host

    def _kill_flow(
        self, flow: HTTPFlow, decision: PolicyDecision,
        ctx: RequestContext, request_id: str,
    ) -> None:
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
        self._log_event(ctx, "outbound", "blocked", decision.findings, request_id)

    def _log_event(
        self,
        ctx: RequestContext,
        direction: str,
        action_taken: str,
        findings: list,
        request_id: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float | None = None,
        latency_ms: int | None = None,
        routed_to: str | None = None,
        session_id: str | None = None,
        task_type: str | None = None,
        complexity: str | None = None,
    ) -> None:
        event = AuditEvent(
            machine_id=self._mid,
            provider=ctx.provider_name,
            model=ctx.model,
            direction=direction,
            action_taken=action_taken,
            findings=findings,
            request_id=request_id,
            input_tokens=input_tokens or None,
            output_tokens=output_tokens or None,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            routed_to=routed_to,
            session_id=session_id,
            task_type=task_type,
            complexity=complexity,
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
                # Anthropic streaming
                if "delta" in chunk and "text" in chunk.get("delta", {}):
                    parts.append(chunk["delta"]["text"])
                # OpenAI-compatible streaming
                elif choices := chunk.get("choices"):
                    delta = choices[0].get("delta", {})
                    if content := delta.get("content"):
                        parts.append(content)
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
        return "".join(parts)


def _extract_session_id(body: dict, headers: Any) -> str | None:
    """
    Extract a stable session/conversation ID from the request.
    Checks common locations used by Claude Code, OpenAI SDKs, and other AI tools.
    """
    # Explicit session/conversation ID fields in body
    for key in ("conversation_id", "session_id", "thread_id", "chat_id", "request_id"):
        if val := body.get(key):
            return str(val)

    # Claude Code sends metadata in the system prompt or top-level
    if meta := body.get("metadata"):
        if isinstance(meta, dict):
            for key in ("conversation_id", "session_id", "user_id"):
                if val := meta.get(key):
                    return str(val)

    # OpenAI Assistants API thread
    if thread := body.get("thread_id"):
        return str(thread)

    # Some clients embed session info in headers
    for header in ("x-session-id", "x-conversation-id", "x-thread-id"):
        if val := headers.get(header):
            return str(val)

    return None


def _convert_body(body: dict, from_fmt: str, to_fmt: str) -> dict:
    """Best-effort format conversion when routing crosses provider formats."""
    if from_fmt == to_fmt:
        return body

    # Anthropic → OpenAI-compatible
    if from_fmt == "anthropic" and to_fmt in ("openai", "ollama"):
        messages = list(body.get("messages", []))
        if system := body.get("system"):
            messages.insert(0, {"role": "system", "content": system})
        new = {
            "model": body.get("model", ""),
            "messages": messages,
            "stream": body.get("stream", False),
        }
        if max_tokens := body.get("max_tokens"):
            new["max_tokens"] = max_tokens
        return new

    # OpenAI-compatible → Anthropic
    if from_fmt in ("openai", "ollama") and to_fmt == "anthropic":
        messages = body.get("messages", [])
        system_msgs = [m["content"] for m in messages if m.get("role") == "system"]
        other_msgs = [m for m in messages if m.get("role") != "system"]
        new = {
            "model": body.get("model", ""),
            "messages": other_msgs,
            "max_tokens": body.get("max_tokens", 4096),
            "stream": body.get("stream", False),
        }
        if system_msgs:
            new["system"] = " ".join(system_msgs)
        return new

    # Same format family — return as-is
    return body
