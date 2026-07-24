from __future__ import annotations

import json
import logging
import time
import uuid
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from airiskguard_gateway.auth import GatewayAuth
from airiskguard_gateway.audit.logger import AuditEvent, AuditLogger
from airiskguard_gateway.config import GatewayConfig, machine_id
from airiskguard_gateway.costs import calculate_cost
from airiskguard_gateway.models import Category, Finding, PolicyDecision, Severity
from airiskguard_gateway.policy.engine import PolicyEngine
from airiskguard_gateway.proxy.provider import (
    extract_request_context,
    extract_response_text,
    extract_token_counts,
    get_chat_path,
)
from airiskguard_gateway.routing.classifier import classify
from airiskguard_gateway.routing.engine import RoutingEngine
from airiskguard_gateway.routing.models import RoutingDestination
from airiskguard_gateway.cost_limits import CostLimitChecker
from airiskguard_gateway.scanner.engine import ScanEngine

log = logging.getLogger(__name__)

# Provider → upstream base URL mapping
PROVIDER_UPSTREAM = {
    "anthropic":    "https://api.anthropic.com",
    "openai":       "https://api.openai.com",
    "deepseek":     "https://api.deepseek.com",
    "moonshot":     "https://api.moonshot.cn",
    "glm":          "https://open.bigmodel.cn",
    "minimax":      "https://api.minimax.chat",
    "mistral":      "https://api.mistral.ai",
    "google":       "https://generativelanguage.googleapis.com",
}


def create_api_server(
    config: GatewayConfig,
    logger: AuditLogger,
    scanner: ScanEngine,
    policy: PolicyEngine,
    router: RoutingEngine,
) -> FastAPI:
    app = FastAPI(title="AIRiskGuard Gateway API Proxy", docs_url=None, redoc_url=None)
    mid = machine_id()
    gw_auth = GatewayAuth(config)
    cost_checker = CostLimitChecker(config)

    if not gw_auth.is_enabled():
        log.warning(
            "⚠️  Gateway authentication is DISABLED — anyone who can reach this "
            "gateway can use it. Set AIRISKGUARD_GATEWAY_KEY or gateway_key in config.yaml."
        )

    @app.api_route("/{provider}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    async def proxy(provider: str, path: str, request: Request) -> Response:
        # ── Auth ─────────────────────────────────────────────────────────
        client_key = request.headers.get("x-api-key") or request.headers.get("authorization", "")
        identity = gw_auth.validate(client_key)
        if identity is None:
            return Response(
                content=json.dumps({
                    "error": {
                        "type": "authentication_error",
                        "message": "Invalid or missing gateway API key. "
                                   "Set ANTHROPIC_API_KEY=<your-gateway-key> on the client.",
                    }
                }),
                status_code=401,
                media_type="application/json",
                headers={"x-airiskguard": "unauthorized"},
            )

        start = time.monotonic()
        providers = config.resolved_providers()
        provider_cfg = providers.get(provider)
        if not provider_cfg:
            return Response(
                content=json.dumps({"error": f"Unknown provider: {provider}. Supported: {list(providers.keys())}"}),
                status_code=404,
                media_type="application/json",
            )

        # ── Cost limit check ─────────────────────────────────────────────
        allowed, limit_msg = cost_checker.check(provider)
        if not allowed:
            return Response(
                content=json.dumps({
                    "error": {
                        "type": "cost_limit_exceeded",
                        "message": limit_msg,
                    }
                }),
                status_code=429,
                media_type="application/json",
                headers={"x-airiskguard": "cost-limit"},
            )

        # Read body
        body_bytes = await request.body()
        body: dict = {}
        try:
            body = json.loads(body_bytes) if body_bytes else {}
        except json.JSONDecodeError:
            pass

        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        ctx = extract_request_context(
            provider_cfg.host(), f"/{path}", body, request_id, providers
        )

        # 1. Model allowlist
        model_decision = policy.check_model_allowed(ctx.model)
        if model_decision.action == "block":
            return _block_response(model_decision)

        # 2. Outbound scan
        findings = scanner._scan_outbound_sync(ctx.prompt_text, f"/{provider}/{path}")
        outbound_decision = policy.evaluate_outbound(findings)

        if outbound_decision.action == "block":
            return _block_response(outbound_decision)

        if outbound_decision.action == "redact":
            redacted = scanner.redact(ctx.prompt_text)
            body_str = body_bytes.decode()
            body_bytes = body_str.replace(ctx.prompt_text, redacted).encode()
            body = json.loads(body_bytes)

        # 3. Routing
        session_id = body.get("conversation_id") or body.get("session_id")
        routing_decision = router.evaluate(ctx, findings, session_id=session_id)

        # Determine actual destination
        dest_provider = provider
        dest_cfg = provider_cfg
        if routing_decision.action == "route_to" and routing_decision.destination:
            dest = routing_decision.destination
            dest_cfg = providers.get(dest.provider) or provider_cfg
            dest_provider = dest.provider
            # Rewrite model in body
            body["model"] = dest.model
            body_bytes = json.dumps(body).encode()
            log.info("Routed %s → %s:%s", ctx.model, dest.provider, dest.model)
        elif routing_decision.action == "block":
            finding = Finding(
                id=str(uuid.uuid4()), category=Category.MODEL_POLICY,
                severity=Severity.HIGH, title="Blocked by routing rule",
                description="", evidence="", location="routing", remediation="",
            )
            return _block_response(PolicyDecision(action="block", findings=[finding], message="Blocked by routing rule."))

        # 4. Forward to upstream
        upstream_base = dest.base_url if (routing_decision.action == "route_to" and routing_decision.destination and routing_decision.destination.base_url) else dest_cfg.base_url
        upstream_url = f"{upstream_base.rstrip('/')}/{path}"

        # Build upstream headers
        upstream_headers = _build_upstream_headers(request, dest_cfg, body_bytes)
        is_streaming = body.get("stream", False)

        signals = classify(ctx.prompt_text)
        routed_to = f"{dest_provider}:{body.get('model', ctx.model)}" if routing_decision.action == "route_to" else None

        if is_streaming:
            return await _stream_response(
                upstream_url, upstream_headers, body_bytes,
                ctx, logger, scanner, policy, mid,
                request_id, signals, routed_to, start,
            )

        # Non-streaming
        async with httpx.AsyncClient(timeout=120) as client:
            try:
                upstream_resp = await client.post(
                    upstream_url,
                    content=body_bytes,
                    headers=upstream_headers,
                )
            except httpx.RequestError as e:
                return Response(
                    content=json.dumps({"error": f"Upstream error: {e}"}),
                    status_code=502, media_type="application/json",
                )

        # Inbound scan
        resp_body: dict = {}
        try:
            resp_body = upstream_resp.json()
        except Exception:
            pass

        response_text = extract_response_text(dest_cfg.format, resp_body)
        inbound_findings = scanner._scan_inbound_sync(response_text, upstream_url) if response_text else []
        input_tokens, output_tokens = extract_token_counts(dest_cfg.format, resp_body)
        cost = calculate_cost(body.get("model", ctx.model), input_tokens, output_tokens)
        latency = int((time.monotonic() - start) * 1000)

        _log(logger, mid, ctx, "outbound", "routed" if routed_to else "allowed",
             findings, request_id, routed_to=routed_to,
             task_type=signals.task_type.value, complexity=signals.complexity.value,
             developer=identity.name or identity.key_id)
        if inbound_findings:
            _log(logger, mid, ctx, "inbound", "allowed", inbound_findings, request_id,
                 input_tokens=input_tokens, output_tokens=output_tokens, cost_usd=cost,
                 latency_ms=latency, developer=identity.name or identity.key_id)
                 input_tokens=input_tokens, output_tokens=output_tokens, cost_usd=cost, latency_ms=latency)

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers),
            media_type=upstream_resp.headers.get("content-type"),
        )

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "0.5.0"}

    return app


async def _stream_response(
    upstream_url, upstream_headers, body_bytes,
    ctx, logger, scanner, policy, mid,
    request_id, signals, routed_to, start,
) -> StreamingResponse:
    accumulated: list[str] = []

    async def generate() -> AsyncIterator[bytes]:
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST", upstream_url, content=body_bytes, headers=upstream_headers) as resp:
                async for chunk in resp.aiter_bytes():
                    # Accumulate SSE for inbound scan
                    try:
                        text = chunk.decode()
                        accumulated.append(text)
                    except Exception:
                        pass
                    yield chunk

        # Scan assembled stream after it completes
        full = "".join(accumulated)
        inbound_findings = scanner._scan_inbound_sync(full, upstream_url)
        latency = int((time.monotonic() - start) * 1000)
        _log(logger, mid, ctx, "inbound", "allowed", inbound_findings, request_id, latency_ms=latency)

    _log(logger, mid, ctx, "outbound", "routed" if routed_to else "allowed",
         [], request_id, routed_to=routed_to,
         task_type=signals.task_type.value, complexity=signals.complexity.value)

    return StreamingResponse(generate(), media_type="text/event-stream")


def _build_upstream_headers(request: Request, dest_cfg, body_bytes: bytes) -> dict:
    """Build headers for the upstream request."""
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in skip}

    # Inject API key from env
    api_key = dest_cfg.get_api_key()
    if api_key and dest_cfg.auth_header:
        # Remove any existing auth
        for h in ("authorization", "x-api-key", "api-key"):
            headers.pop(h, None)
        value = f"{dest_cfg.auth_prefix}{api_key}".strip()
        headers[dest_cfg.auth_header] = value

    headers["content-length"] = str(len(body_bytes))
    return headers


def _block_response(decision: PolicyDecision) -> Response:
    return Response(
        content=json.dumps({
            "error": {
                "type": "policy_violation",
                "message": decision.message,
                "findings": [f.to_dict() for f in decision.findings],
            }
        }),
        status_code=400,
        media_type="application/json",
        headers={"x-airiskguard": "blocked"},
    )


def _log(logger, mid, ctx, direction, action, findings, request_id, **kwargs):
    try:
        logger.log(AuditEvent(
            machine_id=mid,
            provider=ctx.provider_name,
            model=ctx.model,
            direction=direction,
            action_taken=action,
            findings=findings,
            request_id=request_id,
            **kwargs,
        ))
    except Exception as e:
        log.warning("Audit log error: %s", e)
