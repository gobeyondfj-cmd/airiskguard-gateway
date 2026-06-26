from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from airiskguard_gateway.models import (
    Category,
    Finding,
    PolicyDecision,
    Severity,
    SEVERITY_ORDER,
)

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig
    from airiskguard_gateway.policy.models import PolicySet


class PolicyEngine:
    def __init__(self, config: "GatewayConfig") -> None:
        self._config = config
        self._policy_set: "PolicySet | None" = None

    def update_policy(self, policy_set: "PolicySet") -> None:
        self._policy_set = policy_set

    def evaluate_outbound(self, findings: list[Finding]) -> PolicyDecision:
        if not findings:
            return PolicyDecision(action="allow")

        action = self._config.outbound.action
        threshold = Severity.MEDIUM  # only act on medium+

        triggered = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[threshold]]
        if not triggered:
            return PolicyDecision(action="allow", findings=findings)

        return PolicyDecision(
            action=action,
            findings=triggered,
            message=f"{len(triggered)} policy violation(s) detected in outbound request.",
        )

    def evaluate_inbound(self, findings: list[Finding]) -> PolicyDecision:
        if not findings:
            return PolicyDecision(action="allow")

        action = self._config.inbound.action
        triggered = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.MEDIUM]]

        if not triggered:
            return PolicyDecision(action="allow", findings=findings)

        return PolicyDecision(
            action=action,
            findings=triggered,
            message=f"{len(triggered)} policy violation(s) detected in inbound response.",
        )

    def check_model_allowed(self, model: str) -> PolicyDecision:
        if not self._config.model_allowlist.enabled:
            return PolicyDecision(action="allow")

        allowed = self._config.model_allowlist.allowed_models
        if model in allowed or any(model.startswith(m) for m in allowed):
            return PolicyDecision(action="allow")

        import uuid
        finding = Finding(
            id=str(uuid.uuid4()),
            category=Category.MODEL_POLICY,
            severity=Severity.HIGH,
            title=f"Model not in allowlist: {model}",
            description=f"The requested model '{model}' is not in the organization's approved model list.",
            evidence=f"Requested: {model}",
            location="model_allowlist",
            remediation=f"Use an approved model. Allowed: {', '.join(allowed[:5])}{'...' if len(allowed) > 5 else ''}",
        )

        action = self._config.model_allowlist.action
        return PolicyDecision(
            action=action,
            findings=[finding],
            message=f"Model '{model}' is not in the approved allowlist.",
        )
