from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

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
        """Hot-reload policy from the policy server."""
        self._policy_set = policy_set

    def check_model_allowed(self, model: str) -> PolicyDecision:
        """
        Remote policy (from policy server) takes priority over local config.
        Falls back to local allowed_models when no remote policy is loaded.
        """
        # Remote policy first
        if self._policy_set and self._policy_set.model_allowlist:
            allowed = self._policy_set.model_allowlist
            if model in allowed or any(model.startswith(m) for m in allowed):
                return PolicyDecision(action="allow")
            finding = Finding(
                id=str(uuid.uuid4()),
                category=Category.MODEL_POLICY,
                severity=Severity.HIGH,
                title=f"Model not in team allowlist: {model}",
                description=f"The requested model '{model}' is not in the team's approved list.",
                evidence=f"Requested: {model}",
                location="remote_policy",
                remediation=f"Use an approved model: {', '.join(allowed[:5])}",
            )
            return PolicyDecision(
                action=self._config.on_disallowed_model,
                findings=[finding],
                message=f"Model '{model}' blocked by team policy.",
            )

        # Local config fallback
        if not self._config.model_allowlist_enabled:
            return PolicyDecision(action="allow")

        allowed = self._config.allowed_models
        if model in allowed or any(model.startswith(m) for m in allowed):
            return PolicyDecision(action="allow")

        finding = Finding(
            id=str(uuid.uuid4()),
            category=Category.MODEL_POLICY,
            severity=Severity.HIGH,
            title=f"Model not in allowlist: {model}",
            description=f"The requested model '{model}' is not in the approved list.",
            evidence=f"Requested: {model}",
            location="model_allowlist",
            remediation=f"Use an approved model: {', '.join(allowed[:5])}",
        )
        return PolicyDecision(
            action=self._config.on_disallowed_model,
            findings=[finding],
            message=f"Model '{model}' is not in the approved allowlist.",
        )

    def evaluate_outbound(self, findings: list[Finding]) -> PolicyDecision:
        if not findings:
            return PolicyDecision(action="allow")

        triggered: list[Finding] = []
        worst_action = "allow"

        for f in findings:
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[Severity.MEDIUM]:
                continue
            triggered.append(f)
            if f.category == Category.HARDCODED_SECRETS:
                action = self._config.on_secrets_detected
            elif f.category == Category.PII_LEAKAGE:
                action = self._config.on_pii_detected
            else:
                action = self._config.on_secrets_detected

            if _action_severity(action) > _action_severity(worst_action):
                worst_action = action

        if not triggered:
            return PolicyDecision(action="allow", findings=findings)

        return PolicyDecision(
            action=worst_action,  # type: ignore
            findings=triggered,
            message=f"{len(triggered)} policy violation(s) in outbound request.",
        )

    def evaluate_inbound(self, findings: list[Finding]) -> PolicyDecision:
        if not findings:
            return PolicyDecision(action="allow")
        triggered = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.MEDIUM]]
        if not triggered:
            return PolicyDecision(action="allow", findings=findings)
        return PolicyDecision(
            action="log",
            findings=triggered,
            message=f"{len(triggered)} vulnerability pattern(s) in AI-generated code.",
        )


def _action_severity(action: str) -> int:
    return {"allow": 0, "log": 1, "redact": 2, "block": 3}.get(action, 0)
