from __future__ import annotations

from typing import TYPE_CHECKING

from airiskguard_gateway.routing.models import (
    RoutingDecision,
    RoutingDestination,
    RoutingRule,
    FINANCIAL_KEYWORDS,
)

if TYPE_CHECKING:
    from airiskguard_gateway.models import Category, Finding
    from airiskguard_gateway.proxy.provider import RequestContext


class RoutingEngine:
    """Evaluates routing rules in order. First match wins."""

    def __init__(
        self,
        rules: list[RoutingRule],
        destinations: dict[str, RoutingDestination],
    ) -> None:
        self._rules = rules
        self._destinations = destinations

    def evaluate(
        self,
        context: "RequestContext",
        findings: list["Finding"],
    ) -> RoutingDecision:
        """Return the first matching routing decision, or allow passthrough."""
        if not self._rules:
            return RoutingDecision(action="allow")

        finding_categories = {f.category.value for f in findings}
        prompt_lower = context.prompt_text.lower()

        for rule in self._rules:
            if self._matches(rule, context, finding_categories, prompt_lower):
                return self._make_decision(rule)

        return RoutingDecision(action="allow")

    def _matches(
        self,
        rule: RoutingRule,
        context: "RequestContext",
        finding_categories: set[str],
        prompt_lower: str,
    ) -> bool:
        if rule.match == "always":
            return True
        if rule.match == "contains_pii":
            return "pii_leakage" in finding_categories
        if rule.match == "contains_secrets":
            return "hardcoded_secrets" in finding_categories
        if rule.match == "contains_financial_data":
            return any(kw in prompt_lower for kw in FINANCIAL_KEYWORDS)
        if rule.match == "model_pattern":
            return _glob_match(rule.model_pattern, context.model)
        return False

    def _make_decision(self, rule: RoutingRule) -> RoutingDecision:
        if rule.action == "block":
            return RoutingDecision(action="block", matched_rule=rule)
        if rule.action == "allow":
            return RoutingDecision(action="allow", matched_rule=rule)
        # route_to
        dest = self._destinations.get(rule.destination)
        if dest is None:
            # Destination not configured — fall through to allow
            return RoutingDecision(action="allow", matched_rule=rule)
        return RoutingDecision(action="route_to", destination=dest, matched_rule=rule)


def _glob_match(pattern: str, value: str) -> bool:
    """Simple glob: only supports leading/trailing/middle * wildcards."""
    if not pattern:
        return False
    if pattern == "*":
        return True
    if pattern.startswith("*") and pattern.endswith("*"):
        return pattern[1:-1] in value
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    if pattern.startswith("*"):
        return value.endswith(pattern[1:])
    return pattern == value
