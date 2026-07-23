from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from airiskguard_gateway.routing.classifier import classify, ContentSignals
from airiskguard_gateway.routing.models import (
    RoutingDecision,
    RoutingDestination,
    RoutingRule,
    FINANCIAL_KEYWORDS,
)
from airiskguard_gateway.routing.session import SessionStore

if TYPE_CHECKING:
    from airiskguard_gateway.models import Finding
    from airiskguard_gateway.proxy.provider import RequestContext

log = logging.getLogger(__name__)


class RoutingEngine:
    """
    Evaluates routing rules in order. First match wins.
    Session stickiness: once a conversation is routed, subsequent requests
    in the same conversation go to the same destination.
    """

    def __init__(
        self,
        rules: list[RoutingRule],
        destinations: dict[str, RoutingDestination],
        sticky_sessions: bool = True,
        session_ttl_hours: int = 24,
        session_store_path: Path | None = None,
    ) -> None:
        self._rules = rules
        self._destinations = destinations
        self._sticky = sticky_sessions
        self._sessions = SessionStore(
            path=session_store_path or (Path.home() / ".local" / "share" / "airiskguard-gateway" / "sessions.json"),
            ttl_hours=session_ttl_hours,
        )

    def evaluate(
        self,
        context: "RequestContext",
        findings: list["Finding"],
        session_id: str | None = None,
    ) -> RoutingDecision:
        # 1. Session stickiness — check if this conversation is already pinned
        if self._sticky and session_id:
            pinned = self._sessions.get(session_id)
            if pinned:
                log.debug("Session %s pinned to %s:%s", session_id, pinned.provider, pinned.model)
                return RoutingDecision(
                    action="route_to",
                    destination=pinned,
                    session_pinned=True,
                )

        if not self._rules:
            return RoutingDecision(action="allow")

        # 2. Classify content once — used by multiple rule types
        signals: ContentSignals | None = None

        def get_signals() -> ContentSignals:
            nonlocal signals
            if signals is None:
                signals = classify(context.prompt_text)
            return signals

        finding_categories = {f.category.value for f in findings}
        prompt_lower = context.prompt_text.lower()

        # 3. Evaluate rules in order
        for rule in self._rules:
            if self._matches(rule, context, finding_categories, prompt_lower, get_signals):
                decision = self._make_decision(rule)
                # Pin the session if stickiness is on and we're routing
                if self._sticky and session_id and decision.action == "route_to" and decision.destination:
                    self._sessions.pin(session_id, decision.destination)
                    log.debug("Pinned session %s → %s:%s",
                              session_id, decision.destination.provider, decision.destination.model)
                return decision

        return RoutingDecision(action="allow")

    def _matches(
        self,
        rule: RoutingRule,
        context: "RequestContext",
        finding_categories: set[str],
        prompt_lower: str,
        get_signals,
    ) -> bool:
        match rule.match:
            case "always":
                return True
            case "contains_pii":
                return "pii_leakage" in finding_categories
            case "contains_secrets":
                return "hardcoded_secrets" in finding_categories
            case "contains_financial_data":
                return any(kw in prompt_lower for kw in FINANCIAL_KEYWORDS)
            case "model_pattern":
                return _glob_match(rule.model_pattern, context.model)
            case "provider":
                return context.provider_name == rule.provider
            case "task_type":
                return get_signals().task_type.value == rule.task_type
            case "complexity":
                return get_signals().complexity.value == rule.complexity
            case "language":
                return get_signals().language == rule.language
        return False

    def _make_decision(self, rule: RoutingRule) -> RoutingDecision:
        if rule.action == "block":
            return RoutingDecision(action="block", matched_rule=rule)
        if rule.action == "allow":
            return RoutingDecision(action="allow", matched_rule=rule)
        dest = self._destinations.get(rule.destination)
        if dest is None:
            log.warning("Routing destination '%s' not found — allowing", rule.destination)
            return RoutingDecision(action="allow", matched_rule=rule)
        return RoutingDecision(action="route_to", destination=dest, matched_rule=rule)


def _glob_match(pattern: str, value: str) -> bool:
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
