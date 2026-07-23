from airiskguard_gateway.routing.engine import RoutingEngine, _glob_match
from airiskguard_gateway.routing.models import RoutingRule, RoutingDestination
from airiskguard_gateway.models import Category, Finding, Severity
from airiskguard_gateway.proxy.provider import RequestContext
import pytest


def _ctx(model: str = "gpt-4o", prompt: str = "hello", provider: str = "openai") -> RequestContext:
    return RequestContext(
        provider_name=provider,
        provider_format="openai",
        model=model,
        prompt_text=prompt,
        host="api.openai.com",
        path="/v1/chat/completions",
        request_id="test",
    )


def _finding(category: Category) -> Finding:
    return Finding(
        id="x", category=category, severity=Severity.HIGH,
        title="t", description="d", evidence="e", location="l", remediation="r",
    )


DEST_CHEAP = RoutingDestination(provider="openai", model="gpt-4o-mini")
DEST_LOCAL = RoutingDestination(provider="ollama", model="llama3.2", base_url="http://localhost:11434")
DEST_DEEPSEEK = RoutingDestination(provider="deepseek", model="deepseek-chat")


def _engine(rules, destinations=None, sticky=False):
    return RoutingEngine(
        rules=rules,
        destinations=destinations or {},
        sticky_sessions=sticky,
    )


def test_passthrough_when_no_rules():
    assert _engine([]).evaluate(_ctx(), []).action == "allow"


def test_routes_pii_to_internal():
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    engine = _engine(rules, {"internal": DEST_LOCAL})
    decision = engine.evaluate(_ctx(), [_finding(Category.PII_LEAKAGE)])
    assert decision.action == "route_to"
    assert decision.destination.model == "llama3.2"


def test_no_pii_no_route():
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    assert _engine(rules, {"internal": DEST_LOCAL}).evaluate(_ctx(), []).action == "allow"


def test_model_pattern_downgrade():
    rules = [RoutingRule(match="model_pattern", model_pattern="gpt-4*", action="route_to", destination="cheap")]
    decision = _engine(rules, {"cheap": DEST_CHEAP}).evaluate(_ctx(model="gpt-4o"), [])
    assert decision.action == "route_to"
    assert decision.destination.model == "gpt-4o-mini"


def test_model_pattern_no_match():
    rules = [RoutingRule(match="model_pattern", model_pattern="gpt-4*", action="route_to", destination="cheap")]
    assert _engine(rules, {"cheap": DEST_CHEAP}).evaluate(_ctx(model="claude-sonnet-4-6"), []).action == "allow"


def test_financial_data_route():
    rules = [RoutingRule(match="contains_financial_data", action="route_to", destination="deepseek")]
    ctx = _ctx(prompt="show me the revenue and ebitda for Q3")
    assert _engine(rules, {"deepseek": DEST_DEEPSEEK}).evaluate(ctx, []).action == "route_to"


def test_provider_match_rule():
    rules = [RoutingRule(match="provider", provider="openai", action="route_to", destination="deepseek")]
    decision = _engine(rules, {"deepseek": DEST_DEEPSEEK}).evaluate(_ctx(provider="openai"), [])
    assert decision.action == "route_to"
    assert decision.destination.provider == "deepseek"


def test_provider_no_match():
    rules = [RoutingRule(match="provider", provider="openai", action="route_to", destination="deepseek")]
    assert _engine(rules, {"deepseek": DEST_DEEPSEEK}).evaluate(_ctx(provider="anthropic"), []).action == "allow"


def test_task_type_route():
    rules = [RoutingRule(match="task_type", task_type="simple_qa", action="route_to", destination="cheap")]
    ctx = _ctx(prompt="What is the capital of France?")
    decision = _engine(rules, {"cheap": DEST_CHEAP}).evaluate(ctx, [])
    assert decision.action == "route_to"


def test_complexity_low_route():
    rules = [RoutingRule(match="complexity", complexity="low", action="route_to", destination="cheap")]
    ctx = _ctx(prompt="What is Python?")
    decision = _engine(rules, {"cheap": DEST_CHEAP}).evaluate(ctx, [])
    assert decision.action == "route_to"


def test_language_zh_route():
    rules = [RoutingRule(match="language", language="zh", action="route_to", destination="deepseek")]
    ctx = _ctx(prompt="请帮我写一个排序函数")
    decision = _engine(rules, {"deepseek": DEST_DEEPSEEK}).evaluate(ctx, [])
    assert decision.action == "route_to"


def test_always_rule_as_fallback():
    rules = [
        RoutingRule(match="contains_pii", action="route_to", destination="internal"),
        RoutingRule(match="always", action="route_to", destination="cheap"),
    ]
    decision = _engine(rules, {"internal": DEST_LOCAL, "cheap": DEST_CHEAP}).evaluate(_ctx(), [])
    assert decision.action == "route_to"
    assert decision.destination.model == "gpt-4o-mini"


def test_block_rule():
    rules = [RoutingRule(match="contains_secrets", action="block")]
    assert _engine(rules).evaluate(_ctx(), [_finding(Category.HARDCODED_SECRETS)]).action == "block"


def test_session_stickiness(tmp_path):
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    engine = RoutingEngine(
        rules=rules,
        destinations={"internal": DEST_LOCAL},
        sticky_sessions=True,
        session_store_path=tmp_path / "sessions.json",
    )
    # First request with PII — gets routed and pinned
    decision1 = engine.evaluate(_ctx(), [_finding(Category.PII_LEAKAGE)], session_id="conv-abc")
    assert decision1.action == "route_to"
    assert not decision1.session_pinned

    # Second request in same session — no PII, but pinned to same destination
    decision2 = engine.evaluate(_ctx(), [], session_id="conv-abc")
    assert decision2.action == "route_to"
    assert decision2.session_pinned
    assert decision2.destination.model == "llama3.2"


def test_different_sessions_independent(tmp_path):
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    engine = RoutingEngine(
        rules=rules,
        destinations={"internal": DEST_LOCAL},
        sticky_sessions=True,
        session_store_path=tmp_path / "sessions.json",
    )
    engine.evaluate(_ctx(), [_finding(Category.PII_LEAKAGE)], session_id="session-A")
    # Different session, no PII — should not be pinned
    decision = engine.evaluate(_ctx(), [], session_id="session-B")
    assert decision.action == "allow"


def test_glob_match():
    assert _glob_match("gpt-4*", "gpt-4o") is True
    assert _glob_match("gpt-4*", "gpt-4o-mini") is True
    assert _glob_match("gpt-4*", "claude-sonnet") is False
    assert _glob_match("*opus*", "claude-opus-4-8") is True
    assert _glob_match("deepseek-*", "deepseek-chat") is True
    assert _glob_match("moonshot-*", "moonshot-v1-8k") is True
