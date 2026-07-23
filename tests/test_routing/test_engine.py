from airiskguard_gateway.routing.engine import RoutingEngine, _glob_match
from airiskguard_gateway.routing.models import RoutingRule, RoutingDestination
from airiskguard_gateway.models import Category, Finding, Severity
from airiskguard_gateway.proxy.provider import RequestContext


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


def test_passthrough_when_no_rules():
    engine = RoutingEngine(rules=[], destinations={})
    assert engine.evaluate(_ctx(), []).action == "allow"


def test_routes_pii_to_internal():
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    engine = RoutingEngine(rules=rules, destinations={"internal": DEST_LOCAL})
    decision = engine.evaluate(_ctx(), [_finding(Category.PII_LEAKAGE)])
    assert decision.action == "route_to"
    assert decision.destination.model == "llama3.2"


def test_no_pii_no_route():
    rules = [RoutingRule(match="contains_pii", action="route_to", destination="internal")]
    engine = RoutingEngine(rules=rules, destinations={"internal": DEST_LOCAL})
    assert engine.evaluate(_ctx(), []).action == "allow"


def test_model_pattern_downgrade():
    rules = [RoutingRule(match="model_pattern", model_pattern="gpt-4*", action="route_to", destination="cheap")]
    engine = RoutingEngine(rules=rules, destinations={"cheap": DEST_CHEAP})
    decision = engine.evaluate(_ctx(model="gpt-4o"), [])
    assert decision.action == "route_to"
    assert decision.destination.model == "gpt-4o-mini"


def test_model_pattern_no_match():
    rules = [RoutingRule(match="model_pattern", model_pattern="gpt-4*", action="route_to", destination="cheap")]
    engine = RoutingEngine(rules=rules, destinations={"cheap": DEST_CHEAP})
    assert engine.evaluate(_ctx(model="claude-sonnet-4-6"), []).action == "allow"


def test_financial_data_route():
    rules = [RoutingRule(match="contains_financial_data", action="route_to", destination="deepseek")]
    engine = RoutingEngine(rules=rules, destinations={"deepseek": DEST_DEEPSEEK})
    ctx = _ctx(prompt="show me the revenue and ebitda for Q3")
    assert engine.evaluate(ctx, []).action == "route_to"


def test_provider_match_rule():
    rules = [RoutingRule(match="provider", provider="openai", action="route_to", destination="deepseek")]
    engine = RoutingEngine(rules=rules, destinations={"deepseek": DEST_DEEPSEEK})
    decision = engine.evaluate(_ctx(provider="openai"), [])
    assert decision.action == "route_to"
    assert decision.destination.provider == "deepseek"


def test_provider_no_match():
    rules = [RoutingRule(match="provider", provider="openai", action="route_to", destination="deepseek")]
    engine = RoutingEngine(rules=rules, destinations={"deepseek": DEST_DEEPSEEK})
    assert engine.evaluate(_ctx(provider="anthropic"), []).action == "allow"


def test_always_rule_as_fallback():
    rules = [
        RoutingRule(match="contains_pii", action="route_to", destination="internal"),
        RoutingRule(match="always", action="route_to", destination="cheap"),
    ]
    engine = RoutingEngine(rules=rules, destinations={"internal": DEST_LOCAL, "cheap": DEST_CHEAP})
    decision = engine.evaluate(_ctx(), [])
    assert decision.action == "route_to"
    assert decision.destination.model == "gpt-4o-mini"


def test_block_rule():
    rules = [RoutingRule(match="contains_secrets", action="block")]
    engine = RoutingEngine(rules=rules, destinations={})
    assert engine.evaluate(_ctx(), [_finding(Category.HARDCODED_SECRETS)]).action == "block"


def test_glob_match():
    assert _glob_match("gpt-4*", "gpt-4o") is True
    assert _glob_match("gpt-4*", "gpt-4o-mini") is True
    assert _glob_match("gpt-4*", "claude-sonnet") is False
    assert _glob_match("*opus*", "claude-opus-4-8") is True
    assert _glob_match("deepseek-*", "deepseek-chat") is True
    assert _glob_match("moonshot-*", "moonshot-v1-8k") is True
