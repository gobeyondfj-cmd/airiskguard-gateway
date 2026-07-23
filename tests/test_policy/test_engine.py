from airiskguard_gateway.config import GatewayConfig
from airiskguard_gateway.models import Category, Finding, Severity
from airiskguard_gateway.policy.engine import PolicyEngine


def _finding(severity: Severity, category: Category = Category.HARDCODED_SECRETS) -> Finding:
    return Finding(
        id="test-id",
        category=category,
        severity=severity,
        title="Test finding",
        description="Test",
        evidence="test",
        location="test",
        remediation="test",
    )


def test_allows_clean_request():
    cfg = GatewayConfig()
    engine = PolicyEngine(cfg)
    decision = engine.evaluate_outbound([])
    assert decision.action == "allow"


def test_blocks_critical_finding():
    cfg = GatewayConfig()
    engine = PolicyEngine(cfg)
    decision = engine.evaluate_outbound([_finding(Severity.CRITICAL)])
    assert decision.action == "block"


def test_blocks_model_not_in_allowlist():
    cfg = GatewayConfig()
    engine = PolicyEngine(cfg)
    decision = engine.check_model_allowed("gpt-99-turbo-ultra")
    assert decision.action == "block"
    assert any("not in" in f.description.lower() for f in decision.findings)


def test_allows_model_in_allowlist():
    cfg = GatewayConfig()
    engine = PolicyEngine(cfg)
    decision = engine.check_model_allowed("claude-sonnet-4-6")
    assert decision.action == "allow"


def test_log_action_on_low_severity():
    cfg = GatewayConfig()
    cfg.on_secrets_detected = "log"
    engine = PolicyEngine(cfg)
    # Low severity should not trigger (below medium threshold)
    decision = engine.evaluate_outbound([_finding(Severity.LOW)])
    assert decision.action == "allow"
