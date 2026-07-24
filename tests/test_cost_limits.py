import json
import tempfile
from pathlib import Path

from airiskguard_gateway.config import GatewayConfig
from airiskguard_gateway.cost_limits import CostLimitChecker


def _cfg_with_spend(overall: float = 0, per_provider: dict = None, action: str = "block") -> tuple[GatewayConfig, Path]:
    cfg = GatewayConfig()
    cfg.overall_limit_usd = overall
    cfg.per_provider_limits = per_provider or {}
    cfg.on_limit_reached = action
    return cfg


def _write_audit(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def test_no_limits_always_allows():
    cfg = _cfg_with_spend()
    checker = CostLimitChecker(cfg)
    allowed, msg = checker.check("openai")
    assert allowed
    assert msg == ""


def test_overall_limit_blocks_when_exceeded(tmp_path):
    cfg = _cfg_with_spend(overall=10.0)
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": f"{month}-15T10:00:00+00:00", "provider": "openai", "cost_usd": 6.0},
        {"timestamp": f"{month}-16T10:00:00+00:00", "provider": "anthropic", "cost_usd": 5.0},
    ])

    checker = CostLimitChecker(cfg)
    allowed, msg = checker.check("openai")
    assert not allowed
    assert "overall" in msg.lower()


def test_overall_limit_allows_under_limit(tmp_path):
    cfg = _cfg_with_spend(overall=100.0)
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": f"{month}-15T10:00:00+00:00", "provider": "openai", "cost_usd": 5.0},
    ])

    checker = CostLimitChecker(cfg)
    allowed, msg = checker.check("openai")
    assert allowed


def test_per_provider_limit_blocks(tmp_path):
    cfg = _cfg_with_spend(per_provider={"openai": 10.0})
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": f"{month}-10T10:00:00+00:00", "provider": "openai", "cost_usd": 12.0},
    ])

    checker = CostLimitChecker(cfg)
    # openai is over limit
    allowed, msg = checker.check("openai")
    assert not allowed
    assert "openai" in msg.lower()

    # anthropic is not limited
    allowed2, _ = checker.check("anthropic")
    assert allowed2


def test_alert_mode_allows_but_logs(tmp_path):
    cfg = _cfg_with_spend(overall=5.0, action="alert")
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": f"{month}-10T10:00:00+00:00", "provider": "openai", "cost_usd": 10.0},
    ])

    checker = CostLimitChecker(cfg)
    # Alert mode: limit exceeded but request still allowed
    allowed, msg = checker.check("openai")
    assert allowed  # alert mode does not block
    assert msg != ""  # but returns a message


def test_previous_month_not_counted(tmp_path):
    cfg = _cfg_with_spend(overall=10.0)
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": "2020-01-15T10:00:00+00:00", "provider": "openai", "cost_usd": 999.0},
        {"timestamp": f"{month}-01T10:00:00+00:00", "provider": "openai", "cost_usd": 1.0},
    ])

    checker = CostLimitChecker(cfg)
    allowed, _ = checker.check("openai")
    assert allowed  # old spend not counted


def test_current_spend_returns_correct_totals(tmp_path):
    cfg = _cfg_with_spend()
    audit = tmp_path / "audit.jsonl"
    cfg.audit.local_path = str(audit)

    from datetime import datetime, UTC
    month = datetime.now(UTC).strftime("%Y-%m")
    _write_audit(audit, [
        {"timestamp": f"{month}-01T00:00:00+00:00", "provider": "openai", "cost_usd": 3.5},
        {"timestamp": f"{month}-02T00:00:00+00:00", "provider": "openai", "cost_usd": 2.5},
        {"timestamp": f"{month}-03T00:00:00+00:00", "provider": "anthropic", "cost_usd": 1.0},
    ])

    checker = CostLimitChecker(cfg)
    spend = checker.current_spend()
    assert abs(spend["openai"] - 6.0) < 0.001
    assert abs(spend["anthropic"] - 1.0) < 0.001
    assert abs(spend["__total__"] - 7.0) < 0.001
