from airiskguard_gateway.costs import calculate_cost, get_pricing, MODEL_PRICING


def test_known_model_cost():
    # claude-sonnet-4-6: $3/M input, $15/M output
    cost = calculate_cost("claude-sonnet-4-6", input_tokens=1_000, output_tokens=500)
    expected = (1_000 / 1_000_000 * 3.0) + (500 / 1_000_000 * 15.0)
    assert abs(cost - expected) < 1e-9


def test_gpt4o_mini_cheap():
    cost = calculate_cost("gpt-4o-mini", input_tokens=10_000, output_tokens=5_000)
    expected = (10_000 / 1_000_000 * 0.15) + (5_000 / 1_000_000 * 0.60)
    assert abs(cost - expected) < 1e-9


def test_zero_tokens_zero_cost():
    assert calculate_cost("gpt-4o", 0, 0) == 0.0


def test_prefix_match():
    # versioned model name should match prefix
    cost = calculate_cost("claude-sonnet-4-6-20260101", 1_000_000, 0)
    assert cost == 3.0  # exact match on prefix


def test_unknown_model_fallback():
    # Unknown model uses fallback pricing — should not raise
    cost = calculate_cost("some-unknown-model-v99", 1_000, 1_000)
    assert cost > 0


def test_all_known_models_have_pricing():
    for model in MODEL_PRICING:
        p = get_pricing(model)
        assert p["input"] > 0
        assert p["output"] > 0


def test_savings_comparison():
    # Routing from gpt-4o to gpt-4o-mini saves ~94% on input
    expensive = calculate_cost("gpt-4o", 100_000, 50_000)
    cheap = calculate_cost("gpt-4o-mini", 100_000, 50_000)
    assert cheap < expensive * 0.2  # at least 80% savings
