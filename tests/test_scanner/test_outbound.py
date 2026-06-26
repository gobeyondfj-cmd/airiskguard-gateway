from airiskguard_gateway.scanner.outbound.secrets import scan_outbound_secrets, redact_secrets
from airiskguard_gateway.scanner.outbound.pii import scan_outbound_pii
from airiskguard_gateway.models import Severity, Category


def test_detects_anthropic_key():
    text = "Here is my key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ"
    findings = scan_outbound_secrets(text)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].category == Category.HARDCODED_SECRETS


def test_detects_openai_key():
    text = "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456 for the API"
    findings = scan_outbound_secrets(text)
    assert any(f.category == Category.HARDCODED_SECRETS for f in findings)


def test_detects_db_connection_string():
    text = "Connect using postgresql://admin:secret123@db.example.com/mydb"
    findings = scan_outbound_secrets(text)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    findings = scan_outbound_secrets(text)
    assert any(f.title == "Private key material in prompt" for f in findings)


def test_no_false_positives_on_clean_text():
    text = "Please help me write a Python function that sorts a list."
    findings = scan_outbound_secrets(text)
    assert len(findings) == 0


def test_redact_replaces_secret():
    text = "My key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ"
    redacted = redact_secrets(text)
    assert "sk-ant" not in redacted
    assert "[REDACTED]" in redacted


def test_detects_email():
    text = "The customer john.smith@bigbank.com called about his account."
    findings = scan_outbound_pii(text)
    assert any(f.category == Category.PII_LEAKAGE for f in findings)


def test_ignores_example_email():
    text = "Send to example@example.com for testing."
    findings = scan_outbound_pii(text)
    assert len(findings) == 0


def test_detects_ssn():
    text = "Patient SSN: 123-45-6789"
    findings = scan_outbound_pii(text)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_credit_card():
    text = "Card number: 4532 1234 5678 9012"
    findings = scan_outbound_pii(text)
    assert any(f.severity == Severity.CRITICAL for f in findings)
