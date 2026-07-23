import os
import pytest
from airiskguard_gateway.license import (
    validate_license, _compute_key, write_license_file, LICENSE_ENV_VAR
)


SECRET = "test-secret-key-for-testing"
SUB_ID = "sub_1TwDeoKHT8tEtpBt123456"


def test_no_key_returns_invalid():
    status = validate_license(license_key="", secret=SECRET)
    assert not status.valid
    assert "No license key" in status.reason


def test_invalid_format_rejected():
    status = validate_license(license_key="not-a-valid-key", secret=SECRET)
    assert not status.valid
    assert "format" in status.reason.lower()


def test_valid_hmac_key_accepted(tmp_path):
    key = _compute_key(SUB_ID, SECRET)
    # Write a license file so the verifier can check sub_id → key mapping
    license_file = tmp_path / ".airiskguard-license"
    write_license_file(SUB_ID, key, str(license_file))

    # Patch _find_license_file to return our temp file
    import airiskguard_gateway.license as lic_module
    original = lic_module._find_license_file
    lic_module._find_license_file = lambda: str(license_file)
    try:
        status = validate_license(license_key=key, secret=SECRET)
        assert status.valid, status.reason
        assert status.subscription_id == SUB_ID
    finally:
        lic_module._find_license_file = original


def test_wrong_key_rejected(tmp_path):
    real_key = _compute_key(SUB_ID, SECRET)
    fake_key = _compute_key("sub_fake_different_id", SECRET)

    license_file = tmp_path / ".airiskguard-license"
    write_license_file(SUB_ID, real_key, str(license_file))

    import airiskguard_gateway.license as lic_module
    original = lic_module._find_license_file
    lic_module._find_license_file = lambda: str(license_file)
    try:
        status = validate_license(license_key=fake_key, secret=SECRET)
        assert not status.valid
    finally:
        lic_module._find_license_file = original


def test_key_format():
    key = _compute_key(SUB_ID, SECRET)
    parts = key.split("-")
    assert len(parts) == 4
    assert all(len(p) == 8 for p in parts)
    assert key == key.upper()


def test_no_secret_accepts_formatted_key():
    key = _compute_key(SUB_ID, SECRET)
    # Without a secret, any correctly formatted key is accepted
    status = validate_license(license_key=key, secret="")
    assert status.valid


def test_env_var_used_when_no_arg(monkeypatch):
    key = _compute_key(SUB_ID, SECRET)
    monkeypatch.setenv(LICENSE_ENV_VAR, key)
    status = validate_license(secret="")
    assert status.valid


def test_write_and_parse_license_file(tmp_path):
    key = _compute_key(SUB_ID, SECRET)
    path = str(tmp_path / "test.license")
    written = write_license_file(SUB_ID, key, path)

    from airiskguard_gateway.license import _parse_license_file
    sub_id, parsed_key = _parse_license_file(written)
    assert sub_id == SUB_ID
    assert parsed_key == key.upper()
