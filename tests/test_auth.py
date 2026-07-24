import os
import tempfile
import pytest
from airiskguard_gateway.auth import (
    GatewayAuth, generate_gateway_key, GATEWAY_KEY_ENV
)
from airiskguard_gateway.config import GatewayConfig


def _cfg(**kwargs) -> GatewayConfig:
    cfg = GatewayConfig()
    for k, v in kwargs.items():
        setattr(cfg, k, v)
    return cfg


def test_auth_disabled_when_no_key():
    cfg = _cfg(gateway_key="", gateway_keys_file="")
    auth = GatewayAuth(cfg)
    assert not auth.is_enabled()
    # Returns default open identity when disabled
    identity = auth.validate(None)
    assert identity is not None
    assert identity.key_id == "open"


def test_shared_key_via_config():
    key = generate_gateway_key()
    cfg = _cfg(gateway_key=key)
    auth = GatewayAuth(cfg)
    assert auth.is_enabled()

    identity = auth.validate(key)
    assert identity is not None
    assert identity.is_valid


def test_shared_key_via_env(monkeypatch):
    key = generate_gateway_key()
    monkeypatch.setenv(GATEWAY_KEY_ENV, key)
    cfg = _cfg(gateway_key="")
    auth = GatewayAuth(cfg)
    assert auth.is_enabled()
    assert auth.validate(key) is not None


def test_wrong_key_rejected():
    key = generate_gateway_key()
    cfg = _cfg(gateway_key=key)
    auth = GatewayAuth(cfg)
    assert auth.validate("gw-wrong-key") is None
    assert auth.validate("") is None
    assert auth.validate(None) is None


def test_bearer_prefix_stripped():
    key = generate_gateway_key()
    cfg = _cfg(gateway_key=key)
    auth = GatewayAuth(cfg)
    assert auth.validate(f"Bearer {key}") is not None


def test_keys_file_multi_developer():
    key1 = generate_gateway_key()
    key2 = generate_gateway_key()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(f"# Gateway keys\n")
        f.write(f"key={key1}  name=john@company.com  team=engineering\n")
        f.write(f"key={key2}  name=jane@company.com  team=data\n")
        path = f.name

    cfg = _cfg(gateway_keys_file=path)
    auth = GatewayAuth(cfg)
    assert auth.is_enabled()

    id1 = auth.validate(key1)
    assert id1 is not None
    assert id1.name == "john@company.com"
    assert id1.team == "engineering"

    id2 = auth.validate(key2)
    assert id2 is not None
    assert id2.name == "jane@company.com"
    assert id2.team == "data"

    assert auth.validate("gw-not-a-key") is None
    os.unlink(path)


def test_key_format():
    key = generate_gateway_key()
    assert key.startswith("gw-")
    assert len(key) > 20


def test_key_id_is_first_8_chars():
    key = generate_gateway_key()
    cfg = _cfg(gateway_key=key)
    auth = GatewayAuth(cfg)
    identity = auth.validate(key)
    assert identity.key_id == key[:8]
