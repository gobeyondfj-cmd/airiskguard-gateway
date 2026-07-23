import time
from pathlib import Path

import pytest

from airiskguard_gateway.routing.session import SessionStore
from airiskguard_gateway.routing.models import RoutingDestination


@pytest.fixture
def store(tmp_path):
    return SessionStore(path=tmp_path / "sessions.json", ttl_hours=1)


DEST = RoutingDestination(provider="deepseek", model="deepseek-chat")


def test_pin_and_retrieve(store):
    store.pin("conv-123", DEST)
    result = store.get("conv-123")
    assert result is not None
    assert result.provider == "deepseek"
    assert result.model == "deepseek-chat"


def test_unknown_session_returns_none(store):
    assert store.get("conv-unknown") is None


def test_expired_session_returns_none(tmp_path):
    store = SessionStore(path=tmp_path / "s.json", ttl_hours=0)
    store.pin("conv-456", DEST)
    # TTL is 0 hours = expires immediately
    time.sleep(0.01)
    assert store.get("conv-456") is None


def test_overwrite_pin(store):
    dest2 = RoutingDestination(provider="openai", model="gpt-4o-mini")
    store.pin("conv-789", DEST)
    store.pin("conv-789", dest2)
    result = store.get("conv-789")
    assert result.provider == "openai"


def test_persists_to_disk(tmp_path):
    path = tmp_path / "sessions.json"
    s1 = SessionStore(path=path, ttl_hours=1)
    s1.pin("conv-abc", DEST)

    # New instance reads from same file
    s2 = SessionStore(path=path, ttl_hours=1)
    result = s2.get("conv-abc")
    assert result is not None
    assert result.provider == "deepseek"


def test_clear_expired(store):
    store.pin("active", DEST)
    removed = store.clear_expired()
    assert removed == 0
