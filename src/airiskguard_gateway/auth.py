from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig


GATEWAY_KEY_PREFIX = "gw-"
GATEWAY_KEY_ENV = "AIRISKGUARD_GATEWAY_KEY"    # single shared key (free tier)
KEYS_FILE_ENV = "AIRISKGUARD_KEYS_FILE"         # path to multi-key file (team tier)


@dataclass
class GatewayIdentity:
    """Who made this request."""
    key_id: str           # first 8 chars of key (safe to log)
    name: str = ""        # developer name/email if configured
    team: str = ""        # team name if configured
    is_valid: bool = True


@dataclass
class GatewayKeyEntry:
    key_hash: str         # sha256 of the key — never store plaintext
    key_id: str           # first 8 chars for display
    name: str = ""
    team: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True


class GatewayAuth:
    """
    Validates gateway-issued API keys on every inbound request.

    Free tier:  single shared key via AIRISKGUARD_GATEWAY_KEY env var
                or gateway_key in config.yaml
    Team tier:  per-developer keys in a keys file or policy server
    """

    def __init__(self, config: "GatewayConfig") -> None:
        self._config = config
        self._keys: dict[str, GatewayKeyEntry] = {}
        self._enabled = False
        self._load()

    def _load(self) -> None:
        """Load keys from config and/or keys file."""
        # Single shared key — free tier
        shared_key = (
            os.environ.get(GATEWAY_KEY_ENV, "")
            or self._config.gateway_key
        )
        if shared_key:
            self._enabled = True
            entry = _make_entry(shared_key, name="shared", team="")
            self._keys[entry.key_hash] = entry

        # Multi-key file — team tier
        keys_file = (
            os.environ.get(KEYS_FILE_ENV, "")
            or self._config.gateway_keys_file
        )
        if keys_file and Path(keys_file).exists():
            self._enabled = True
            self._load_keys_file(Path(keys_file))

        # If no auth configured — open access (warn at startup)
        if not self._enabled:
            pass  # warning printed by start command

    def _load_keys_file(self, path: Path) -> None:
        """
        Load a keys file. Format (one per line):
            key=gw-abc123   name=john@company.com   team=engineering
        or just:
            gw-abc123
        Lines starting with # are comments.
        """
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = dict(p.split("=", 1) for p in line.split() if "=" in p)
            raw_key = parts.get("key", line)
            if not raw_key:
                continue
            entry = _make_entry(
                raw_key,
                name=parts.get("name", ""),
                team=parts.get("team", ""),
            )
            self._keys[entry.key_hash] = entry

    def is_enabled(self) -> bool:
        return self._enabled

    def validate(self, key: str | None) -> GatewayIdentity | None:
        """
        Return GatewayIdentity if key is valid, None if invalid.
        If auth is disabled, always returns a default identity.
        """
        if not self._enabled:
            return GatewayIdentity(key_id="open", name="unauthenticated")

        if not key:
            return None

        # Strip common prefixes the SDK might add
        raw = key.strip()
        for prefix in ("Bearer ", "bearer "):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]

        key_hash = _hash_key(raw)
        entry = self._keys.get(key_hash)
        if not entry or not entry.active:
            return None

        return GatewayIdentity(
            key_id=entry.key_id,
            name=entry.name,
            team=entry.team,
            is_valid=True,
        )

    def reload(self) -> None:
        """Reload keys from disk (hot-reload without restart)."""
        self._keys.clear()
        self._enabled = False
        self._load()


def generate_gateway_key() -> str:
    """Generate a new gateway API key."""
    return GATEWAY_KEY_PREFIX + secrets.token_urlsafe(32)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _make_entry(key: str, name: str = "", team: str = "") -> GatewayKeyEntry:
    return GatewayKeyEntry(
        key_hash=_hash_key(key),
        key_id=key[:8] if len(key) >= 8 else key,
        name=name,
        team=team,
    )
