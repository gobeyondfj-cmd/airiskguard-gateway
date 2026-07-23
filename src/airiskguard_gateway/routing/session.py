from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from airiskguard_gateway.routing.models import RoutingDestination


class SessionStore:
    """
    Local on-disk store mapping conversation/session IDs to routing destinations.
    Thread-safe. Entries expire after ttl_hours.
    """

    def __init__(self, path: Path, ttl_hours: int = 24) -> None:
        self._path = path
        self._ttl_seconds = ttl_hours * 3600
        self._lock = threading.Lock()
        self._store: dict[str, dict] = {}
        self._load()

    def get(self, session_id: str) -> "RoutingDestination | None":
        """Return the pinned destination for this session, or None if expired/unknown."""
        with self._lock:
            entry = self._store.get(session_id)
            if not entry:
                return None
            if time.time() - entry["ts"] > self._ttl_seconds:
                del self._store[session_id]
                self._persist()
                return None
            from airiskguard_gateway.routing.models import RoutingDestination
            return RoutingDestination(**entry["destination"])

    def pin(self, session_id: str, destination: "RoutingDestination") -> None:
        """Pin a destination to this session ID."""
        with self._lock:
            self._store[session_id] = {
                "destination": {
                    "provider": destination.provider,
                    "model": destination.model,
                    "base_url": destination.base_url,
                    "api_key_env": destination.api_key_env,
                },
                "ts": time.time(),
            }
            self._persist()

    def clear_expired(self) -> int:
        """Remove expired entries. Returns number removed."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._store.items()
                       if now - v["ts"] > self._ttl_seconds]
            for k in expired:
                del self._store[k]
            if expired:
                self._persist()
        return len(expired)

    def _load(self) -> None:
        try:
            if self._path.exists():
                with open(self._path) as f:
                    self._store = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._store = {}

    def _persist(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(self._store, f)
            tmp.replace(self._path)
        except OSError:
            pass  # Non-fatal — sessions just won't survive restarts
