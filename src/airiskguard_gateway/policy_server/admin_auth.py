from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from fastapi import Cookie, HTTPException, Request, status
from fastapi.responses import RedirectResponse

# Admin credentials from env or config
ADMIN_USERNAME_ENV = "AIRISKGUARD_ADMIN_USER"
ADMIN_PASSWORD_ENV = "AIRISKGUARD_ADMIN_PASS"
SESSION_SECRET_ENV = "AIRISKGUARD_SESSION_SECRET"

DEFAULT_USERNAME = "admin"
# Sessions: token → expiry timestamp
_sessions: dict[str, float] = {}
SESSION_TTL = 8 * 3600  # 8 hours


def get_admin_credentials() -> tuple[str, str]:
    username = os.environ.get(ADMIN_USERNAME_ENV, DEFAULT_USERNAME)
    password = os.environ.get(ADMIN_PASSWORD_ENV, "")
    return username, password


def _session_secret() -> str:
    return os.environ.get(SESSION_SECRET_ENV, "airiskguard-default-secret-change-me")


def verify_login(username: str, password: str) -> Optional[str]:
    """Verify credentials. Returns session token on success, None on failure."""
    expected_user, expected_pass = get_admin_credentials()
    if not expected_pass:
        # No password set — allow any login (single-machine dev mode)
        if username == expected_user:
            return _create_session()
        return None
    if hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_pass):
        return _create_session()
    return None


def _create_session() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + SESSION_TTL
    return token


def validate_session(token: Optional[str]) -> bool:
    if not token:
        return False
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if time.time() > expiry:
        del _sessions[token]
        return False
    return True


def logout(token: Optional[str]) -> None:
    if token and token in _sessions:
        del _sessions[token]


def require_auth(request: Request, airiskguard_session: Optional[str] = Cookie(default=None)):
    """FastAPI dependency — redirects to login if not authenticated."""
    _, password = get_admin_credentials()
    if not password:
        return  # No password configured — open access
    if not validate_session(airiskguard_session):
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": f"/login?next={request.url.path}"},
        )
