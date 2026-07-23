from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from airiskguard_gateway.license import validate_license, LicenseStatus
from airiskguard_gateway.policy_server.database import init_db
from airiskguard_gateway.policy_server.routers import teams, policies, events, dashboard

log = logging.getLogger(__name__)

# Module-level license status — set at startup, read by routes
_license: LicenseStatus | None = None


def get_license() -> LicenseStatus:
    return _license or LicenseStatus(False, "License not checked yet.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _license

    # Validate license on startup
    _license = validate_license()
    if _license.valid:
        log.info("License valid. Team tier features enabled.")
    else:
        log.warning("License invalid: %s — Team features locked.", _license.reason)

    await init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIRiskGuard Gateway — Policy Server",
        description="Centralized policy management for AIRiskGuard Gateway.",
        version="0.5.0",
        lifespan=lifespan,
    )

    app.include_router(teams.router)
    app.include_router(policies.router)
    app.include_router(events.router)
    app.include_router(dashboard.router)

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/dashboard")

    @app.get("/health")
    async def health():
        lic = get_license()
        return {
            "status": "ok",
            "licensed": lic.valid,
            "license_message": lic.reason if not lic.valid else "valid",
        }

    return app


app = create_app()
