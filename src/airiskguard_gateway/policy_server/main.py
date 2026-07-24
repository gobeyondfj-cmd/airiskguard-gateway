from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from airiskguard_gateway.license import validate_license
from airiskguard_gateway.policy_server.database import init_db, AsyncSessionLocal
from airiskguard_gateway.policy_server.license_state import set_license, get_license
from airiskguard_gateway.policy_server.routers import teams, policies, events, dashboard
from airiskguard_gateway.policy_server.routers.settings import router as settings_router, purge_old_events

log = logging.getLogger(__name__)


async def _daily_purge(retention_days: int = 30) -> None:
    """Background task: purge events older than retention_days once per day."""
    while True:
        await asyncio.sleep(86_400)  # 24 hours
        try:
            async with AsyncSessionLocal() as db:
                await purge_old_events(db, retention_days)
        except Exception as e:
            log.warning("Purge task error: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    lic = validate_license()
    set_license(lic)
    if lic.valid:
        log.info("License valid. Team tier features enabled.")
    else:
        log.warning("License invalid: %s — Team features locked.", lic.reason)

    await init_db()

    # Start 30-day retention purge in background
    purge_task = asyncio.create_task(_daily_purge(retention_days=30))

    yield

    purge_task.cancel()


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIRiskGuard Gateway — Policy Server",
        description="Centralized policy management for AIRiskGuard Gateway.",
        version="0.8.0",
        lifespan=lifespan,
    )
    app.include_router(teams.router)
    app.include_router(policies.router)
    app.include_router(events.router)
    app.include_router(settings_router)
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
