from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from airiskguard_gateway.policy_server.database import init_db
from airiskguard_gateway.policy_server.routers import teams, policies, events, dashboard


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AIRiskGuard Gateway — Policy Server",
        description="Centralized policy management and audit log storage for AIRiskGuard Gateway.",
        version="0.1.0",
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
        return {"status": "ok", "service": "airiskguard-gateway-policy-server"}

    return app


app = create_app()
