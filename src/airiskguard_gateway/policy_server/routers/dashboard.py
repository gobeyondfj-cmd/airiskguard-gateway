from __future__ import annotations

from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    since = datetime.now(UTC) - timedelta(hours=24)
    stats = await _get_stats(db, since)
    recent = await _get_recent_events(db, limit=20)
    teams = await db.scalars(select(Team).order_by(Team.created_at.desc()))
    return templates.TemplateResponse(request, "dashboard.html", {
        "request": request,
        "stats": stats,
        "recent_events": recent,
        "teams": list(teams.all()),
    })


@router.get("/dashboard/violations", response_class=HTMLResponse)
async def violations_partial(
    request: Request,
    action: str | None = None,
    provider: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """HTMX partial: violation feed."""
    events = await _get_recent_events(db, limit=50, action=action, provider=provider)
    return templates.TemplateResponse(request, "violations.html", {
        "request": request,
        "events": events,
    })


@router.get("/dashboard/stats", response_class=HTMLResponse)
async def stats_partial(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    """HTMX partial: stats cards (auto-refreshed)."""
    since = datetime.now(UTC) - timedelta(hours=24)
    stats = await _get_stats(db, since)
    return templates.TemplateResponse(request, "stats_cards.html", {
        "request": request,
        "stats": stats,
    })


async def _get_stats(db: AsyncSession, since: datetime) -> dict:
    total = await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since)) or 0
    blocked = await db.scalar(
        select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.action_taken == "blocked")
    ) or 0
    redacted = await db.scalar(
        select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.action_taken == "redacted")
    ) or 0
    return {
        "total": total,
        "blocked": blocked,
        "redacted": redacted,
        "allowed": total - blocked - redacted,
        "block_rate": f"{(blocked / total * 100):.1f}%" if total else "0%",
    }


async def _get_recent_events(
    db: AsyncSession,
    limit: int = 20,
    action: str | None = None,
    provider: str | None = None,
) -> list[AuditEventRecord]:
    filters = []
    if action:
        filters.append(AuditEventRecord.action_taken == action)
    if provider:
        filters.append(AuditEventRecord.provider == provider)

    q = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(limit)
    if filters:
        q = q.where(and_(*filters))

    result = await db.scalars(q)
    return list(result.all())
