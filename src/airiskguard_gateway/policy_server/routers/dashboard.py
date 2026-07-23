from __future__ import annotations

from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team
from airiskguard_gateway.policy_server.main import get_license
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    lic = get_license()
    if not lic.valid:
        return templates.TemplateResponse(request, "unlicensed.html", {
            "reason": lic.reason,
        })

    since_24h = datetime.now(UTC) - timedelta(hours=24)
    stats = await _get_stats(db, since_24h)
    cost_data = await _get_cost_data(db)
    recent = await _get_recent_events(db, limit=25)
    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats,
        "cost_data": cost_data,
        "events": recent,
    })


@router.get("/dashboard/violations", response_class=HTMLResponse)
async def violations_partial(
    request: Request,
    action: str | None = None,
    routed: int | None = None,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    events = await _get_recent_events(db, limit=50, action=action, routed_only=bool(routed))
    return templates.TemplateResponse(request, "violations.html", {"events": events})


@router.get("/dashboard/costs", response_class=HTMLResponse)
async def costs_partial(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    since_24h = datetime.now(UTC) - timedelta(hours=24)
    stats = await _get_stats(db, since_24h)
    cost_data = await _get_cost_data(db)
    return templates.TemplateResponse(request, "cost_cards.html", {
        "stats": stats,
        "cost_data": cost_data,
    })


async def _get_stats(db: AsyncSession, since: datetime) -> dict:
    total = await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since)) or 0
    blocked = await db.scalar(
        select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.action_taken == "blocked")
    ) or 0
    return {
        "total": total, "blocked": blocked,
        "block_rate": f"{(blocked / total * 100):.1f}%" if total else "0%",
    }


async def _get_cost_data(db: AsyncSession, since_hours: int = 720) -> dict:
    since = datetime.now(UTC) - timedelta(hours=since_hours)
    total_cost = float(await db.scalar(
        select(func.sum(AuditEventRecord.cost_usd)).where(AuditEventRecord.timestamp >= since)
    ) or 0)
    total_in = int(await db.scalar(
        select(func.sum(AuditEventRecord.input_tokens)).where(AuditEventRecord.timestamp >= since)
    ) or 0)
    total_out = int(await db.scalar(
        select(func.sum(AuditEventRecord.output_tokens)).where(AuditEventRecord.timestamp >= since)
    ) or 0)
    model_rows = await db.execute(
        select(
            AuditEventRecord.model,
            func.sum(AuditEventRecord.cost_usd).label("cost"),
            func.sum(AuditEventRecord.input_tokens).label("input_tokens"),
            func.sum(AuditEventRecord.output_tokens).label("output_tokens"),
            func.count(AuditEventRecord.id).label("requests"),
        )
        .where(AuditEventRecord.timestamp >= since)
        .group_by(AuditEventRecord.model)
        .order_by(func.sum(AuditEventRecord.cost_usd).desc())
    )
    by_model = [
        {
            "model": row.model,
            "cost_usd": round(float(row.cost or 0), 4),
            "input_tokens": row.input_tokens or 0,
            "output_tokens": row.output_tokens or 0,
            "requests": row.requests or 0,
            "pct": round(float(row.cost or 0) / total_cost * 100, 1) if total_cost else 0,
        }
        for row in model_rows
    ]
    routed = int(await db.scalar(
        select(func.count()).where(
            AuditEventRecord.timestamp >= since,
            AuditEventRecord.routed_to.isnot(None),
        )
    ) or 0)
    return {
        "total_cost_usd": round(total_cost, 4),
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "routed_requests": routed,
        "by_model": by_model,
    }


async def _get_recent_events(
    db: AsyncSession, limit: int = 25,
    action: str | None = None, routed_only: bool = False,
) -> list[AuditEventRecord]:
    filters = []
    if action:
        filters.append(AuditEventRecord.action_taken == action)
    if routed_only:
        filters.append(AuditEventRecord.routed_to.isnot(None))
    q = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(limit)
    if filters:
        q = q.where(and_(*filters))
    result = await db.scalars(q)
    return list(result.all())
