from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team, Policy
from airiskguard_gateway.policy_server.license_state import get_license
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

DEFAULT_MODELS = [
    "claude-sonnet-4-6", "claude-haiku-4-5-20251001",
    "gpt-4o", "gpt-4o-mini", "deepseek-chat",
]

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


@router.get("/dashboard/policies", response_class=HTMLResponse)
async def policies_page(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    lic = get_license()
    if not lic.valid:
        return templates.TemplateResponse(request, "unlicensed.html", {"reason": lic.reason})

    teams_result = await db.scalars(select(Team).order_by(Team.created_at))
    teams = list(teams_result.all())

    # Build policies_by_team map
    policies_by_team: dict[str, dict] = {}
    for team in teams:
        policy_result = await db.scalars(
            select(Policy)
            .where(Policy.team_id == team.id, Policy.is_active == True)
            .order_by(Policy.version.desc())
            .limit(1)
        )
        p = policy_result.first()
        if p:
            policies_by_team[team.id] = {
                "version": p.version,
                "model_allowlist": p.model_allowlist,
            }

    return templates.TemplateResponse(request, "policies.html", {
        "teams": teams,
        "policies_by_team": policies_by_team,
        "default_models": DEFAULT_MODELS,
    })


@router.post("/dashboard/policies/{team_id}", response_class=HTMLResponse)
async def save_policy(
    team_id: str,
    request: Request,
    model_allowlist: str = Form(""),
    slack_webhook_url: str = Form(""),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    team = await db.get(Team, team_id)
    if not team:
        from fastapi import HTTPException
        raise HTTPException(404, "Team not found")

    # Parse model list
    models = [m.strip() for m in model_allowlist.strip().splitlines() if m.strip()]

    # Deactivate existing active policy
    existing = await db.scalars(
        select(Policy).where(Policy.team_id == team_id, Policy.is_active == True)
    )
    latest_version = 0
    for p in existing.all():
        p.is_active = False
        latest_version = max(latest_version, p.version)

    # Create new policy version
    new_policy = Policy(
        id=str(uuid.uuid4()),
        team_id=team_id,
        version=latest_version + 1,
        rules_json="[]",
        model_allowlist_json=json.dumps(models),
        is_active=True,
    )
    db.add(new_policy)

    # Update Slack webhook
    team.slack_webhook_url = slack_webhook_url.strip() or None
    await db.commit()

    # Re-render the updated card
    policies_by_team = {
        team_id: {"version": new_policy.version, "model_allowlist": models}
    }
    return templates.TemplateResponse(request, "policies.html", {
        "teams": [team],
        "policies_by_team": policies_by_team,
        "default_models": DEFAULT_MODELS,
        "saved": True,
    })


@router.post("/dashboard/teams", response_class=HTMLResponse)
async def create_team_ui(
    request: Request,
    name: str = Form(""),
    slug: str = Form(""),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    if not name or not slug:
        return RedirectResponse("/dashboard/policies", status_code=303)
    existing = await db.scalar(select(Team).where(Team.slug == slug))
    if not existing:
        team = Team(id=str(uuid.uuid4()), name=name, slug=slug)
        db.add(team)
        await db.commit()
    return RedirectResponse("/dashboard/policies", status_code=303)
