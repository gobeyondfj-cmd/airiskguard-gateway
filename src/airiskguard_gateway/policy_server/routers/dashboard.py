from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, UTC
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, and_, text
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.admin_auth import require_auth, verify_login, logout, get_admin_credentials
from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team, Policy
from airiskguard_gateway.policy_server.license_state import get_license
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["format_number"] = lambda n: "{:,}".format(int(n or 0))

DEFAULT_MODELS = [
    "claude-sonnet-4-6", "claude-haiku-4-5-20251001",
    "gpt-4o", "gpt-4o-mini", "deepseek-chat",
]

router = APIRouter(tags=["dashboard"])


# ── Auth routes ───────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/dashboard", error: str = "") -> HTMLResponse:
    _, password = get_admin_credentials()
    if not password:
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": error})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/dashboard"),
):
    token = verify_login(username, password)
    if not token:
        return templates.TemplateResponse(request, "login.html", {
            "next": next, "error": "Invalid username or password."
        }, status_code=401)
    response = RedirectResponse(next, status_code=303)
    response.set_cookie("airiskguard_session", token, httponly=True, samesite="lax", max_age=28800)
    return response


@router.get("/logout")
async def logout_route(airiskguard_session: Optional[str] = Cookie(default=None)):
    logout(airiskguard_session)
    resp = RedirectResponse("/login")
    resp.delete_cookie("airiskguard_session")
    return resp


# ── Dashboard pages ───────────────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    hours: int = Query(24),
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    lic = get_license()
    if not lic.valid:
        return templates.TemplateResponse(request, "unlicensed.html", {"reason": lic.reason})

    since = _since(hours)
    stats = await _get_stats(db, since)
    cost_data = await _get_cost_data(db, since)
    events = await _get_recent_events(db, limit=10)
    top_users = await _get_user_stats(db, since, limit=5)
    user_count = len(set(u["developer"] or u["machine_id"] for u in top_users))

    return templates.TemplateResponse(request, "dashboard.html", {
        "stats": stats, "cost_data": cost_data, "events": events,
        "top_users": top_users, "user_count": user_count,
        "selected_hours": hours,
    })


@router.get("/dashboard/analytics", response_class=HTMLResponse)
async def analytics(
    request: Request,
    hours: int = Query(168),
    action: str = Query(""),
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    since = _since(hours)
    stats = await _get_stats(db, since)
    cost_data = await _get_cost_data(db, since)
    events = await _get_recent_events(db, limit=100, action=action or None)
    detection_stats = await _get_detection_stats(db, since)

    return templates.TemplateResponse(request, "analytics.html", {
        "stats": stats, "cost_data": cost_data, "events": events,
        "detection_stats": detection_stats,
        "selected_hours": hours, "filter_action": action,
    })


@router.get("/dashboard/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    hours: int = Query(168),
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    since = _since(hours)
    users = await _get_user_stats(db, since, limit=50)
    return templates.TemplateResponse(request, "users.html", {
        "users": users, "selected_hours": hours,
    })


@router.get("/dashboard/providers", response_class=HTMLResponse)
async def providers_page(
    request: Request,
    saved: bool = Query(False),
    airiskguard_session: Optional[str] = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    from airiskguard_gateway.config import GatewayConfig
    cfg = GatewayConfig.load()
    providers = cfg.resolved_providers()
    disabled = set(cfg.providers.get(n, {}).get("disabled", False) and n for n in providers)

    # Which models have been seen per provider
    provider_models: dict[str, list[str]] = {}
    rows = await db.execute(
        select(AuditEventRecord.provider, AuditEventRecord.model)
        .group_by(AuditEventRecord.provider, AuditEventRecord.model)
        .order_by(AuditEventRecord.provider, func.count(AuditEventRecord.id).desc())
    )
    for row in rows:
        provider_models.setdefault(row.provider, []).append(row.model)

    return templates.TemplateResponse(request, "providers.html", {
        "providers": providers, "disabled_providers": disabled,
        "provider_models": provider_models, "saved": saved,
    })


@router.post("/dashboard/providers/save")
async def save_providers(
    request: Request,
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> RedirectResponse:
    _check_auth(airiskguard_session)
    from airiskguard_gateway.config import GatewayConfig, CONFIG_DIR, BUILTIN_PROVIDERS
    cfg = GatewayConfig.load()

    form = await request.form()
    # Update api_keys from form
    for name in BUILTIN_PROVIDERS:
        key_val = str(form.get(f"key_{name}", "")).strip()
        if key_val and not key_val.endswith("..."):
            cfg.api_keys[name] = key_val
        # Handle enable/disable
        enabled = f"enabled_{name}" in form
        if not enabled and name != "ollama":
            cfg.providers.setdefault(name, {})["disabled"] = True
        elif name in cfg.providers:
            cfg.providers[name].pop("disabled", None)

    cfg.save()
    return RedirectResponse("/dashboard/providers?saved=1", status_code=303)


@router.get("/dashboard/policies", response_class=HTMLResponse)
async def policies_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    lic = get_license()
    if not lic.valid:
        return templates.TemplateResponse(request, "unlicensed.html", {"reason": lic.reason})

    teams_result = await db.scalars(select(Team).order_by(Team.created_at))
    teams = list(teams_result.all())

    policies_by_team: dict[str, dict] = {}
    for team in teams:
        p_result = await db.scalars(
            select(Policy).where(Policy.team_id == team.id, Policy.is_active == True)
            .order_by(Policy.version.desc()).limit(1)
        )
        p = p_result.first()
        if p:
            policies_by_team[team.id] = {"version": p.version, "model_allowlist": p.model_allowlist}

    return templates.TemplateResponse(request, "policies.html", {
        "teams": teams, "policies_by_team": policies_by_team,
        "default_models": DEFAULT_MODELS,
    })


@router.post("/dashboard/policies/{team_id}", response_class=HTMLResponse)
async def save_policy(
    team_id: str,
    request: Request,
    model_allowlist: str = Form(""),
    slack_webhook_url: str = Form(""),
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
) -> HTMLResponse:
    _check_auth(airiskguard_session)
    team = await db.get(Team, team_id)
    if not team:
        from fastapi import HTTPException
        raise HTTPException(404, "Team not found")

    models = [m.strip() for m in model_allowlist.strip().splitlines() if m.strip()]
    existing = await db.scalars(select(Policy).where(Policy.team_id == team_id, Policy.is_active == True))
    latest_version = 0
    for p in existing.all():
        p.is_active = False
        latest_version = max(latest_version, p.version)

    new_policy = Policy(
        id=str(uuid.uuid4()), team_id=team_id, version=latest_version + 1,
        rules_json="[]", model_allowlist_json=json.dumps(models), is_active=True,
    )
    db.add(new_policy)
    team.slack_webhook_url = slack_webhook_url.strip() or None
    await db.commit()

    return templates.TemplateResponse(request, "policies.html", {
        "teams": [team],
        "policies_by_team": {team_id: {"version": new_policy.version, "model_allowlist": models}},
        "default_models": DEFAULT_MODELS, "saved": True,
    })


@router.post("/dashboard/teams")
async def create_team_ui(
    name: str = Form(""), slug: str = Form(""),
    db: AsyncSession = Depends(get_db),
    airiskguard_session: Optional[str] = Cookie(default=None),
):
    _check_auth(airiskguard_session)
    if name and slug:
        existing = await db.scalar(select(Team).where(Team.slug == slug))
        if not existing:
            db.add(Team(id=str(uuid.uuid4()), name=name, slug=slug))
            await db.commit()
    return RedirectResponse("/dashboard/policies", status_code=303)


# HTMX partials kept for auto-refresh
@router.get("/dashboard/violations", response_class=HTMLResponse)
async def violations_partial(
    request: Request,
    action: Optional[str] = None,
    routed: int = 0,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    events = await _get_recent_events(db, limit=50, action=action, routed_only=bool(routed))
    return templates.TemplateResponse(request, "violations.html", {"events": events})


@router.get("/dashboard/costs", response_class=HTMLResponse)
async def costs_partial(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    since = _since(24)
    stats = await _get_stats(db, since)
    cost_data = await _get_cost_data(db, since)
    return templates.TemplateResponse(request, "cost_cards.html", {"stats": stats, "cost_data": cost_data})


# ── Data helpers ──────────────────────────────────────────────────────────────

def _since(hours: int) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _check_auth(token: Optional[str]) -> None:
    from airiskguard_gateway.policy_server.admin_auth import validate_session, get_admin_credentials
    _, password = get_admin_credentials()
    if not password:
        return
    if not validate_session(token):
        from fastapi import HTTPException
        raise HTTPException(307, headers={"Location": "/login"})


async def _get_stats(db: AsyncSession, since: datetime) -> dict:
    total = await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since)) or 0
    blocked = await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.action_taken == "blocked")) or 0
    redacted = await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.action_taken == "redacted")) or 0
    return {"total": total, "blocked": blocked, "redacted": redacted,
            "allowed": total - blocked - redacted,
            "block_rate": f"{(blocked / total * 100):.1f}%" if total else "0%"}


async def _get_cost_data(db: AsyncSession, since: datetime) -> dict:
    total_cost = float(await db.scalar(select(func.sum(AuditEventRecord.cost_usd)).where(AuditEventRecord.timestamp >= since)) or 0)
    total_in = int(await db.scalar(select(func.sum(AuditEventRecord.input_tokens)).where(AuditEventRecord.timestamp >= since)) or 0)
    total_out = int(await db.scalar(select(func.sum(AuditEventRecord.output_tokens)).where(AuditEventRecord.timestamp >= since)) or 0)

    model_rows = await db.execute(
        select(AuditEventRecord.model, func.sum(AuditEventRecord.cost_usd).label("cost"),
               func.sum(AuditEventRecord.input_tokens).label("input_tokens"),
               func.sum(AuditEventRecord.output_tokens).label("output_tokens"),
               func.count(AuditEventRecord.id).label("requests"))
        .where(AuditEventRecord.timestamp >= since)
        .group_by(AuditEventRecord.model)
        .order_by(func.sum(AuditEventRecord.cost_usd).desc())
    )
    by_model = [{"model": r.model, "cost_usd": round(float(r.cost or 0), 6),
                 "input_tokens": r.input_tokens or 0, "output_tokens": r.output_tokens or 0,
                 "requests": r.requests or 0,
                 "pct": round(float(r.cost or 0) / total_cost * 100, 1) if total_cost else 0}
                for r in model_rows]

    routed = int(await db.scalar(select(func.count()).where(AuditEventRecord.timestamp >= since, AuditEventRecord.routed_to.isnot(None))) or 0)
    return {"total_cost_usd": round(total_cost, 6), "total_input_tokens": total_in,
            "total_output_tokens": total_out, "routed_requests": routed, "by_model": by_model}


async def _get_recent_events(db: AsyncSession, limit: int = 25, action: Optional[str] = None, routed_only: bool = False) -> list:
    filters = []
    if action:
        filters.append(AuditEventRecord.action_taken == action)
    if routed_only:
        filters.append(AuditEventRecord.routed_to.isnot(None))
    q = select(AuditEventRecord).order_by(AuditEventRecord.timestamp.desc()).limit(limit)
    if filters:
        q = q.where(and_(*filters))
    result = await db.scalars(q)
    events = list(result.all())
    # Parse event_json for developer field
    for e in events:
        try:
            e.event_json_parsed = json.loads(e.event_json)
        except Exception:
            e.event_json_parsed = {}
    return events


async def _get_user_stats(db: AsyncSession, since: datetime, limit: int = 50) -> list:
    rows = await db.execute(
        select(
            func.json_extract(AuditEventRecord.event_json, "$.developer").label("developer"),
            AuditEventRecord.machine_id,
            func.count(AuditEventRecord.id).label("requests"),
            func.sum(AuditEventRecord.cost_usd).label("total_cost"),
            func.sum(AuditEventRecord.input_tokens).label("input_tokens"),
            func.sum(AuditEventRecord.output_tokens).label("output_tokens"),
        )
        .where(AuditEventRecord.timestamp >= since)
        .group_by(func.json_extract(AuditEventRecord.event_json, "$.developer"), AuditEventRecord.machine_id)
        .order_by(func.sum(AuditEventRecord.cost_usd).desc())
        .limit(limit)
    )
    users = []
    for r in rows:
        # Top model per user
        top_model_row = await db.scalar(
            select(AuditEventRecord.model)
            .where(AuditEventRecord.timestamp >= since,
                   AuditEventRecord.machine_id == r.machine_id)
            .group_by(AuditEventRecord.model)
            .order_by(func.count(AuditEventRecord.id).desc())
            .limit(1)
        )
        blocked_count = await db.scalar(
            select(func.count()).where(
                AuditEventRecord.timestamp >= since,
                AuditEventRecord.machine_id == r.machine_id,
                AuditEventRecord.action_taken == "blocked",
            )
        ) or 0
        users.append({
            "developer": r.developer,
            "machine_id": r.machine_id,
            "requests": r.requests or 0,
            "total_cost": float(r.total_cost or 0),
            "input_tokens": r.input_tokens or 0,
            "output_tokens": r.output_tokens or 0,
            "blocked": blocked_count,
            "top_model": top_model_row or "",
        })
    return users


async def _get_detection_stats(db: AsyncSession, since: datetime) -> list:
    # Count findings by category from event_json
    result = await db.execute(
        select(AuditEventRecord.event_json)
        .where(AuditEventRecord.timestamp >= since, AuditEventRecord.findings_count > 0)
    )
    category_counts: dict[str, int] = {}
    for (event_json,) in result:
        try:
            data = json.loads(event_json)
            for f in data.get("findings", []):
                cat = f.get("category", "unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1
        except Exception:
            pass
    return [{"category": k, "count": v} for k, v in sorted(category_counts.items(), key=lambda x: -x[1])]
