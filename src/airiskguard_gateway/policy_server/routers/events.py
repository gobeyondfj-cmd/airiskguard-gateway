from __future__ import annotations

import json
import uuid
from datetime import datetime, UTC, timedelta

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team
from airiskguard_gateway.policy_server.schemas import AuditEventIn, AuditEventOut

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", status_code=202)
async def ingest_events(
    events: list[AuditEventIn],
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Receive batched audit events from gateway instances."""
    records: list[AuditEventRecord] = []

    for e in events:
        try:
            ts = datetime.fromisoformat(e.timestamp.rstrip("Z"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
        except ValueError:
            ts = datetime.now(UTC)

        record = AuditEventRecord(
            id=str(uuid.uuid4()),
            team_id=None,
            machine_id=e.machine_id,
            event_json=json.dumps(e.model_dump()),
            timestamp=ts,
            provider=e.provider,
            model=e.model,
            action_taken=e.action_taken,
            direction=e.direction,
            findings_count=len(e.findings),
            input_tokens=e.input_tokens or 0,
            output_tokens=e.output_tokens or 0,
            cost_usd=e.cost_usd or 0.0,
            routed_to=e.routed_to,
        )
        records.append(record)

        if e.action_taken == "blocked" or any(
            f.get("severity") in ("critical", "high") for f in e.findings
        ):
            db.add(record)
            await db.flush()
            await _maybe_notify_slack(db, record, e)

    for r in records:
        if r not in db.new:
            db.add(r)

    await db.commit()
    return {"accepted": len(records)}


@router.get("", response_model=list[AuditEventOut])
async def list_events(
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    action: str | None = Query(None),
    provider: str | None = Query(None),
    since_hours: int = Query(24),
    db: AsyncSession = Depends(get_db),
) -> list[AuditEventRecord]:
    since = datetime.now(UTC) - timedelta(hours=since_hours)
    filters = [AuditEventRecord.timestamp >= since]
    if action:
        filters.append(AuditEventRecord.action_taken == action)
    if provider:
        filters.append(AuditEventRecord.provider == provider)

    result = await db.scalars(
        select(AuditEventRecord)
        .where(and_(*filters))
        .order_by(AuditEventRecord.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.all())


@router.get("/stats")
async def event_stats(
    since_hours: int = Query(24),
    db: AsyncSession = Depends(get_db),
) -> dict:
    since = datetime.now(UTC) - timedelta(hours=since_hours)
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
        "since_hours": since_hours,
    }


@router.get("/costs")
async def cost_breakdown(
    since_hours: int = Query(720),  # default 30 days
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cost breakdown by model, last N hours."""
    since = datetime.now(UTC) - timedelta(hours=since_hours)

    # Total cost
    total_cost = await db.scalar(
        select(func.sum(AuditEventRecord.cost_usd)).where(AuditEventRecord.timestamp >= since)
    ) or 0.0

    total_tokens_in = await db.scalar(
        select(func.sum(AuditEventRecord.input_tokens)).where(AuditEventRecord.timestamp >= since)
    ) or 0
    total_tokens_out = await db.scalar(
        select(func.sum(AuditEventRecord.output_tokens)).where(AuditEventRecord.timestamp >= since)
    ) or 0

    # Cost + tokens by model
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
            "cost_usd": round(row.cost or 0, 4),
            "input_tokens": row.input_tokens or 0,
            "output_tokens": row.output_tokens or 0,
            "requests": row.requests or 0,
            "pct": round((row.cost or 0) / total_cost * 100, 1) if total_cost else 0,
        }
        for row in model_rows
    ]

    # Routed requests (savings proxy)
    routed = await db.scalar(
        select(func.count()).where(
            AuditEventRecord.timestamp >= since,
            AuditEventRecord.routed_to.isnot(None),
        )
    ) or 0

    return {
        "since_hours": since_hours,
        "total_cost_usd": round(total_cost, 4),
        "total_input_tokens": total_tokens_in,
        "total_output_tokens": total_tokens_out,
        "routed_requests": routed,
        "by_model": by_model,
    }


async def _maybe_notify_slack(db: AsyncSession, record: AuditEventRecord, event: AuditEventIn) -> None:
    if not record.team_id:
        return
    team = await db.get(Team, record.team_id)
    if not team or not team.slack_webhook_url:
        return

    severity = "critical" if any(f.get("severity") == "critical" for f in event.findings) else "high"
    payload = {
        "text": f":shield: *AIRiskGuard Gateway* — {event.action_taken.upper()}",
        "attachments": [{
            "color": "#dc2626" if event.action_taken == "blocked" else "#ea580c",
            "fields": [
                {"title": "Provider", "value": event.provider, "short": True},
                {"title": "Model", "value": event.model, "short": True},
                {"title": "Machine", "value": event.machine_id, "short": True},
                {"title": "Findings", "value": str(event.findings_count), "short": True},
                {"title": "Top severity", "value": severity, "short": True},
            ],
        }],
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(team.slack_webhook_url, json=payload)
    except Exception:
        pass
