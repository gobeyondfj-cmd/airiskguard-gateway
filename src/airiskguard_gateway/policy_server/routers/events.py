from __future__ import annotations

import json
import uuid
from datetime import datetime, UTC

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
        except ValueError:
            ts = datetime.now(UTC)

        record = AuditEventRecord(
            id=str(uuid.uuid4()),
            team_id=None,  # Resolved via API key auth in full implementation
            machine_id=e.machine_id,
            event_json=json.dumps(e.model_dump()),
            timestamp=ts,
            provider=e.provider,
            model=e.model,
            action_taken=e.action_taken,
            direction=e.direction,
            findings_count=len(e.findings),
        )
        records.append(record)

        # Slack notification for blocked requests
        if e.action_taken == "blocked" or any(
            f.get("severity") in ("critical", "high") for f in e.findings
        ):
            db.add(record)
            await db.flush()
            await _maybe_notify_slack(db, record, e)

    for r in records:
        if r not in db.new:  # Avoid double-add
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
    from datetime import timedelta
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
    from datetime import timedelta
    since = datetime.now(UTC) - timedelta(hours=since_hours)

    total = await db.scalar(
        select(func.count()).where(AuditEventRecord.timestamp >= since)
    )
    blocked = await db.scalar(
        select(func.count()).where(
            AuditEventRecord.timestamp >= since,
            AuditEventRecord.action_taken == "blocked",
        )
    )
    redacted = await db.scalar(
        select(func.count()).where(
            AuditEventRecord.timestamp >= since,
            AuditEventRecord.action_taken == "redacted",
        )
    )

    return {
        "total": total or 0,
        "blocked": blocked or 0,
        "redacted": redacted or 0,
        "allowed": (total or 0) - (blocked or 0) - (redacted or 0),
        "since_hours": since_hours,
    }


async def _maybe_notify_slack(db: AsyncSession, record: AuditEventRecord, event: AuditEventIn) -> None:
    """Fire Slack webhook if team has one configured."""
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
        pass  # Non-blocking
