from __future__ import annotations

import logging
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import AuditEventRecord, Team
from airiskguard_gateway.policy_server.schemas import TeamCreate, TeamOut

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])
log = logging.getLogger(__name__)


@router.post("/slack-webhook")
async def set_slack_webhook(
    team_id: str,
    webhook_url: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Set or update the Slack webhook URL for a team."""
    team = await db.get(Team, team_id)
    if not team:
        from fastapi import HTTPException
        raise HTTPException(404, "Team not found")
    team.slack_webhook_url = webhook_url or None
    await db.commit()
    return {"status": "ok", "team_id": team_id, "webhook_configured": bool(webhook_url)}


@router.delete("/slack-webhook/{team_id}")
async def remove_slack_webhook(team_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    team = await db.get(Team, team_id)
    if not team:
        from fastapi import HTTPException
        raise HTTPException(404, "Team not found")
    team.slack_webhook_url = None
    await db.commit()
    return {"status": "ok"}


async def purge_old_events(db: AsyncSession, retention_days: int = 30) -> int:
    """Delete audit events older than retention_days. Returns count deleted."""
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    result = await db.execute(
        delete(AuditEventRecord).where(AuditEventRecord.timestamp < cutoff)
    )
    await db.commit()
    count = result.rowcount
    if count:
        log.info("Purged %d audit events older than %d days", count, retention_days)
    return count
