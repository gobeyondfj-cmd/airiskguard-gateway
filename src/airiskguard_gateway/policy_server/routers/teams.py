from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, UTC

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import Team, ApiKey
from airiskguard_gateway.policy_server.schemas import TeamCreate, TeamOut, ApiKeyCreate, ApiKeyOut

router = APIRouter(prefix="/api/v1/teams", tags=["teams"])


@router.post("", response_model=TeamOut, status_code=201)
async def create_team(body: TeamCreate, db: AsyncSession = Depends(get_db)) -> Team:
    existing = await db.scalar(select(Team).where(Team.slug == body.slug))
    if existing:
        raise HTTPException(400, f"Team slug '{body.slug}' already exists")
    team = Team(
        id=str(uuid.uuid4()),
        name=body.name,
        slug=body.slug,
        slack_webhook_url=body.slack_webhook_url,
    )
    db.add(team)
    await db.commit()
    await db.refresh(team)
    return team


@router.get("", response_model=list[TeamOut])
async def list_teams(db: AsyncSession = Depends(get_db)) -> list[Team]:
    result = await db.scalars(select(Team).order_by(Team.created_at.desc()))
    return list(result.all())


@router.get("/{team_id}", response_model=TeamOut)
async def get_team(team_id: str, db: AsyncSession = Depends(get_db)) -> Team:
    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(404, "Team not found")
    return team


@router.post("/{team_id}/keys", response_model=ApiKeyOut, status_code=201)
async def create_api_key(
    team_id: str,
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
) -> ApiKeyOut:
    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    raw_key, key_hash = ApiKey.generate()
    api_key = ApiKey(
        id=str(uuid.uuid4()),
        team_id=team_id,
        name=body.name,
        key_hash=key_hash,
        provider=body.provider,
        real_key_encrypted=body.real_key or "",
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    # Return raw key only once
    out = ApiKeyOut.model_validate(api_key)
    out.raw_key = raw_key
    return out


@router.get("/{team_id}/keys", response_model=list[ApiKeyOut])
async def list_api_keys(team_id: str, db: AsyncSession = Depends(get_db)) -> list[ApiKey]:
    result = await db.scalars(
        select(ApiKey).where(ApiKey.team_id == team_id, ApiKey.revoked_at.is_(None))
    )
    return list(result.all())


@router.delete("/{team_id}/keys/{key_id}", status_code=204)
async def revoke_api_key(team_id: str, key_id: str, db: AsyncSession = Depends(get_db)) -> None:
    key = await db.get(ApiKey, key_id)
    if not key or key.team_id != team_id:
        raise HTTPException(404, "Key not found")
    key.revoked_at = datetime.now(UTC)
    await db.commit()
