from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from airiskguard_gateway.policy_server.database import get_db
from airiskguard_gateway.policy_server.models import Policy, Team
from airiskguard_gateway.policy_server.schemas import PolicyOut, PolicyUpdate

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.get("/current", response_model=dict)
async def get_current_policy(
    x_api_key: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Gateway polls this to get its current policy. Returns policy_server-compatible format."""
    # In a full implementation, authenticate via API key and return team-specific policy
    # For MVP, return the most recently updated active policy
    result = await db.scalars(
        select(Policy).where(Policy.is_active == True).order_by(Policy.updated_at.desc()).limit(1)
    )
    policy = result.first()
    if not policy:
        return {
            "policy_id": "default",
            "team_id": None,
            "version": 0,
            "rules": [],
            "model_allowlist": [],
            "updated_at": "2026-01-01T00:00:00Z",
        }

    return {
        "policy_id": policy.id,
        "team_id": policy.team_id,
        "version": policy.version,
        "rules": policy.rules,
        "model_allowlist": policy.model_allowlist,
        "updated_at": policy.updated_at.isoformat() + "Z",
    }


@router.post("/{team_id}", response_model=PolicyOut, status_code=201)
async def upsert_policy(
    team_id: str,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
) -> Policy:
    team = await db.get(Team, team_id)
    if not team:
        raise HTTPException(404, "Team not found")

    # Deactivate existing policies for this team
    existing = await db.scalars(select(Policy).where(Policy.team_id == team_id, Policy.is_active == True))
    latest_version = 0
    for p in existing.all():
        p.is_active = False
        latest_version = max(latest_version, p.version)

    policy = Policy(
        id=str(uuid.uuid4()),
        team_id=team_id,
        version=latest_version + 1,
        rules_json=json.dumps([r.model_dump() for r in body.rules]),
        model_allowlist_json=json.dumps(body.model_allowlist),
        is_active=True,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("/{team_id}", response_model=list[PolicyOut])
async def list_policies(team_id: str, db: AsyncSession = Depends(get_db)) -> list[Policy]:
    result = await db.scalars(
        select(Policy).where(Policy.team_id == team_id).order_by(Policy.version.desc())
    )
    return list(result.all())
