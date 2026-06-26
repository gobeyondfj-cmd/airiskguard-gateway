import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Must be set before any app imports
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    """Create all tables in the in-memory DB before each test."""
    from airiskguard_gateway.policy_server.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client(setup_db):
    from airiskguard_gateway.policy_server.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
