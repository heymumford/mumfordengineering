from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_index(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "Mumford Engineering" in resp.text
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_security_headers(client):
    resp = await client.get("/")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "strict-origin" in resp.headers["referrer-policy"]


@pytest.mark.asyncio
async def test_contact_valid(client):
    resp = await client.post(
        "/contact",
        data={"name": "Test User", "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "message" in data


@pytest.mark.asyncio
async def test_contact_honeypot(client):
    resp = await client.post(
        "/contact",
        data={"name": "Bot", "email": "bot@spam.com", "message": "Buy now", "website": "http://spam.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "message" not in data  # silent drop


@pytest.mark.asyncio
async def test_404_returns_html(client):
    resp = await client.get("/nonexistent-page")
    assert resp.status_code == 404
