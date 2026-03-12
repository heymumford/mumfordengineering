from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# --- Health ---


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# --- Index ---


@pytest.mark.asyncio
async def test_index(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "Mumford Engineering" in resp.text
    assert "text/html" in resp.headers["content-type"]


# --- Security headers ---


@pytest.mark.asyncio
async def test_security_headers(client):
    resp = await client.get("/")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert "strict-origin" in resp.headers["referrer-policy"]


@pytest.mark.asyncio
async def test_hsts_header(client):
    resp = await client.get("/")
    assert "max-age=" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


@pytest.mark.asyncio
async def test_csp_no_unsafe_inline_scripts(client):
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]


# --- Contact form: valid ---


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


# --- Contact form: honeypot ---


@pytest.mark.asyncio
async def test_contact_honeypot(client):
    resp = await client.post(
        "/contact",
        data={"name": "Bot", "email": "bot@spam.com", "message": "Buy now", "website": "http://spam.com"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "message" in data  # same response shape to avoid info leak


# --- Contact form: validation ---


@pytest.mark.asyncio
async def test_contact_invalid_email(client):
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "notanemail", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 422
    assert resp.json()["status"] == "error"


@pytest.mark.asyncio
async def test_contact_empty_fields(client):
    resp = await client.post(
        "/contact",
        data={"name": "   ", "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 422
    assert resp.json()["status"] == "error"


@pytest.mark.asyncio
async def test_contact_missing_fields(client):
    resp = await client.post("/contact", data={"name": "Test"})
    assert resp.status_code == 422


# --- Rate limiting ---


@pytest.mark.asyncio
async def test_contact_rate_limit(client):
    for _ in range(5):
        resp = await client.post(
            "/contact",
            data={"name": "User", "email": "user@example.com", "message": "Hi", "website": ""},
        )
        assert resp.status_code == 200

    # 6th request is rate-limited but returns same response shape
    resp = await client.post(
        "/contact",
        data={"name": "User", "email": "user@example.com", "message": "Hi", "website": ""},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Message received. I'll get back to you."


# --- 404 ---


@pytest.mark.asyncio
async def test_404_returns_html(client):
    resp = await client.get("/nonexistent-page")
    assert resp.status_code == 404


# --- Cache headers ---


@pytest.mark.asyncio
async def test_cache_control_dynamic(client):
    resp = await client.get("/")
    assert resp.headers["cache-control"] == "no-cache"
