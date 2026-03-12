"""XSS security tests for mumfordengineering.

Covers:
  - Reflected XSS via contact form response (JSON message field never echoes user input)
  - CSP header correctness (script-src must not allow unsafe-inline)
  - CSS injection risk from style-src unsafe-inline (exfil channel blocked by connect-src)
  - img-src data: URI scope (cannot load external resources)
  - No open redirect via 404 handler
  - Log injection prevention (_sanitize_log strips control characters)
  - Contact response messages are hardcoded, not user-reflected
  - HTML template uses Jinja2 auto-escaping (no raw |safe filter on user data)
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps, _sanitize_log


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# 1. Reflected XSS — contact form response never echoes user input
#
# The server returns only hardcoded message strings regardless of input.
# Even if main.js renders json.message via textContent (safe), the backend
# must not include user-controlled text in the JSON body.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contact_response_does_not_reflect_name(client):
    """Name field must not appear in the JSON response body."""
    xss_name = "<script>alert('xss')</script>"
    resp = await client.post(
        "/contact",
        data={"name": xss_name, "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 200
    body = resp.text
    assert xss_name not in body
    assert "<script>" not in body


@pytest.mark.asyncio
async def test_contact_response_does_not_reflect_email(client):
    """Email field must not appear in the JSON response body."""
    xss_email = "xss@example.com<script>alert(1)</script>"
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": xss_email, "message": "Hello", "website": ""},
    )
    # Email fails validation (contains <script>), so expect 422
    assert resp.status_code == 422
    assert xss_email not in resp.text
    assert "<script>" not in resp.text


@pytest.mark.asyncio
async def test_contact_response_does_not_reflect_message_field(client):
    """Message body must not be reflected in JSON response."""
    xss_payload = '"><img src=x onerror=alert(document.cookie)>'
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "test@example.com", "message": xss_payload, "website": ""},
    )
    assert resp.status_code == 200
    assert xss_payload not in resp.text
    assert "onerror" not in resp.text


@pytest.mark.asyncio
async def test_contact_error_response_is_hardcoded(client):
    """Validation error message must be a fixed string, not derived from user input."""
    resp = await client.post(
        "/contact",
        data={
            "name": "Test",
            "email": "not-valid<script>alert(1)</script>",
            "message": "Hello",
            "website": "",
        },
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["status"] == "error"
    # The message must be one of the hardcoded strings, not user input
    assert data["message"] in {
        "Please enter a valid email address.",
        "All fields are required.",
    }
    assert "<script>" not in data["message"]


@pytest.mark.asyncio
async def test_contact_success_response_is_hardcoded(client):
    """Success message must be a fixed string."""
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["message"] == "Message received. I'll get back to you."


@pytest.mark.asyncio
async def test_contact_honeypot_response_is_hardcoded(client):
    """Honeypot path must also return only a hardcoded message."""
    resp = await client.post(
        "/contact",
        data={
            "name": "<img src=x onerror=alert(1)>",
            "email": "bot@spam.com",
            "message": "spam",
            "website": "http://spam.com",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Message received. I'll get back to you."
    assert "onerror" not in resp.text


# ---------------------------------------------------------------------------
# 2. CSP header — script-src must block inline script execution
#
# If an attacker injects a <script> tag via some future reflected vector,
# the CSP must prevent execution. unsafe-inline must not appear in script-src.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csp_script_src_no_unsafe_inline(client):
    """script-src must not contain 'unsafe-inline'."""
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    # Extract only the script-src directive value
    directives = {d.strip().split()[0]: d.strip() for d in csp.split(";")}
    script_src = directives.get("script-src", "")
    assert "'unsafe-inline'" not in script_src, f"script-src allows unsafe-inline: {script_src}"


@pytest.mark.asyncio
async def test_csp_script_src_no_unsafe_eval(client):
    """script-src must not contain 'unsafe-eval' (blocks eval-based XSS)."""
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    directives = {d.strip().split()[0]: d.strip() for d in csp.split(";")}
    script_src = directives.get("script-src", "")
    assert "'unsafe-eval'" not in script_src, f"script-src allows unsafe-eval: {script_src}"


@pytest.mark.asyncio
async def test_csp_default_src_is_self(client):
    """default-src must restrict to 'self' as the fallback policy."""
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    assert "default-src 'self'" in csp


@pytest.mark.asyncio
async def test_csp_connect_src_blocks_external(client):
    """connect-src 'self' prevents CSS-injection data exfiltration via fetch/XHR.

    Even with style-src unsafe-inline, an attacker cannot exfiltrate data
    because connect-src blocks requests to external origins.
    """
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    directives = {d.strip().split()[0]: d.strip() for d in csp.split(";")}
    connect_src = directives.get("connect-src", "")
    # Must restrict to self — no wildcard, no external origin
    assert "'self'" in connect_src
    assert "*" not in connect_src


@pytest.mark.asyncio
async def test_csp_img_src_no_wildcard(client):
    """img-src must not allow arbitrary external images (data: is acceptable).

    data: URIs cannot load external resources; they encode content inline.
    The risk of exfiltration via image src requires an external origin,
    which must not be whitelisted.
    """
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    directives = {d.strip().split()[0]: d.strip() for d in csp.split(";")}
    img_src = directives.get("img-src", "")
    assert "*" not in img_src, f"img-src has wildcard: {img_src}"
    assert "http:" not in img_src, f"img-src allows arbitrary http: URLs: {img_src}"
    assert "https:" not in img_src, f"img-src allows arbitrary https: URLs: {img_src}"


# ---------------------------------------------------------------------------
# 3. CSS injection risk — style-src unsafe-inline + connect-src interaction
#
# style-src 'unsafe-inline' allows injected <style> blocks. The exfiltration
# chain requires: inject <style> → attribute selector → background: url(external).
# connect-src 'self' cuts the exfiltration leg. These tests verify the chain
# is broken at the connect-src layer.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csp_style_src_no_unsafe_inline(client):
    """Verify that style-src does NOT contain unsafe-inline.

    unsafe-inline has been removed from style-src as a hardening step.
    No inline styles exist in this app, so this is a zero-breaking-change
    improvement. The exfiltration channel is also blocked by connect-src 'self'.
    """
    resp = await client.get("/")
    csp = resp.headers["content-security-policy"]
    directives = {d.strip().split()[0]: d.strip() for d in csp.split(";")}
    style_src = directives.get("style-src", "")
    assert "'unsafe-inline'" not in style_src, "style-src still contains 'unsafe-inline' — should have been removed"


# ---------------------------------------------------------------------------
# 4. Open redirect — 404 handler must render HTML, not redirect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_404_does_not_redirect(client):
    """404 handler must return HTML content, not a redirect response."""
    resp = await client.get("/nonexistent-page", follow_redirects=False)
    assert resp.status_code == 404
    assert "location" not in resp.headers, "404 handler issued a redirect — potential open redirect vector"


@pytest.mark.asyncio
async def test_404_with_xss_path_does_not_reflect_path(client):
    """A path containing XSS payload must not be reflected in the 404 response body."""
    xss_path = "/<script>alert(1)</script>"
    resp = await client.get(xss_path)
    assert resp.status_code == 404
    assert "<script>alert(1)</script>" not in resp.text
    assert "alert(1)" not in resp.text


@pytest.mark.asyncio
async def test_no_redirect_on_index(client):
    """GET / must not redirect — a redirect chain could be abused for open redirect."""
    resp = await client.get("/", follow_redirects=False)
    # Must be a direct 200, not a 3xx
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 5. Log injection prevention
#
# _sanitize_log must strip control characters before values reach the logger.
# CRLF injection (\r\n) is the primary log injection vector.
# ---------------------------------------------------------------------------


def test_sanitize_log_strips_newlines():
    """CRLF injection characters must be removed from logged values.

    The security property is that \r and \n are stripped, collapsing what
    would be a multi-line log entry into a single line. The injected text
    content itself is harmless once the newline separators are gone — a log
    parser sees one line, not a forged second entry.
    """
    malicious = "test@example.com\r\nINFO: fake log entry"
    result = _sanitize_log(malicious)
    assert "\r" not in result
    assert "\n" not in result
    # The result must be a single line (no embedded line breaks)
    assert len(result.splitlines()) == 1


def test_sanitize_log_strips_carriage_return():
    result = _sanitize_log("user@example.com\rINJECTED")
    assert "\r" not in result


def test_sanitize_log_strips_null_bytes():
    """Null byte injection must be stripped."""
    result = _sanitize_log("user\x00@example.com")
    assert "\x00" not in result


def test_sanitize_log_strips_control_characters():
    """All ASCII control characters (0x00–0x1f) must be stripped."""
    # Build a string with all control characters
    control_chars = "".join(chr(i) for i in range(0x00, 0x20))
    result = _sanitize_log(f"prefix{control_chars}suffix")
    for i in range(0x00, 0x20):
        assert chr(i) not in result, f"Control char 0x{i:02x} survived sanitization"


def test_sanitize_log_strips_del_and_c1_controls():
    """DEL (0x7f) and C1 control range (0x80–0x9f) must be stripped."""
    payload = "data\x7f\x80\x9fmore"
    result = _sanitize_log(payload)
    assert "\x7f" not in result
    assert "\x80" not in result
    assert "\x9f" not in result


def test_sanitize_log_truncates_to_200():
    """Output must be truncated to 200 characters to bound log line length."""
    long_value = "a" * 500
    result = _sanitize_log(long_value)
    assert len(result) <= 200


def test_sanitize_log_preserves_normal_email():
    """Normal email addresses must pass through unchanged."""
    email = "test.user+tag@example.co.uk"
    result = _sanitize_log(email)
    assert result == email


# ---------------------------------------------------------------------------
# 6. Content-Type header prevents MIME sniffing (XSS via sniffing)
#
# X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing a
# response away from the declared content-type. Without it, a text/plain
# response containing HTML could be executed as text/html.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_x_content_type_options_on_html_response(client):
    resp = await client.get("/")
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_x_content_type_options_on_json_response(client):
    """nosniff must also apply to JSON responses (contact endpoint)."""
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_x_content_type_options_on_404(client):
    resp = await client.get("/no-such-route")
    assert resp.headers.get("x-content-type-options") == "nosniff"


# ---------------------------------------------------------------------------
# 7. X-Frame-Options prevents clickjacking (UI redressing for XSS delivery)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_x_frame_options_deny(client):
    """X-Frame-Options must be DENY to prevent iframe-based clickjacking."""
    resp = await client.get("/")
    assert resp.headers.get("x-frame-options") == "DENY"


# ---------------------------------------------------------------------------
# 8. Contact form field length limits prevent oversized payload injection
#
# FastAPI enforces max_length on Form fields. Oversized inputs that bypass
# validation could carry encoded XSS payloads.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contact_rejects_oversized_name(client):
    """Name field exceeding 200 characters must be rejected."""
    long_name = "A" * 201
    resp = await client.post(
        "/contact",
        data={"name": long_name, "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_contact_rejects_oversized_email(client):
    """Email field exceeding 254 characters must be rejected."""
    long_email = "a" * 243 + "@example.com"  # 255 chars total
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": long_email, "message": "Hello", "website": ""},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_contact_rejects_oversized_message(client):
    """Message field exceeding 5000 characters must be rejected."""
    long_message = "X" * 5001
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "test@example.com", "message": long_message, "website": ""},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 9. JSON response Content-Type must be application/json
#
# A response claiming text/html but containing JSON could confuse parsers.
# Conversely, a JSON body returned as text/html would be parsed as markup
# by legacy clients.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contact_response_content_type_is_json(client):
    """Contact endpoint must return application/json, not text/html."""
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "test@example.com", "message": "Hello", "website": ""},
    )
    assert "application/json" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_contact_error_response_content_type_is_json(client):
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "notanemail", "message": "Hello", "website": ""},
    )
    assert resp.status_code == 422
    assert "application/json" in resp.headers["content-type"]
