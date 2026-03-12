"""Information Disclosure Security Tests

Covers:
- ID-01: Server version header leakage (uvicorn/FastAPI)
- ID-02: 500 handler stack trace leakage
- ID-03: FastAPI 422 validation detail leakage
- ID-04: Technology fingerprinting via response headers
- ID-05: HTML debug comments (REPLACE: stubs) in production template
- ID-06: JSON-LD schema.org personal data exposure
- ID-07: robots.txt and sitemap.xml absence
- ID-08: Source map file exposure
- ID-09: Docker Python version fingerprinting
- ID-10: /.git/ directory exposure
- ID-11: /health endpoint data exposure
- ID-12: Contact form error enumeration
- ID-13: X-Powered-By / Server header suppression
"""

from __future__ import annotations

import json
import re

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps

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
# ID-01  Server version header leakage
#
# Severity: MEDIUM
# FastAPI/Starlette sets `server: uvicorn` by default on every response.
# Combined with the `x-asgi-scope` header that Starlette may emit, an
# attacker can enumerate framework version without any other probing.
# Fix: add `server_header=False` to the Uvicorn instantiation and strip the
# `server` header in the security-header middleware.
# CWE-200 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id01_no_server_version_header(client):
    """Server header must not disclose uvicorn or version strings."""
    resp = await client.get("/")
    server = resp.headers.get("server", "")
    # The header may be absent (ideal) or present but must not contain
    # version information.
    assert "uvicorn" not in server.lower(), (
        f"ID-01 FAIL: 'server' header reveals ASGI server identity: {server!r}. "
        "Fix: pass server_header=False to uvicorn or strip 'server' in middleware."
    )


@pytest.mark.asyncio
async def test_id01_no_server_header_on_error(client):
    """Server header must not be disclosed on 404 responses."""
    resp = await client.get("/this-does-not-exist")
    server = resp.headers.get("server", "")
    assert "uvicorn" not in server.lower(), f"ID-01 FAIL: 'server' header reveals identity on 404: {server!r}."


# ---------------------------------------------------------------------------
# ID-02  500 handler stack trace leakage
#
# Severity: HIGH
# The middleware catches unhandled exceptions and returns a generic JSON body
# {"error": "internal server error"}.  This is correct.  The test verifies
# the contract holds: no Python traceback, module paths, or line numbers leak
# into the response body for any 5xx scenario.
# CWE-209 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id02_500_no_stack_trace(client):
    """500 responses must not contain Python tracebacks."""
    # Force a 500 by sending a malformed body to a JSON-only endpoint that
    # isn't the contact form — this hits the middleware exception wrapper.
    # We also exercise the /contact path with content-type mismatch.
    resp = await client.post(
        "/contact",
        content=b"\xff\xfe invalid utf-8 \x00",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    body = resp.text
    for leak_pattern in ("Traceback", 'File "', "line ", "raise ", "Exception", "Error:"):
        assert leak_pattern not in body, (
            f"ID-02 FAIL: Response body contains Python traceback indicator {leak_pattern!r}. Full body: {body[:500]!r}"
        )


@pytest.mark.asyncio
async def test_id02_500_response_is_generic(client):
    """Any 5xx response body must contain only a generic error key."""
    resp = await client.post(
        "/contact",
        content=b"\xff\xfe",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    # Status is either 4xx (validation) or 5xx (unhandled) — either way, no
    # internal paths or module names should appear.
    assert "mumfordengineering" not in resp.text, "ID-02 FAIL: Module path leaked in error response."
    assert "/app/" not in resp.text, "ID-02 FAIL: Filesystem path leaked in error response."


# ---------------------------------------------------------------------------
# ID-03  FastAPI 422 validation detail leakage
#
# Severity: MEDIUM
# FastAPI's default 422 handler returns Pydantic validation errors verbatim,
# including field names, expected types, and internal model detail.  The
# /contact endpoint uses custom validation and returns its own 422, so
# FastAPI's built-in handler is only triggered for missing required fields
# before the route body runs.  The test checks that even if FastAPI's default
# 422 fires, the response does not expose Pydantic internals beyond what the
# app explicitly controls.
# CWE-209 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id03_422_does_not_expose_pydantic_model_internals(client):
    """FastAPI 422 must not expose Pydantic model class names or field types."""
    # Trigger FastAPI's own 422 by submitting a completely empty body.
    resp = await client.post("/contact", data={})
    assert resp.status_code == 422
    body = resp.text
    # Pydantic internal class names and model detail that would aid an attacker.
    for pydantic_leak in ("pydantic", "ValidationError", "value_error", "type_error"):
        assert pydantic_leak not in body.lower(), (
            f"ID-03 FAIL: Pydantic internal string {pydantic_leak!r} in 422 body. Body: {body[:500]!r}"
        )


@pytest.mark.asyncio
async def test_id03_custom_422_uses_safe_format(client):
    """Custom 422 responses must use the app's safe {status, message} shape."""
    resp = await client.post(
        "/contact",
        data={"name": "Test", "email": "bad-email", "message": "hello", "website": ""},
    )
    assert resp.status_code == 422
    data = resp.json()
    # Only these two keys should be present — no 'detail', 'loc', 'type', etc.
    assert set(data.keys()) == {"status", "message"}, (
        f"ID-03 FAIL: Custom 422 body exposes unexpected keys: {set(data.keys())}"
    )
    assert data["status"] == "error"


# ---------------------------------------------------------------------------
# ID-04  Technology fingerprinting via response headers
#
# Severity: LOW-MEDIUM
# Starlette may emit x-asgi-scope or similar debug headers in development
# mode.  FastAPI does not set X-Powered-By by default, but middleware or
# dependencies might.  This test enforces the negative.
# CWE-200 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id04_no_x_powered_by(client):
    """X-Powered-By header must be absent — reveals framework identity."""
    resp = await client.get("/")
    assert "x-powered-by" not in resp.headers, (
        f"ID-04 FAIL: X-Powered-By header present: {resp.headers.get('x-powered-by')!r}"
    )


@pytest.mark.asyncio
async def test_id04_no_debug_headers(client):
    """Debug or ASGI-scope headers must not be present in responses."""
    resp = await client.get("/")
    for debug_header in ("x-asgi-scope", "x-request-id-internal", "x-debug"):
        assert debug_header not in resp.headers, f"ID-04 FAIL: Debug header {debug_header!r} present in response."


@pytest.mark.asyncio
async def test_id04_content_type_does_not_reveal_version(client):
    """Content-Type must not include framework version strings."""
    resp = await client.get("/")
    ct = resp.headers.get("content-type", "")
    assert "fastapi" not in ct.lower()
    assert "starlette" not in ct.lower()


# ---------------------------------------------------------------------------
# ID-05  HTML debug comments in production template
#
# Severity: LOW
# The template contains <!-- REPLACE: Add product photo here --> comments on
# lines 104, 120, 136, 154.  These are developer scaffolding stubs.  In
# production they reveal that the site is unfinished and could help an
# attacker understand the technology stack or locate injectable insertion
# points.  They should be removed before go-live.
# CWE-615 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id05_no_replace_comments_in_html(client):
    """Template must not contain REPLACE: scaffolding comments in rendered HTML."""
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "REPLACE:" not in resp.text, (
        "ID-05 FAIL: HTML response contains developer scaffolding comment "
        "'REPLACE:'. Remove all <!-- REPLACE: ... --> stubs from index.html "
        "before deploying to production. Found at lines 104, 120, 136, 154."
    )


@pytest.mark.asyncio
async def test_id05_no_todo_comments_in_html(client):
    """Template must not contain TODO or FIXME comments in rendered HTML."""
    resp = await client.get("/")
    body_lower = resp.text.lower()
    for debug_comment in ("<!-- todo", "<!-- fixme", "<!-- hack", "<!-- debug"):
        assert debug_comment not in body_lower, (
            f"ID-05 FAIL: Debug HTML comment {debug_comment!r} found in rendered page."
        )


# ---------------------------------------------------------------------------
# ID-06  JSON-LD schema.org personal data exposure
#
# Severity: LOW
# The schema.org Person markup in <head> exposes: full name, job title,
# GitHub username, website URL, and knowledge domains.  The current set is
# intentional for a portfolio site.  However it also provides an aggregation
# target.  Tests verify no *unintended* fields are present (email, telephone,
# address, birthDate) which would be a clear disclosure violation.
# CWE-359 / OWASP A02:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id06_jsonld_no_email_address(client):
    """JSON-LD schema.org data must not contain an email address."""
    resp = await client.get("/")
    body = resp.text
    # Extract the JSON-LD block.
    match = re.search(
        r'<script type="application/ld\+json">(.*?)</script>',
        body,
        re.DOTALL,
    )
    assert match, "JSON-LD block not found in page — test precondition failed."
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        pytest.fail(f"JSON-LD block is not valid JSON: {exc}")

    assert "email" not in data, (
        f"ID-06 FAIL: JSON-LD exposes 'email' field: {data.get('email')!r}. "
        "Email addresses in structured data are indexed by scrapers."
    )
    assert "telephone" not in data, "ID-06 FAIL: JSON-LD exposes 'telephone' field."


@pytest.mark.asyncio
async def test_id06_jsonld_no_physical_address(client):
    """JSON-LD schema.org data must not contain a postal or physical address."""
    resp = await client.get("/")
    match = re.search(
        r'<script type="application/ld\+json">(.*?)</script>',
        resp.text,
        re.DOTALL,
    )
    assert match
    data = json.loads(match.group(1))
    assert "address" not in data, "ID-06 FAIL: JSON-LD exposes 'address' field."
    assert "homeLocation" not in data, "ID-06 FAIL: JSON-LD exposes 'homeLocation' field."


@pytest.mark.asyncio
async def test_id06_jsonld_is_valid_json(client):
    """JSON-LD block must parse as valid JSON (malformed JSON-LD can cause XSS)."""
    resp = await client.get("/")
    match = re.search(
        r'<script type="application/ld\+json">(.*?)</script>',
        resp.text,
        re.DOTALL,
    )
    assert match, "No JSON-LD block found."
    try:
        json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"ID-06 FAIL: JSON-LD block contains invalid JSON — could be exploited as an injection vector: {exc}"
        )


# ---------------------------------------------------------------------------
# ID-07  robots.txt and sitemap.xml absence
#
# Severity: LOW
# Missing robots.txt is a low-severity information disclosure issue: search
# engines and scanners treat its absence as "crawl everything," potentially
# indexing admin paths or test pages.  A missing sitemap.xml is primarily
# an SEO gap.  Neither is critical for a portfolio site, but both should
# return 200 with appropriate content rather than a 404 that routes to the
# index page (which leaks that the 404 handler serves HTML to all paths).
# CWE-16 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id07_robots_txt_present(client):
    """GET /static/robots.txt must return 200 with text/plain content."""
    resp = await client.get("/static/robots.txt")
    assert resp.status_code == 200, (
        f"ID-07 FAIL: /static/robots.txt returns {resp.status_code}. robots.txt should be in the static/ directory."
    )
    assert "text/plain" in resp.headers.get("content-type", ""), (
        "ID-07 FAIL: /static/robots.txt does not return text/plain content-type."
    )


@pytest.mark.asyncio
async def test_id07_robots_txt_not_html_fallback(client):
    """GET /static/robots.txt must not return the HTML index page as a 404 fallback."""
    resp = await client.get("/static/robots.txt")
    # If the 404 handler is serving index.html for /robots.txt, that is a
    # disclosure: it reveals that ALL paths serve the same HTML, enabling
    # enumeration of the tech stack from any URL.
    assert "<!DOCTYPE html" not in resp.text, (
        "ID-07 FAIL: /static/robots.txt returns the HTML index page. "
        "This reveals that the 404 handler serves HTML for every unknown path."
    )


@pytest.mark.asyncio
async def test_id07_sitemap_xml_present(client):
    """GET /static/sitemap.xml must return 200."""
    resp = await client.get("/static/sitemap.xml")
    assert resp.status_code == 200, (
        f"ID-07 FAIL: /static/sitemap.xml returns {resp.status_code}. sitemap.xml should be in the static/ directory."
    )


# ---------------------------------------------------------------------------
# ID-08  Source map file exposure
#
# Severity: LOW
# If CSS or JS files contain a sourceMappingURL comment, the browser (and
# any scanner) will request the .map file.  If the map file is served, it
# exposes the original pre-minification source code.  The current JS and CSS
# are not minified (they are source files), but the test verifies no map
# references exist that could be followed.
# CWE-540 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id08_no_source_map_references_in_js(client):
    """JS files must not contain sourceMappingURL directives."""
    resp = await client.get("/static/js/main.js")
    assert resp.status_code == 200
    assert "sourceMappingURL" not in resp.text, (
        "ID-08 FAIL: main.js contains a sourceMappingURL directive. "
        "Remove it or ensure the .map file is not publicly accessible."
    )


@pytest.mark.asyncio
async def test_id08_no_source_map_references_in_css(client):
    """CSS files must not contain sourceMappingURL directives."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    assert "sourceMappingURL" not in resp.text, "ID-08 FAIL: style.css contains a sourceMappingURL directive."


@pytest.mark.asyncio
async def test_id08_js_map_file_not_served(client):
    """GET /static/js/main.js.map must return 404, not source map content."""
    resp = await client.get("/static/js/main.js.map")
    assert resp.status_code == 404, (
        f"ID-08 FAIL: /static/js/main.js.map returned {resp.status_code}. "
        "Source map files expose original source code. Ensure no .map files "
        "are present in the static/ directory."
    )


@pytest.mark.asyncio
async def test_id08_css_map_file_not_served(client):
    """GET /static/css/style.css.map must return 404."""
    resp = await client.get("/static/css/style.css.map")
    assert resp.status_code == 404, f"ID-08 FAIL: /static/css/style.css.map returned {resp.status_code}."


# ---------------------------------------------------------------------------
# ID-09  Docker Python version fingerprinting
#
# Severity: INFORMATIONAL
# The Dockerfile uses `FROM python:3.12-slim`.  This is intentional and not
# a runtime disclosure issue (the image tag is not served via HTTP).  However
# the Python version CAN be inferred from the response if uvicorn's default
# server header includes it.  This test is a belt-and-suspenders check that
# neither the `server` header nor any other header exposes the Python version.
# CWE-200 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id09_no_python_version_in_headers(client):
    """Response headers must not disclose the Python runtime version."""
    resp = await client.get("/")
    for header_name, header_value in resp.headers.items():
        assert "python/3" not in header_value.lower(), (
            f"ID-09 FAIL: Header {header_name!r} discloses Python version: {header_value!r}"
        )
        assert "cpython" not in header_value.lower(), (
            f"ID-09 FAIL: Header {header_name!r} discloses CPython runtime: {header_value!r}"
        )


@pytest.mark.asyncio
async def test_id09_no_python_version_in_health_response(client):
    """Health endpoint must not expose Python runtime version."""
    resp = await client.get("/health")
    body = resp.text
    assert "python" not in body.lower(), f"ID-09 FAIL: /health response body discloses Python version: {body!r}"
    assert "3.12" not in body and "3.13" not in body, (
        f"ID-09 FAIL: /health response body discloses Python minor version: {body!r}"
    )


# ---------------------------------------------------------------------------
# ID-10  /.git/ directory exposure
#
# Severity: CRITICAL
# If the Git metadata directory is served as a static file, an attacker can
# reconstruct the entire source tree including any secrets committed in
# history.  The StaticFiles mount only covers /static/, but a misconfigured
# mount or symlink could expose /.git/.
# CWE-538 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id10_git_directory_not_accessible(client):
    """GET /.git/HEAD must return 404, not git metadata."""
    resp = await client.get("/.git/HEAD")
    assert resp.status_code == 404, (
        f"ID-10 CRITICAL FAIL: /.git/HEAD returned {resp.status_code}. "
        "Git metadata directory is accessible. This allows reconstruction of "
        "the full source tree and git history. Ensure /.git/ is never served."
    )
    # If it did return something, it must not contain git ref content.
    assert "ref:" not in resp.text, "ID-10 CRITICAL FAIL: /.git/HEAD response contains git ref data."


@pytest.mark.asyncio
async def test_id10_git_config_not_accessible(client):
    """GET /.git/config must return 404."""
    resp = await client.get("/.git/config")
    assert resp.status_code == 404, (
        f"ID-10 CRITICAL FAIL: /.git/config returned {resp.status_code}. "
        "Git config can expose remote URLs, user identities, and hooks."
    )


@pytest.mark.asyncio
async def test_id10_git_objects_not_accessible(client):
    """GET /.git/objects/ must return 404."""
    resp = await client.get("/.git/objects/")
    assert resp.status_code == 404, f"ID-10 CRITICAL FAIL: /.git/objects/ returned {resp.status_code}."


# ---------------------------------------------------------------------------
# ID-11  /health endpoint data exposure
#
# Severity: LOW
# The /health endpoint returns {"status": "ok"} — clean.  This test enforces
# that it does not expand to include version strings, uptime, dependency
# connection strings, or internal metrics in the future.
# CWE-200 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id11_health_endpoint_minimal_response(client):
    """Health endpoint must return only {status: ok} — no extra fields."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"status"}, (
        f"ID-11 FAIL: /health exposes unexpected fields: {set(data.keys())}. "
        "Health endpoints must not expose version, uptime, or dependency status "
        "without authentication."
    )
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_id11_health_no_version_string(client):
    """Health endpoint must not contain version or build metadata."""
    resp = await client.get("/health")
    body = resp.text
    for leak in ("version", "build", "commit", "sha", "branch", "deploy"):
        assert leak not in body.lower(), (
            f"ID-11 FAIL: /health response contains deployment metadata indicator {leak!r}: {body!r}"
        )


# ---------------------------------------------------------------------------
# ID-12  Contact form error enumeration
#
# Severity: LOW
# If invalid-email returns a different response shape than rate-limited,
# an attacker can distinguish between validation failure and rate-limiting,
# aiding brute-force or spam enumeration.  The app currently returns identical
# shapes for both, which is correct.  This test verifies that contract.
# CWE-204 / OWASP A07:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id12_rate_limit_indistinguishable_from_success(client):
    """Rate-limited responses must be indistinguishable from success responses."""
    success_resp = await client.post(
        "/contact",
        data={"name": "Alice", "email": "alice@example.com", "message": "Hi", "website": ""},
    )
    # Exhaust the rate limit.
    for _ in range(10):
        await client.post(
            "/contact",
            data={"name": "Alice", "email": "alice@example.com", "message": "Hi", "website": ""},
        )
    rate_limited_resp = await client.post(
        "/contact",
        data={"name": "Alice", "email": "alice@example.com", "message": "Hi", "website": ""},
    )
    assert success_resp.status_code == rate_limited_resp.status_code, (
        "ID-12 FAIL: Rate-limited response has different status code than "
        "success response — reveals rate limiting to the caller."
    )
    assert success_resp.json()["status"] == rate_limited_resp.json()["status"], (
        "ID-12 FAIL: Rate-limited response body 'status' field differs from "
        "success response — reveals rate limiting to the caller."
    )


@pytest.mark.asyncio
async def test_id12_honeypot_indistinguishable_from_success(client):
    """Honeypot-triggered responses must be indistinguishable from success."""
    success_resp = await client.post(
        "/contact",
        data={"name": "Real", "email": "real@example.com", "message": "Hi", "website": ""},
    )
    bot_resp = await client.post(
        "/contact",
        data={"name": "Bot", "email": "bot@spam.com", "message": "Buy", "website": "http://spam.com"},
    )
    assert success_resp.status_code == bot_resp.status_code, (
        "ID-12 FAIL: Honeypot response status code differs from success — reveals honeypot detection to bots."
    )
    assert success_resp.json()["status"] == bot_resp.json()["status"], (
        "ID-12 FAIL: Honeypot response body 'status' differs from success."
    )


# ---------------------------------------------------------------------------
# ID-13  Server header must be absent or non-identifying
#
# Severity: MEDIUM
# This is a focused check specifically about the `server` header value.
# uvicorn emits `server: uvicorn` by default.  An attacker who knows the
# ASGI server can cross-reference known CVEs for that version.
#
# Fix options (in priority order):
#   1. Pass `--no-server-header` to uvicorn (uvicorn >= 0.17.0)
#   2. Add `server_header=False` to `uvicorn.Config` if calling programmatically
#   3. Override in the security header middleware:
#      response.headers["server"] = ""  (or delete the key)
#
# CWE-200 / OWASP A05:2021
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id13_server_header_absent_or_redacted(client):
    """Server header must be absent or contain a non-identifying value."""
    resp = await client.get("/")
    server = resp.headers.get("server", "")
    assert server == "" or server.lower() not in ("uvicorn",), (
        f"ID-13 FAIL: 'server' header is {server!r}. "
        "This identifies the ASGI server to attackers. "
        "Fix: add to Dockerfile CMD: --no-server-header, or in middleware: "
        "del response.headers['server']"
    )


@pytest.mark.asyncio
async def test_id13_server_header_on_static_files(client):
    """Static file responses must also suppress the server identity header."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    server = resp.headers.get("server", "")
    assert "uvicorn" not in server.lower(), f"ID-13 FAIL: Static file response reveals server identity: {server!r}."


# ---------------------------------------------------------------------------
# Composite: all routes have all required security headers
# (belt-and-suspenders — the middleware applies these, but verify on key routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/health"])
async def test_required_security_headers_present(client, path):
    """All routes must carry the full security header set."""
    resp = await client.get(path)
    required = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "strict-transport-security": None,  # presence only
        "content-security-policy": None,
        "referrer-policy": None,
        "permissions-policy": None,
    }
    for header, expected_value in required.items():
        assert header in resp.headers, f"Missing required security header {header!r} on {path}"
        if expected_value is not None:
            assert resp.headers[header] == expected_value, (
                f"Header {header!r} on {path}: expected {expected_value!r}, got {resp.headers[header]!r}"
            )


@pytest.mark.asyncio
async def test_csp_no_unsafe_eval(client):
    """CSP must not permit 'unsafe-eval' which enables JS injection."""
    resp = await client.get("/")
    csp = resp.headers.get("content-security-policy", "")
    assert "'unsafe-eval'" not in csp, "FAIL: CSP contains 'unsafe-eval' which allows eval()-based XSS."
