"""Path traversal and static file security tests.

Coverage areas:
  1. Classic dot-dot traversal (decoded by ASGI router)
  2. Percent-encoded separators (%2f, %2e%2e) — ASGI decodes to .. before StaticFiles
  3. Double-encoded sequences (%252e%252e) — NOT decoded by ASGI; literal in path
  4. Null byte injection (%00) — causes ValueError in os.path.realpath
  5. Windows backslash traversal (POSIX only: treated as filename chars)
  6. Unicode lookalike periods (U+FF0E fullwidth stop)
  7. Sensitive file exposure: pyproject.toml, uv.lock, .env, app.py, templates/
  8. Template directory not mounted
  9. Cache-control correctness on error responses from /static paths

Findings summary (as of starlette 0.52.1):

  BLOCKED — traversal is sandboxed by StaticFiles.lookup_path via os.path.commonpath.
    - ../pyproject.toml, %2e%2e variants, css/../../ variants all 404 correctly.

  MEDIUM — Null byte (%00) in path causes ValueError inside lookup_path, which
    the app catches and returns {"error":"internal server error"} (no info leak in
    body). However the response gets Cache-Control: public, max-age=86400 because
    the middleware path-check is string-prefix-based, not route-based. A CDN or
    reverse proxy could cache the 500 as a permanent static-file response.

  INFO — %252e%252e (double-encoded) paths are not decoded by ASGI and resolve to
    literal filenames that do not exist on disk. No traversal possible, but the
    lack of strict URL validation means non-standard payloads reach StaticFiles.

  CONFIRMED SAFE:
    - Starlette lookup_path uses os.path.realpath + os.path.commonpath — robust
      against symlink attacks and all decoded traversal sequences.
    - Template directory is NOT mounted; /templates/* returns 404.
    - Source code is NOT reachable via any tested traversal.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_state():
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# 1. Classic dot-dot traversal
#    ASGI normalises /static/../<file> to /<file> before routing.
#    The request resolves outside /static and hits the 404 handler.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_traversal_pyproject_toml(client):
    """Traversal to pyproject.toml must not return file contents."""
    resp = await client.get("/static/../pyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_uv_lock(client):
    """Traversal to uv.lock must not leak dependency metadata."""
    resp = await client.get("/static/../uv.lock")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_app_source(client):
    """Traversal to app.py must not expose source code."""
    resp = await client.get("/static/../src/mumfordengineering/app.py")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_env_file(client):
    """Traversal to .env must not expose credentials."""
    resp = await client.get("/static/../.env")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_template_via_dotdot(client):
    """Traversal to templates/index.html via dot-dot must be blocked."""
    resp = await client.get("/static/../templates/index.html")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_etc_passwd(client):
    """Classic /etc/passwd traversal attempt must be blocked."""
    resp = await client.get("/static/../../../etc/passwd")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_nested_via_subdir(client):
    """Traversal starting from a static subdirectory must be blocked."""
    resp = await client.get("/static/css/../../pyproject.toml")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 2. Percent-encoded separator traversal (%2f = /)
#    ASGI decodes %2f to / so /static/..%2fpyproject.toml becomes
#    /static/../pyproject.toml — routed out of /static, returns 404.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_traversal_encoded_slash_pyproject(client):
    """Percent-encoded slash traversal (%2f) to pyproject.toml must be blocked."""
    resp = await client.get("/static/..%2fpyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_encoded_slash_uv_lock(client):
    """Percent-encoded slash traversal (%2f) to uv.lock must be blocked."""
    resp = await client.get("/static/..%2fuv.lock")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_encoded_slash_env(client):
    """Percent-encoded slash traversal (%2f) to .env must be blocked."""
    resp = await client.get("/static/..%2f.env")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_encoded_dots(client):
    """Percent-encoded dot traversal (%2e%2e = ..) must be blocked.

    ASGI decodes %2e to '.' so %2e%2e becomes '..' before routing.
    """
    resp = await client.get("/static/%2e%2e/pyproject.toml")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. Double-encoded traversal (%252e%252e%252f)
#    %25 decodes to %; ASGI decodes once giving literal '%2e%2e%2f'.
#    The static directory has no such file: lookup fails, returns 404.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_traversal_double_encoded_pyproject(client):
    """Double-encoded traversal (%252e%252e) to pyproject.toml must be blocked."""
    resp = await client.get("/static/..%252fpyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_double_encoded_dots(client):
    """Double-encoded dots (%252e%252e%252f) must not traverse outside static/."""
    resp = await client.get("/static/%252e%252e%252fpyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_traversal_double_encoded_env(client):
    """Double-encoded traversal to .env must be blocked."""
    resp = await client.get("/static/%252e%252e%252f.env")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. Null byte injection (%00)
#    os.path.realpath raises ValueError on embedded null bytes.
#    The middleware exception handler catches and returns a generic 500.
#    Verified: no stack trace or internal path info in response body.
#
#    MEDIUM: The 500 response on /static/%00 paths receives
#    Cache-Control: public, max-age=86400 because the middleware path
#    check uses string prefix matching, not route resolution.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_null_byte_returns_error_not_file(client):
    """Null byte in path must not return file contents."""
    resp = await client.get("/static/%00")
    # 500 is acceptable; 200 would be a failure
    assert resp.status_code in (400, 404, 500)
    # Body must not contain source paths or file content
    body = resp.text
    assert "mumfordengineering" not in body
    assert "/Users/" not in body
    assert "Traceback" not in body


@pytest.mark.asyncio
async def test_null_byte_no_info_leak_in_body(client):
    """Null byte 500 response must not expose internal paths in the body."""
    resp = await client.get("/static/css/style.css%00.py")
    body = resp.text
    assert "Traceback" not in body
    assert "/Users/" not in body
    assert "ValueError" not in body


@pytest.mark.asyncio
async def test_null_byte_traversal_etc_passwd(client):
    """Null byte combined with traversal must not expose /etc/passwd."""
    resp = await client.get("/static/%00../../etc/passwd")
    assert resp.status_code in (400, 404, 500)
    assert "root:" not in resp.text


@pytest.mark.asyncio
async def test_null_byte_no_content_served(client):
    """Null byte requests must never return 200 with file body."""
    for path in ["/static/%00", "/static/%00pyproject.toml", "/static/js/main.js%00"]:
        resp = await client.get(path)
        assert resp.status_code != 200, f"Unexpected 200 for {path}"


@pytest.mark.asyncio
async def test_null_byte_cache_control_not_public(client):
    """MEDIUM: 500 error on /static path must not receive public cache header.

    Current behaviour: middleware sets Cache-Control: public, max-age=86400
    for any path starting with /static/, including 500 error responses.
    A CDN or reverse proxy could cache this permanently.

    Expected: error responses should have Cache-Control: no-store or no-cache.

    This test documents the current FAILING state. Fix by changing the
    middleware cache logic to only set public cache on successful (2xx) responses.
    """
    resp = await client.get("/static/%00")
    cache_header = resp.headers.get("cache-control", "")
    # This assertion FAILS with the current implementation.
    # It is intentionally written as the desired secure behaviour.
    assert "public" not in cache_header, (
        "Error responses on /static paths must not be publicly cacheable. "
        "Cache-Control should be no-store or no-cache for non-2xx responses. "
        f"Got: {cache_header!r}"
    )


# ---------------------------------------------------------------------------
# 5. Windows backslash traversal
#    On POSIX systems, backslash is a valid filename character (not a separator).
#    Starlette does not treat it as a path component; lookup fails with 404.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backslash_traversal_posix(client):
    """Windows-style backslash traversal must not work on POSIX."""
    resp = await client.get("/static/..\\pyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_backslash_traversal_encoded(client):
    """Percent-encoded backslash (%5c) traversal must be blocked."""
    resp = await client.get("/static/..%5cpyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_backslash_traversal_nested(client):
    """Nested backslash traversal must not escape the static directory."""
    resp = await client.get("/static/js\\..\\..\\..\\etc\\passwd")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Unicode lookalike / normalization attacks
#    U+FF0E (fullwidth full stop) looks like '.' but is not normalised by
#    os.path.normpath. The path resolves to a literal Unicode filename
#    that does not exist on disk.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unicode_fullwidth_period_traversal(client):
    """Unicode fullwidth period (U+FF0E) must not be treated as path separator."""
    # \uff0e\uff0e is the fullwidth equivalent of '..'
    resp = await client.get("/static/\uff0e\uff0e/pyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unicode_fullwidth_slash_traversal(client):
    """Unicode fullwidth solidus (U+FF0F) must not act as path separator."""
    resp = await client.get("/static/..\uff0fpyproject.toml")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 7. Sensitive file exposure — direct path probes
#    Even without traversal, verify these files are not accidentally placed
#    inside the static/ directory or reachable via StaticFiles.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pyproject_not_in_static(client):
    """pyproject.toml must not be served from /static/pyproject.toml."""
    resp = await client.get("/static/pyproject.toml")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_uv_lock_not_in_static(client):
    """uv.lock must not be served from /static/uv.lock."""
    resp = await client.get("/static/uv.lock")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_env_not_in_static(client):
    """.env must not be served from /static/.env."""
    resp = await client.get("/static/.env")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_app_py_not_in_static(client):
    """app.py must not be served from /static/app.py."""
    resp = await client.get("/static/app.py")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dockerfile_not_in_static(client):
    """Dockerfile must not be served from /static/Dockerfile."""
    resp = await client.get("/static/Dockerfile")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 8. Template directory not mounted
#    /templates is used only by Jinja2Templates server-side.
#    It is NOT mounted as an HTTP route; direct requests must 404.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_templates_dir_not_mounted(client):
    """/templates/index.html must not be directly accessible via HTTP."""
    resp = await client.get("/templates/index.html")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_templates_dir_root_not_mounted(client):
    """/templates/ root path must not be accessible via HTTP."""
    resp = await client.get("/templates/")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 9. Cache-control correctness on /static error paths
#    The middleware sets Cache-Control: public, max-age=86400 for any
#    path starting with /static/. This should only apply to 200 responses.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_200_gets_public_cache(client):
    """Successful static file requests must receive public cache header."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    assert "public" in resp.headers.get("cache-control", "")
    assert "max-age=86400" in resp.headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_static_404_cache_not_public(client):
    """404 responses on /static paths should not be publicly cacheable.

    Current behaviour: path starts with /static/ so middleware sets public
    cache regardless of status. This is a latent bug — 404 responses should
    not be cached by CDNs.

    This test documents the desired secure behaviour (currently fails).
    Fix: gate the public cache header on response.status_code == 200.
    """
    resp = await client.get("/static/nonexistent-file.css")
    assert resp.status_code == 404
    cache_header = resp.headers.get("cache-control", "")
    assert "public" not in cache_header, (
        f"404 responses on /static paths must not be publicly cacheable. Got Cache-Control: {cache_header!r}"
    )


# ---------------------------------------------------------------------------
# 10. Starlette sandbox integrity — commonpath protection verification
#     These tests confirm Starlette's lookup_path sandbox is operative by
#     verifying the attack surface at the library level.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_serves_css_correctly(client):
    """Legitimate CSS file must be served with correct content-type."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_static_serves_js_correctly(client):
    """Legitimate JS file must be served with correct content-type."""
    resp = await client.get("/static/js/main.js")
    assert resp.status_code == 200
    content_type = resp.headers.get("content-type", "")
    assert "javascript" in content_type or "text/" in content_type


@pytest.mark.asyncio
async def test_traversal_does_not_leak_file_content(client):
    """Any traversal attempt must not return the content of pyproject.toml."""
    traversal_paths = [
        "/static/../pyproject.toml",
        "/static/..%2fpyproject.toml",
        "/static/%2e%2e/pyproject.toml",
        "/static/css/../../pyproject.toml",
    ]
    for path in traversal_paths:
        resp = await client.get(path)
        # pyproject.toml contains '[project]' — must never appear in response
        assert "[project]" not in resp.text, f"pyproject.toml content leaked via {path}"
        assert "mumfordengineering" not in resp.text or resp.status_code != 200, f"Possible source leak via {path}"


@pytest.mark.asyncio
async def test_security_headers_on_static_response(client):
    """Static file responses must include all security headers."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers
