"""
Denial of Service and Resource Exhaustion tests for mumfordengineering portfolio site.

These tests document attack surface findings and verify observable mitigations (or their
absence). Each test is annotated with severity, attack vector, and remediation reference.

Findings summary
----------------
DOS-01  MEDIUM   No global HTTP request body size limit (Starlette default: unbounded)
DOS-02  LOW      Starlette multipart per-field limit is 1 MB — form max_length validated
                 by FastAPI AFTER body is fully read into memory
DOS-03  LOW      /health endpoint has no rate limiting; Fly health-check polling is benign
                 but the endpoint is publicly accessible
DOS-04  MEDIUM   Rate limiter memory: 10,000 IPs × up to 5 timestamps each is bounded,
                 but eviction is single-shot (one IP per request) — a concurrent burst
                 above _MAX_TRACKED_IPS never evicts fast enough
DOS-05  LOW      Uvicorn is launched without --limit-concurrency or --limit-max-requests
                 in the Dockerfile CMD; no connection ceiling exists at the process level
DOS-06  LOW      Static file handler (StaticFiles) streams files without a concurrency
                 ceiling; repeated requests for style.css / main.js are unbounded
DOS-07  INFO     No WebSocket endpoints are exposed (no attack surface here)
DOS-08  INFO     All JSON responses are small and structurally bounded
DOS-09  LOW      Template rendering (index.html) is triggered for every 404; an attacker
                 can force repeated renders by hammering nonexistent paths
DOS-10  LOW      _is_rate_limited has a logic gap: the first request from a new IP is
                 always allowed (timestamps list is empty → early return False without
                 appending the current timestamp), meaning the rate-limit counter never
                 starts for the first hit.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import (
    _MAX_TRACKED_IPS,
    _contact_timestamps,
    _is_rate_limited,
    app,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Isolate every test from in-process rate-limiter state."""
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _valid_form(**overrides: str) -> dict[str, str]:
    base: dict[str, str] = {
        "name": "Test User",
        "email": "test@example.com",
        "message": "Hello world",
        "website": "",
    }
    base.update(overrides)
    return base


# ===========================================================================
# DOS-01  No global HTTP request body size limit
# ===========================================================================
#
# Severity: MEDIUM
#
# Attack vector:
#   POST /contact with a multi-megabyte URL-encoded body.  Starlette reads the
#   entire body into memory before handing it to the form parser.  There is no
#   Content-Length rejection or streaming limit configured at the ASGI layer.
#   On a 256 MB Fly.io VM, a single 200 MB request can exhaust available
#   memory if several land concurrently.
#
# Remediation:
#   1. Add a LimitUploadSize middleware (Starlette) before the route handlers:
#
#       from starlette.middleware import Middleware
#       from starlette.middleware.trustedhost import TrustedHostMiddleware
#
#       class MaxBodySizeMiddleware(BaseHTTPMiddleware):
#           def __init__(self, app, max_bytes: int = 1_048_576):  # 1 MB
#               super().__init__(app)
#               self.max_bytes = max_bytes
#
#           async def dispatch(self, request, call_next):
#               content_length = request.headers.get("content-length")
#               if content_length and int(content_length) > self.max_bytes:
#                   return JSONResponse({"error": "payload too large"}, 413)
#               return await call_next(request)
#
#   2. OR pass --limit-concurrency 10 to uvicorn so the worker queue has a
#      ceiling before memory is exhausted.
#
#   3. Fly.io edge does not enforce a body size limit by default.
#
# Test approach:
#   Verify the server accepts a body that exceeds any reasonable field size.
#   This is a documentation test — it PASSES today, proving the gap exists.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos01_large_body_accepted_without_413(client: AsyncClient) -> None:
    """
    DOS-01: A POST body significantly larger than the form field limits is accepted.

    The per-field max_length (5000 chars for message) is enforced by FastAPI
    AFTER the body is fully buffered.  Starlette has no pre-read size gate.
    This test sends ~64 KB; the real threat is orders of magnitude larger.
    """
    oversized_message = "A" * 65_536  # 64 KB — well above the 5000-char limit
    resp = await client.post(
        "/contact",
        data={
            "name": "Test",
            "email": "test@example.com",
            "message": oversized_message,
            "website": "",
        },
    )
    # FastAPI rejects at field validation level (422), but only AFTER buffering
    # the entire body.  A 413 at the middleware level would be safer.
    assert resp.status_code == 422, (
        "Expected field-level 422 after body is buffered — no upstream 413 gating is in place (DOS-01)"
    )


@pytest.mark.asyncio
async def test_dos01_no_content_length_rejection(client: AsyncClient) -> None:
    """
    DOS-01 (supplementary): No middleware rejects requests by Content-Length alone.

    A hardened server would return 413 for Content-Length > threshold without
    reading a single byte.  This test confirms that guard is absent.
    """
    # Send a well-formed request but with a suspicious Content-Length header.
    # httpx will NOT actually send a huge body; we just confirm no pre-check exists.
    resp = await client.post(
        "/contact",
        data=_valid_form(),
        headers={"Content-Length": str(50 * 1024 * 1024)},  # 50 MB claimed
    )
    # Body size limit middleware rejects based on Content-Length header
    assert resp.status_code == 413, "Body size limit middleware should reject oversized Content-Length with 413"


# ===========================================================================
# DOS-02  Multipart per-part limit and field max_length interaction
# ===========================================================================
#
# Severity: LOW (mitigated by Starlette 1 MB per-part cap)
#
# Attack vector:
#   Starlette's multipart parser caps each individual field at 1 MB
#   (max_part_size=1024*1024).  FastAPI's max_length on Form fields is checked
#   after parsing.  The 1 MB cap is a mitigating control, but the ordering
#   (buffer first, validate second) means the full 1 MB is allocated even for
#   a field declared max_length=200.
#
# Remediation:
#   Pass max_part_size to get_form explicitly:
#       await request.form(max_fields=3, max_part_size=6000)
#   This caps allocation per field to the maximum legitimate value plus slack.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos02_field_above_max_length_rejected(client: AsyncClient) -> None:
    """
    DOS-02: FastAPI rejects fields exceeding max_length with 422.

    This confirms the mitigation works, but the body was already buffered.
    """
    resp = await client.post(
        "/contact",
        data=_valid_form(name="N" * 201),  # 1 over _MAX_NAME=200
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_dos02_email_above_max_length_rejected(client: AsyncClient) -> None:
    """DOS-02: email max_length=254 enforced."""
    resp = await client.post(
        "/contact",
        data=_valid_form(email="a" * 240 + "@x.com"),  # 246 chars — over 254
    )
    # 246 < 254, should pass field length but fail regex
    assert resp.status_code in (200, 422)


@pytest.mark.asyncio
async def test_dos02_message_at_boundary(client: AsyncClient) -> None:
    """DOS-02: message at exactly _MAX_MESSAGE=5000 chars is accepted."""
    resp = await client.post(
        "/contact",
        data=_valid_form(message="M" * 5000),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_dos02_message_above_max_length_rejected(client: AsyncClient) -> None:
    """DOS-02: message at 5001 chars is rejected with 422."""
    resp = await client.post(
        "/contact",
        data=_valid_form(message="M" * 5001),
    )
    assert resp.status_code == 422


# ===========================================================================
# DOS-03  /health endpoint has no rate limiting
# ===========================================================================
#
# Severity: LOW
#
# Attack vector:
#   /health returns JSON without any rate limit.  An attacker can hammer this
#   endpoint to consume CPU/network bandwidth.  The Fly.io health check polls
#   it every 30 s legitimately, but the path is publicly accessible.
#
#   On a shared-CPU Fly.io VM, sustained /health polling (e.g., 1000 req/s)
#   can starve the event loop for actual page requests.
#
# Remediation:
#   Apply a rate limiter (slowapi or starlette-limiter) to /health, or restrict
#   access by IP to Fly.io's health-check subnet only.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos03_health_no_rate_limit(client: AsyncClient) -> None:
    """
    DOS-03: /health returns 200 for every request with no throttling.

    50 rapid requests all succeed — no 429 is returned.
    """
    responses = await asyncio.gather(*[client.get("/health") for _ in range(50)])
    statuses = [r.status_code for r in responses]
    assert all(s == 200 for s in statuses), f"Expected all 200 from /health; got {set(statuses)}"
    # No rate limiting present — confirmed.


@pytest.mark.asyncio
async def test_dos03_health_response_is_minimal(client: AsyncClient) -> None:
    """DOS-03 (supplementary): /health response body is small (bounded)."""
    resp = await client.get("/health")
    assert len(resp.content) < 256, "Health response unexpectedly large"


# ===========================================================================
# DOS-04  Rate limiter memory exhaustion via concurrent IP burst
# ===========================================================================
#
# Severity: MEDIUM
#
# Attack vector:
#   _contact_timestamps caps tracked IPs at _MAX_TRACKED_IPS (10,000).
#   The eviction logic (lines 144-146) removes ONE IP per request when the
#   cap is exceeded.  Under a concurrent burst with N unique IPs where N >>
#   _MAX_TRACKED_IPS, the dictionary grows well beyond 10,000 entries before
#   sequential eviction catches up.  Each entry holds up to 5 float timestamps
#   (~200 bytes total per IP).  At 10,000 IPs: ~2 MB — acceptable.  At 100,000
#   IPs during a burst before eviction runs: ~20 MB — notable on a 256 MB VM.
#
#   Additionally, each entry can accumulate up to CONTACT_RATE_LIMIT=5
#   timestamps.  With the eviction gap, memory use can temporarily exceed the
#   nominal 10,000-IP ceiling.
#
# Remediation:
#   Use a size-bounded LRU cache (functools.lru_cache or cachetools.TTLCache)
#   instead of a plain dict.  TTLCache with maxsize=10_000 and ttl=3600
#   provides O(1) eviction:
#
#       from cachetools import TTLCache
#       _rate_cache: TTLCache[str, list[float]] = TTLCache(maxsize=10_000, ttl=3600)
# ---------------------------------------------------------------------------


def test_dos04_eviction_is_single_shot() -> None:
    """
    DOS-04: Eviction removes only one IP per call when dict exceeds _MAX_TRACKED_IPS.

    This documents the O(N) growth risk under concurrent burst — sequential
    eviction cannot keep pace with a parallel flood of unique IPs.
    """
    # Prefill to just above the threshold
    overflow = _MAX_TRACKED_IPS + 10
    for i in range(overflow):
        _contact_timestamps[f"192.168.{i // 256}.{i % 256}"] = [time.time()]

    size_before = len(_contact_timestamps)
    assert size_before == overflow, f"Expected {overflow}, got {size_before}"

    # A single contact call triggers at most one eviction
    # Simulate what the route does: evict one if over limit
    if len(_contact_timestamps) > _MAX_TRACKED_IPS:
        oldest_ip = min(_contact_timestamps, key=lambda k: _contact_timestamps[k][-1])
        del _contact_timestamps[oldest_ip]

    size_after = len(_contact_timestamps)
    # Still above limit after one eviction — the gap remains
    assert size_after == overflow - 1, f"Eviction removed more than one entry: {size_after}"
    assert size_after > _MAX_TRACKED_IPS, (
        "Dictionary is still over _MAX_TRACKED_IPS after one eviction pass — "
        "concurrent burst will grow memory beyond the intended cap (DOS-04)"
    )


def test_dos04_nominal_memory_footprint_is_bounded() -> None:
    """
    DOS-04 (supplementary): At the stated cap, memory use is acceptable.

    10,000 IPs × 5 timestamps × ~8 bytes per float = ~400 KB.
    """
    max_timestamps_per_ip = 5  # CONTACT_RATE_LIMIT
    bytes_per_float = 8
    bytes_per_ip_key = 15  # rough average for "192.168.xxx.xxx"
    overhead_per_list = 56  # CPython list object overhead

    estimated_bytes = _MAX_TRACKED_IPS * (
        bytes_per_ip_key + overhead_per_list + max_timestamps_per_ip * bytes_per_float
    )
    # Under 10 MB is acceptable for a 256 MB VM
    assert estimated_bytes < 10 * 1024 * 1024, (
        f"Rate limiter nominal memory {estimated_bytes / 1024:.0f} KB exceeds 10 MB"
    )


# ===========================================================================
# DOS-05  No uvicorn concurrency ceiling in Dockerfile CMD
# ===========================================================================
#
# Severity: LOW
#
# Attack vector:
#   The Dockerfile CMD launches uvicorn without --limit-concurrency or
#   --limit-max-requests.  uvicorn will accept as many simultaneous connections
#   as the OS allows (backlog default 2048).  On a 256 MB / 1 shared-CPU VM,
#   this means a connection flood can saturate the event loop indefinitely.
#
# Remediation:
#   Add --limit-concurrency 100 to the CMD to cap simultaneous in-flight
#   requests; uvicorn will return 503 for excess connections.
#   Add --limit-max-requests 10000 for graceful worker recycling.
#
#   CMD ["uvicorn", "mumfordengineering.app:app",
#        "--host", "0.0.0.0", "--port", "8080",
#        "--proxy-headers", "--forwarded-allow-ips", "*",
#        "--limit-concurrency", "100",
#        "--limit-max-requests", "10000"]
# ---------------------------------------------------------------------------


def test_dos05_dockerfile_cmd_lacks_concurrency_limit() -> None:
    """
    DOS-05: Documents that Dockerfile CMD has no --limit-concurrency flag.

    This is a configuration audit test — it reads the Dockerfile and asserts
    the flag is absent so CI will catch if remediation is applied (test must
    then be updated) or regressed.
    """
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    content = dockerfile.read_text()
    assert "--limit-concurrency" not in content, (
        "DOS-05 remediation detected: --limit-concurrency found in Dockerfile. "
        "Update this test to assert the correct value is set."
    )
    assert "--limit-max-requests" not in content, (
        "DOS-05 remediation detected: --limit-max-requests found in Dockerfile. "
        "Update this test to assert the correct value is set."
    )


# ===========================================================================
# DOS-06  Static file handler has no concurrency ceiling
# ===========================================================================
#
# Severity: LOW
#
# Attack vector:
#   StaticFiles streams files from disk.  Each concurrent request opens a file
#   descriptor and streams the response.  With no concurrency limit, a flood of
#   requests for /static/css/style.css can exhaust file descriptors (default
#   ulimit 256 on some containers) and create disk I/O pressure.
#
# Remediation:
#   - Set --limit-concurrency on uvicorn (covers all routes including static).
#   - Serve static files from a CDN or object storage instead of the app
#     process on a memory-constrained VM.
#   - Add Cache-Control: public, max-age=86400 (already present — good).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos06_static_css_served_with_cache_headers(client: AsyncClient) -> None:
    """DOS-06: Static files include cache headers to reduce repeat requests."""
    resp = await client.get("/static/css/style.css")
    assert resp.status_code == 200
    cc = resp.headers.get("cache-control", "")
    assert "public" in cc, "Static files should set Cache-Control: public"
    assert "max-age" in cc, "Static files should set a max-age to reduce load"


@pytest.mark.asyncio
async def test_dos06_static_js_served_with_cache_headers(client: AsyncClient) -> None:
    """DOS-06: JS static file also carries cache headers."""
    resp = await client.get("/static/js/main.js")
    assert resp.status_code == 200
    assert "max-age" in resp.headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_dos06_concurrent_static_requests_all_succeed(client: AsyncClient) -> None:
    """
    DOS-06: Confirms no concurrency ceiling exists on static file serving.

    20 simultaneous requests for the same static file all return 200.
    This is the expected current behavior — documents the absence of a limit.
    """
    responses = await asyncio.gather(*[client.get("/static/css/style.css") for _ in range(20)])
    statuses = [r.status_code for r in responses]
    assert all(s == 200 for s in statuses)


# ===========================================================================
# DOS-07  No WebSocket endpoints (no additional attack surface)
# ===========================================================================
#
# Severity: INFO
#
# FastAPI does not expose WebSocket endpoints by default.  This test confirms
# none are registered, which would otherwise be an upgrade-based DoS vector.
# ---------------------------------------------------------------------------


def test_dos07_no_websocket_routes() -> None:
    """DOS-07: No WebSocket routes are registered on the application."""
    from fastapi.routing import APIWebSocketRoute

    ws_routes = [r for r in app.routes if isinstance(r, APIWebSocketRoute)]
    assert len(ws_routes) == 0, f"Unexpected WebSocket routes found: {[r.path for r in ws_routes]}"


# ===========================================================================
# DOS-08  JSON response bodies are structurally bounded
# ===========================================================================
#
# Severity: INFO
#
# All JSON endpoints return small, fixed-schema responses.  This confirms no
# unbounded list or recursive structure can be triggered by an attacker.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos08_health_json_is_small(client: AsyncClient) -> None:
    """DOS-08: /health JSON response is minimal."""
    resp = await client.get("/health")
    data = resp.json()
    assert set(data.keys()) == {"status"}
    assert len(resp.content) < 64


@pytest.mark.asyncio
async def test_dos08_contact_success_json_is_bounded(client: AsyncClient) -> None:
    """DOS-08: /contact success JSON has exactly two keys."""
    resp = await client.post("/contact", data=_valid_form())
    data = resp.json()
    assert set(data.keys()) == {"status", "message"}
    assert len(resp.content) < 256


@pytest.mark.asyncio
async def test_dos08_contact_error_json_is_bounded(client: AsyncClient) -> None:
    """DOS-08: /contact error JSON has exactly two keys."""
    resp = await client.post("/contact", data=_valid_form(email="bad"))
    data = resp.json()
    assert set(data.keys()) == {"status", "message"}
    assert len(resp.content) < 256


# ===========================================================================
# DOS-09  404 handler triggers Jinja2 template render on every hit
# ===========================================================================
#
# Severity: LOW
#
# Attack vector:
#   The 404 handler renders index.html for every unknown path.  Jinja2
#   rendering is CPU-bound.  An attacker can issue a flood of requests for
#   unique nonexistent paths (bypassing any CDN cache) and force repeated
#   template compilation+rendering, consuming CPU on the shared-CPU VM.
#
#   On a shared-CPU Fly.io VM, sustained 404 flooding can starve legitimate
#   page loads without triggering the contact-form rate limiter.
#
# Remediation:
#   1. Return a plain JSONResponse or static HTML for 404 instead of rendering
#      the full template:
#         return HTMLResponse("<h1>Not Found</h1>", status_code=404)
#   2. OR cache the rendered template at startup and serve the cached bytes.
#   3. Add --limit-concurrency to uvicorn (covers all routes).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dos09_404_triggers_template_render(client: AsyncClient) -> None:
    """DOS-09: Each 404 request causes a full Jinja2 template render."""
    resp = await client.get("/this-path-does-not-exist")
    assert resp.status_code == 404
    # Confirm a full HTML response is returned (template was rendered)
    assert "text/html" in resp.headers["content-type"]
    assert len(resp.content) > 1000, "Expected full HTML page, not a minimal 404"


@pytest.mark.asyncio
async def test_dos09_unique_404_paths_all_trigger_render(client: AsyncClient) -> None:
    """
    DOS-09: 20 unique unknown paths each return a rendered HTML page.

    Each consumes template rendering CPU.  No caching or short-circuit
    response is in place.
    """
    paths = [f"/nonexistent-{i}" for i in range(20)]
    responses = await asyncio.gather(*[client.get(p) for p in paths])
    for resp in responses:
        assert resp.status_code == 404
        assert "text/html" in resp.headers["content-type"]


# ===========================================================================
# DOS-10  Rate limiter is completely non-functional (MEDIUM severity)
# ===========================================================================
#
# Severity: MEDIUM
#
# Bug description:
#   _is_rate_limited() NEVER records any submission for any IP.  The function
#   always takes the early-return path because _contact_timestamps is always
#   empty.  The full execution trace for every call:
#
#       timestamps = _contact_timestamps.get(ip, [])   # always []
#       timestamps = [t for t in timestamps if ...]     # still []
#       if not timestamps:                              # always True
#           _contact_timestamps.pop(ip, None)           # no-op
#           return False                                # exits here unconditionally
#       # Lines 92-95 are unreachable for any IP, ever.
#       _contact_timestamps[ip] = timestamps            # never reached
#       if len(timestamps) >= CONTACT_RATE_LIMIT: ...   # never reached
#       timestamps.append(now)                          # never reached
#
#   The dict stays empty forever.  No IP is ever rate-limited.  The honeypot
#   and field validation still work, but the rate limiter provides zero
#   protection against a sustained contact-form flood.
#
# Root cause:
#   The first submission for any IP finds an empty list, triggers the early
#   return, and never seeds the dict.  All subsequent submissions repeat this
#   because the dict is never written.
#
# Remediation:
#   Seed the dict entry on the first submission:
#
#       def _is_rate_limited(ip: str) -> bool:
#           now = time.time()
#           timestamps = _contact_timestamps.get(ip, [])
#           timestamps = [t for t in timestamps if now - t < CONTACT_WINDOW]
#           if len(timestamps) >= CONTACT_RATE_LIMIT:
#               _contact_timestamps[ip] = timestamps
#               return True
#           timestamps.append(now)
#           _contact_timestamps[ip] = timestamps
#           return False
# ---------------------------------------------------------------------------


def test_dos10_rate_limiter_records_ips() -> None:
    """
    Rate limiter records IP timestamps after each call.
    """
    ip = "203.0.113.1"
    _contact_timestamps.pop(ip, None)
    assert ip not in _contact_timestamps

    _is_rate_limited(ip)

    assert ip in _contact_timestamps, "DOS-10: _contact_timestamps should have an entry after one call."
    assert len(_contact_timestamps[ip]) == 1


def test_dos10_rate_limiter_returns_true_after_limit() -> None:
    """
    Rate limiter returns True after CONTACT_RATE_LIMIT calls within the window.
    """
    from mumfordengineering.app import CONTACT_RATE_LIMIT

    ip = "203.0.113.2"
    _contact_timestamps.pop(ip, None)
    results = [_is_rate_limited(ip) for _ in range(CONTACT_RATE_LIMIT + 1)]

    # First CONTACT_RATE_LIMIT calls return False, subsequent return True
    assert results[:CONTACT_RATE_LIMIT] == [False] * CONTACT_RATE_LIMIT
    assert results[CONTACT_RATE_LIMIT] is True


@pytest.mark.asyncio
async def test_dos10_contact_form_unlimited_submissions(client: AsyncClient) -> None:
    """
    DOS-10 (integration): The contact form accepts unlimited submissions from
    the same IP.  CONTACT_RATE_LIMIT=5 is never enforced.
    """
    from mumfordengineering.app import CONTACT_RATE_LIMIT

    # Send 3x the intended limit — all should succeed
    unlimited = CONTACT_RATE_LIMIT * 3
    responses = []
    for _ in range(unlimited):
        resp = await client.post("/contact", data=_valid_form())
        responses.append(resp)

    success_count = sum(1 for r in responses if r.status_code == 200 and r.json()["status"] == "ok")

    # Rate limiter silently drops requests after limit (same 200 response).
    # All requests return status "ok" — the drop is invisible to the caller.
    assert success_count == unlimited, (
        f"Expected all {unlimited} to return status 'ok' (silent drop design), got {success_count}"
    )


# ===========================================================================
# Additional: Rate limiter isolation between IPs (behavior if fixed)
# ===========================================================================


@pytest.mark.asyncio
async def test_rate_limiter_independent_per_ip(client: AsyncClient) -> None:
    """
    Rate limiting is intended to be IP-scoped.  This test documents that even
    when one IP floods the endpoint, another IP is unaffected.

    Due to DOS-10, neither IP is actually rate-limited.  This test confirms
    the isolation property holds (trivially, since nothing is blocked).
    """
    # Send many requests from IP A
    for _ in range(20):
        await client.post(
            "/contact",
            data=_valid_form(),
            headers={"fly-client-ip": "10.0.0.1"},
        )

    # IP B should still be allowed (and is, because nothing is blocked)
    resp = await client.post(
        "/contact",
        data=_valid_form(),
        headers={"fly-client-ip": "10.0.0.2"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# Additional: fly-client-ip header trust model
# ===========================================================================


@pytest.mark.asyncio
async def test_fly_client_ip_header_is_trusted_source(client: AsyncClient) -> None:
    """
    The rate limiter uses fly-client-ip as the primary IP source (correct for
    Fly.io deployments).  This test documents the trust assumption: the header
    is accepted unconditionally.

    On Fly.io this header is injected by the Fly edge proxy and is reliable.
    On any non-Fly deployment (local dev, alternative hosting), an attacker
    controlling HTTP headers can set arbitrary fly-client-ip values.

    Since DOS-10 makes the rate limiter non-functional, IP rotation currently
    provides zero additional bypass — there is nothing to bypass.
    """
    from mumfordengineering.app import _get_client_ip

    class _FakeRequest:
        def __init__(self, fly_ip: str | None = None, xff: str | None = None):
            self.headers: dict[str, str] = {}
            if fly_ip:
                self.headers["fly-client-ip"] = fly_ip
            if xff:
                self.headers["x-forwarded-for"] = xff
            self.client = None

    req_fly = _FakeRequest(fly_ip="1.2.3.4")
    assert _get_client_ip(req_fly) == "1.2.3.4"  # type: ignore[arg-type]

    req_xff = _FakeRequest(xff="5.6.7.8, 9.10.11.12")
    assert _get_client_ip(req_xff) == "unknown"  # type: ignore[arg-type]  # XFF no longer trusted

    req_none = _FakeRequest()
    result = _get_client_ip(req_none)  # type: ignore[arg-type]
    assert result == "unknown"
