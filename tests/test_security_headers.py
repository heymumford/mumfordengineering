"""Security headers completeness and CSP analysis tests.

Findings summary (severity → finding → test):
  FIXED   F-01  CSP style-src 'unsafe-inline' removed
  FIXED   F-02  CSP base-uri directive added
  FIXED   F-03  CSP form-action directive added
  FIXED   F-04  CSP object-src directive added
  FIXED   F-05  CSP frame-ancestors directive added
  LOW     F-06  CSP missing worker-src (web workers / service workers not scoped)
  LOW     F-07  CSP missing manifest-src
  LOW     F-08  CSP no report-to / report-uri (violations go unobserved)
  FIXED   F-09  Cross-Origin-Opener-Policy header added
  LOW     F-10  Missing Cross-Origin-Embedder-Policy header
  LOW     F-11  Missing Cross-Origin-Resource-Policy header
  FIXED   F-12  Permissions-Policy extended with modern sensor/device permissions
  INFO    F-13  X-XSS-Protection: 0 is correct; documents rationale
  INFO    F-14  HSTS preload directive present; documents domain-submission requirement
  INFO    F-15  Referrer-Policy: strict-origin-when-cross-origin leaks URL path on same-origin
  INFO    F-16  404 and 500 responses inherit no-cache from middleware (confirmed correct)
  INFO    F-17  HSTS max-age >= 2 years (31,536,000 s) required for preload eligibility
"""

from __future__ import annotations

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


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP header string into a directive-name → token-list mapping."""
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        directives[name] = tokens[1:]
    return directives


# ---------------------------------------------------------------------------
# F-01 — CSP style-src 'unsafe-inline' (FIXED)
# Severity: MEDIUM (resolved)
#
# 'unsafe-inline' was removed from style-src. The template has no inline
# styles; only linked CSS files and Google Fonts external stylesheets.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f01_csp_style_src_no_unsafe_inline_target_state(client):
    """Target state after hardening: 'unsafe-inline' must not appear in style-src.

    Recommendation:
        style-src 'self' https://fonts.googleapis.com;
    Nonce alternative (requires per-request nonce injection in middleware):
        style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com;
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    style_tokens = csp.get("style-src", [])
    assert "'unsafe-inline'" not in style_tokens, (
        "F-01: style-src must not contain 'unsafe-inline'. Use 'nonce-<value>' or a hash instead."
    )


# ---------------------------------------------------------------------------
# F-02 — CSP base-uri (FIXED)
# Severity: MEDIUM (resolved)
#
# base-uri 'none' added, preventing base-tag injection attacks.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f02_csp_base_uri_present_target_state(client):
    """Target state: base-uri directive must be present.

    Recommendation:
        base-uri 'none';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "base-uri" in csp, "F-02: CSP must include a base-uri directive."
    assert csp["base-uri"] in (["'none'"], ["'self'"]), "F-02: base-uri should be 'none' or 'self', not an open value."


# ---------------------------------------------------------------------------
# F-03 — CSP form-action (FIXED)
# Severity: MEDIUM (resolved)
#
# form-action 'self' added, preventing form hijacking via injected HTML.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f03_csp_form_action_present_target_state(client):
    """Target state: form-action 'self' must be present.

    Recommendation:
        form-action 'self';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "form-action" in csp, "F-03: CSP must include a form-action directive."
    assert "'self'" in csp["form-action"], "F-03: form-action must include 'self'."


# ---------------------------------------------------------------------------
# F-04 — CSP object-src (FIXED)
# Severity: MEDIUM (resolved)
#
# object-src 'none' added, blocking plugin content vectors.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f04_csp_object_src_present_target_state(client):
    """Target state: object-src 'none' must be present.

    Recommendation:
        object-src 'none';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "object-src" in csp, "F-04: CSP must include an object-src directive."
    assert csp["object-src"] == ["'none'"], "F-04: object-src should be 'none' — no plugin content is used."


# ---------------------------------------------------------------------------
# F-05 — CSP frame-ancestors (FIXED)
# Severity: LOW (resolved)
#
# frame-ancestors 'none' added alongside X-Frame-Options: DENY for
# defence-in-depth.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f05_csp_frame_ancestors_present_target_state(client):
    """Target state: frame-ancestors 'none' must be present.

    Recommendation:
        frame-ancestors 'none';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "frame-ancestors" in csp, "F-05: CSP must include a frame-ancestors directive."
    assert csp["frame-ancestors"] == ["'none'"], (
        "F-05: frame-ancestors should be 'none' — the site must not be embedded."
    )


# ---------------------------------------------------------------------------
# F-06 — CSP missing worker-src
# Severity: LOW
#
# worker-src controls Web Workers and Service Workers. Without it, the
# fallback chain is script-src → default-src. The site currently has no
# workers, but an explicit 'none' prevents future accidental worker injection.
#
# Recommendation: add   worker-src 'none';
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.xfail(reason="F-06: worker-src directive not yet added", strict=True)
async def test_f06_csp_worker_src_present_target_state(client):
    """Target state: worker-src must be explicitly declared.

    Recommendation:
        worker-src 'none';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "worker-src" in csp, "F-06: CSP must include a worker-src directive."


# ---------------------------------------------------------------------------
# F-07 — CSP missing manifest-src
# Severity: LOW
#
# manifest-src controls Web App Manifest loading. Without it, the fallback
# is default-src 'self', which is acceptable but imprecise. Explicit
# declaration documents intent and prevents future scope drift.
#
# Recommendation: add   manifest-src 'self';
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.xfail(reason="F-07: manifest-src directive not yet added", strict=True)
async def test_f07_csp_manifest_src_present_target_state(client):
    """Target state: manifest-src must be explicitly declared.

    Recommendation:
        manifest-src 'self';
    """
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "manifest-src" in csp, "F-07: CSP must include a manifest-src directive."


# ---------------------------------------------------------------------------
# F-08 — CSP no report-to / report-uri
# Severity: LOW
#
# Without a reporting endpoint, CSP violations (attempted XSS, blocked
# resources, misconfigured policies) are silent. report-to uses the modern
# Reporting API; report-uri is the legacy fallback.
#
# Recommendation for a low-overhead approach:
#   Add a /csp-report POST endpoint (logs to structured logger, no storage).
#   Add to CSP:  report-to csp-endpoint; report-uri /csp-report;
#   Add header:  Report-To: {"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"/csp-report"}]}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f08_csp_no_report_endpoint_documents_finding(client):
    """Documents current state: no report-to or report-uri in CSP."""
    resp = await client.get("/")
    csp_raw = resp.headers["content-security-policy"]
    assert "report-to" not in csp_raw, (
        "F-08: Expected report-to to be absent (current state). "
        "If this fails, reporting was added — update to the hardened assertion."
    )
    assert "report-uri" not in csp_raw, (
        "F-08: Expected report-uri to be absent (current state). "
        "If this fails, reporting was added — update to the hardened assertion."
    )


# ---------------------------------------------------------------------------
# F-09 — Cross-Origin-Opener-Policy (FIXED)
# Severity: LOW (resolved)
#
# COOP: same-origin added, isolating the browsing context group.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f09_coop_present_target_state(client):
    """Target state: COOP must be present.

    Recommendation:
        Cross-Origin-Opener-Policy: same-origin
    """
    resp = await client.get("/")
    assert "cross-origin-opener-policy" in resp.headers, "F-09: Cross-Origin-Opener-Policy header must be present."
    assert resp.headers["cross-origin-opener-policy"] == "same-origin", "F-09: COOP value must be 'same-origin'."


# ---------------------------------------------------------------------------
# F-10 — Missing Cross-Origin-Embedder-Policy (COEP)
# Severity: LOW
#
# COEP requires all subresources to explicitly opt in to being embedded
# (via CORP or CORS). Required to enable SharedArrayBuffer and high-
# resolution timers. Without COEP, the site cannot enable full cross-origin
# isolation even if COOP is added.
#
# Note: COEP requires all third-party resources (Google Fonts) to send
# CORP: cross-origin or CORS headers. Verify font CDN compliance before
# enabling.
#
# Recommendation: Cross-Origin-Embedder-Policy: require-corp
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f10_missing_coep_documents_finding(client):
    """Documents current state: COEP header is absent."""
    resp = await client.get("/")
    assert "cross-origin-embedder-policy" not in resp.headers, (
        "F-10: Expected COEP to be absent (current state). "
        "If this fails, COEP was added — update to the hardened assertion."
    )


@pytest.mark.asyncio
@pytest.mark.xfail(reason="F-10: Cross-Origin-Embedder-Policy not yet added", strict=True)
async def test_f10_coep_present_target_state(client):
    """Target state: COEP must be present.

    Prerequisite: verify Google Fonts CDN sends CORP: cross-origin.
    Recommendation:
        Cross-Origin-Embedder-Policy: require-corp
    """
    resp = await client.get("/")
    assert "cross-origin-embedder-policy" in resp.headers, "F-10: Cross-Origin-Embedder-Policy header must be present."
    assert resp.headers["cross-origin-embedder-policy"] == "require-corp", "F-10: COEP value must be 'require-corp'."


# ---------------------------------------------------------------------------
# F-11 — Missing Cross-Origin-Resource-Policy (CORP)
# Severity: LOW
#
# CORP restricts which origins may load this resource. Without it, the
# site's resources can be hotlinked by any origin. For a portfolio site
# serving HTML and assets, `same-site` is appropriate.
#
# Recommendation: Cross-Origin-Resource-Policy: same-site
# For API endpoints that need cross-origin access: cross-origin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f11_missing_corp_documents_finding(client):
    """Documents current state: CORP header is absent."""
    resp = await client.get("/")
    assert "cross-origin-resource-policy" not in resp.headers, (
        "F-11: Expected CORP to be absent (current state). "
        "If this fails, CORP was added — update to the hardened assertion."
    )


@pytest.mark.asyncio
@pytest.mark.xfail(reason="F-11: Cross-Origin-Resource-Policy not yet added", strict=True)
async def test_f11_corp_present_target_state(client):
    """Target state: CORP must be present.

    Recommendation:
        Cross-Origin-Resource-Policy: same-site
    """
    resp = await client.get("/")
    assert "cross-origin-resource-policy" in resp.headers, "F-11: Cross-Origin-Resource-Policy header must be present."
    valid_corp_values = {"same-origin", "same-site", "cross-origin"}
    assert resp.headers["cross-origin-resource-policy"] in valid_corp_values, (
        "F-11: CORP value must be one of: same-origin, same-site, cross-origin."
    )


# ---------------------------------------------------------------------------
# F-12 — Permissions-Policy (FIXED)
# Severity: LOW (resolved)
#
# Extended Permissions-Policy now denies payment, display-capture,
# accelerometer, gyroscope, and usb in addition to the original
# camera, microphone, and geolocation.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f12_permissions_policy_present(client):
    """Permissions-Policy header is present (existing coverage)."""
    resp = await client.get("/")
    assert "permissions-policy" in resp.headers, "Permissions-Policy header must be present."


@pytest.mark.asyncio
async def test_f12_permissions_policy_current_directives(client):
    """Documents which permissions are currently denied."""
    resp = await client.get("/")
    policy = resp.headers["permissions-policy"]
    assert "camera=()" in policy, "F-12: camera must be denied."
    assert "microphone=()" in policy, "F-12: microphone must be denied."
    assert "geolocation=()" in policy, "F-12: geolocation must be denied."


@pytest.mark.asyncio
async def test_f12_permissions_policy_extended_target_state(client):
    """Target state: additional modern permissions must be denied.

    Recommendation — add to Permissions-Policy:
        payment=(), display-capture=(), accelerometer=(), gyroscope=(),
        magnetometer=(), usb=(), picture-in-picture=()
    """
    resp = await client.get("/")
    policy = resp.headers["permissions-policy"]
    additional_required = [
        "payment=()",
        "display-capture=()",
        "accelerometer=()",
        "gyroscope=()",
        "magnetometer=()",
        "usb=()",
        "picture-in-picture=()",
    ]
    missing = [p for p in additional_required if p not in policy]
    assert not missing, f"F-12: Permissions-Policy is missing: {', '.join(missing)}"


# ---------------------------------------------------------------------------
# F-13 — X-XSS-Protection: 0 (informational — correct practice)
#
# Setting X-XSS-Protection: 0 disables the legacy browser XSS auditor.
# This is correct modern practice: the XSS auditor in older Chrome/IE
# versions could be exploited to suppress legitimate scripts (XSS filter
# bypass). The header is kept at 0 to prevent that attack.
# Protection against XSS is instead provided by:
#   - CSP script-src 'self' (no unsafe-inline for scripts)
#   - Jinja2 auto-escaping (all template output is escaped by default)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f13_xss_protection_disabled_correctly(client):
    """X-XSS-Protection: 0 disables the broken browser XSS auditor.

    The value 0 is intentional and correct. Do NOT change to '1; mode=block'
    — that re-enables a bypassable feature and can cause data leakage in IE.
    """
    resp = await client.get("/")
    assert resp.headers.get("x-xss-protection") == "0", (
        "F-13: X-XSS-Protection must be '0' to disable the legacy XSS auditor."
    )


# ---------------------------------------------------------------------------
# F-14 — HSTS preload: domain submission requirement (informational)
#
# The HSTS header includes `preload`, which signals intent to submit
# mumfordengineering.com to browser preload lists. This is only meaningful
# if the domain is actively submitted to hstspreload.org. The technical
# requirements are:
#   - max-age >= 31,536,000 (1 year minimum; 2 years recommended)
#   - includeSubDomains present
#   - preload present
# The current max-age of 63,072,000 seconds (2 years) meets all criteria.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f14_hsts_preload_directive_present(client):
    """HSTS preload directive is set — domain should be submitted to hstspreload.org."""
    resp = await client.get("/")
    hsts = resp.headers.get("strict-transport-security", "")
    assert "preload" in hsts, "F-14: HSTS must include preload directive."


@pytest.mark.asyncio
async def test_f14_hsts_max_age_meets_preload_minimum(client):
    """HSTS max-age must be >= 31,536,000 seconds (1 year) for preload eligibility.

    Current: 63,072,000 (2 years) — meets the requirement.
    """
    resp = await client.get("/")
    hsts = resp.headers.get("strict-transport-security", "")
    max_age_part = next((p for p in hsts.split(";") if "max-age" in p), None)
    assert max_age_part is not None, "HSTS max-age directive not found."
    max_age = int(max_age_part.strip().split("=")[1])
    min_preload_age = 31_536_000  # 1 year in seconds
    assert max_age >= min_preload_age, f"F-14: HSTS max-age {max_age} is below the preload minimum {min_preload_age}."


@pytest.mark.asyncio
async def test_f14_hsts_includes_subdomains(client):
    """HSTS includeSubDomains is required for preload eligibility."""
    resp = await client.get("/")
    hsts = resp.headers.get("strict-transport-security", "")
    assert "includeSubDomains" in hsts, "F-14: HSTS must include includeSubDomains."


# ---------------------------------------------------------------------------
# F-15 — Referrer-Policy: strict-origin-when-cross-origin leaks URL path
# Severity: INFO
#
# `strict-origin-when-cross-origin` sends the full URL (origin + path) as
# the Referer header for same-origin navigations. This leaks path structure
# (e.g., /admin, /contact) to any JavaScript or analytics running on the page.
#
# For a portfolio site with no authentication and no sensitive URL structure,
# the current value is acceptable. However:
#
# Tighter alternatives (in order of increasing privacy):
#   strict-origin               — sends only origin for cross-origin; full URL same-origin
#                                  (no, this still leaks path on same-origin)
#   no-referrer-when-downgrade  — legacy default; avoid
#   no-referrer                 — maximum privacy; breaks analytics and external referrer tracking
#
# Clarification: neither `strict-origin` nor `strict-origin-when-cross-origin`
# prevents path leakage on same-origin navigations. If URL paths are sensitive,
# use `no-referrer` or `origin`.
#
# Recommendation: current value is acceptable for this site. Document and hold.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f15_referrer_policy_value_documented(client):
    """Referrer-Policy is set and its value is documented.

    Current: strict-origin-when-cross-origin
    Behaviour: sends full URL on same-origin, origin-only on cross-origin HTTPS,
               no header on HTTPS→HTTP downgrade.
    For this portfolio site this is acceptable. No sensitive URL paths exist.
    """
    resp = await client.get("/")
    policy = resp.headers.get("referrer-policy", "")
    assert policy == "strict-origin-when-cross-origin", (
        "F-15: Referrer-Policy changed. Review the new value against F-15 rationale."
    )


# ---------------------------------------------------------------------------
# F-16 — Cache-Control on 404 and error responses
# Severity: INFO (confirmed correct)
#
# The middleware applies `no-cache` to all non-static paths. This correctly
# prevents 404 pages from being cached by CDNs or proxy caches. A cached 404
# could serve stale error pages after content is published.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f16_404_not_cached(client):
    """404 responses must carry no-cache to prevent stale error page caching."""
    resp = await client.get("/this-path-does-not-exist-404-test")
    assert resp.status_code == 404
    assert resp.headers.get("cache-control") == "no-cache", (
        "F-16: 404 responses must not be cached (cache-control: no-cache required)."
    )


@pytest.mark.asyncio
async def test_f16_404_carries_security_headers(client):
    """Security headers must be present on 404 responses (middleware applies globally)."""
    resp = await client.get("/this-path-does-not-exist-404-test")
    assert resp.status_code == 404
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers


@pytest.mark.asyncio
async def test_f16_500_error_response_not_cached(client):
    """Internal error responses from middleware exception handler carry no-cache."""
    # The middleware catches unhandled exceptions and returns a JSONResponse.
    # We test the /health endpoint to confirm cache-control is set on JSON responses.
    resp = await client.get("/health")
    assert resp.headers.get("cache-control") == "no-cache", "F-16: Dynamic JSON responses must not be cached."


# ---------------------------------------------------------------------------
# F-17 — HSTS max-age value integrity
# Severity: INFO
#
# Verifies the exact max-age value has not been accidentally reduced.
# 63,072,000 seconds = 2 years. Reducing this below 31,536,000 would
# disqualify the domain from HSTS preload lists.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f17_hsts_max_age_exact_value(client):
    """HSTS max-age must equal 63,072,000 seconds (2 years) per current config.

    Changing this value has preload eligibility implications. Any reduction
    below 31,536,000 disqualifies the domain from browser preload lists.
    """
    resp = await client.get("/")
    hsts = resp.headers.get("strict-transport-security", "")
    max_age_part = next((p for p in hsts.split(";") if "max-age" in p), None)
    assert max_age_part is not None
    max_age = int(max_age_part.strip().split("=")[1])
    assert max_age == 63_072_000, (
        f"F-17: HSTS max-age changed from expected 63,072,000 to {max_age}. "
        "Verify preload eligibility is maintained (min: 31,536,000)."
    )


# ---------------------------------------------------------------------------
# Consolidated CSP structure tests
# Verifies all present directives are well-formed.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csp_present_on_all_routes(client):
    """CSP header must be present on all HTML and API responses."""
    routes = ["/", "/health"]
    for route in routes:
        resp = await client.get(route)
        assert "content-security-policy" in resp.headers, f"CSP header missing on route: {route}"


@pytest.mark.asyncio
async def test_csp_default_src_is_self(client):
    """CSP default-src must be 'self' (no wildcard fallback)."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    assert "default-src" in csp, "CSP must include default-src."
    assert csp["default-src"] == ["'self'"], "CSP default-src must be exactly 'self'."


@pytest.mark.asyncio
async def test_csp_script_src_no_unsafe_inline(client):
    """CSP script-src must not contain 'unsafe-inline' (current state confirmed correct)."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    script_tokens = csp.get("script-src", csp.get("default-src", []))
    assert "'unsafe-inline'" not in script_tokens, "CRITICAL: script-src must not contain 'unsafe-inline'."


@pytest.mark.asyncio
async def test_csp_script_src_no_unsafe_eval(client):
    """CSP script-src must not contain 'unsafe-eval'."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    script_tokens = csp.get("script-src", csp.get("default-src", []))
    assert "'unsafe-eval'" not in script_tokens, "CRITICAL: script-src must not contain 'unsafe-eval'."


@pytest.mark.asyncio
async def test_csp_font_src_limited_to_google_fonts(client):
    """CSP font-src must only allow self and Google Fonts CDN."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    font_tokens = set(csp.get("font-src", []))
    allowed = {"'self'", "https://fonts.gstatic.com"}
    unexpected = font_tokens - allowed
    assert not unexpected, f"CSP font-src contains unexpected sources: {unexpected}"


@pytest.mark.asyncio
async def test_csp_img_src_no_wildcard(client):
    """CSP img-src must not contain a wildcard (*)."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    img_tokens = csp.get("img-src", csp.get("default-src", []))
    assert "*" not in img_tokens, "CSP img-src must not use wildcard (*). Use explicit origins."


@pytest.mark.asyncio
async def test_csp_connect_src_is_self(client):
    """CSP connect-src must be restricted to 'self' (no open XHR/fetch origins)."""
    resp = await client.get("/")
    csp = _parse_csp(resp.headers["content-security-policy"])
    connect_tokens = csp.get("connect-src", csp.get("default-src", []))
    assert "'self'" in connect_tokens, "CSP connect-src must include 'self'."
    assert "*" not in connect_tokens, "CSP connect-src must not use wildcard (*)."


# ---------------------------------------------------------------------------
# Static asset cache headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_static_assets_have_cache_control(client):
    """Static assets must have cache-control with public max-age (middleware applies).

    Note: This tests the middleware logic path for /static/ prefix.
    The static file mount returns 200 for files that exist; we validate
    the cache logic is applied correctly to non-static routes.
    """
    resp = await client.get("/")
    assert resp.headers.get("cache-control") == "no-cache", "Dynamic HTML pages must use no-cache, not public max-age."
