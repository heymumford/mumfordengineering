"""
HTTP Method Tampering and Verb Abuse — Security Tests
======================================================
Covers OWASP A05:2021 (Security Misconfiguration) and A01:2021 (Broken Access Control).

Findings Summary (verified against FastAPI 0.135.1 / Starlette 0.52.1):

  MEDIUM  HEAD on GET-only routes returns 405 (RFC 9110 requires HEAD to mirror GET)
  LOW     OPTIONS returns 405 — standard behavior but leaks minimal method info via Allow header
  INFO    TRACE/WebDAV/CONNECT all return 405 or 404 — no server-side reflection
  INFO    Method-override headers (X-HTTP-Method-Override, X-Method-Override) are NOT honored
  INFO    Security headers are present on all 4xx responses — middleware is comprehensive
  INFO    405 response bodies are minimal — no stack traces, no framework version disclosure
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


# ---------------------------------------------------------------------------
# Section 1: Verb abuse on /contact (POST-only endpoint)
# ---------------------------------------------------------------------------


class TestContactVerbAbuse:
    """PUT/DELETE/PATCH/GET on a POST-only endpoint must be rejected with 405."""

    @pytest.mark.asyncio
    async def test_put_contact_returns_405(self, client):
        """PUT /contact must be rejected — not silently accepted or forwarded."""
        resp = await client.put("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_delete_contact_returns_405(self, client):
        """DELETE /contact must be rejected — verb abuse cannot trigger destructive ops."""
        resp = await client.delete("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_patch_contact_returns_405(self, client):
        """PATCH /contact must be rejected."""
        resp = await client.patch("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_get_contact_returns_405(self, client):
        """GET /contact must be rejected — endpoint is write-only."""
        resp = await client.get("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_head_contact_returns_405(self, client):
        """HEAD /contact must be rejected — same routing as other non-POST verbs."""
        resp = await client.head("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_405_allow_header_lists_only_post(self, client):
        """
        Allow header on /contact 405 must list only POST.

        If Allow contained GET or HEAD, it would signal enumerable read paths that
        don't exist, causing misleading scanner output. Minimal disclosure is correct.
        """
        resp = await client.put("/contact")
        allow = resp.headers.get("allow", "")
        assert "POST" in allow
        # GET must not appear — there is no GET handler for /contact
        assert "GET" not in allow

    @pytest.mark.asyncio
    async def test_405_body_does_not_disclose_framework(self, client):
        """
        405 response body must not expose framework version, route list, or stack trace.

        FastAPI default 405 body is {"detail":"Method Not Allowed"} — acceptable.
        Any richer body (e.g., "FastAPI 0.x.y", traceback, route enumeration) would
        constitute information disclosure (OWASP A05).
        """
        resp = await client.put("/contact")
        body = resp.text
        assert "traceback" not in body.lower()
        assert "fastapi" not in body.lower()
        assert "starlette" not in body.lower()
        assert "uvicorn" not in body.lower()
        # Must not dump the full route table
        assert "/static" not in body


# ---------------------------------------------------------------------------
# Section 2: Method-override header attacks
# ---------------------------------------------------------------------------


class TestMethodOverrideHeaders:
    """
    X-HTTP-Method-Override and X-Method-Override are tunneling mechanisms used
    historically by frameworks (Rails, some proxies) to route non-POST verbs
    over POST bodies. FastAPI does not implement them — verify this holds.
    """

    @pytest.mark.asyncio
    async def test_x_http_method_override_not_honored_on_get(self, client):
        """
        GET /contact with X-HTTP-Method-Override: POST must not succeed.

        If honored, an attacker could read the endpoint's POST logic via GET,
        potentially bypassing logging, CSRF tokens, or auth checks tied to method.
        """
        resp = await client.get("/contact", headers={"X-HTTP-Method-Override": "POST"})
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_x_method_override_not_honored_on_get(self, client):
        """GET /contact with X-Method-Override: POST must not succeed."""
        resp = await client.get("/contact", headers={"X-Method-Override": "POST"})
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_x_http_method_override_delete_on_post_does_not_route_to_delete(self, client):
        """
        POST /contact with X-HTTP-Method-Override: DELETE must not trigger a DELETE
        handler. The override header must have no effect on routing.

        Expected: 422 (validation failure from missing form fields) because FastAPI
        processes it as a normal POST with no valid body — not a 405/DELETE dispatch.
        """
        resp = await client.post("/contact", headers={"X-HTTP-Method-Override": "DELETE"})
        # Must not 200 (override succeeded), must not return a 405 for DELETE
        # (which would indicate the override was interpreted then rejected)
        assert resp.status_code in {422, 400}

    @pytest.mark.asyncio
    async def test_x_override_on_health_does_not_bypass_get_constraint(self, client):
        """
        POST /health with X-HTTP-Method-Override: GET must not return health data.
        /health is GET-only; override must not create a read path via POST.
        """
        resp = await client.post("/health", headers={"X-HTTP-Method-Override": "GET"})
        assert resp.status_code in {405, 404}


# ---------------------------------------------------------------------------
# Section 3: OPTIONS method — information disclosure
# ---------------------------------------------------------------------------


class TestOptionsMethod:
    """
    OPTIONS is used by CORS preflight and by attackers to enumerate capabilities.
    FastAPI does not implement a global OPTIONS handler — it returns 405 on user
    routes. The Allow header on 405 is the only method information disclosed.
    """

    @pytest.mark.asyncio
    async def test_options_contact_returns_405(self, client):
        """
        OPTIONS /contact returns 405 (no OPTIONS handler registered).

        This is acceptable — it means no CORS preflight handling either, which is
        correct for a form endpoint that should only be called same-origin.
        """
        resp = await client.options("/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_options_contact_allow_header_minimal(self, client):
        """
        Allow header on OPTIONS /contact must list only POST — not a broad method set.

        A broad Allow (e.g., 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE')
        would indicate a misconfigured server advertising capabilities it doesn't have.
        """
        resp = await client.options("/contact")
        allow = resp.headers.get("allow", "")
        assert allow == "POST", f"Allow header disclosed unexpected methods: {allow!r}"

    @pytest.mark.asyncio
    async def test_options_index_returns_405(self, client):
        """OPTIONS / returns 405 — no global OPTIONS handler."""
        resp = await client.options("/")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_options_index_allow_header_minimal(self, client):
        """Allow header on OPTIONS / must list only GET and HEAD — not an expanded method set."""
        resp = await client.options("/")
        allow = resp.headers.get("allow", "")
        allowed_methods = {m.strip() for m in allow.split(",") if m.strip()}
        # FastAPI may list only HEAD when HEAD is a separate route
        assert allowed_methods <= {"GET", "HEAD"}, f"Allow header disclosed unexpected methods: {allow!r}"
        assert "HEAD" in allowed_methods, "HEAD should be in Allow header"

    @pytest.mark.asyncio
    async def test_options_response_has_no_cors_wildcards(self, client):
        """
        OPTIONS response must not expose Access-Control-Allow-Origin: *.

        A wildcard CORS header on a form endpoint would allow cross-origin POST
        from any domain — a direct CSRF vector.
        """
        resp = await client.options("/contact")
        acao = resp.headers.get("access-control-allow-origin", "")
        assert acao != "*", "Wildcard CORS on /contact is a CSRF vector"

    @pytest.mark.asyncio
    async def test_options_does_not_reflect_origin_header(self, client):
        """
        OPTIONS with an Origin header must not echo it back in Access-Control-Allow-Origin.

        Reflected ACAO without a whitelist check is equivalent to a wildcard.
        """
        resp = await client.options("/contact", headers={"Origin": "https://attacker.example.com"})
        acao = resp.headers.get("access-control-allow-origin", "")
        assert "attacker.example.com" not in acao


# ---------------------------------------------------------------------------
# Section 4: TRACE method — cross-site tracing (XST)
# ---------------------------------------------------------------------------


class TestTraceMethod:
    """
    HTTP TRACE echoes the request back to the client including headers. When
    combined with XSS or CORS misconfigurations, this enables Cross-Site Tracing
    (XST) — an attacker can exfiltrate cookies or auth tokens via a TRACE request
    from a malicious page. TRACE must be rejected.
    """

    @pytest.mark.asyncio
    async def test_trace_index_returns_405(self, client):
        """TRACE / must return 405 — not echo the request body."""
        resp = await client.request("TRACE", "/")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_trace_contact_returns_405(self, client):
        """TRACE /contact must return 405."""
        resp = await client.request("TRACE", "/contact")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_trace_does_not_echo_request_headers(self, client):
        """
        TRACE must not echo the Authorization or Cookie headers back.

        The attack: a TRACE response body containing 'Authorization: Bearer <token>'
        can be read by JavaScript on a malicious page, exfiltrating the token.
        """
        resp = await client.request(
            "TRACE",
            "/",
            headers={"Authorization": "Bearer SENSITIVE_TOKEN_12345"},
        )
        # Either rejected (405) or, if 200, must not echo headers back
        if resp.status_code == 200:
            assert "SENSITIVE_TOKEN_12345" not in resp.text, "TRACE echoed Authorization header — XST vulnerability"

    @pytest.mark.asyncio
    async def test_trace_does_not_echo_cookie(self, client):
        """TRACE must not echo Cookie header — cookie theft vector."""
        resp = await client.request(
            "TRACE",
            "/",
            headers={"Cookie": "session=STOLEN_SESSION_VALUE"},
        )
        if resp.status_code == 200:
            assert "STOLEN_SESSION_VALUE" not in resp.text, "TRACE echoed Cookie header — session hijacking vector"


# ---------------------------------------------------------------------------
# Section 5: HEAD method behavior
# ---------------------------------------------------------------------------


class TestHeadMethod:
    """
    RFC 9110 §9.3.2: HEAD must respond identically to GET except without a body.
    FastAPI/Starlette 0.52.1 does NOT automatically handle HEAD for GET routes —
    HEAD returns 405 on GET-only routes. This is a deviation from RFC 9110.

    FINDING (MEDIUM): HEAD /health and HEAD / return 405 instead of 200.
    - Impact: monitoring tools using HEAD for liveness checks will fail.
    - Fix: register explicit HEAD handlers or upgrade to a Starlette version that
      auto-handles HEAD, or add a middleware that converts HEAD to GET and strips body.
    """

    @pytest.mark.asyncio
    async def test_head_health_returns_200(self, client):
        """
        HEAD /health now returns 200 per RFC 9110 compliance.
        Response body must be empty.
        """
        resp = await client.head("/health")
        assert resp.status_code == 200
        assert resp.content == b"", "HEAD response must not contain a body"

    @pytest.mark.asyncio
    async def test_head_index_returns_200(self, client):
        """HEAD / now returns 200 per RFC 9110 compliance."""
        resp = await client.head("/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_head_health_does_not_leak_body_content(self, client):
        """
        If HEAD /health ever returns 200, it must not have a response body.

        A HEAD response with a body would violate RFC 9110 and leak data.
        """
        resp = await client.head("/health")
        # Whether 405 or 200, body must be empty
        assert resp.content == b"", f"HEAD response must not contain a body, got: {resp.content!r}"

    @pytest.mark.asyncio
    async def test_head_health_returns_200_with_matching_headers(self, client):
        """
        HEAD /health returns 200 and its headers should be consistent with GET.
        """
        get_resp = await client.get("/health")
        head_resp = await client.head("/health")
        assert head_resp.status_code == 200
        # HEAD route explicitly sets media_type to match GET response
        head_ct = head_resp.headers.get("content-type", "").split(";")[0].strip()
        get_ct = get_resp.headers.get("content-type", "").split(";")[0].strip()
        assert head_ct == get_ct

    @pytest.mark.asyncio
    async def test_head_vs_get_health_no_extra_header_disclosure(self, client):
        """
        HEAD /health must not expose headers that GET /health does not.

        A HEAD response that includes a Server header with version info but GET does
        not would constitute differential disclosure.
        """
        get_resp = await client.get("/health")
        head_resp = await client.head("/health")
        get_keys = set(get_resp.headers.keys())
        head_keys = set(head_resp.headers.keys())
        # HEAD-only headers beyond 'allow' (405 artifact) are unexpected
        head_only = head_keys - get_keys - {"allow"}
        assert not head_only, f"HEAD /health disclosed extra headers not in GET: {head_only}"


# ---------------------------------------------------------------------------
# Section 6: WebDAV methods — server capability probe
# ---------------------------------------------------------------------------


class TestWebDavMethods:
    """
    WebDAV methods (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK) are
    used to probe whether a server accidentally exposes WebDAV. A live WebDAV
    endpoint enables filesystem access, file upload, and directory traversal.
    """

    @pytest.mark.asyncio
    async def test_propfind_index_rejected(self, client):
        """PROPFIND / must not return 207 Multi-Status (WebDAV active)."""
        resp = await client.request("PROPFIND", "/")
        assert resp.status_code != 207, "WebDAV PROPFIND returned 207 — filesystem exposure risk"
        assert resp.status_code in {405, 404, 400}

    @pytest.mark.asyncio
    async def test_mkcol_rejected(self, client):
        """MKCOL /testdir must not create a server-side directory."""
        resp = await client.request("MKCOL", "/testdir")
        assert resp.status_code not in {201, 207}, "WebDAV MKCOL created a directory"

    @pytest.mark.asyncio
    async def test_put_to_arbitrary_path_rejected(self, client):
        """
        PUT to an arbitrary path must not write a file to the server.

        WebDAV or misconfigured static file handlers could allow file upload via PUT.
        """
        resp = await client.put("/uploads/malicious.py", content=b"import os; os.system('id')")
        assert resp.status_code not in {200, 201, 204}, "PUT to arbitrary path succeeded — file write risk"

    @pytest.mark.asyncio
    async def test_copy_method_rejected(self, client):
        """COPY method must not be handled."""
        resp = await client.request("COPY", "/", headers={"Destination": "/copied"})
        assert resp.status_code in {405, 404}

    @pytest.mark.asyncio
    async def test_move_method_rejected(self, client):
        """MOVE method must not be handled."""
        resp = await client.request("MOVE", "/", headers={"Destination": "/moved"})
        assert resp.status_code in {405, 404}


# ---------------------------------------------------------------------------
# Section 7: CONNECT method
# ---------------------------------------------------------------------------


class TestConnectMethod:
    """
    HTTP CONNECT is used for proxy tunneling. If handled by the application server,
    an attacker can use it as an open proxy to reach internal services.
    """

    @pytest.mark.asyncio
    async def test_connect_index_rejected(self, client):
        """CONNECT / must not return 200 — open proxy vulnerability."""
        resp = await client.request("CONNECT", "/")
        assert resp.status_code != 200, "CONNECT succeeded — potential open proxy"
        assert resp.status_code in {405, 404, 400}

    @pytest.mark.asyncio
    async def test_connect_does_not_tunnel(self, client):
        """CONNECT to an internal target must not succeed."""
        resp = await client.request("CONNECT", "localhost:5432")
        assert resp.status_code not in {200, 201}, "CONNECT tunneling to internal host succeeded"


# ---------------------------------------------------------------------------
# Section 8: Arbitrary / unknown methods
# ---------------------------------------------------------------------------


class TestArbitraryMethods:
    """
    Arbitrary HTTP methods should be rejected cleanly without crashing the server
    or leaking diagnostic information.
    """

    @pytest.mark.asyncio
    async def test_foobar_method_rejected(self, client):
        """Unknown method FOOBAR must not return 200 or 500."""
        resp = await client.request("FOOBAR", "/")
        assert resp.status_code in {405, 400, 501}

    @pytest.mark.asyncio
    async def test_unknown_method_does_not_crash(self, client):
        """Unknown methods must not cause unhandled 500 errors."""
        resp = await client.request("XYZZY", "/health")
        assert resp.status_code != 500, "Unknown HTTP method caused 500 — server crash risk"

    @pytest.mark.asyncio
    async def test_unknown_method_body_safe(self, client):
        """Unknown method response must not contain a traceback or internal path."""
        resp = await client.request("HACK", "/")
        body = resp.text.lower()
        assert "traceback" not in body
        assert "/users/" not in body  # no filesystem paths


# ---------------------------------------------------------------------------
# Section 9: Security headers present on all error responses
# ---------------------------------------------------------------------------


class TestSecurityHeadersOnErrorResponses:
    """
    Security headers must be present on 4xx responses, not just 2xx.

    An attacker probing with invalid methods might bypass security headers if the
    middleware only applies them to successful responses. The add_security_headers
    middleware wraps call_next, so it should cover all paths — this verifies it.
    """

    @pytest.mark.asyncio
    async def test_405_has_x_frame_options(self, client):
        """X-Frame-Options must be present on 405 responses."""
        resp = await client.put("/contact")
        assert resp.headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_405_has_csp(self, client):
        """Content-Security-Policy must be present on 405 responses."""
        resp = await client.put("/contact")
        assert resp.headers.get("content-security-policy"), "CSP missing on 405"

    @pytest.mark.asyncio
    async def test_405_has_hsts(self, client):
        """Strict-Transport-Security must be present on 405 responses."""
        resp = await client.put("/contact")
        hsts = resp.headers.get("strict-transport-security", "")
        assert "max-age=" in hsts

    @pytest.mark.asyncio
    async def test_405_has_x_content_type_options(self, client):
        """X-Content-Type-Options must be present on 405 responses."""
        resp = await client.put("/contact")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    @pytest.mark.asyncio
    async def test_404_has_security_headers(self, client):
        """All security headers must be present on 404 responses too."""
        resp = await client.get("/nonexistent-definitely-not-a-route")
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("content-security-policy")

    @pytest.mark.asyncio
    async def test_no_server_header_disclosure(self, client):
        """
        Server header must not disclose framework version.

        FastAPI/Uvicorn default does not set a Server header — verify this is
        not accidentally re-introduced (e.g., by middleware or proxy config).
        """
        resp = await client.get("/health")
        server = resp.headers.get("server", "")
        # Acceptable: empty or generic. Not acceptable: 'uvicorn/0.x.y', 'FastAPI'.
        assert "fastapi" not in server.lower()
        assert "uvicorn" not in server.lower()
        assert "starlette" not in server.lower()


# ---------------------------------------------------------------------------
# Section 10: Method override via query string
# ---------------------------------------------------------------------------


class TestQueryStringMethodOverride:
    """
    Some frameworks honor _method query parameters (e.g., Rails, Laravel).
    FastAPI does not — verify this holds so verb tunneling via query string is blocked.
    """

    @pytest.mark.asyncio
    async def test_get_with_method_override_query_param_rejected(self, client):
        """GET /contact?_method=POST must not route to the POST handler."""
        resp = await client.get("/contact", params={"_method": "POST"})
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_post_with_method_delete_query_param_does_not_dispatch_delete(self, client):
        """POST /contact?_method=DELETE must be processed as POST (validation fail), not DELETE."""
        resp = await client.post("/contact", params={"_method": "DELETE"})
        # Processed as POST with missing form fields → 422, not routed as DELETE
        assert resp.status_code in {422, 400}
        assert resp.status_code != 405  # 405 would indicate DELETE routing attempt
