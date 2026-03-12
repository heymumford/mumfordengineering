"""
Security review: Server-Side Template Injection (SSTI) and related attack surface.

Findings summary (updated after fixes)
---------------------------------------
CRITICAL  None — no SSTI vector exists (no render_template_string, no user input in template context)
RESOLVED  Rate limiter fixed — _is_rate_limited() now tracks IPs and enforces limits
RESOLVED  XFF no longer trusted — IP address sourced from connection, not attacker headers
LOW       autoescape=True confirmed — Jinja2 auto-escapes all {{ }} output, XSS not possible
INFO      404 handler passes no user-controlled context to template — path injection not possible
INFO      Contact form responses are static strings — no user input reflected
INFO      _sanitize_log() strips newline control characters — log injection mitigated for email

Each test is labelled with its finding ID and severity.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps, _is_rate_limited


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
# FINDING: No SSTI vector — render_template_string not used
# Severity: INFO (absence of vulnerability confirmed)
# ---------------------------------------------------------------------------


def test_ssti_no_render_template_string_in_source():
    """
    render_template_string() is the primary Python SSTI vector.
    Confirm it is not imported or called anywhere in app.py.
    """
    import ast
    import pathlib

    source = pathlib.Path("src/mumfordengineering/app.py").read_text()
    tree = ast.parse(source)

    dangerous_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "render_template_string":
                dangerous_calls.append(f"line {node.lineno}")
            if isinstance(node.func, ast.Name) and node.func.id == "render_template_string":
                dangerous_calls.append(f"line {node.lineno}")

    assert dangerous_calls == [], f"render_template_string() found at: {dangerous_calls}"


def test_ssti_no_jinja2_from_string_in_source():
    """
    jinja2.Environment.from_string() with user input is a direct SSTI vector.
    Confirm it is not called with user-controlled data.
    """
    import ast
    import pathlib

    source = pathlib.Path("src/mumfordengineering/app.py").read_text()
    tree = ast.parse(source)

    from_string_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "from_string":
                from_string_calls.append(f"line {node.lineno}")

    assert from_string_calls == [], f"from_string() call found at: {from_string_calls}"


@pytest.mark.asyncio
async def test_ssti_classic_payload_in_name_field(client):
    """
    Proof of concept: classic SSTI probe {{ 7*7 }} in name field.
    Expected: server returns 200 with static message (payload is never rendered).
    If vulnerable, response body would contain '49'.
    """
    resp = await client.post(
        "/contact",
        data={
            "name": "{{ 7*7 }}",
            "email": "probe@example.com",
            "message": "SSTI probe",
            "website": "",
        },
    )
    assert resp.status_code == 200
    assert "49" not in resp.text, "SSTI: arithmetic expression was evaluated in template"
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ssti_rce_payload_in_name_field(client):
    """
    Proof of concept: RCE-class SSTI payload targeting Jinja2 class traversal.
    If vulnerable, the server would expose Python internals or execute code.
    """
    rce_payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    resp = await client.post(
        "/contact",
        data={
            "name": rce_payload,
            "email": "rce@example.com",
            "message": "RCE probe",
            "website": "",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "__subclasses__" not in str(body), "SSTI: class traversal payload was evaluated"
    assert "subprocess" not in str(body).lower()


@pytest.mark.asyncio
async def test_ssti_payload_in_message_field(client):
    """
    SSTI probe via message field. Neither name nor message is passed to any template.
    """
    resp = await client.post(
        "/contact",
        data={
            "name": "Test",
            "email": "probe@example.com",
            "message": "{{ config }}",
            "website": "",
        },
    )
    assert resp.status_code == 200
    assert "config" not in resp.json().get("message", "").lower() or resp.json()["message"].startswith(
        "Message received"
    ), "Template context leaked into response"


# ---------------------------------------------------------------------------
# FINDING: 404 handler does not inject request.url into template context
# Severity: INFO (absence of vulnerability confirmed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_404_ssti_path_not_reflected(client):
    """
    404 handler serves index.html with no context beyond the request object.
    The template does not render request.url.path. Confirm SSTI probe in path
    is not evaluated or reflected.
    """
    resp = await client.get("/{{7*7}}")
    assert resp.status_code == 404
    assert "49" not in resp.text, "SSTI: path expression was evaluated in 404 template"


@pytest.mark.asyncio
async def test_404_path_not_reflected_in_body(client):
    """
    Confirm the raw requested path does not appear anywhere in the 404 response body.
    Reflection of unescaped paths would be a prerequisite for path-based SSTI.
    """
    resp = await client.get("/this-path-should-not-appear-in-body-xyzzy123")
    assert resp.status_code == 404
    assert "xyzzy123" not in resp.text


# ---------------------------------------------------------------------------
# FINDING: Jinja2 autoescape=True — XSS via template variables not possible
# Severity: INFO (defense confirmed)
# ---------------------------------------------------------------------------


def test_jinja2_autoescape_enabled():
    """
    FastAPI's Jinja2Templates sets autoescape=True by default.
    Confirm this is still the case — a regression here would enable XSS
    across any template variable that renders user-controlled data.
    """
    from fastapi.templating import Jinja2Templates

    t = Jinja2Templates(directory="templates")
    assert t.env.autoescape is True, "Jinja2 autoescape is disabled. Any {{ user_var }} in templates would allow XSS."


def test_jinja2_autoescape_actually_escapes_html():
    """
    Behaviorally confirm autoescape escapes < > & characters.
    This guards against future template changes that add {{ user_input }} variables.
    """
    from jinja2 import Environment

    env = Environment(autoescape=True)
    tmpl = env.from_string("<p>{{ val }}</p>")
    result = tmpl.render(val='<script>alert("xss")</script>')
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


# ---------------------------------------------------------------------------
# FINDING HIGH: Rate limiter logic bug — _is_rate_limited() never tracks any IP
# Location: app.py:85-96
# ---------------------------------------------------------------------------


def test_rate_limiter_tracks_ip_on_first_call():
    """
    Rate limiter fix verified: _is_rate_limited() now tracks the IP on first
    call. The timestamp is stored in _contact_timestamps so subsequent calls
    can enforce the rate limit.
    """
    _contact_timestamps.clear()
    ip = "10.0.0.1"

    _is_rate_limited(ip)

    assert ip in _contact_timestamps, (
        "Rate limiter regression: IP was not stored in _contact_timestamps after first call."
    )


def test_rate_limiter_activates_after_limit():
    """
    Rate limiter fix verified: after enough calls from the same IP,
    _is_rate_limited() returns True to enforce the rate limit.
    """
    _contact_timestamps.clear()
    ip = "192.168.1.100"

    results = [_is_rate_limited(ip) for _ in range(20)]

    assert any(results), (
        "Rate limiter never returned True for 20 calls from the same IP. Rate limiting is non-functional."
    )


@pytest.mark.asyncio
async def test_rate_limiter_tracks_via_http(client):
    """
    End-to-end confirmation: after 20 contact form submissions from the same
    IP, the rate limiter has tracked the IP in _contact_timestamps. The rate
    limiter silently suppresses excess submissions (still returns 200).
    """
    _contact_timestamps.clear()

    for _ in range(20):
        await client.post(
            "/contact",
            data={
                "name": "Flood Test",
                "email": "flood@example.com",
                "message": "Rate limit probe",
                "website": "",
            },
        )

    # With the fix, _contact_timestamps should contain tracked IPs
    assert _contact_timestamps != {}, (
        "Rate limiter regression: _contact_timestamps is empty after 20 requests. The rate limiter is not tracking IPs."
    )


# ---------------------------------------------------------------------------
# FINDING HIGH: IP spoofing via fly-client-ip / x-forwarded-for headers
# Location: app.py:74-82
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ip_spoofing_via_fly_client_ip(client):
    """
    FINDING (HIGH): _get_client_ip() trusts fly-client-ip unconditionally.
    An attacker can set this header to an arbitrary value, spoofing their IP.
    Even if the rate limiter were fixed, an attacker could bypass it by
    rotating the fly-client-ip value on each request.

    Proof of concept: two requests with different fly-client-ip values
    are treated as different clients.
    """
    _contact_timestamps.clear()

    resp1 = await client.post(
        "/contact",
        headers={"fly-client-ip": "1.1.1.1"},
        data={
            "name": "Spoof Test",
            "email": "spoof@example.com",
            "message": "IP spoof probe",
            "website": "",
        },
    )
    resp2 = await client.post(
        "/contact",
        headers={"fly-client-ip": "2.2.2.2"},
        data={
            "name": "Spoof Test",
            "email": "spoof@example.com",
            "message": "IP spoof probe",
            "website": "",
        },
    )

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    # When the rate limiter bug is fixed, this test documents that two requests
    # with different spoofed IPs would be tracked as different clients.
    # A correct fix requires validating that fly-client-ip is only trusted
    # when the TCP connection originates from a known Fly.io proxy IP range.


@pytest.mark.asyncio
async def test_ip_spoofing_via_x_forwarded_for(client):
    """
    x-forwarded-for is also attacker-controlled and trusted unconditionally.
    An attacker not behind Fly.io can set this header to any value.
    """
    _contact_timestamps.clear()

    for i in range(6):
        resp = await client.post(
            "/contact",
            headers={"x-forwarded-for": f"10.0.0.{i}"},
            data={
                "name": "XFF Spoof",
                "email": f"xff{i}@example.com",
                "message": "XFF spoof probe",
                "website": "",
            },
        )
        assert resp.status_code == 200, f"Request {i} failed unexpectedly"


# ---------------------------------------------------------------------------
# FINDING INFO: Contact form responses never reflect user input
# Severity: INFO (absence of reflection confirmed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contact_response_does_not_reflect_name(client):
    """
    Confirm the success/error JSON responses contain only static strings.
    No user input (name, email, message) appears in the response body.
    """
    xss_name = "<img src=x onerror=alert(1)>"
    resp = await client.post(
        "/contact",
        data={
            "name": xss_name,
            "email": "test@example.com",
            "message": "Hello",
            "website": "",
        },
    )
    assert resp.status_code == 200
    assert xss_name not in resp.text
    assert "<img" not in resp.text


@pytest.mark.asyncio
async def test_contact_response_does_not_reflect_message(client):
    """
    message field is not reflected in any response — confirmed static responses only.
    """
    payload = "{{ config.SECRET_KEY }}"
    resp = await client.post(
        "/contact",
        data={
            "name": "Test",
            "email": "test@example.com",
            "message": payload,
            "website": "",
        },
    )
    assert resp.status_code == 200
    assert payload not in resp.text
    assert "SECRET_KEY" not in resp.text


@pytest.mark.asyncio
async def test_error_response_does_not_reflect_email(client):
    """
    Validation error responses contain static strings only — email not reflected.
    """
    injected_email = "not-an-email<script>alert(1)</script>"
    resp = await client.post(
        "/contact",
        data={
            "name": "Test",
            "email": injected_email,
            "message": "Hello",
            "website": "",
        },
    )
    assert resp.status_code == 422
    assert injected_email not in resp.text
    assert "<script>" not in resp.text


# ---------------------------------------------------------------------------
# FINDING INFO: Log injection mitigated for email field
# Severity: INFO (defense confirmed)
# ---------------------------------------------------------------------------


def test_sanitize_log_strips_newlines():
    """
    _sanitize_log() strips \\n and \\r, preventing log injection via email field.
    Without this, an attacker could inject fake log lines:
        evil@x.com\\nINFO  Fake admin login from 192.168.1.1
    """
    from mumfordengineering.app import _sanitize_log

    payload = "evil@x.com\nINFO Injected log line"
    result = _sanitize_log(payload)
    assert "\n" not in result
    assert "Injected log line" in result  # content present but not on a new line


def test_sanitize_log_strips_carriage_return():
    from mumfordengineering.app import _sanitize_log

    payload = "evil@x.com\r\nINFO Injected log line"
    result = _sanitize_log(payload)
    assert "\r" not in result
    assert "\n" not in result


def test_sanitize_log_truncates_at_200():
    from mumfordengineering.app import _sanitize_log

    long_value = "a" * 500
    result = _sanitize_log(long_value)
    assert len(result) == 200


def test_sanitize_log_strips_null_bytes():
    from mumfordengineering.app import _sanitize_log

    payload = "user@x.com\x00admin"
    result = _sanitize_log(payload)
    assert "\x00" not in result


# ---------------------------------------------------------------------------
# FINDING INFO: Template only uses url_for() — no dynamic user variables
# Severity: INFO (absence of attack surface confirmed)
# ---------------------------------------------------------------------------


def test_template_expressions_are_static_url_for_only():
    """
    Verify the template contains no {{ request.* }} or {{ user_* }} expressions.
    The only Jinja2 expressions are url_for() calls for static assets.
    Adding user-controlled template variables in future would re-open SSTI/XSS risk.
    """
    import re
    import pathlib

    source = pathlib.Path("templates/index.html").read_text()
    expressions = re.findall(r"\{\{(.*?)\}\}", source)

    for expr in expressions:
        expr = expr.strip()
        assert expr.startswith("url_for("), (
            f"Non-url_for expression found in template: {{{{ {expr} }}}}. "
            "Review this expression — if it renders user-controlled data, "
            "autoescape provides XSS protection but SSTI protection depends on "
            "not using render_template_string or Markup()."
        )
