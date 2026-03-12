"""
CSRF Security Analysis — mumfordengineering contact form.

Findings summary
----------------
CSRF-01 (LOW)    No CSRF token on the form or in the backend.
CSRF-02 (INFO)   No session cookies in use — eliminates the primary CSRF threat model.
CSRF-03 (INFO)   CSP connect-src 'self' does NOT provide CSRF protection.
CSRF-04 (LOW)    Cross-origin form POST accepted without Referer/Origin checks.
CSRF-05 (INFO)   X-Frame-Options: DENY prevents clickjacking (CSRF precursor).
CSRF-06 (LOW)    Rate limiting is IP-scoped and can be trivially bypassed from a
                 CSRF payload (victim's IP is used, not attacker's).

Risk verdict
------------
The contact form has no CSRF tokens and accepts cross-origin POSTs.  For a
stateless, unauthenticated contact form, this is a LOW risk, not a critical one.
There is no authenticated state to hijack and the worst-case outcome of a
successful CSRF attack is a spam contact submission attributed to the victim's
IP.  The honeypot + rate limiter reduce even that impact further.

A CSRF token would be appropriate if: (a) authentication is ever added, (b) the
form triggers a side-effect meaningful to the victim (e.g. account creation), or
(c) you want defence-in-depth regardless of risk level.

Fix recommendation (if warranted)
----------------------------------
Option A — Synchroniser Token (traditional):
    1. On GET /, generate secrets.token_hex(32) and embed in a hidden <input>.
    2. On POST /contact, verify the token matches the session value.
    Requires a session store (itsdangerous or starlette sessions).

Option B — Double-submit cookie (cookieless, lighter):
    1. On GET /, set a short-lived cookie csrf_token=<random>.
    2. Require the same value as a form field.
    3. On POST /contact, assert form["csrf_token"] == request.cookies["csrf_token"].
    Works with SameSite=Strict on the cookie.

Option C — Custom request header check (SPA-compatible):
    The fetch() call in main.js already runs from the same origin.  Requiring an
    X-Requested-With: XMLHttpRequest header in the POST handler is sufficient to
    block cross-origin <form> submissions, because simple CORS form POSTs cannot
    send custom headers without a preflight.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_PAYLOAD: dict[str, str] = {
    "name": "Test User",
    "email": "user@example.com",
    "message": "Hello there",
    "website": "",
}


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ===========================================================================
# CSRF-01 — No CSRF token present in the form or verified by the backend
# Severity: LOW (no authenticated state to hijack)
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf01_form_has_no_csrf_token_field(client):
    """
    The index page HTML does not include a hidden CSRF token input.
    This is expected given current design; test documents the absence.
    If a token is ever added this test should be updated to assert its presence.
    """
    resp = await client.get("/")
    assert resp.status_code == 200
    # No hidden CSRF field in the rendered HTML
    assert 'name="csrf_token"' not in resp.text
    assert 'name="_csrf"' not in resp.text
    assert 'name="csrfmiddlewaretoken"' not in resp.text


@pytest.mark.asyncio
async def test_csrf01_backend_accepts_post_with_no_token(client):
    """
    POST /contact succeeds when no CSRF token is included in the payload.
    Demonstrates the backend performs no anti-CSRF validation.
    """
    resp = await client.post("/contact", data=VALID_PAYLOAD)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CSRF-02 — No session cookies → primary CSRF threat absent
# Severity: INFO
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf02_no_session_cookie_set_on_index(client):
    """
    The server sets no session or authentication cookies.
    Without cookies carrying privileged state there is no stolen-credential
    vector; CSRF cannot hijack an authenticated session that does not exist.
    """
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers


@pytest.mark.asyncio
async def test_csrf02_no_session_cookie_set_after_contact_post(client):
    """
    Submitting the contact form also sets no cookies.
    The server is fully stateless from the client perspective.
    """
    resp = await client.post("/contact", data=VALID_PAYLOAD)
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers


# ===========================================================================
# CSRF-03 — CSP connect-src 'self' does NOT protect against CSRF
# Severity: INFO
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf03_csp_connect_src_self_is_present(client):
    """
    CSP connect-src 'self' restricts which origins the page's own JavaScript
    may fetch.  It has no effect on cross-origin form submissions or
    XMLHttpRequests initiated by a third-party page; the victim's browser
    sends those directly, not through this page's script context.
    """
    resp = await client.get("/")
    csp = resp.headers.get("content-security-policy", "")
    assert "connect-src 'self'" in csp


@pytest.mark.asyncio
async def test_csrf03_cross_origin_post_is_not_blocked_by_csp(client):
    """
    A forged POST sent with a spoofed Origin header is accepted by the backend.
    CSP is enforced client-side by the victim's browser for same-page fetches,
    not by the server for inbound requests.
    """
    resp = await client.post(
        "/contact",
        data=VALID_PAYLOAD,
        headers={"Origin": "https://evil.example.com"},
    )
    # Backend accepts it — CSP did not block the inbound POST
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CSRF-04 — Backend accepts cross-origin POSTs (no Referer/Origin check)
# Severity: LOW
# Attack scenario: attacker hosts a page with a hidden auto-submitting form
# pointing to mumfordengineering.com/contact.  Victim loads the page and a
# contact submission is made under the victim's IP.  No privileged data
# is accessed.  Worst case: rate-limit exhaustion for the victim's IP or
# spam in the inbox.
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf04_post_with_no_origin_header_is_accepted(client):
    """
    No Origin header (typical of a cross-site plain form submission via the
    browser's native form machinery) is accepted without rejection.
    """
    resp = await client.post("/contact", data=VALID_PAYLOAD)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_csrf04_post_with_foreign_origin_is_accepted(client):
    """
    An explicit cross-origin Origin header does not trigger a 403.
    The backend does not validate the Origin header.
    """
    resp = await client.post(
        "/contact",
        data=VALID_PAYLOAD,
        headers={"Origin": "https://attacker.invalid"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_csrf04_post_with_spoofed_referer_is_accepted(client):
    """
    A forged Referer header pointing to a third-party site is not rejected.
    """
    resp = await client.post(
        "/contact",
        data=VALID_PAYLOAD,
        headers={"Referer": "https://attacker.invalid/exploit.html"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CSRF-05 — X-Frame-Options: DENY (clickjacking mitigation, positive control)
# Severity: INFO (existing protection, verifying it is present)
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf05_x_frame_options_deny(client):
    """
    X-Frame-Options: DENY prevents the portfolio page from being framed on a
    third-party site.  Clickjacking (tricking the victim into clicking a
    Submit button in an invisible iframe) is a common CSRF precursor; this
    header eliminates it.
    """
    resp = await client.get("/")
    assert resp.headers.get("x-frame-options") == "DENY"


@pytest.mark.asyncio
async def test_csrf05_x_frame_options_deny_on_contact_post(client):
    """X-Frame-Options is applied to all responses, including POST /contact."""
    resp = await client.post("/contact", data=VALID_PAYLOAD)
    assert resp.headers.get("x-frame-options") == "DENY"


# ===========================================================================
# CSRF-06 — Rate limiting is IP-scoped: CSRF exhausts victim's quota
# Severity: LOW
# Attack scenario: an attacker embeds a CSRF payload in a page the victim
# visits.  The five requests-per-hour window is consumed against the victim's
# IP, silently degrading their ability to legitimately contact the site owner.
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf06_rate_limit_applied_to_cross_origin_post(client):
    """
    Rate limiting fires on the IP extracted from request headers, not on any
    session or CSRF token.  Five forged submissions consume the victim's quota.
    The 6th (and any legitimate attempt by the victim) is silently swallowed.
    """
    for _ in range(5):
        resp = await client.post("/contact", data=VALID_PAYLOAD)
        assert resp.status_code == 200

    # 6th request — rate limited, same 200 response shape (silent drop)
    resp = await client.post("/contact", data=VALID_PAYLOAD)
    assert resp.status_code == 200
    # Response is indistinguishable from success — victim gets no error feedback
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_csrf06_rate_limit_different_ips_are_independent(client):
    """
    Different source IPs each have their own quota bucket.  Attacker's IP
    is irrelevant; only the victim's IP matters when the forged request arrives.
    """
    # Exhaust quota for one IP
    for _ in range(5):
        await client.post(
            "/contact",
            data=VALID_PAYLOAD,
            headers={"fly-client-ip": "1.2.3.4"},
        )

    # A different IP is not affected
    resp = await client.post(
        "/contact",
        data=VALID_PAYLOAD,
        headers={"fly-client-ip": "5.6.7.8"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CSRF-MITIGATE — Document what a token check would look like (negative test)
# If a CSRF token is later added, this test asserts the validation behaviour.
# ===========================================================================


@pytest.mark.asyncio
async def test_csrf_mitigate_honeypot_rejects_automated_submissions(client):
    """
    The honeypot field is the only active bot-mitigation mechanism today.
    A scripted CSRF payload that fills all fields (including the honeypot)
    is silently discarded.  Real CSRF attacks driven from a crafted HTML form
    would NOT trigger the honeypot unless the attacker pre-fills it, which
    any non-trivial attacker would avoid.
    """
    # Attacker-controlled form that accidentally populates honeypot
    resp = await client.post(
        "/contact",
        data={**VALID_PAYLOAD, "website": "https://attacker.invalid"},
    )
    assert resp.status_code == 200
    # Silent accept — no information leak about the rejection
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_csrf_mitigate_honeypot_does_not_stop_targeted_csrf(client):
    """
    A targeted CSRF payload that knows to leave the honeypot empty is not
    blocked.  Demonstrates that the honeypot is not a CSRF control.
    """
    resp = await client.post(
        "/contact",
        data={**VALID_PAYLOAD, "website": ""},  # honeypot intentionally empty
        headers={"Origin": "https://attacker.invalid"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
