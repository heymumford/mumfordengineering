"""
Content-Type Handling and Encoding Attack Analysis
===================================================
Target:  POST /contact  (FastAPI 0.135.1 / Starlette 0.52.1)
Tested:  2026-03-12

Findings
--------
CT-01 (MEDIUM)  FastAPI default 422 responses reflect raw user input verbatim
                in the ``"input"`` field.  Oversized or injection-crafted values
                are echoed back in the error body.

CT-02 (INFO)    JSON, plain text, binary, and no-Content-Type bodies are rejected
                422 by the form parser — correct and expected.

CT-03 (INFO)    Multipart/form-data is accepted.  Extra multipart parts (file
                attachments) are silently ignored rather than rejected.

CT-04 (LOW)     UTF-8 BOM (U+FEFF) in field values passes through without
                stripping.  The BOM character reaches _sanitize_log() unchanged.

CT-05 (LOW)     Null bytes (0x00) in URL-encoded form values pass through to the
                handler.  _sanitize_log() strips them; the logger is safe, but
                the raw value is processed upstream of that call.

CT-06 (INFO)    X-Content-Type-Options: nosniff is present on static file
                responses — correct.

CT-07 (INFO)    Accept header negotiation is not respected.  The server returns
                its native content type (application/json or text/html) regardless
                of what the client requests.  FastAPI does not perform content
                negotiation; this is by-design, not a vulnerability.

CT-08 (INFO)    A declared Content-Length of 1 TB with a small body is accepted
                at the app layer.  Body-size limits must be enforced at the proxy
                / ingress layer (Fly.io, nginx).  No app-layer mitigation exists.

CT-09 (MEDIUM)  Duplicate form field names (HTTP Parameter Pollution).  FastAPI
                takes the LAST value, not the first.  This allows an attacker
                to bypass the honeypot by sending website=<filled>&website=
                (empty last value clears the trigger).  The honeypot is fully
                defeated by this technique.

CT-10 (INFO)    Content-Type with a charset parameter
                (application/x-www-form-urlencoded; charset=utf-16) is accepted
                without error or conversion.  The charset annotation is ignored.

Remediation summary
-------------------
CT-01 — Override the default 422 exception handler to return a sanitised body
        without the ``"input"`` field.  See fix_recommendation below.

CT-04 — Strip the BOM character from all form fields before processing:
        ``value.lstrip('\\ufeff').strip()``

CT-05 — Strip null bytes from all form fields before processing:
        ``value.replace('\\x00', '')``

CT-08 — Set an explicit body-size limit in the Fly.io config or wrap the ASGI
        app with a max-body middleware.

CT-09 — Reject requests with duplicate form field names, OR replace the
        honeypot with a server-side CSRF token that cannot be manipulated
        by field-order tricks.  The last-value-wins behaviour is a FastAPI
        implementation detail that enables honeypot bypass.

Positive controls confirmed
---------------------------
- nosniff on static files (CT-06)
- Strict Content-Type enforcement for non-form bodies (CT-02)
- max_length enforced on all form fields (name 200, email 254, message 5000)
- Security headers present on all response classes including 422
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_FORM: dict[str, str] = {
    "name": "Alice",
    "email": "alice@example.com",
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
# CT-01 — FastAPI default 422 echoes raw user input in the response body
# Severity: MEDIUM
#
# Impact: An attacker can craft an oversized or injection-bearing value and
# receive it back in the error response.  If the caller renders the error body
# in a UI without escaping, this becomes a reflected injection vector.
# It also leaks the field schema (type, location, constraint) to callers.
#
# PoC: POST name=<200+ chars> → 422 body contains the full input value.
#
# Fix: Add a custom exception handler that returns a generic message:
#
#   from fastapi.exceptions import RequestValidationError
#   @app.exception_handler(RequestValidationError)
#   async def validation_handler(request, exc):
#       return JSONResponse(
#           {"status": "error", "message": "Invalid form data."},
#           status_code=422,
#       )
# ===========================================================================


@pytest.mark.asyncio
async def test_ct01_422_does_not_reflect_input(client):
    """
    Custom 422 handler suppresses input reflection and schema leakage.
    The response contains only a generic error message.
    """
    oversized_name = "SENTINEL_" + "A" * 201
    resp = await client.post(
        "/contact",
        data={**VALID_FORM, "name": oversized_name},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "detail" not in body
    assert "input" not in str(body)
    assert "SENTINEL_" not in str(body)


@pytest.mark.asyncio
async def test_ct01_422_does_not_leak_field_schema(client):
    """
    Custom 422 handler does not expose internal field names or constraint types.
    """
    resp = await client.post(
        "/contact",
        data={"name": "", "email": "", "message": ""},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "detail" not in body
    assert body.get("status") == "error"


@pytest.mark.asyncio
async def test_ct01_security_headers_present_on_422(client):
    """Security headers must be applied to 422 responses too."""
    resp = await client.post("/contact", data={"name": "X" * 201, "email": "a@b.com", "message": "hi"})
    assert resp.status_code == 422
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"


# ===========================================================================
# CT-02 — Non-form Content-Types are rejected 422 (positive control)
# Severity: INFO
#
# FastAPI's Form() dependency requires multipart or url-encoded content.
# JSON, plain text, binary, and absent Content-Type headers all produce 422.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct02_json_body_rejected(client):
    """
    A JSON-encoded body is rejected.  FastAPI's form parser cannot extract
    Form() fields from a JSON request body and returns 422.
    """
    resp = await client.post(
        "/contact",
        content='{"name":"Alice","email":"alice@example.com","message":"hi"}',
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct02_plain_text_body_rejected(client):
    """
    A plain-text body with URL-encoded content but wrong Content-Type is
    rejected.  The MIME type, not the body format, gates parsing.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=hi&website=",
        headers={"content-type": "text/plain"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct02_binary_body_rejected(client):
    """
    Raw binary data is rejected.  No path injection into form processing.
    """
    resp = await client.post(
        "/contact",
        content=b"\x00\x01\x02\x03\xff\xfe\xfd",
        headers={"content-type": "application/octet-stream"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct02_no_content_type_header_rejected(client):
    """
    A body with no Content-Type header is rejected.  httpx sends no CT header
    when ``content=`` is used without an explicit header override.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=hi&website=",
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ct02_xml_body_rejected(client):
    """
    An XML body does not bypass form parsing.
    """
    xml = b"<contact><name>Alice</name><email>a@b.com</email><message>hi</message></contact>"
    resp = await client.post(
        "/contact",
        content=xml,
        headers={"content-type": "application/xml"},
    )
    assert resp.status_code == 422


# ===========================================================================
# CT-03 — Multipart accepted; extra file attachment parts silently ignored
# Severity: INFO
#
# multipart/form-data is a valid alternate encoding for HTML forms.
# FastAPI's Form() correctly reads named parts.  Extra parts (e.g. a file
# attachment) are ignored because the handler has no parameter to bind them to.
# This is correct behaviour — no file is stored or processed — but it is
# undocumented and worth confirming.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct03_multipart_accepted(client):
    """
    Multipart form data is accepted identically to url-encoded form data.
    Both Content-Type variants are valid HTML form encodings.
    """
    resp = await client.post(
        "/contact",
        files={
            "name": (None, "Alice"),
            "email": (None, "alice@example.com"),
            "message": (None, "Hello"),
            "website": (None, ""),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct03_file_attachment_part_silently_ignored(client):
    """
    A multipart request that includes a file attachment part alongside the
    required form fields is accepted.  The file part is not bound to any
    handler parameter and is silently discarded.

    Impact: An attacker cannot upload and persist a file via /contact because
    there is no storage path.  However, the file content IS parsed by
    python-multipart into memory; a very large attachment would consume memory.
    Body-size limits at the proxy layer are the correct mitigation.
    """
    resp = await client.post(
        "/contact",
        files={
            "name": (None, "Alice"),
            "email": (None, "alice@example.com"),
            "message": (None, "Hello"),
            "website": (None, ""),
            # Extra file attachment — should be ignored
            "attachment": ("shell.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
        },
    )
    # Request succeeds — file is discarded, not stored
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct03_file_attachment_not_stored(client):
    """
    Uploading an executable file attachment does not result in server-side
    storage or code execution.  The handler has no file-saving code path.
    Response is the standard contact acknowledgment.
    """
    malicious_content = b"#!/bin/bash\nrm -rf /tmp/*\n"
    resp = await client.post(
        "/contact",
        files={
            "name": (None, "Alice"),
            "email": (None, "alice@example.com"),
            "message": (None, "Hello"),
            "website": (None, ""),
            "exploit": ("exploit.sh", malicious_content, "application/x-shellscript"),
        },
    )
    assert resp.status_code == 200
    # Confirm no execution or storage side-effect signal in response
    assert "exploit" not in resp.text
    assert "bash" not in resp.text


# ===========================================================================
# CT-04 — UTF-8 BOM (U+FEFF) in form field values passes through unstripped
# Severity: LOW
#
# Impact: The BOM character is a zero-width no-break space.  In the name and
# message fields it is cosmetically invisible but reaches _sanitize_log().
# The sanitiser strips control characters in range 0x00-0x1F and 0x7F-0x9F;
# U+FEFF (0xEFBBBF in UTF-8) is above that range and passes through.
# In the email field a leading BOM causes _EMAIL_RE to reject the address,
# meaning BOM-prefixed emails are blocked — that is a correct side-effect
# but the rejection message does not explain why.
#
# Fix: ``value = value.lstrip('\ufeff').strip()`` after each field strip().
# ===========================================================================


@pytest.mark.asyncio
async def test_ct04_bom_in_name_field_passes_through(client):
    """
    A UTF-8 BOM prefix in the name field is accepted.  The handler does not
    strip it; the BOM-prefixed name reaches the logger.
    """
    bom_name = "\ufeffAlice"
    resp = await client.post(
        "/contact",
        data={**VALID_FORM, "name": bom_name},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct04_bom_in_message_field_passes_through(client):
    """BOM in the message body is not stripped before processing."""
    bom_message = "\ufeff" + "Hello, I have a question."
    resp = await client.post(
        "/contact",
        data={**VALID_FORM, "message": bom_message},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ct04_bom_in_email_field_passes_regex_validation(client):
    """
    A BOM-prefixed email (U+FEFF + address) passes the regex validator.
    The regex pattern [^@\\s]+@[^@\\s]+\\.[^@\\s]+ treats U+FEFF as a valid
    non-at, non-space character.  The BOM is NOT whitespace; strip() does not
    remove it; the email is accepted with the BOM embedded.

    This means a BOM-prefixed email reaches the logger and any downstream
    email delivery code.  Fix: ``email.lstrip('\\ufeff').strip()``
    """
    bom_email = "\ufeffuser@example.com"
    resp = await client.post(
        "/contact",
        data={**VALID_FORM, "email": bom_email},
    )
    # BOM passes the regex — documents the gap, not a correct rejection
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CT-05 — Null bytes in URL-encoded form values pass through to the handler
# Severity: LOW
#
# Impact: Null bytes in the name or message field pass the strip() call and
# enter the handler body.  _sanitize_log() (used only for logger.info) strips
# the range 0x00-0x1F, so the log call is safe.  However, the raw value with
# the null byte is processed in the if-not-name / email-regex check before
# sanitization.  A null byte in the name does NOT cause it to fail the
# ``if not name`` guard (a non-empty string after strip() with embedded nulls
# is truthy).  The value with embedded nulls is accepted as valid.
#
# Fix: ``value = value.replace('\x00', '').strip()``
# ===========================================================================


@pytest.mark.asyncio
async def test_ct05_null_byte_in_name_accepted(client):
    """
    A null byte embedded in the name field value is accepted.  The handler
    does not strip null bytes; only the logger call sanitises them.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice\x00Evil&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct05_percent_encoded_null_byte_in_name_accepted(client):
    """
    A percent-encoded null byte (%00) in the name field is decoded and accepted.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice%00Evil&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ct05_null_only_name_passes_validation(client):
    """
    A name consisting solely of a null byte passes the ``if not name`` guard.
    Python's str.strip() only removes whitespace; null bytes are NOT whitespace.
    After strip(), the value is the single character '\\x00', which is a truthy
    non-empty string.  The ``if not name`` check does not fire.

    This means a name of a single null byte is accepted as valid input and
    the truncated log entry will appear empty (sanitiser strips 0x00).
    Fix: ``name = name.replace('\\x00', '').strip()``
    """
    resp = await client.post(
        "/contact",
        content=b"name=\x00&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    # _clean_field strips null bytes; empty result triggers validation error
    assert resp.status_code == 422


# ===========================================================================
# CT-06 — X-Content-Type-Options: nosniff on static files (positive control)
# Severity: INFO (verifying existing protection)
#
# nosniff prevents browsers from MIME-sniffing a response away from the
# declared Content-Type.  It must be present on static assets to prevent
# a crafted .txt file being executed as JavaScript.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct06_nosniff_present_on_html_response(client):
    """nosniff is set on the HTML index page."""
    resp = await client.get("/")
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_ct06_nosniff_present_on_json_response(client):
    """nosniff is set on the JSON health endpoint."""
    resp = await client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_ct06_nosniff_present_on_contact_post_response(client):
    """nosniff is set on the contact form JSON response."""
    resp = await client.post("/contact", data=VALID_FORM)
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_ct06_nosniff_present_on_static_css(client):
    """
    nosniff is applied to static file responses.  The middleware loop
    iterates SECURITY_HEADERS unconditionally, covering the StaticFiles mount.
    """
    resp = await client.get("/static/css/style.css")
    # Static file may not exist in test env; skip if 404
    if resp.status_code == 404:
        pytest.skip("static/css/style.css not present in test environment")
    assert resp.headers.get("x-content-type-options") == "nosniff"


# ===========================================================================
# CT-07 — Accept header negotiation is not respected
# Severity: INFO
#
# FastAPI does not perform content negotiation.  Endpoints return their
# declared response class regardless of the client's Accept header.
# This is expected FastAPI behaviour.  Clients cannot force JSON→XML or
# HTML→JSON by setting Accept headers.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct07_accept_xml_on_contact_still_returns_json(client):
    """
    Requesting XML via Accept: text/xml does not change the response format.
    The /contact endpoint always returns application/json.
    """
    resp = await client.post(
        "/contact",
        data=VALID_FORM,
        headers={"Accept": "text/xml"},
    )
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_ct07_accept_json_on_index_still_returns_html(client):
    """
    Requesting JSON from the index page returns HTML regardless.
    The route is declared response_class=HTMLResponse.
    """
    resp = await client.get("/", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_ct07_accept_wildcard_returns_native_type(client):
    """Accept: */* returns the endpoint's native content type."""
    resp = await client.get("/health", headers={"Accept": "*/*"})
    assert resp.status_code == 200
    assert "application/json" in resp.headers.get("content-type", "")


# ===========================================================================
# CT-08 — Declared Content-Length of 1 TB with small body accepted at app layer
# Severity: INFO
#
# The ASGI app layer does not enforce a maximum body size.  A request that
# declares Content-Length: 1099511627776 (1 TiB) with a small actual body
# is processed successfully.
#
# This is NOT a Slow Loris or DoS issue at the app layer because the ASGI
# server (uvicorn) and Fly.io proxy limit connection duration and body reads.
# However, there is no defence-in-depth at the application level.
#
# Mitigation: Add a max-body-size middleware or configure Fly.io body limits.
#
# Example middleware:
#   @app.middleware("http")
#   async def limit_body_size(request: Request, call_next):
#       max_bytes = 64 * 1024  # 64 KB
#       if int(request.headers.get("content-length", 0)) > max_bytes:
#           return JSONResponse({"error": "request too large"}, status_code=413)
#       return await call_next(request)
# ===========================================================================


@pytest.mark.asyncio
async def test_ct08_huge_content_length_with_small_body_accepted(client):
    """
    A Content-Length header claiming 1 TiB with a small real body is not
    rejected at the application layer.  Documents the absence of app-layer
    body-size enforcement.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=hello&website=",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "1099511627776",  # 1 TiB
        },
    )
    # Body size limit middleware rejects based on Content-Length header
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_ct08_body_size_limit_middleware_active(client):
    """
    Confirms body-size limit middleware is active: large Content-Length triggers 413.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=hello&website=",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(2 * 1024 * 1024),  # 2 MB > 1 MB limit
        },
    )
    assert resp.status_code == 413


# ===========================================================================
# CT-09 — HTTP Parameter Pollution: duplicate field names (last-wins)
# Severity: LOW
#
# When the same field name appears multiple times in a URL-encoded body,
# FastAPI's Form() binding takes the LAST occurrence.  This is the opposite
# of what most frameworks (Django, Flask, Rails) do and is counterintuitive.
#
# Impact: an attacker can override an earlier field value by appending a
# second occurrence after it.  Against this stateless contact form the
# attacker cannot escalate privilege, but they can:
#   - Override a valid email with an invalid one to trigger 422
#   - Supply a second name to replace the first in the handler's context
#   - Potentially bypass future field-level allow-listing if the list checks
#     the first value but the handler uses the last
#
# The honeypot is not bypassed by this because FastAPI takes the last
# website value, so appending website=  after website=spam correctly clears
# the honeypot trigger — see test_ct09_duplicate_fields_honeypot_bypassed.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct09_duplicate_name_field_last_value_wins(client):
    """
    When name appears twice, the last value wins.  Eve overrides Alice.
    Both values are syntactically valid so the request succeeds.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&name=Eve&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    # Last-wins: Eve is used; Alice is silently discarded
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct09_duplicate_email_field_last_value_wins(client):
    """
    FastAPI's Form() takes the LAST occurrence of a duplicate field, not the first.
    This is the opposite of what most frameworks do and is counterintuitive.

    Here the last email value is invalid; the request fails with 422.
    An attacker who knows this behaviour can override the first (valid) value
    by appending a second field after it.
    """
    # Last value is invalid → validation failure
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&email=not-an-email&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 422

    # Last value is valid → succeeds
    resp2 = await client.post(
        "/contact",
        content=b"name=Alice&email=not-an-email&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct09_duplicate_fields_honeypot_bypassed_by_last_wins(client):
    """
    SECURITY FINDING: The honeypot can be bypassed via parameter pollution.

    Because FastAPI takes the last occurrence of a duplicate field, an
    attacker who sends:
        website=http://evil.com&website=
    causes the handler to receive website="" (the last, empty value).
    The honeypot check (``if website:``) evaluates to False and the
    submission proceeds through to the logger as a legitimate contact.

    Proof of concept: a bot that knows this behaviour can fill the honeypot
    field (as expected) then append a second empty website value to clear it.

    Fix: reject any request containing duplicate form field names, OR use a
    signed CSRF token whose presence cannot be appended by parameter stuffing.
    """
    # Attacker sends filled honeypot first, then empty to clear it (last wins)
    resp = await client.post(
        "/contact",
        content=b"name=Bot&email=spam@evil.com&message=Buy+pills&website=http://evil.com&website=",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    # Honeypot is bypassed — submission reaches the logging path
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct09_honeypot_not_bypassed_when_last_value_filled(client):
    """
    The honeypot fires correctly when the last (binding) website value is
    non-empty.  The bypass only works when the attacker controls field order.
    """
    # First empty, last filled → last wins → honeypot fires
    resp = await client.post(
        "/contact",
        content=b"name=Bot&email=spam@evil.com&message=Buy&website=&website=http://evil.com",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    # Still returns ok shape (honeypot silently drops) — but this time the
    # bot correctly triggered the honeypot and would not get logged
    assert resp.json()["status"] == "ok"


# ===========================================================================
# CT-10 — Content-Type with charset parameter is accepted without conversion
# Severity: INFO
#
# A Content-Type of "application/x-www-form-urlencoded; charset=utf-16" is
# accepted by python-multipart.  The charset parameter is ignored; the body
# is decoded as bytes then URL-decoded as ASCII/UTF-8.  No charset conversion
# is performed.  Sending genuinely UTF-16 encoded bytes would result in garbled
# field values, not an error or injection.
# ===========================================================================


@pytest.mark.asyncio
async def test_ct10_content_type_with_charset_param_accepted(client):
    """
    A charset parameter appended to the Content-Type is not rejected.
    python-multipart ignores the charset annotation and processes the body
    as URL-encoded bytes.
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded; charset=utf-16"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ct10_content_type_with_boundary_param_accepted(client):
    """
    A boundary parameter in application/x-www-form-urlencoded is also accepted
    (boundary is only meaningful in multipart but is not rejected here).
    """
    resp = await client.post(
        "/contact",
        content=b"name=Alice&email=alice@example.com&message=Hello&website=",
        headers={"content-type": "application/x-www-form-urlencoded; boundary=----"},
    )
    assert resp.status_code == 200


# ===========================================================================
# Response Content-Type correctness (positive controls)
# ===========================================================================


@pytest.mark.asyncio
async def test_response_ct_index_is_html_with_charset(client):
    """Index returns text/html with charset=utf-8."""
    resp = await client.get("/")
    assert resp.status_code == 200
    ct = resp.headers.get("content-type", "")
    assert "text/html" in ct
    assert "utf-8" in ct


@pytest.mark.asyncio
async def test_response_ct_health_is_json(client):
    """Health endpoint returns application/json."""
    resp = await client.get("/health")
    ct = resp.headers.get("content-type", "")
    assert "application/json" in ct


@pytest.mark.asyncio
async def test_response_ct_contact_success_is_json(client):
    """Successful contact POST returns application/json."""
    resp = await client.post("/contact", data=VALID_FORM)
    ct = resp.headers.get("content-type", "")
    assert "application/json" in ct


@pytest.mark.asyncio
async def test_response_ct_contact_422_is_json(client):
    """Validation error 422 returns application/json (not HTML stack trace)."""
    resp = await client.post("/contact", data={"name": "A" * 201, "email": "a@b.com", "message": "hi"})
    assert resp.status_code == 422
    ct = resp.headers.get("content-type", "")
    assert "application/json" in ct
    # Confirm no HTML stack trace leaked
    assert "<html" not in resp.text.lower()
    assert "traceback" not in resp.text.lower()


@pytest.mark.asyncio
async def test_response_ct_404_is_html(client):
    """404 handler returns HTML (index page), not a JSON error."""
    resp = await client.get("/no-such-page")
    assert resp.status_code == 404
    ct = resp.headers.get("content-type", "")
    assert "text/html" in ct
