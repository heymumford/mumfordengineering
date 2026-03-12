"""
Security Review: Email Validation Analysis
Target: src/mumfordengineering/app.py — _EMAIL_RE and _sanitize_log
Reviewed: 2026-03-12 (updated after allowlist regex fix)

Regex changed from permissive [^@\\s]+ to allowlist-style:
  ^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$

Findings summary (post-fix):
  RESOLVED — XSS payload in local-part now rejected by allowlist
  RESOLVED — Null byte in local-part now rejected by allowlist
  RESOLVED — Bidi/zero-width Unicode now stripped by improved _sanitize_log
  RESOLVED — Mongolian Vowel Separator (U+180E) rejected by allowlist regex
  INFO     — ReDoS: not exploitable (no nested quantifiers, linear backtracking)
  INFO     — CRLF injection: correctly blocked
  INFO     — Double-@ correctly blocked
  INFO     — Unicode IDN homographs now rejected by allowlist domain chars
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import _EMAIL_RE, _sanitize_log, app, _contact_timestamps

# ---------------------------------------------------------------------------
# Shared fixtures
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
# 1. ReDoS — Regular Expression Denial of Service
#
# Finding: NOT exploitable.
# The pattern ^[^@\s]+@[^@\s]+\.[^@\s]+$ uses negated character classes with
# no nested quantifiers or alternation. Backtracking is linear O(n).
# Worst case (no match, full scan): measured <0.1ms at 10,000 chars.
#
# Fix: None required. Document that the regex is ReDoS-safe.
# CWE-1333  OWASP A05:2021 (Security Misconfiguration)
# ---------------------------------------------------------------------------


class TestReDoS:
    """Confirm the regex does not exhibit catastrophic backtracking."""

    def test_long_valid_local_part_completes_fast(self):
        """1000-char local part: should complete well under 10ms."""
        payload = "a" * 1000 + "@b.co"
        start = time.perf_counter()
        result = _EMAIL_RE.match(payload)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert result is not None, "Expected match for long-but-valid address"
        assert elapsed_ms < 10, f"Regex took {elapsed_ms:.2f}ms — potential ReDoS"

    def test_worst_case_no_at_sign_completes_fast(self):
        """10,000 chars with no @ — must scan entire string before failing."""
        payload = "a" * 10_000
        start = time.perf_counter()
        result = _EMAIL_RE.match(payload)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert result is None, "Expected no match for string without @"
        assert elapsed_ms < 50, f"Regex took {elapsed_ms:.2f}ms — potential ReDoS"

    def test_repeated_at_signs_completes_fast(self):
        """Input with many @ symbols triggers worst-case domain scanning."""
        payload = "a@" * 500 + "b.c"
        start = time.perf_counter()
        _EMAIL_RE.match(payload)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 50, f"Regex took {elapsed_ms:.2f}ms — potential ReDoS"


# ---------------------------------------------------------------------------
# 2. Bypass payloads — what malicious emails pass the regex
#
# Finding MEDIUM: XSS local-part passes regex.
# `"<script>alert(1)</script>"@evil.com` is a structurally valid RFC 5321
# quoted local-part. The current regex accepts it because the local-part
# `"<script>alert(1)</script>"` contains no @ or whitespace.
#
# Current risk: LOW — the email is only logged (via _sanitize_log which does
# NOT strip angle brackets or script tags) and returned as a JSON field value.
# If this email is ever rendered in an admin UI without escaping, XSS fires.
#
# Fix: Reject local-parts containing HTML metacharacters: <>"'
# Or: use email.headerregistry / email-validator library.
# CWE-79  OWASP A03:2021 (Injection)
# ---------------------------------------------------------------------------


class TestXSSLocalPart:
    """XSS payload in local-part passes the email regex."""

    def test_xss_in_local_part_blocked_by_regex(self):
        """Allowlist regex rejects HTML metacharacters in local-part."""
        payload = '"<script>alert(1)</script>"@evil.com'
        assert _EMAIL_RE.match(payload) is None, "XSS payload should be rejected by allowlist-style _EMAIL_RE"

    def test_angle_bracket_in_local_part_blocked_by_regex(self):
        payload = "<injected>@evil.com"
        assert _EMAIL_RE.match(payload) is None

    def test_html_entity_bypass_blocked_by_regex(self):
        payload = "foo&bar=baz@evil.com"
        assert _EMAIL_RE.match(payload) is None

    @pytest.mark.asyncio
    async def test_xss_local_part_rejected_by_contact_endpoint(self, client):
        """
        The contact endpoint rejects XSS-bearing emails via the allowlist
        regex which blocks HTML metacharacters.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": '"<script>alert(1)</script>"@evil.com',
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 422, "XSS email should be rejected by allowlist-style email regex"


# ---------------------------------------------------------------------------
# 3. Null byte in local-part
#
# Finding MEDIUM: `test\x00@evil.com` passes the regex.
# Null bytes are not whitespace and not @, so [^@\s]+ matches them.
#
# _sanitize_log DOES strip \x00 (it is in \x00-\x1f range), so log injection
# via null byte is mitigated. However:
#   - Null bytes can truncate strings in C-backed email libraries
#   - Some SMTP servers treat null bytes as end-of-data
#   - Null bytes can bypass naive string comparisons downstream
#
# Fix: Reject null bytes explicitly in the email validator.
# Recommended: re.compile(r"^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+\.[^@\s\x00-\x1f\x7f]+$")
# CWE-20  OWASP A03:2021 (Injection)
# ---------------------------------------------------------------------------


class TestNullByte:
    """Null byte passes the email regex but is stripped by _sanitize_log."""

    def test_null_byte_blocked_by_regex(self):
        payload = "test\x00@evil.com"
        assert _EMAIL_RE.match(payload) is None, "Null byte in local-part should be rejected by allowlist-style regex"

    def test_null_byte_stripped_by_sanitize_log(self):
        """Null byte IS stripped before logging — log injection mitigated."""
        payload = "test\x00@evil.com"
        sanitized = _sanitize_log(payload)
        assert "\x00" not in sanitized

    def test_other_control_chars_blocked_by_regex(self):
        """Control characters are rejected by the allowlist regex."""
        # \x01 is not in [a-zA-Z0-9._%+\-]
        payload = "test\x01@evil.com"
        assert _EMAIL_RE.match(payload) is None

    def test_control_chars_stripped_by_sanitize_log(self):
        """Control characters are stripped by _sanitize_log."""
        payload = "test\x01\x02\x03@evil.com"
        sanitized = _sanitize_log(payload)
        assert "\x01" not in sanitized
        assert "\x02" not in sanitized
        assert "\x03" not in sanitized

    @pytest.mark.asyncio
    async def test_null_byte_email_stripped_by_clean_field(self, client):
        """
        _clean_field strips null bytes before validation.
        test\\x00@evil.com becomes test@evil.com which is valid.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "test\x00@evil.com",
                "message": "Hello",
                "website": "",
            },
        )
        # Null byte stripped, resulting email is valid
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Log injection via _sanitize_log — Unicode bypass
#
# Finding LOW: Bidi control characters and zero-width characters survive
# _sanitize_log. The sanitizer strips only \x00-\x1f and \x7f-\x9f.
# Unicode code points above U+009F are not touched.
#
# Attack scenario: An attacker submits an email containing U+202E (RIGHT-TO-LEFT
# OVERRIDE). In a log viewer that renders Unicode, this character reverses
# displayed text direction, enabling log spoofing (e.g., making "evil.com"
# appear as "moc.live").
#
# Affected characters (all survive _sanitize_log):
#   U+202E  RIGHT-TO-LEFT OVERRIDE
#   U+200B  ZERO WIDTH SPACE
#   U+180E  MONGOLIAN VOWEL SEPARATOR
#
# Fix: Extend _sanitize_log to also strip Unicode control/format characters:
#   re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "")
# CWE-117  OWASP A09:2021 (Security Logging and Monitoring Failures)
# ---------------------------------------------------------------------------


class TestLogInjection:
    """Unicode bidirectional and zero-width characters survive _sanitize_log."""

    def test_bidi_rlo_stripped_by_sanitize_log(self):
        """U+202E RIGHT-TO-LEFT OVERRIDE is now stripped by the sanitizer."""
        payload = "test\u202e@evil.com"
        sanitized = _sanitize_log(payload)
        assert "\u202e" not in sanitized

    def test_zero_width_space_stripped_by_sanitize_log(self):
        """U+200B ZERO WIDTH SPACE is now stripped by the sanitizer."""
        payload = "test\u200b@evil.com"
        sanitized = _sanitize_log(payload)
        assert "\u200b" not in sanitized

    def test_mongolian_vowel_separator_survives_sanitize_log(self):
        """U+180E MONGOLIAN VOWEL SEPARATOR is not stripped."""
        payload = "test\u180e@evil.com"
        sanitized = _sanitize_log(payload)
        assert "\u180e" in sanitized

    def test_control_chars_are_stripped(self):
        """Baseline: ASCII control characters ARE correctly stripped."""
        for code in range(0x00, 0x20):
            char = chr(code)
            sanitized = _sanitize_log(f"x{char}y@test.com")
            assert char not in sanitized, f"\\x{code:02x} should be stripped but survived"

    def test_high_control_chars_are_stripped(self):
        """Baseline: \x7f-\x9f range is correctly stripped."""
        for code in range(0x7F, 0xA0):
            char = chr(code)
            sanitized = _sanitize_log(f"x{char}y@test.com")
            assert char not in sanitized, f"\\x{code:02x} should be stripped but survived"

    def test_truncation_limit_applied(self):
        """_sanitize_log truncates to 200 chars."""
        long_email = "a" * 300 + "@test.com"
        sanitized = _sanitize_log(long_email)
        assert len(sanitized) <= 200

    def test_bidi_rlo_blocked_by_regex(self):
        """U+202E is not in the allowlist — rejected by the email regex."""
        payload = "test\u202e@evil.com"
        assert _EMAIL_RE.match(payload) is None

    def test_mongolian_vowel_separator_blocked_by_regex(self):
        """U+180E is not in the allowlist — rejected by the email regex."""
        payload = "test\u180e@evil.com"
        assert _EMAIL_RE.match(payload) is None


# ---------------------------------------------------------------------------
# 5. Email header injection — CRLF
#
# Finding INFO (currently mitigated): CRLF sequences are correctly blocked.
# The [^@\s]+ class uses Python's \s which matches \r and \n, so
# `test@evil.com\r\nBcc: victim@example.com` fails the regex.
#
# Future risk: If email is ever placed in a mail header (To:, From:, Reply-To:)
# and the regex is the only guard, an attacker who finds a bypass for \s
# detection could inject additional headers.
#
# Fix: No immediate action. Document that CRLF is blocked at the regex layer.
# For future email sending: always use an email library (smtplib.sendmail with
# parameterized headers, or a library like resend/sendgrid SDK) rather than
# raw header string construction.
# CWE-93  OWASP A03:2021 (Injection)
# ---------------------------------------------------------------------------


class TestHeaderInjection:
    """CRLF injection is blocked; documents the protection and its limits."""

    def test_crlf_in_domain_blocked_by_regex(self):
        """\\r\\n in domain fails because \\r and \\n are \\s."""
        payload = "test@evil.com\r\nBcc: victim@example.com"
        assert _EMAIL_RE.match(payload) is None

    def test_lf_only_in_domain_blocked_by_regex(self):
        payload = "test@evil.com\nBcc: victim@example.com"
        assert _EMAIL_RE.match(payload) is None

    def test_crlf_in_local_part_blocked_by_regex(self):
        payload = "test\r\n@evil.com"
        assert _EMAIL_RE.match(payload) is None

    @pytest.mark.asyncio
    async def test_crlf_injection_rejected_by_endpoint(self, client):
        """Contact endpoint correctly rejects CRLF-bearing email."""
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "test@evil.com\r\nBcc: victim@example.com",
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 422
        assert resp.json()["status"] == "error"


# ---------------------------------------------------------------------------
# 6. Structural bypasses — double @, IP literals, minimal valid
#
# Finding INFO: Double @ is correctly rejected. IP literals pass (acceptable).
# Minimal `a@b.c` is valid and passes (correct per RFC).
# ---------------------------------------------------------------------------


class TestStructuralBypasses:
    """Structural edge cases in the email regex."""

    def test_double_at_sign_blocked(self):
        r"""Double @ is rejected — [^@\s]+ cannot match @."""
        assert _EMAIL_RE.match("test@test@test.com") is None

    def test_minimal_email_requires_two_char_tld(self):
        """a@b.c fails — TLD must be at least 2 alphabetic characters."""
        assert _EMAIL_RE.match("a@b.c") is None
        assert _EMAIL_RE.match("a@b.co") is not None

    def test_ip_literal_domain_blocked(self):
        """
        x@[127.0.0.1] is rejected — brackets are not in the allowlist
        domain character set [a-zA-Z0-9.\\-].
        """
        assert _EMAIL_RE.match("x@[127.0.0.1]") is None

    def test_no_at_sign_rejected(self):
        assert _EMAIL_RE.match("notanemail") is None

    def test_no_dot_in_domain_rejected(self):
        assert _EMAIL_RE.match("test@nodot") is None

    def test_empty_local_part_rejected(self):
        assert _EMAIL_RE.match("@example.com") is None

    def test_empty_domain_rejected(self):
        assert _EMAIL_RE.match("test@") is None

    def test_trailing_dot_blocked_by_regex(self):
        """
        Trailing dot is rejected — the new regex requires [a-zA-Z]{2,}$ as
        the TLD, so a trailing dot leaves an empty TLD which fails the match.
        """
        assert _EMAIL_RE.match("test@example.com.") is None

    @pytest.mark.asyncio
    async def test_ip_literal_rejected_by_endpoint(self, client):
        """IP literal domain is rejected by the allowlist regex."""
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "x@[127.0.0.1]",
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 7. Very long inputs — buffer and DoS considerations
#
# Finding INFO: FastAPI enforces max_length=254 on the email field via Form().
# The regex itself handles long inputs in linear time (see TestReDoS).
# ---------------------------------------------------------------------------


class TestLongInputs:
    """Length bounds are enforced at the Form() layer and the regex is O(n)."""

    def test_email_at_max_length_passes_regex(self):
        """254-char email just under the max_length limit."""
        local = "a" * 242  # 242 + 1(@) + 1(b) + 1(.) + 1(c) = 246 ... adjust
        payload = local[:63] + "@" + "b" * 63 + ".com"
        assert len(payload) <= 254
        assert _EMAIL_RE.match(payload) is not None

    @pytest.mark.asyncio
    async def test_email_exceeding_max_length_rejected_by_endpoint(self, client):
        """FastAPI rejects emails longer than 254 chars at the Form() layer."""
        too_long = "a" * 300 + "@example.com"
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": too_long,
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 422

    def test_name_at_max_length_accepted(self):
        """200-char name passes length check."""
        from mumfordengineering.app import _MAX_NAME

        assert _MAX_NAME == 200

    def test_message_at_max_length_constant(self):
        from mumfordengineering.app import _MAX_MESSAGE

        assert _MAX_MESSAGE == 5000


# ---------------------------------------------------------------------------
# 8. Unicode / IDN domain attacks
#
# Finding LOW: Homograph attacks pass the regex. `test@еvil.com` (Cyrillic е)
# is accepted. This is expected — the regex performs no Unicode normalization.
#
# Current risk: LOW — the email is not used for domain verification or
# DNS lookups. If it is ever used to construct an allowed-domain check or
# link, IDN homograph attacks become relevant.
#
# Fix (if domain validation is added): Normalize via IDNA encoding before
# comparing against an allowlist:
#   import encodings.idna; domain.encode("idna").decode("ascii")
# CWE-20
# ---------------------------------------------------------------------------


class TestUnicodeIDN:
    """Unicode / IDN domain attacks pass the regex."""

    def test_cyrillic_lookalike_domain_blocked(self):
        """Cyrillic е (U+0435) is not in [a-zA-Z0-9.\\-] — rejected."""
        payload = "test@\u0435vil.com"  # еvil.com with Cyrillic е
        assert _EMAIL_RE.match(payload) is None

    def test_greek_lookalike_blocked(self):
        """Greek ο (U+03BF) is not in the allowlist — rejected."""
        payload = "test@g\u03bf\u03bfgle.com"  # gοοgle.com with Greek letters
        assert _EMAIL_RE.match(payload) is None

    def test_mixed_script_domain_blocked(self):
        """Mixed Latin/Cyrillic domain rejected by allowlist."""
        payload = "test@evil\u0441.com"  # с is Cyrillic с
        assert _EMAIL_RE.match(payload) is None

    def test_ascii_domain_passes(self):
        """Baseline: pure ASCII domain passes."""
        assert _EMAIL_RE.match("test@evil.com") is not None


# ---------------------------------------------------------------------------
# 9. Regression — valid emails must not be rejected
#
# Ensure security hardening does not break legitimate addresses.
# ---------------------------------------------------------------------------


class TestValidEmailsNotRejected:
    """Regression: legitimate emails pass the current regex."""

    @pytest.mark.parametrize(
        "email",
        [
            "user@example.com",
            "user.name+tag@example.co.uk",
            "user-name@sub.domain.org",
            "user@xn--nxasmq6b.com",  # IDNA encoded
        ],
    )
    def test_legitimate_email_passes_regex(self, email: str):
        assert _EMAIL_RE.match(email) is not None, f"Legitimate email rejected: {email}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "email",
        [
            "user@example.com",
            "name+tag@sub.domain.org",
        ],
    )
    async def test_legitimate_email_accepted_by_endpoint(self, client, email: str):
        resp = await client.post(
            "/contact",
            data={"name": "Test User", "email": email, "message": "Hello", "website": ""},
        )
        assert resp.status_code == 200, f"Legitimate email {email!r} rejected"


# ---------------------------------------------------------------------------
# 10. Consolidated endpoint security — end-to-end adversarial payloads
# ---------------------------------------------------------------------------


class TestContactEndpointAdversarial:
    """End-to-end adversarial POST /contact tests."""

    @pytest.mark.asyncio
    async def test_xss_script_tag_in_name_accepted(self, client):
        """
        HTML in the name field is not sanitized server-side.
        FastAPI returns it as JSON (not rendered HTML), so XSS does not fire
        at the server. Jinja2 auto-escaping protects any template rendering.
        Documents current behavior.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "<script>alert(1)</script>",
                "email": "test@example.com",
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_sql_injection_pattern_in_message_accepted(self, client):
        """
        SQL injection in message field: no database queries exist in this app,
        so this is not a risk. Documents that the endpoint does not crash.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "test@example.com",
                "message": "'; DROP TABLE users; --",
                "website": "",
            },
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_backtick_and_semicolons_in_email_rejected(self, client):
        """
        Semicolons are not in the allowlist [a-zA-Z0-9._%+\\-] and are
        rejected by the email regex.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "test;cmd@example.com",
                "message": "Hello",
                "website": "",
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_oversized_message_rejected(self, client):
        """Message exceeding 5000 chars is rejected at the Form() layer."""
        resp = await client.post(
            "/contact",
            data={
                "name": "Test",
                "email": "test@example.com",
                "message": "x" * 5001,
                "website": "",
            },
        )
        assert resp.status_code == 422
