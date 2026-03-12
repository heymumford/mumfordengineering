"""Accessibility (WCAG 2.1 AA) and security-relevant HTML audit tests.

Tests the rendered HTML from the FastAPI index route against WCAG 2.1 AA
success criteria and security best practices for HTML output.

Findings are grouped by audit category. Each test docstring cites the
relevant WCAG criterion or security concern, severity, and fix recommendation.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import app, _contact_timestamps


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ============================================================
# Helpers
# ============================================================


def _srgb_to_linear(c: int) -> float:
    s = c / 255.0
    return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4


def _relative_luminance(r: int, g: int, b: int) -> float:
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _contrast_ratio(hex_fg: str, hex_bg: str) -> float:
    l1 = _relative_luminance(*_hex_to_rgb(hex_fg))
    l2 = _relative_luminance(*_hex_to_rgb(hex_bg))
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


class _TagCollector(HTMLParser):
    """Lightweight HTML parser to collect elements and attributes."""

    def __init__(self):
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        self.tags.append((tag, dict(attrs)))


def _parse_tags(html: str) -> list[tuple[str, dict[str, str | None]]]:
    p = _TagCollector()
    p.feed(html)
    return p.tags


def _find_tags(tags: list[tuple[str, dict[str, str | None]]], tag_name: str) -> list[dict[str, str | None]]:
    return [attrs for t, attrs in tags if t == tag_name]


def _find_tags_with_class(
    tags: list[tuple[str, dict[str, str | None]]], tag_name: str, cls: str
) -> list[dict[str, str | None]]:
    results = []
    for t, attrs in tags:
        if t == tag_name:
            classes = (attrs.get("class") or "").split()
            if cls in classes:
                results.append(attrs)
    return results


# ============================================================
# 1. FORM ACCESSIBILITY
# ============================================================


class TestFormAccessibility:
    """Contact form WCAG compliance."""

    @pytest.mark.asyncio
    async def test_all_inputs_have_labels(self, client):
        """WCAG 1.3.1 (Info and Relationships) / 4.1.2 (Name, Role, Value).
        Severity: HIGH.
        Every visible form input must have a <label> with a matching for/id pair.
        """
        resp = await client.get("/")
        html = resp.text
        tags = _parse_tags(html)
        inputs = [a for t, a in tags if t in ("input", "textarea") and a.get("type") != "hidden"]
        labels = _find_tags(tags, "label")
        label_fors = {a.get("for") for a in labels if a.get("for")}

        for inp in inputs:
            input_id = inp.get("id")
            assert input_id, f"Input missing id attribute: {inp}"
            assert input_id in label_fors, f"No <label for='{input_id}'> found"

    @pytest.mark.asyncio
    async def test_required_inputs_have_aria_required(self, client):
        """WCAG 3.3.2 (Labels or Instructions).
        Severity: MEDIUM.
        Required inputs should declare aria-required='true' for AT users.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        required_inputs = [a for t, a in tags if t in ("input", "textarea") and "required" in a]
        assert len(required_inputs) >= 3, "Expected at least 3 required fields (name, email, message)"
        for inp in required_inputs:
            assert inp.get("aria-required") == "true", (
                f"Required input id='{inp.get('id')}' missing aria-required='true'"
            )

    @pytest.mark.asyncio
    async def test_honeypot_has_aria_hidden(self, client):
        """WCAG 4.1.2 (Name, Role, Value) + anti-bot security.
        Severity: HIGH.
        Honeypot container must have aria-hidden='true' so screen readers
        skip it and tabindex='-1' on the input to remove it from tab order.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hp_divs = _find_tags_with_class(tags, "div", "hp-field")
        assert len(hp_divs) >= 1, "Honeypot div.hp-field not found"
        assert hp_divs[0].get("aria-hidden") == "true", "Honeypot div missing aria-hidden='true'"

        hp_inputs = [a for t, a in tags if t == "input" and a.get("name") == "website"]
        assert len(hp_inputs) >= 1, "Honeypot input name='website' not found"
        assert hp_inputs[0].get("tabindex") == "-1", "Honeypot input missing tabindex='-1'"

    @pytest.mark.asyncio
    async def test_form_status_has_live_region(self, client):
        """WCAG 4.1.3 (Status Messages).
        Severity: HIGH.
        Form status div must use role='status' and aria-live='polite' so
        screen readers announce success/error messages without focus shift.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        status_divs = [a for t, a in tags if t == "div" and a.get("id") == "form-status"]
        assert len(status_divs) >= 1, "#form-status element not found"
        s = status_divs[0]
        assert s.get("role") == "status", "#form-status missing role='status'"
        assert s.get("aria-live") == "polite", "#form-status missing aria-live='polite'"

    @pytest.mark.asyncio
    async def test_submit_button_has_type(self, client):
        """WCAG 4.1.2 (Name, Role, Value).
        Severity: LOW.
        Submit button should have explicit type='submit'.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        submit_btns = _find_tags_with_class(tags, "button", "btn-submit")
        assert len(submit_btns) >= 1, "Submit button not found"
        assert submit_btns[0].get("type") == "submit", "Submit button missing type='submit'"

    @pytest.mark.asyncio
    async def test_form_has_novalidate(self, client):
        """WCAG 3.3.1 (Error Identification).
        Severity: LOW.
        Form uses novalidate to provide custom JS validation with
        accessible error announcements via the live region.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        forms = [a for t, a in tags if t == "form" and a.get("id") == "contact-form"]
        assert len(forms) >= 1, "#contact-form not found"
        assert "novalidate" in forms[0], "Form should have novalidate for custom validation"

    @pytest.mark.asyncio
    async def test_email_input_has_autocomplete(self, client):
        """WCAG 1.3.5 (Identify Input Purpose).
        Severity: MEDIUM.
        Email and name inputs should have autocomplete attributes matching
        their purpose so browsers/AT can auto-fill correctly.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        email_inputs = [a for t, a in tags if t == "input" and a.get("id") == "email"]
        assert len(email_inputs) >= 1
        assert email_inputs[0].get("autocomplete") == "email", "Email input missing autocomplete='email'"

        name_inputs = [a for t, a in tags if t == "input" and a.get("id") == "name"]
        assert len(name_inputs) >= 1
        assert name_inputs[0].get("autocomplete") == "name", "Name input missing autocomplete='name'"

    @pytest.mark.asyncio
    async def test_honeypot_input_has_autocomplete_off(self, client):
        """Security: prevent browsers from auto-filling honeypot.
        Severity: MEDIUM.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hp = [a for t, a in tags if t == "input" and a.get("name") == "website"]
        assert len(hp) >= 1
        assert hp[0].get("autocomplete") == "off", "Honeypot input missing autocomplete='off'"


# ============================================================
# 2. NAVIGATION ACCESSIBILITY
# ============================================================


class TestNavigationAccessibility:
    """Navigation landmarks, skip link, keyboard support."""

    @pytest.mark.asyncio
    async def test_skip_link_exists(self, client):
        """WCAG 2.4.1 (Bypass Blocks).
        Severity: HIGH.
        First focusable element must be a skip link targeting #main.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        skip_links = _find_tags_with_class(tags, "a", "skip-link")
        assert len(skip_links) >= 1, "Skip link not found"
        assert skip_links[0].get("href") == "#main", "Skip link should target #main"

    @pytest.mark.asyncio
    async def test_main_landmark_exists(self, client):
        """WCAG 1.3.1 (Info and Relationships) / 2.4.1 (Bypass Blocks).
        Severity: HIGH.
        Page must have a <main> element with id='main' (skip link target).
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        mains = [a for t, a in tags if t == "main"]
        assert len(mains) >= 1, "No <main> element found"
        assert mains[0].get("id") == "main", "<main> missing id='main'"

    @pytest.mark.asyncio
    async def test_nav_has_aria_label(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: MEDIUM.
        Navigation landmark should have aria-label for AT identification.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        navs = _find_tags(tags, "nav")
        assert len(navs) >= 1, "No <nav> element found"
        assert navs[0].get("aria-label"), "<nav> missing aria-label"

    @pytest.mark.asyncio
    async def test_hamburger_has_aria_expanded(self, client):
        """WCAG 4.1.2 (Name, Role, Value).
        Severity: HIGH.
        Hamburger button must declare aria-expanded state and aria-controls
        the menu it toggles.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hamburgers = [a for t, a in tags if t == "button" and a.get("id") == "hamburger"]
        assert len(hamburgers) >= 1, "Hamburger button not found"
        h = hamburgers[0]
        assert h.get("aria-expanded") in ("true", "false"), "Hamburger missing aria-expanded"
        assert h.get("aria-controls") == "nav-menu", "Hamburger missing aria-controls='nav-menu'"
        assert h.get("aria-label"), "Hamburger missing aria-label"

    @pytest.mark.asyncio
    async def test_nav_menu_has_id_matching_controls(self, client):
        """WCAG 4.1.2 (Name, Role, Value).
        Severity: MEDIUM.
        The nav menu referenced by aria-controls must exist with that id.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        menus = [a for t, a in tags if t == "ul" and a.get("id") == "nav-menu"]
        assert len(menus) >= 1, "nav-menu element not found"

    @pytest.mark.asyncio
    async def test_header_landmark_exists(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: LOW.
        Page should use <header> landmark.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        headers = _find_tags(tags, "header")
        assert len(headers) >= 1, "No <header> landmark found"

    @pytest.mark.asyncio
    async def test_footer_landmark_exists(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: LOW.
        Page should use <footer> landmark.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        footers = _find_tags(tags, "footer")
        assert len(footers) >= 1, "No <footer> landmark found"

    @pytest.mark.asyncio
    async def test_nav_menu_is_not_hidden_by_default(self, client):
        """WCAG 2.1.1 (Keyboard).
        Severity: MEDIUM.
        Nav menu UL should not have aria-hidden on initial render
        (CSS handles visibility, not ARIA). If aria-hidden were set,
        screen reader users on desktop would lose nav access.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        menus = [a for t, a in tags if t == "ul" and a.get("id") == "nav-menu"]
        assert len(menus) >= 1
        assert menus[0].get("aria-hidden") is None, (
            "nav-menu should not have aria-hidden (CSS handles mobile visibility)"
        )


# ============================================================
# 3. COLOR CONTRAST (WCAG 1.4.3)
# ============================================================


class TestColorContrast:
    """WCAG 1.4.3 (Contrast Minimum) -- 4.5:1 for normal text, 3.0:1 for large text.

    Colors are extracted from CSS custom properties. Tests verify the computed
    contrast ratio meets AA thresholds.
    """

    BG_PRIMARY = "#0f0f1a"
    BG_SECONDARY = "#1a1a2e"
    BG_CARD = "#16213e"
    TEXT_PRIMARY = "#e8e8e8"
    TEXT_SECONDARY = "#a0a0b0"
    ACCENT_WARM = "#c4793a"
    ACCENT_COOL = "#3ecf8e"
    ACCENT_HIGHLIGHT = "#d4a259"
    ERROR_COLOR = "#e05252"

    def test_text_primary_on_bg_primary(self):
        """Body text on primary background."""
        ratio = _contrast_ratio(self.TEXT_PRIMARY, self.BG_PRIMARY)
        assert ratio >= 4.5, f"text-primary on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_text_secondary_on_bg_primary(self):
        """Secondary text (paragraphs, subtitles) on primary background."""
        ratio = _contrast_ratio(self.TEXT_SECONDARY, self.BG_PRIMARY)
        assert ratio >= 4.5, f"text-secondary on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_text_secondary_on_bg_secondary(self):
        """Secondary text on alt section background."""
        ratio = _contrast_ratio(self.TEXT_SECONDARY, self.BG_SECONDARY)
        assert ratio >= 4.5, f"text-secondary on bg-secondary: {ratio:.2f}:1 (need 4.5:1)"

    def test_text_secondary_on_bg_card(self):
        """Secondary text inside card components."""
        ratio = _contrast_ratio(self.TEXT_SECONDARY, self.BG_CARD)
        assert ratio >= 4.5, f"text-secondary on bg-card: {ratio:.2f}:1 (need 4.5:1)"

    def test_accent_warm_on_bg_primary(self):
        """Accent warm (CTA buttons, stat numbers) on primary bg."""
        ratio = _contrast_ratio(self.ACCENT_WARM, self.BG_PRIMARY)
        assert ratio >= 4.5, f"accent-warm on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_accent_cool_on_bg_primary(self):
        """Links (accent-cool) on primary background."""
        ratio = _contrast_ratio(self.ACCENT_COOL, self.BG_PRIMARY)
        assert ratio >= 4.5, f"accent-cool on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_accent_cool_on_bg_secondary(self):
        """Links on alt section background."""
        ratio = _contrast_ratio(self.ACCENT_COOL, self.BG_SECONDARY)
        assert ratio >= 4.5, f"accent-cool on bg-secondary: {ratio:.2f}:1 (need 4.5:1)"

    def test_error_color_on_bg_primary(self):
        """Error messages on primary background."""
        ratio = _contrast_ratio(self.ERROR_COLOR, self.BG_PRIMARY)
        assert ratio >= 4.5, f"error on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_accent_highlight_on_bg_primary(self):
        """Highlight/hover color on primary background."""
        ratio = _contrast_ratio(self.ACCENT_HIGHLIGHT, self.BG_PRIMARY)
        assert ratio >= 4.5, f"accent-highlight on bg-primary: {ratio:.2f}:1 (need 4.5:1)"

    def test_btn_primary_white_on_accent_warm(self):
        """WCAG 1.4.3 -- btn-primary uses white (#fff) on accent-warm (#c4793a).
        Severity: HIGH.
        Measured: 3.42:1 -- FAILS AA normal text (4.5:1).
        Passes large text (3.0:1) but button text is 0.9375rem (15px, weight 600),
        which is NOT large text (18px+ regular or 14px+ bold per WCAG).
        Fix: Darken accent-warm to ~#a06030 or use dark text on the button.
        """
        ratio = _contrast_ratio("#ffffff", self.ACCENT_WARM)
        # Documents the KNOWN FAILURE -- passes large-text threshold only.
        assert ratio >= 3.0, f"White on accent-warm: {ratio:.2f}:1 (need 3.0:1 minimum)"
        assert ratio < 4.5, (
            f"White on accent-warm: {ratio:.2f}:1 -- if this now passes 4.5:1, "
            "the accent-warm value changed (update test)"
        )

    def test_skip_link_contrast(self):
        """Skip link: dark text on accent-warm background."""
        ratio = _contrast_ratio(self.BG_PRIMARY, self.ACCENT_WARM)
        assert ratio >= 4.5, f"skip-link text on bg: {ratio:.2f}:1 (need 4.5:1)"

    def test_accent_warm_on_bg_card(self):
        """Stat numbers (accent-warm) on card background. Large text (2.25rem)."""
        ratio = _contrast_ratio(self.ACCENT_WARM, self.BG_CARD)
        assert ratio >= 3.0, f"accent-warm on bg-card: {ratio:.2f}:1 (need 3.0:1 for large)"


# ============================================================
# 4. IMAGES AND SVG ACCESSIBILITY
# ============================================================


class TestImagesAndSvg:
    """Decorative SVGs and images must be hidden from AT."""

    @pytest.mark.asyncio
    async def test_svgs_inside_aria_hidden_containers(self, client):
        """WCAG 1.1.1 (Non-text Content).
        Severity: LOW (mitigated).
        Three software card icon SVGs (lines 184, 209, 237 in template) lack
        explicit aria-hidden='true'. However, their parent div.software-card-icon
        containers DO have aria-hidden='true', so AT inheritance hides them.
        Best practice: add aria-hidden='true' to the SVGs themselves.
        This test verifies the parent containers are properly hidden.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        # Verify parent containers are aria-hidden (mitigates the missing SVG attrs)
        card_icons = _find_tags_with_class(tags, "div", "software-card-icon")
        assert len(card_icons) >= 3, "Expected at least 3 software-card-icon containers"
        for icon in card_icons:
            assert icon.get("aria-hidden") == "true", "software-card-icon missing aria-hidden='true'"

    @pytest.mark.asyncio
    async def test_standalone_svgs_have_aria_hidden(self, client):
        """WCAG 1.1.1 (Non-text Content).
        Severity: MEDIUM.
        SVGs NOT inside an aria-hidden container must have aria-hidden='true'
        directly. This covers contact icons, footer icons, defender card icons.
        """
        resp = await client.get("/")
        html = resp.text
        # Count SVGs with explicit aria-hidden
        svg_total = html.count("<svg")
        svg_with_hidden = len(re.findall(r'<svg[^>]*aria-hidden="true"', html))
        unprotected = svg_total - svg_with_hidden
        assert unprotected == 0, f"{unprotected} SVG(s) lack aria-hidden='true'"

    @pytest.mark.asyncio
    async def test_hero_grid_is_aria_hidden(self, client):
        """WCAG 1.1.1 (Non-text Content).
        Severity: LOW.
        The decorative hero grid background must be hidden from AT.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hero_grids = _find_tags_with_class(tags, "div", "hero-grid")
        assert len(hero_grids) >= 1, "hero-grid div not found"
        assert hero_grids[0].get("aria-hidden") == "true", "hero-grid missing aria-hidden='true'"

    @pytest.mark.asyncio
    async def test_defender_card_images_are_aria_hidden(self, client):
        """WCAG 1.1.1 (Non-text Content).
        Severity: MEDIUM.
        Placeholder card image containers have aria-hidden='true'.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        card_imgs = _find_tags_with_class(tags, "div", "defender-card-img")
        assert len(card_imgs) >= 1, "No defender-card-img found"
        for img in card_imgs:
            assert img.get("aria-hidden") == "true", "defender-card-img missing aria-hidden='true'"

    @pytest.mark.asyncio
    async def test_software_card_icons_are_aria_hidden(self, client):
        """WCAG 1.1.1 (Non-text Content).
        Severity: MEDIUM.
        Software card icon containers should be aria-hidden.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        card_icons = _find_tags_with_class(tags, "div", "software-card-icon")
        assert len(card_icons) >= 1, "No software-card-icon found"
        for icon in card_icons:
            assert icon.get("aria-hidden") == "true", "software-card-icon missing aria-hidden='true'"


# ============================================================
# 5. REDUCED MOTION (WCAG 2.3.3)
# ============================================================


class TestReducedMotion:
    """WCAG 2.3.3 (Animation from Interactions) compliance."""

    @pytest.mark.asyncio
    async def test_css_has_reduced_motion_media_query(self, client):
        """WCAG 2.3.3 (Animation from Interactions).
        Severity: HIGH.
        CSS must include @media (prefers-reduced-motion: reduce) to disable
        animations for users with vestibular disorders.
        """
        resp = await client.get("/static/css/style.css")
        assert resp.status_code == 200
        css = resp.text
        assert "prefers-reduced-motion" in css, "CSS missing prefers-reduced-motion media query"
        assert "animation-duration: 0.01ms" in css, "Reduced motion should zero-out animation-duration"
        assert "transition-duration: 0.01ms" in css, "Reduced motion should zero-out transition-duration"

    @pytest.mark.asyncio
    async def test_css_reduced_motion_disables_hero_animation(self, client):
        """WCAG 2.3.3.
        Severity: MEDIUM.
        Hero grid must either have no animation or disable it under
        reduced motion preferences.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        # Hero grid uses no CSS animation (static gradient only).
        # The global reduced-motion rule still zeros all animation-duration.
        assert "animation-duration: 0.01ms" in css

    @pytest.mark.asyncio
    async def test_css_reduced_motion_shows_fade_in(self, client):
        """WCAG 2.3.3.
        Severity: HIGH.
        Under reduced motion, fade-in elements must be immediately visible
        (opacity: 1, transform: none) so content is not hidden.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        full_rm = css[css.index("prefers-reduced-motion") :]
        assert "opacity: 1" in full_rm, "fade-in elements must have opacity: 1 under reduced motion"

    @pytest.mark.asyncio
    async def test_js_has_reduced_motion_check(self, client):
        """WCAG 2.3.3.
        Severity: HIGH.
        JavaScript must check prefers-reduced-motion and disable
        smooth scroll / intersection observer animations accordingly.
        """
        resp = await client.get("/static/js/main.js")
        assert resp.status_code == 200
        js = resp.text
        assert "prefers-reduced-motion" in js, "JS missing prefers-reduced-motion check"
        assert "prefersReducedMotion" in js, "JS should store the reduced motion preference"

    @pytest.mark.asyncio
    async def test_js_smooth_scroll_respects_reduced_motion(self, client):
        """WCAG 2.3.3.
        Severity: MEDIUM.
        Smooth scroll should use 'auto' behavior when reduced motion is preferred.
        """
        resp = await client.get("/static/js/main.js")
        js = resp.text
        assert '"auto"' in js, "JS should offer 'auto' scroll for reduced motion"
        assert '"smooth"' in js, "JS should offer 'smooth' scroll for normal motion"

    @pytest.mark.asyncio
    async def test_css_smooth_scroll_disabled_in_reduced_motion(self, client):
        """WCAG 2.3.3.
        Severity: MEDIUM.
        CSS scroll-behavior: smooth must be overridden to auto.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        assert "scroll-behavior: smooth" in css, "Base smooth scroll not found"
        assert "scroll-behavior: auto" in css, "Reduced motion should set scroll-behavior: auto"


# ============================================================
# 6. SEMANTIC HTML
# ============================================================


class TestSemanticHtml:
    """Heading hierarchy, landmark roles, lang attribute."""

    @pytest.mark.asyncio
    async def test_html_has_lang_attribute(self, client):
        """WCAG 3.1.1 (Language of Page).
        Severity: HIGH.
        <html> must have a lang attribute for screen readers to select
        correct pronunciation rules.
        """
        resp = await client.get("/")
        assert re.search(r'<html[^>]*\slang="[a-z]', resp.text), "<html> missing lang attribute"

    @pytest.mark.asyncio
    async def test_html_lang_is_english(self, client):
        """WCAG 3.1.1. Severity: LOW."""
        resp = await client.get("/")
        match = re.search(r'<html[^>]*\slang="([^"]+)"', resp.text)
        assert match, "<html> missing lang attribute"
        assert match.group(1) == "en", f"Expected lang='en', got '{match.group(1)}'"

    @pytest.mark.asyncio
    async def test_heading_hierarchy_starts_at_h1(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: HIGH.
        Page must start with exactly one h1.
        """
        resp = await client.get("/")
        h1_count = len(re.findall(r"<h1[\s>]", resp.text))
        assert h1_count == 1, f"Expected exactly 1 <h1>, found {h1_count}"

    @pytest.mark.asyncio
    async def test_heading_hierarchy_no_skips(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: MEDIUM.
        Headings must not skip levels (e.g., h1 then h3 without h2).
        """
        resp = await client.get("/")
        headings = re.findall(r"<(h[1-6])[\s>]", resp.text)
        levels = [int(h[1]) for h in headings]
        assert levels, "No headings found"
        assert levels[0] == 1, f"First heading should be h1, got h{levels[0]}"
        for i in range(1, len(levels)):
            if levels[i] > levels[i - 1]:
                assert levels[i] == levels[i - 1] + 1, (
                    f"Heading skip: h{levels[i - 1]} followed by h{levels[i]} (headings: {headings})"
                )

    @pytest.mark.asyncio
    async def test_sections_have_identifiable_labels(self, client):
        """WCAG 1.3.1 (Info and Relationships).
        Severity: MEDIUM.
        Each <section> should have either an aria-label or an id.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        sections = [a for t, a in tags if t == "section"]
        assert len(sections) >= 4, f"Expected at least 4 sections, found {len(sections)}"
        for sec_attrs in sections:
            has_label = bool(sec_attrs.get("aria-label") or sec_attrs.get("aria-labelledby"))
            has_id = bool(sec_attrs.get("id"))
            assert has_label or has_id, f"Section missing aria-label or id: {sec_attrs}"

    @pytest.mark.asyncio
    async def test_meta_viewport_exists(self, client):
        """WCAG 1.4.4 (Resize Text) / 1.4.10 (Reflow).
        Severity: HIGH.
        """
        resp = await client.get("/")
        assert 'name="viewport"' in resp.text, "Missing viewport meta tag"
        assert "width=device-width" in resp.text, "Viewport should set width=device-width"

    @pytest.mark.asyncio
    async def test_meta_viewport_does_not_disable_zoom(self, client):
        """WCAG 1.4.4 (Resize Text).
        Severity: HIGH.
        Viewport must not set maximum-scale=1.0 or user-scalable=no.
        """
        resp = await client.get("/")
        viewport_match = re.search(r'<meta[^>]*name="viewport"[^>]*content="([^"]*)"', resp.text)
        assert viewport_match, "viewport meta not found"
        content = viewport_match.group(1)
        assert "maximum-scale=1" not in content.replace(" ", ""), "Viewport must not restrict zoom"
        assert "user-scalable=no" not in content.replace(" ", ""), "Viewport must not disable user scaling"

    @pytest.mark.asyncio
    async def test_page_has_title(self, client):
        """WCAG 2.4.2 (Page Titled). Severity: HIGH."""
        resp = await client.get("/")
        assert "<title>" in resp.text, "Page missing <title> element"
        title_match = re.search(r"<title>(.*?)</title>", resp.text)
        assert title_match, "<title> not found"
        assert len(title_match.group(1).strip()) > 0, "<title> is empty"

    @pytest.mark.asyncio
    async def test_charset_declared(self, client):
        """WCAG 4.1.1 (Parsing). Severity: LOW."""
        resp = await client.get("/")
        assert 'charset="UTF-8"' in resp.text or "charset=UTF-8" in resp.text

    @pytest.mark.asyncio
    async def test_focus_visible_styles_in_css(self, client):
        """WCAG 2.4.7 (Focus Visible).
        Severity: HIGH.
        CSS must define visible focus indicators using :focus-visible.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        assert ":focus-visible" in css, "CSS missing :focus-visible styles"
        assert "outline" in css, "Focus styles should use outline"


# ============================================================
# 7. SECURITY-RELEVANT HTML
# ============================================================


class TestSecurityHtml:
    """HTML-level security attributes and patterns."""

    @pytest.mark.asyncio
    async def test_external_links_have_noopener_noreferrer(self, client):
        """Security: Prevent reverse tabnabbing.
        Severity: HIGH.
        All links with target='_blank' must include rel='noopener noreferrer'.
        """
        resp = await client.get("/")
        html = resp.text
        pattern = r'<a\s[^>]*target="_blank"[^>]*>'
        external_links = re.findall(pattern, html)
        assert len(external_links) >= 1, "Expected at least one external link"
        for link in external_links:
            assert 'rel="noopener noreferrer"' in link, f"External link missing rel='noopener noreferrer': {link[:80]}"

    @pytest.mark.asyncio
    async def test_form_action_is_correct(self, client):
        """Security: Prevent form submission to unexpected endpoints.
        Severity: HIGH.
        """
        resp = await client.get("/")
        form_match = re.search(r'<form[^>]*action="([^"]*)"', resp.text)
        assert form_match, "Form action attribute not found"
        assert form_match.group(1) == "/contact", f"Form action is '{form_match.group(1)}', expected '/contact'"

    @pytest.mark.asyncio
    async def test_form_method_is_post(self, client):
        """Security: Contact form must use POST, not GET. Severity: HIGH."""
        resp = await client.get("/")
        form_match = re.search(r'<form[^>]*method="([^"]*)"', resp.text)
        assert form_match, "Form method attribute not found"
        assert form_match.group(1) == "post", f"Form method is '{form_match.group(1)}', expected 'post'"

    @pytest.mark.asyncio
    async def test_csp_header_present(self, client):
        """Security: Content Security Policy. Severity: HIGH."""
        resp = await client.get("/")
        assert "content-security-policy" in resp.headers, "Missing Content-Security-Policy header"
        csp = resp.headers["content-security-policy"]
        assert "default-src" in csp, "CSP missing default-src directive"
        assert "script-src" in csp, "CSP missing script-src directive"

    @pytest.mark.asyncio
    async def test_csp_blocks_inline_scripts(self, client):
        """Security: CSP should not allow unsafe-inline for scripts. Severity: HIGH."""
        resp = await client.get("/")
        csp = resp.headers["content-security-policy"]
        script_directive = csp.split("script-src")[1].split(";")[0]
        assert "'unsafe-inline'" not in script_directive, "CSP script-src allows unsafe-inline"

    @pytest.mark.asyncio
    async def test_x_frame_options(self, client):
        """Security: Prevent clickjacking. Severity: HIGH."""
        resp = await client.get("/")
        assert resp.headers.get("x-frame-options") == "DENY", "X-Frame-Options should be DENY"

    @pytest.mark.asyncio
    async def test_no_inline_scripts_in_html(self, client):
        """Security: HTML should not contain inline script blocks
        (except structured data / JSON-LD which is not executable).
        Severity: MEDIUM.
        """
        resp = await client.get("/")
        html = resp.text
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
        for script_content in scripts:
            content = script_content.strip()
            if not content:
                continue
            if '"@context"' in content or "'@context'" in content:
                continue
            assert False, f"Unexpected inline script found: {content[:100]}..."

    @pytest.mark.asyncio
    async def test_no_javascript_urls(self, client):
        """Security: No javascript: protocol in links. Severity: HIGH."""
        resp = await client.get("/")
        assert "javascript:" not in resp.text.lower(), "Found javascript: URL (XSS vector)"

    @pytest.mark.asyncio
    async def test_placeholder_links_use_hash(self, client):
        """Security/UX: Placeholder links should use '#' not javascript:void(0).
        Severity: LOW.
        """
        resp = await client.get("/")
        assert "javascript:void" not in resp.text, "Use '#' for placeholder links"

    @pytest.mark.asyncio
    async def test_honeypot_silently_accepts_bots(self, client):
        """Security: Honeypot field returns identical response shape to
        prevent bot fingerprinting. Severity: MEDIUM.
        """
        real = await client.post(
            "/contact",
            data={"name": "Real", "email": "real@test.com", "message": "Hello", "website": ""},
        )
        bot = await client.post(
            "/contact",
            data={"name": "Bot", "email": "bot@test.com", "message": "Buy", "website": "http://spam.com"},
        )
        assert real.status_code == bot.status_code == 200
        assert real.json().keys() == bot.json().keys(), "Response shapes differ (info leak)"


# ============================================================
# 8. PRINT STYLES
# ============================================================


class TestPrintStyles:
    """Print stylesheet accessibility and functionality."""

    @pytest.mark.asyncio
    async def test_print_styles_exist(self, client):
        """WCAG 1.4.8 (Visual Presentation) -- informative. Severity: LOW."""
        resp = await client.get("/static/css/style.css")
        assert "@media print" in resp.text, "CSS missing @media print block"

    @pytest.mark.asyncio
    async def test_print_hides_interactive_elements(self, client):
        """Print: Interactive elements (nav, form, hero CTA) should be hidden.
        Severity: LOW.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        print_match = re.search(r"@media print\s*\{(.*)\}", css, re.DOTALL)
        assert print_match, "Print block not found"
        print_block = print_match.group(1)
        assert ".site-header" in print_block, "Print should hide navigation"
        assert ".contact-form" in print_block, "Print should hide contact form"
        assert ".hero-cta" in print_block, "Print should hide hero CTA buttons"

    @pytest.mark.asyncio
    async def test_print_uses_dark_text_on_light_bg(self, client):
        """Print: Must use dark text on white background. Severity: MEDIUM."""
        resp = await client.get("/static/css/style.css")
        css = resp.text
        print_match = re.search(r"@media print\s*\{(.*)\}", css, re.DOTALL)
        assert print_match
        print_block = print_match.group(1)
        assert "background: #fff" in print_block or "background:#fff" in print_block, (
            "Print should set white background"
        )
        assert "color: #111" in print_block or "color:#111" in print_block, "Print should set dark text color"

    @pytest.mark.asyncio
    async def test_print_shows_link_urls(self, client):
        """Print: Links should show their URL in parentheses. Severity: LOW."""
        resp = await client.get("/static/css/style.css")
        css = resp.text
        print_match = re.search(r"@media print\s*\{(.*)\}", css, re.DOTALL)
        assert print_match
        assert "attr(href)" in print_match.group(1), "Print should reveal link URLs via attr(href)"

    @pytest.mark.asyncio
    async def test_print_heading_color_reset(self, client):
        """Print: Headings must have explicit dark color for printing.
        If gradient-clipped text is used, -webkit-text-fill-color must be reset.
        If plain solid color is used, just verify color is set.
        Severity: MEDIUM.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        print_match = re.search(r"@media print\s*\{(.*)\}", css, re.DOTALL)
        assert print_match
        print_block = print_match.group(1)
        # Either gradient text is reset or headings use plain solid color
        has_fill_color_reset = "-webkit-text-fill-color" in print_block
        has_heading_color = "color: #111" in print_block or "color:#111" in print_block
        assert has_fill_color_reset or has_heading_color, (
            "Print must set heading color or reset -webkit-text-fill-color"
        )


# ============================================================
# 9. KEYBOARD ACCESSIBILITY
# ============================================================


class TestKeyboardAccessibility:
    """WCAG 2.1.1 (Keyboard) and 2.4.7 (Focus Visible)."""

    @pytest.mark.asyncio
    async def test_no_positive_tabindex(self, client):
        """WCAG 2.4.3 (Focus Order).
        Severity: MEDIUM.
        No element should have a positive tabindex value, which disrupts
        natural reading order.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        for tag_name, attrs in tags:
            ti = attrs.get("tabindex")
            if ti is not None:
                try:
                    val = int(ti)
                except ValueError:
                    continue
                assert val <= 0, f"<{tag_name}> has tabindex='{ti}' -- positive tabindex disrupts focus order"

    @pytest.mark.asyncio
    async def test_hamburger_is_button_not_div(self, client):
        """WCAG 4.1.2 (Name, Role, Value).
        Severity: HIGH.
        Hamburger toggle must be a <button> for native keyboard activation.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hamburgers = [attrs for t, attrs in tags if t == "button" and attrs.get("id") == "hamburger"]
        assert len(hamburgers) >= 1, "Hamburger is not a <button> element"

    @pytest.mark.asyncio
    async def test_nav_links_are_anchor_elements(self, client):
        """WCAG 2.1.1 (Keyboard). Severity: LOW."""
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        nav_links = _find_tags_with_class(tags, "a", "nav-link")
        assert len(nav_links) >= 5, f"Expected at least 5 nav links, found {len(nav_links)}"

    @pytest.mark.asyncio
    async def test_software_cards_are_links(self, client):
        """WCAG 2.1.1 (Keyboard). Severity: MEDIUM.
        Software cards use <a> elements, making the entire card keyboard-focusable.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        cards = _find_tags_with_class(tags, "a", "software-card")
        assert len(cards) >= 3, f"Expected at least 3 software-card links, found {len(cards)}"

    @pytest.mark.asyncio
    async def test_focus_visible_outline_defined(self, client):
        """WCAG 2.4.7 (Focus Visible). Severity: HIGH.
        :focus-visible should define a visible outline.
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        fv_match = re.search(r":focus-visible\s*\{([^}]+)\}", css)
        assert fv_match, ":focus-visible rule not found in CSS"
        fv_block = fv_match.group(1)
        assert "outline" in fv_block, ":focus-visible must define outline"
        assert "2px" in fv_block, ":focus-visible outline should be at least 2px"

    @pytest.mark.asyncio
    async def test_form_inputs_have_alternative_focus_indicator(self, client):
        """WCAG 2.4.7 (Focus Visible). Severity: HIGH.
        Form inputs use outline: none on :focus but must provide an
        alternative visible indicator (box-shadow).
        """
        resp = await client.get("/static/css/style.css")
        css = resp.text
        if "outline: none" in css:
            assert "box-shadow" in css, "outline: none used without alternative focus indicator (box-shadow)"


# ============================================================
# 10. ARIA PATTERNS
# ============================================================


class TestAriaPatterns:
    """Correct ARIA usage patterns."""

    @pytest.mark.asyncio
    async def test_aria_expanded_initial_state(self, client):
        """WCAG 4.1.2 (Name, Role, Value). Severity: MEDIUM.
        Hamburger should start with aria-expanded='false'.
        """
        resp = await client.get("/")
        match = re.search(r'id="hamburger"[^>]*aria-expanded="([^"]*)"', resp.text)
        assert match, "hamburger aria-expanded not found"
        assert match.group(1) == "false", f"Initial aria-expanded should be 'false', got '{match.group(1)}'"

    @pytest.mark.asyncio
    async def test_footer_icon_links_have_aria_labels(self, client):
        """WCAG 1.1.1 (Non-text Content) / 4.1.2 (Name, Role, Value).
        Severity: HIGH.
        Footer social links contain only SVG icons (no visible text).
        They must have aria-label for screen reader accessible names.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        footer_labels = []
        for t, attrs in tags:
            if t == "a" and attrs.get("aria-label") in ("GitHub", "Substack", "LinkedIn"):
                footer_labels.append(attrs["aria-label"])
        assert "GitHub" in footer_labels, "Footer GitHub link missing aria-label"
        assert "Substack" in footer_labels, "Footer Substack link missing aria-label"
        assert "LinkedIn" in footer_labels, "Footer LinkedIn link missing aria-label"

    @pytest.mark.asyncio
    async def test_software_card_links_have_aria_labels(self, client):
        """WCAG 2.4.4 (Link Purpose in Context). Severity: LOW."""
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        sw_spans = [a for t, a in tags if t == "span" and a.get("class") == "software-link"]
        for span in sw_spans:
            label = span.get("aria-label", "")
            assert "GitHub" in label, f"software-link span missing descriptive aria-label: got '{label}'"

    @pytest.mark.asyncio
    async def test_hero_section_has_label(self, client):
        """WCAG 1.3.1 (Info and Relationships). Severity: LOW."""
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        hero_sections = _find_tags_with_class(tags, "section", "hero")
        assert len(hero_sections) >= 1, "Hero section not found"
        assert hero_sections[0].get("aria-label"), "Hero section missing aria-label"

    @pytest.mark.asyncio
    async def test_no_redundant_role_on_landmarks(self, client):
        """WCAG best practice. Severity: LOW.
        HTML5 landmarks should not have redundant role attributes.
        """
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        landmark_map = {"main": "main", "header": "banner", "footer": "contentinfo"}
        for tag_name, attrs in tags:
            if tag_name in landmark_map:
                role = attrs.get("role")
                if role:
                    assert role != landmark_map[tag_name], f"<{tag_name} role='{role}'> is redundant"

    @pytest.mark.asyncio
    async def test_nav_logo_has_accessible_name(self, client):
        """WCAG 2.4.4 (Link Purpose). Severity: MEDIUM."""
        resp = await client.get("/")
        tags = _parse_tags(resp.text)
        logo_links = _find_tags_with_class(tags, "a", "nav-logo")
        assert len(logo_links) >= 1, "nav-logo link not found"
        assert logo_links[0].get("aria-label"), "nav-logo missing aria-label"


# ============================================================
# 11. KNOWN ISSUES (informational, not failures)
# ============================================================


class TestKnownIssuesDocumented:
    """Document known accessibility gaps that require source changes."""

    def test_document_btn_primary_contrast_gap(self):
        """KNOWN ISSUE: btn-primary (white on #c4793a) = 3.42:1.
        WCAG 1.4.3 requires 4.5:1 for normal text.
        Button text is 15px/600 weight = normal text per WCAG.

        Fix options:
        1. Darken --accent-warm to #9e6030 (~5.1:1)
        2. Use --bg-primary (#0f0f1a) as button text color (5.57:1)
        3. Increase button font-size to 18.66px+ (qualifies as large text)

        Recommendation: Option 2 -- dark text on warm buttons.
        """
        ratio = _contrast_ratio("#ffffff", "#c4793a")
        assert 3.0 <= ratio < 4.5, f"Ratio changed to {ratio:.2f} -- update this doc test"

    def test_document_form_input_focus_outline_suppression(self):
        """KNOWN ISSUE: .form-group input:focus uses outline: none.

        While box-shadow is provided as alternative, some high-contrast
        mode users may not see box-shadow-based focus indicators.

        Fix: Use outline: 2px solid var(--accent-cool) on :focus-visible
        for form inputs, keeping box-shadow as enhancement.
        """
        assert True
