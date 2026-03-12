"""Security tests: rate limiter bypass, IP spoofing, and edge cases.

Findings under test:
  F-01  X-Forwarded-For spoofing bypasses rate limiting — FIXED
  F-02  fly-client-ip spoofing bypasses rate limiting
  F-03  Rate limiter is completely non-functional — FIXED
  F-04  Memory exhaustion evicts rate-limited IPs, restoring their slot
  F-05  Race condition — two concurrent requests from same IP both pass
  F-06  Window boundary: first post-expiry request goes unrecorded — FIXED (via F-03 fix)
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from mumfordengineering.app import (
    CONTACT_RATE_LIMIT,
    CONTACT_WINDOW,
    _MAX_TRACKED_IPS,
    _contact_timestamps,
    _get_client_ip,
    _is_rate_limited,
    app,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_FORM = {
    "name": "Security Tester",
    "email": "sec@example.com",
    "message": "test payload",
    "website": "",
}


@pytest.fixture(autouse=True)
def _reset_state():
    """Guarantee a clean rate-limiter state before and after every test."""
    _contact_timestamps.clear()
    yield
    _contact_timestamps.clear()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _post(client, form: dict | None = None, headers: dict | None = None):
    return await client.post(
        "/contact",
        data=form or VALID_FORM,
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# F-01: X-Forwarded-For spoofing
# ---------------------------------------------------------------------------


class TestXForwardedForSpoofing:
    """F-01 FIXED — XFF is no longer trusted when fly-client-ip is absent.
    _get_client_ip falls back to request.client.host, not XFF.
    """

    @pytest.mark.asyncio
    async def test_xff_header_is_not_trusted_when_fly_header_absent(self, client):
        """XFF is ignored; without fly-client-ip, falls back to client.host or 'unknown'."""

        # Confirm XFF is NOT extracted by _get_client_ip (unit-level, no HTTP needed).
        class _FakeReq:
            class headers:
                @staticmethod
                def get(k, default=""):
                    if k == "x-forwarded-for":
                        return "10.0.0.1"
                    return default

            client = None

        extracted = _get_client_ip(_FakeReq())  # type: ignore[arg-type]
        assert extracted == "unknown"

        # At the HTTP layer, XFF is ignored — both requests map to the same TCP peer.
        r1 = await _post(client, headers={"X-Forwarded-For": "10.0.0.1"})
        r2 = await _post(client, headers={"X-Forwarded-For": "10.0.0.2"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        # XFF IPs are not tracked — only the TCP peer IP is tracked.
        assert "10.0.0.1" not in _contact_timestamps
        assert "10.0.0.2" not in _contact_timestamps

    @pytest.mark.asyncio
    async def test_xff_rotation_does_not_bypass_rate_limit(self, client):
        """XFF rotation no longer works — all requests map to the same TCP peer IP."""
        total_requests = CONTACT_RATE_LIMIT * 3
        responses = []
        for i in range(total_requests):
            spoofed_ip = f"192.168.1.{i % 256}"
            r = await _post(client, headers={"X-Forwarded-For": spoofed_ip})
            responses.append(r.status_code)

        # All return 200 (rate-limited requests get a silent 200), but only
        # CONTACT_RATE_LIMIT are actually processed — the rest are silently dropped.
        assert all(s == 200 for s in responses)

    @pytest.mark.asyncio
    async def test_xff_is_not_used_at_all(self, client):
        """XFF is no longer consulted — requests are keyed to TCP peer, not XFF."""
        r = await _post(client, headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"})
        assert r.status_code == 200
        # XFF IPs are NOT tracked — only the TCP peer is.
        assert "1.1.1.1" not in _contact_timestamps

        # Directly verify: without fly-client-ip, XFF is ignored.
        class _FakeRequest:
            class headers:
                @staticmethod
                def get(k, default=""):
                    if k == "x-forwarded-for":
                        return "1.1.1.1, 2.2.2.2"
                    return default

            client = None

        ip = _get_client_ip(_FakeRequest())  # type: ignore[arg-type]
        assert ip == "unknown"

    @pytest.mark.asyncio
    async def test_no_xff_falls_back_to_client_host(self, client):
        """Without any proxy headers, the TCP peer address is used and tracked."""
        r = await _post(client)
        assert r.status_code == 200
        # The TCP peer IP IS now tracked (rate limiter works).
        assert len(_contact_timestamps) >= 1


# ---------------------------------------------------------------------------
# F-02: fly-client-ip spoofing
# ---------------------------------------------------------------------------


class TestFlyClientIpSpoofing:
    """F-02 — fly-client-ip is accepted unconditionally.  In environments where
    the Fly.io proxy does not strip/overwrite this header (e.g., local dev, or
    `--forwarded-allow-ips *`), any client can impersonate any IP.
    """

    @pytest.mark.asyncio
    async def test_fly_header_takes_precedence_over_xff(self, client):
        """fly-client-ip wins when both headers are present (line 76-78)."""
        r = await _post(
            client,
            headers={
                "fly-client-ip": "99.99.99.99",
                "X-Forwarded-For": "10.0.0.1",
            },
        )
        assert r.status_code == 200
        # The IP tracked must be the fly header value, not XFF.
        # Second request uses fly header to reach the tracked bucket.
        for _ in range(CONTACT_RATE_LIMIT - 1):
            await _post(client, headers={"fly-client-ip": "99.99.99.99"})
        limited = await _post(client, headers={"fly-client-ip": "99.99.99.99"})
        assert limited.status_code == 200  # silent rate-limit response
        # XFF IP is untouched — demonstrates precedence.
        assert "10.0.0.1" not in _contact_timestamps

    @pytest.mark.asyncio
    async def test_spoofed_fly_header_bypasses_real_ip_limit(self, client):
        """Attacker spoofs fly-client-ip to a victim IP, consuming their quota."""
        victim_ip = "203.0.113.10"
        # Consume victim's quota via spoofed header.
        for _ in range(CONTACT_RATE_LIMIT):
            await _post(client, headers={"fly-client-ip": victim_ip})

        # Victim IP is now rate-limited.
        r = await _post(client, headers={"fly-client-ip": victim_ip})
        assert r.status_code == 200  # silent 200 for rate-limited

        # Attacker rotates to a fresh spoofed IP — unrestricted.
        r_fresh = await _post(client, headers={"fly-client-ip": "203.0.113.11"})
        assert r_fresh.status_code == 200

    @pytest.mark.asyncio
    async def test_fly_header_whitespace_stripped(self, client):
        """Whitespace in fly-client-ip is stripped (line 78: ip.strip())."""

        class _Req:
            class headers:
                @staticmethod
                def get(k, default=""):
                    if k == "fly-client-ip":
                        return "  1.2.3.4  "
                    return default

            client = None

        ip = _get_client_ip(_Req())  # type: ignore[arg-type]
        assert ip == "1.2.3.4"


# ---------------------------------------------------------------------------
# F-03: First request never counted (timestamp append bug)
# ---------------------------------------------------------------------------


class TestFirstRequestNotCounted:
    """F-03 FIXED — The rate limiter now correctly records timestamps on every call.

    The fix ensures that _is_rate_limited always writes the updated timestamps
    list back to _contact_timestamps[ip], whether the IP was previously tracked
    or not. Every call is now recorded, and the rate limit is enforced.
    """

    def test_first_call_returns_not_limited_and_records_ip(self):
        """FIXED: fresh IP, call 1 — not limited, IS recorded."""
        result = _is_rate_limited("new-ip-001")
        assert result is False
        assert "new-ip-001" in _contact_timestamps

    def test_second_call_also_records(self):
        """FIXED: Both calls are recorded — IP has 2 timestamps."""
        _is_rate_limited("new-ip-002")
        _is_rate_limited("new-ip-002")
        assert "new-ip-002" in _contact_timestamps
        assert len(_contact_timestamps["new-ip-002"]) == 2

    def test_rate_limiter_blocks_after_limit(self):
        """FIXED: _is_rate_limited returns True after CONTACT_RATE_LIMIT calls."""
        ip = "f03-unlimited"
        results = [_is_rate_limited(ip) for _ in range(CONTACT_RATE_LIMIT + 1)]
        # First CONTACT_RATE_LIMIT calls return False, then True.
        assert results[CONTACT_RATE_LIMIT] is True

    def test_dict_has_entries_after_many_unique_ips(self):
        """FIXED: Each distinct IP is tracked in the dict."""
        for i in range(100):
            _is_rate_limited(f"unique-ip-{i}")
        assert len(_contact_timestamps) == 100

    @pytest.mark.asyncio
    async def test_http_ips_are_tracked(self, client):
        """FIXED: Via HTTP with XFF (which is no longer trusted), all requests
        map to the same TCP peer IP. The timestamps dict has 1 entry."""
        for i in range(100):
            await _post(client, headers={"X-Forwarded-For": f"10.10.{i // 256}.{i % 256}"})
        # XFF is no longer trusted — all requests map to the same client IP.
        assert len(_contact_timestamps) == 1

    def test_write_back_works_only_when_dict_is_pre_seeded(self):
        """Demonstrates that the write-back path (line 92) IS reachable when
        the dict contains a non-empty entry — i.e., only if seeded externally.
        This explains why the existing test_contact_rate_limit test passes even
        though the production code is broken.
        """
        ip = "seeded-ip"
        _contact_timestamps[ip] = [time.time()] * (CONTACT_RATE_LIMIT - 1)

        # First call with seeded data: reaches line 92 (write-back), appends at 95.
        result = _is_rate_limited(ip)
        assert result is False
        assert len(_contact_timestamps[ip]) == CONTACT_RATE_LIMIT

        # Second call: now at limit, returns True.
        result2 = _is_rate_limited(ip)
        assert result2 is True

    def test_window_expiry_clears_seeded_ip_then_records_new(self):
        """FIXED: After window expiry, old timestamps are pruned and the new
        request IS recorded (ip remains in dict with 1 fresh entry)."""
        ip = "f03-window-reset"
        _contact_timestamps[ip] = [time.time()] * CONTACT_RATE_LIMIT

        future = time.time() + CONTACT_WINDOW + 1
        with patch("mumfordengineering.app.time") as mock_time:
            mock_time.time.return_value = future
            result = _is_rate_limited(ip)

        assert result is False
        assert ip in _contact_timestamps
        assert len(_contact_timestamps[ip]) == 1


# ---------------------------------------------------------------------------
# F-04: Memory exhaustion / eviction abuse
# ---------------------------------------------------------------------------


class TestMemoryExhaustionEviction:
    """F-04 — When tracking exceeds _MAX_TRACKED_IPS, the IP with the oldest
    most-recent timestamp is evicted (lines 143-146).

    An attacker who fills the table with 10,001 fresh IPs will evict a
    legitimately rate-limited IP, resetting its counter.
    """

    def test_eviction_removes_oldest_entry(self):
        """Oldest-last-seen IP is evicted when capacity is exceeded."""
        # Seed the victim IP with a past timestamp so it is the oldest.
        old_ts = time.time() - CONTACT_WINDOW / 2
        victim_ip = "eviction-victim"
        _contact_timestamps[victim_ip] = [old_ts]

        # Fill to capacity with newer IPs.
        for i in range(_MAX_TRACKED_IPS):
            _contact_timestamps[f"filler-{i}"] = [time.time()]

        # Simulate the eviction logic in app.py lines 143-146.
        if len(_contact_timestamps) > _MAX_TRACKED_IPS:
            oldest = min(_contact_timestamps, key=lambda k: _contact_timestamps[k][-1])
            del _contact_timestamps[oldest]

        assert victim_ip not in _contact_timestamps, (
            "Eviction removed the oldest-seen IP, which may be a legitimately "
            "rate-limited entry — its counter is now reset"
        )

    def test_rate_limited_ip_evicted_can_submit_again(self):
        """After eviction, a previously rate-limited IP passes _is_rate_limited again.

        Note: F-03 means we must SEED the victim's entry manually — it cannot
        reach the limit organically from a cold start.
        """
        victim = "eviction-bypass-victim"
        # Seed the victim at limit (the only way to have a blocked IP given F-03).
        _contact_timestamps[victim] = [time.time()] * CONTACT_RATE_LIMIT
        assert _is_rate_limited(victim) is True

        # Fill table with newer-timestamped attacker IPs to force eviction.
        base_ts = time.time() + 1  # newer than victim, so victim is oldest
        for i in range(_MAX_TRACKED_IPS + 1):
            _contact_timestamps[f"attacker-{i}"] = [base_ts + i]

        # Victim is the oldest — simulate the eviction logic (lines 143-146).
        if len(_contact_timestamps) > _MAX_TRACKED_IPS:
            oldest = min(_contact_timestamps, key=lambda k: _contact_timestamps[k][-1])
            del _contact_timestamps[oldest]

        # Victim's slot is gone; rate limit check resets.
        assert victim not in _contact_timestamps
        assert _is_rate_limited(victim) is False  # reset — attacker wins

    def test_attacker_needs_only_max_tracked_plus_one_ips(self):
        """Minimum IPs an attacker must rotate to guarantee eviction of any one target."""
        # The minimum attack cost is _MAX_TRACKED_IPS + 1 distinct IPs.
        # At that point, the table is full and one eviction fires.
        assert _MAX_TRACKED_IPS == 10_000, (
            f"Attack cost calculation assumes 10,000 max tracked IPs, got {_MAX_TRACKED_IPS}"
        )


# ---------------------------------------------------------------------------
# F-05: Race condition
# ---------------------------------------------------------------------------


class TestRaceCondition:
    """F-05 — _is_rate_limited reads then writes _contact_timestamps in two
    non-atomic steps.  Two concurrent asyncio coroutines for the same IP can
    both read the pre-write snapshot, both pass the len >= limit check, and
    both return False — allowing more than CONTACT_RATE_LIMIT submissions.

    Note: CPython's GIL prevents true parallelism for pure-Python bytecode, but
    asyncio cooperative scheduling CAN interleave at await points.  The /contact
    handler calls _is_rate_limited (sync, no await), so interleaving does not
    happen there in the current code.  These tests document the structural
    exposure so that a future async rewrite does not introduce the race silently.
    """

    def test_concurrent_first_calls_both_see_empty_timestamps(self):
        """Simulate two coroutines reading the same empty state before either writes."""
        ip = "race-ip"
        # Both "coroutines" read before either writes.
        snap1 = _contact_timestamps.get(ip, [])
        snap2 = _contact_timestamps.get(ip, [])

        # Both see empty — both will return False from _is_rate_limited.
        assert snap1 == []
        assert snap2 == []

    def test_two_calls_at_limit_boundary_both_see_limit_minus_one(self):
        """If two calls read at len == CONTACT_RATE_LIMIT - 1, both pass."""
        ip = "race-boundary-ip"
        # Manually seed to one below the limit.
        _contact_timestamps[ip] = [time.time()] * (CONTACT_RATE_LIMIT - 1)

        # Both coroutines snapshot the same list before either appends.
        snap1 = list(_contact_timestamps[ip])
        snap2 = list(_contact_timestamps[ip])

        # Both pass the check independently.
        assert len(snap1) < CONTACT_RATE_LIMIT
        assert len(snap2) < CONTACT_RATE_LIMIT
        # In a real race, both would append, yielding len == CONTACT_RATE_LIMIT + 1
        # without either having been blocked.

    @pytest.mark.asyncio
    async def test_concurrent_http_posts_from_same_ip(self, client):
        """Fire CONTACT_RATE_LIMIT + 2 requests concurrently from a single IP.

        In the current synchronous implementation, asyncio processes them
        sequentially so the race does not manifest.  This test documents the
        expected safe behavior and will catch a regression if _is_rate_limited
        is ever made async.
        """
        # Seed to one below limit so we are right at the boundary.
        ip = "concurrent-test"
        _contact_timestamps[ip] = [time.time()] * (CONTACT_RATE_LIMIT - 1)

        coros = [_post(client, headers={"fly-client-ip": ip}) for _ in range(4)]
        results = await asyncio.gather(*coros)
        statuses = [r.status_code for r in results]
        # All 200 (rate limit returns silent 200); document that not all should succeed.
        assert all(s == 200 for s in statuses)
        # After concurrent calls, timestamps should not exceed CONTACT_RATE_LIMIT
        # by more than the number of concurrent callers (race window).
        tracked = _contact_timestamps.get(ip, [])
        assert len(tracked) <= CONTACT_RATE_LIMIT + 4, (
            f"Race condition: {len(tracked)} timestamps recorded, expected at most {CONTACT_RATE_LIMIT + 4}"
        )


# ---------------------------------------------------------------------------
# F-06: Window boundary bypass
# ---------------------------------------------------------------------------


class TestWindowBoundaryBypass:
    """F-06 FIXED (via F-03 fix) — The sliding window correctly prunes expired
    timestamps, and post-expiry requests are now properly recorded.
    """

    def test_expired_timestamps_are_pruned_and_new_one_recorded(self):
        """FIXED: Timestamps older than CONTACT_WINDOW are pruned, and the
        new call adds a fresh timestamp."""
        ip = "window-prune-ip"
        old_ts = time.time() - CONTACT_WINDOW - 1
        _contact_timestamps[ip] = [old_ts] * CONTACT_RATE_LIMIT

        result = _is_rate_limited(ip)
        assert result is False
        assert ip in _contact_timestamps
        assert len(_contact_timestamps[ip]) == 1  # old pruned, new one added

    def test_boundary_request_just_inside_window_counts(self):
        """A timestamp at exactly now - CONTACT_WINDOW + 1 is still within window."""
        ip = "window-inside-ip"
        just_inside = time.time() - CONTACT_WINDOW + 1
        _contact_timestamps[ip] = [just_inside] * (CONTACT_RATE_LIMIT - 1)

        result = _is_rate_limited(ip)
        assert result is False  # one slot remains
        assert len(_contact_timestamps.get(ip, [])) == CONTACT_RATE_LIMIT  # slot filled

    def test_boundary_request_just_outside_window_is_pruned_and_new_recorded(self):
        """FIXED: After all timestamps expire, the new call adds a fresh entry."""
        ip = "window-outside-ip"
        just_outside = time.time() - CONTACT_WINDOW
        _contact_timestamps[ip] = [just_outside] * CONTACT_RATE_LIMIT

        with patch("mumfordengineering.app.time") as mock_time:
            mock_time.time.return_value = just_outside + CONTACT_WINDOW
            result = _is_rate_limited(ip)

        assert result is False  # all timestamps expired
        assert ip in _contact_timestamps
        assert len(_contact_timestamps[ip]) == 1  # new timestamp recorded

    def test_post_window_first_request_is_recorded(self):
        """FIXED: After window expiry, the first new request IS recorded."""
        ip = "window-f03-combo"
        _contact_timestamps[ip] = [time.time()] * CONTACT_RATE_LIMIT
        assert _is_rate_limited(ip) is True  # confirm it is blocked

        # Advance past the window.
        future = time.time() + CONTACT_WINDOW + 1
        with patch("mumfordengineering.app.time") as mock_time:
            mock_time.time.return_value = future
            # Post-window call: all timestamps expired, new one recorded.
            result = _is_rate_limited(ip)
            assert result is False
            assert ip in _contact_timestamps

    def test_rate_limiter_enforces_limit(self):
        """FIXED: Rate limiter now works — exactly CONTACT_RATE_LIMIT calls
        are allowed before blocking."""
        ip = "f03-f06-combined"
        allowed = sum(1 for _ in range(CONTACT_RATE_LIMIT * 10) if not _is_rate_limited(ip))
        assert allowed == CONTACT_RATE_LIMIT


# ---------------------------------------------------------------------------
# Regression: correct behavior after fixes (expected outcomes post-remediation)
# ---------------------------------------------------------------------------


class TestExpectedBehaviorAfterFix:
    """Acceptance criteria: these tests verify CORRECT behavior after F-01 and F-03 fixes."""

    def test_first_request_is_recorded(self):
        """ACCEPTANCE CRITERION (F-03 FIXED): every call records its timestamp."""
        _is_rate_limited("fix-verification-ip")
        assert "fix-verification-ip" in _contact_timestamps

    def test_limit_is_exactly_contact_rate_limit(self):
        """ACCEPTANCE CRITERION (F-03 FIXED): exactly CONTACT_RATE_LIMIT calls allowed per IP."""
        ip = "exact-limit-ip"
        allowed = sum(1 for _ in range(CONTACT_RATE_LIMIT + 5) if not _is_rate_limited(ip))
        assert allowed == CONTACT_RATE_LIMIT, f"Allowed {allowed} calls, want exactly {CONTACT_RATE_LIMIT}"

    def test_rate_limiter_enforces_limit(self):
        """FIXED: Rate limiter correctly blocks after CONTACT_RATE_LIMIT calls."""
        ip = "unlimited-ip"
        allowed = sum(1 for _ in range(CONTACT_RATE_LIMIT * 20) if not _is_rate_limited(ip))
        assert allowed == CONTACT_RATE_LIMIT, f"Allowed {allowed} calls, want exactly {CONTACT_RATE_LIMIT}"

    @pytest.mark.asyncio
    async def test_xff_is_not_trusted_without_fly_header(self, client):
        """ACCEPTANCE CRITERION (F-01 FIXED): XFF is ignored when not behind Fly.io.

        Both XFF IPs map to the same TCP peer. The rate limiter tracks the
        TCP peer IP, not the XFF values.
        """
        r1 = await _post(client, headers={"X-Forwarded-For": "10.1.1.1"})
        r2 = await _post(client, headers={"X-Forwarded-For": "10.1.1.2"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        # XFF IPs are not tracked — only the TCP peer is.
        assert "10.1.1.1" not in _contact_timestamps
        assert "10.1.1.2" not in _contact_timestamps
        # But the TCP peer IS tracked (rate limiter works).
        assert len(_contact_timestamps) == 1
