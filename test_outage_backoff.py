"""Tests for outage-aware backoff helpers added in v0.7.0."""
from __future__ import annotations

import datetime

import pytest

from wdgwars_api_tester import (
    OUTAGE_VERDICT_TAGS,
    Result,
    _backoff_sleep_seconds,
    _outage_share,
    _seconds_to_next_midnight_utc,
)


def _mkres(verdict: str, status: int = 200) -> Result:
    return Result(
        probe="p", host="x", auth="a", method="GET", url="",
        status=status, elapsed_ms=10, body_len=0, body_md5="",
        content_type="", cf_cache_status="", x_request_id="",
        server="", verdict=verdict,
    )


class TestOutageShare:
    def test_empty(self):
        assert _outage_share([]) == 0.0

    def test_all_healthy(self):
        assert _outage_share([_mkres("OK")] * 10) == 0.0

    def test_all_429(self):
        assert _outage_share([_mkres("429", 429)] * 10) == 1.0

    def test_30_percent(self):
        results = [_mkres("429", 429)] * 3 + [_mkres("OK")] * 7
        assert _outage_share(results) == pytest.approx(0.30)

    def test_below_threshold(self):
        results = [_mkres("429", 429)] * 5 + [_mkres("OK")] * 15
        assert _outage_share(results) == pytest.approx(0.25)

    def test_transport_errors_count(self):
        results = [_mkres("ERROR", 0)] * 5 + [_mkres("OK")] * 5
        assert _outage_share(results) == 0.5

    def test_dead_does_not_count(self):
        # DEAD endpoints (route not bound) are a baseline, not an outage signal
        results = [_mkres("DEAD", 404)] * 3 + [_mkres("OK")] * 7
        assert _outage_share(results) == 0.0

    def test_auth_required_does_not_count(self):
        results = [_mkres("AUTH-REQUIRED", 401)] * 5 + [_mkres("OK")] * 5
        assert _outage_share(results) == 0.0

    def test_429_by_status_alone(self):
        # If verdict somehow isn't tagged "429" but status is 429, still counts
        r = _mkres("OK", 429)  # contradictory but defensive
        assert _outage_share([r] + [_mkres("OK")] * 9) == 0.1

    def test_outage_verdict_tags_set(self):
        assert OUTAGE_VERDICT_TAGS == {"ERROR", "429"}


class TestSecondsToNextMidnightUtc:
    def test_at_noon_utc(self):
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        secs = _seconds_to_next_midnight_utc(noon)
        assert secs == 12 * 3600

    def test_one_minute_before_midnight(self):
        ts = datetime.datetime(2026, 6, 3, 23, 59, 0, tzinfo=datetime.timezone.utc).timestamp()
        secs = _seconds_to_next_midnight_utc(ts)
        assert secs == 60

    def test_at_midnight_floor(self):
        ts = datetime.datetime(2026, 6, 3, 0, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        secs = _seconds_to_next_midnight_utc(ts)
        # Exactly at midnight, next midnight is 24h away
        assert secs == 24 * 3600

    def test_floor_at_60s(self):
        # Even at 23:59:30, floor returns at least 60s
        ts = datetime.datetime(2026, 6, 3, 23, 59, 30, tzinfo=datetime.timezone.utc).timestamp()
        assert _seconds_to_next_midnight_utc(ts) >= 60


class TestBackoffSleepSeconds:
    def test_streak_1_doubles_base(self):
        # base=1800, streak=1 → 2× = 3600s, cap=86400, far from midnight
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        assert _backoff_sleep_seconds(1800, 1, 86400, now=noon) == 3600

    def test_streak_5_caps_at_32x(self):
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        # base=100, streak=5 → 32× = 3200, midnight = 43200s, cap=86400 → 3200
        assert _backoff_sleep_seconds(100, 5, 86400, now=noon) == 3200

    def test_streak_10_clamped_to_5(self):
        # multiplier maxes out at 32× (streak=5+)
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        assert _backoff_sleep_seconds(100, 10, 86400, now=noon) == 3200

    def test_clamps_to_cap(self):
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        # base=1800, streak=4 → 16× = 28800, but cap=3600 → 3600
        assert _backoff_sleep_seconds(1800, 4, 3600, now=noon) == 3600

    def test_clamps_to_midnight(self):
        # Late in day: 1h to midnight, base=1800, streak=3 → 8× = 14400, but
        # midnight clamp = 3600 → 3600
        late = datetime.datetime(2026, 6, 3, 23, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        assert _backoff_sleep_seconds(1800, 3, 86400, now=late) == 3600

    def test_never_below_base(self):
        # If cap < base, still sleep at least base (no foot-gun where user
        # sets cap too low and we end up busy-looping)
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        assert _backoff_sleep_seconds(1800, 1, 100, now=noon) == 1800

    def test_streak_zero_treated_as_one(self):
        # Defensive: streak=0 shouldn't divide-by-zero or no-op; treated as 1.
        noon = datetime.datetime(2026, 6, 3, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
        assert _backoff_sleep_seconds(1800, 0, 86400, now=noon) == 3600
