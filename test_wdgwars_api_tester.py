#!/usr/bin/env python3
"""Unit tests for wdgwars_api_tester.

Pure-logic coverage only — no network, no fixtures. Run:

    python3 -m unittest test_wdgwars_api_tester
"""
from __future__ import annotations

import unittest

from wdgwars_api_tester import (
    Result,
    SENTINEL_PROBES,
    TELEGRAM_DELTA_LIMIT,
    TELEGRAM_TEXT_LIMIT,
    _canonical_sentinel,
    _classify_severity,
    _format_telegram_text,
    _format_webhook_payload,
    _probe_deltas,
    _redact_webhook_url,
    annotate_verdicts,
    build_probes,
    state_signature,
    summary,
)


def _dsum(improved=0, regressed=0, sideways=0, upstream_flap_count=0,
          unclassified=0):
    return {
        "improved": improved,
        "regressed": regressed,
        "sideways": sideways,
        "total_classified": improved + regressed + sideways,
        "upstream_flap_count": upstream_flap_count,
        "unclassified": unclassified,
    }


def _r(probe, host="https://wdgwars.pl", auth="none", status=200, body_md5="",
       error="", body_len=0, location="", leak_marker="") -> Result:
    return Result(
        probe=probe, host=host, auth=auth, method="GET",
        url=host + "/" + probe, status=status,
        elapsed_ms=10, body_len=body_len, body_md5=body_md5,
        content_type="text/html", cf_cache_status="", x_request_id="",
        server="", error=error, location=location, leak_marker=leak_marker,
    )


def _outage_fixture(host="https://wdgwars.pl") -> list[Result]:
    """A realistic outage snapshot: 3 unanimous sentinels, all probes DEAD.

    `stats-leak-check` carries a `leak_marker` reflecting the LSWS admin
    telemetry fingerprint that the v0.5.x outage exposed — the v0.6.1
    LEAK rule reads this field, not just status, so fixtures need to
    set it explicitly to reproduce the original "DEGRADED+LEAK" state.
    """
    dead = "543951d5e64c80ff543951d5e64c80ff"
    return [
        _r("api-sentinel-404-a", host=host, status=404, body_md5=dead, body_len=919),
        _r("api-sentinel-404-b", host=host, status=404, body_md5=dead, body_len=919),
        _r("api-sentinel-404-c", host=host, status=404, body_md5=dead, body_len=919),
        _r("non-api-sentinel-404", host=host, status=404, body_md5="5a2bce9d", body_len=22),
        _r("me", host=host, auth="valid", status=404, body_md5=dead, body_len=919),
        _r("me", host=host, auth="none", status=404, body_md5=dead, body_len=919),
        _r("upload-history", host=host, auth="valid", status=404, body_md5=dead, body_len=919),
        _r("stats-leak-check", host=host, status=200, body_md5="c08def88",
            body_len=981, leak_marker="lsphp_processes"),
        _r("changelog-control", host=host, status=200, body_md5="3f6a4dc0", body_len=32803),
    ]


class TestQuorumSentinel(unittest.TestCase):
    def test_unanimous(self):
        h = "abc123"
        results = [
            _r("api-sentinel-404-a", body_md5=h),
            _r("api-sentinel-404-b", body_md5=h),
            _r("api-sentinel-404-c", body_md5=h),
        ]
        canonical, status = _canonical_sentinel(results, "https://wdgwars.pl")
        self.assertEqual(status, "unanimous")
        self.assertEqual(canonical, h)

    def test_majority_two_of_three(self):
        results = [
            _r("api-sentinel-404-a", body_md5="abc"),
            _r("api-sentinel-404-b", body_md5="abc"),
            _r("api-sentinel-404-c", body_md5="xyz"),  # CDN cache slip
        ]
        canonical, status = _canonical_sentinel(results, "https://wdgwars.pl")
        self.assertEqual(status, "majority")
        self.assertEqual(canonical, "abc")

    def test_diverged_all_distinct(self):
        results = [
            _r("api-sentinel-404-a", body_md5="aaa"),
            _r("api-sentinel-404-b", body_md5="bbb"),
            _r("api-sentinel-404-c", body_md5="ccc"),
        ]
        canonical, status = _canonical_sentinel(results, "https://wdgwars.pl")
        self.assertEqual(status, "diverged")
        self.assertEqual(canonical, "")

    def test_no_data_when_all_errored(self):
        results = [
            _r("api-sentinel-404-a", error="URLError"),
            _r("api-sentinel-404-b", error="URLError"),
            _r("api-sentinel-404-c", error="URLError"),
        ]
        canonical, status = _canonical_sentinel(results, "https://wdgwars.pl")
        self.assertEqual(status, "no-data")

    def test_per_host_isolation(self):
        a = "https://wdgwars.pl"
        b = "https://www.wdgwars.pl"
        results = [
            _r("api-sentinel-404-a", host=a, body_md5="apex-hash"),
            _r("api-sentinel-404-b", host=a, body_md5="apex-hash"),
            _r("api-sentinel-404-c", host=a, body_md5="apex-hash"),
            _r("api-sentinel-404-a", host=b, body_md5="www-hash"),
            _r("api-sentinel-404-b", host=b, body_md5="www-hash"),
            _r("api-sentinel-404-c", host=b, body_md5="www-hash"),
        ]
        self.assertEqual(_canonical_sentinel(results, a)[0], "apex-hash")
        self.assertEqual(_canonical_sentinel(results, b)[0], "www-hash")


class TestAnnotateVerdicts(unittest.TestCase):
    def test_dead_when_body_matches_canonical(self):
        results = _outage_fixture()
        annotate_verdicts(results)
        dead_probes = {r.probe for r in results if r.verdict == "DEAD"}
        self.assertIn("me", dead_probes)
        self.assertIn("upload-history", dead_probes)

    def test_leak_detected_on_stats_200(self):
        results = _outage_fixture()
        annotate_verdicts(results)
        leak = [r for r in results if r.verdict == "LEAK"]
        self.assertEqual(len(leak), 1)
        self.assertEqual(leak[0].probe, "stats-leak-check")

    def test_changelog_ok_when_unique_body(self):
        results = _outage_fixture()
        annotate_verdicts(results)
        ctrl = next(r for r in results if r.probe == "changelog-control")
        self.assertEqual(ctrl.verdict, "OK")

    def test_sentinel_outlier_flagged_on_2_of_3(self):
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="canon"),
            _r("api-sentinel-404-b", status=404, body_md5="canon"),
            _r("api-sentinel-404-c", status=404, body_md5="oddball"),
        ]
        annotate_verdicts(results)
        outlier = next(r for r in results if r.probe == "api-sentinel-404-c")
        self.assertEqual(outlier.verdict, "SENTINEL-OUTLIER")

    def test_sentinel_diverged_disables_dead_detection(self):
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="aaa"),
            _r("api-sentinel-404-b", status=404, body_md5="bbb"),
            _r("api-sentinel-404-c", status=404, body_md5="ccc"),
            _r("me", auth="valid", status=404, body_md5="aaa"),  # would-be DEAD
        ]
        annotate_verdicts(results)
        me = next(r for r in results if r.probe == "me")
        # With sentinels diverged, no canonical → no DEAD verdict. Falls back
        # to status-code-based verdict (404).
        self.assertEqual(me.verdict, "404")

    def test_auth_required_when_401(self):
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            _r("me", auth="none", status=401, body_md5="some-401-body"),
        ]
        annotate_verdicts(results)
        me = next(r for r in results if r.probe == "me")
        self.assertEqual(me.verdict, "AUTH-REQUIRED")

    def test_error_short_circuits(self):
        results = [_r("me", error="URLError: timed out")]
        annotate_verdicts(results)
        self.assertEqual(results[0].verdict, "ERROR")

    # ───────── v0.6.1 — AUTH-REDIRECT / tightened LEAK / redirects ─────────

    def test_auth_redirect_when_302_to_login(self):
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            _r("aircraft", auth="none", status=302, body_md5="",
                location="/login/?next=%2Fendpoint%2Faircraft"),
        ]
        annotate_verdicts(results)
        ac = next(r for r in results if r.probe == "aircraft")
        self.assertEqual(ac.verdict, "AUTH-REDIRECT")

    def test_redirect_fallback_when_not_login(self):
        # A 3xx whose Location does NOT point at /login is labeled with
        # the bare code so operators see it but it doesn't get mistaken
        # for the WDGWars-specific auth-redirect pattern.
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            _r("me", auth="none", status=301, body_md5="",
                location="https://elsewhere.example/"),
        ]
        annotate_verdicts(results)
        me = next(r for r in results if r.probe == "me")
        self.assertEqual(me.verdict, "REDIRECT-301")

    def test_leak_fires_on_any_probe_with_leak_marker(self):
        # v0.6.1 generalized LEAK away from probe-specific. Any probe
        # whose body carries the LSWS fingerprint now fires LEAK — that
        # catches the case where the leak expands to additional /api/*
        # paths in the future.
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            _r("aircraft", auth="none", status=200, body_md5="ack",
                leak_marker="lsphp"),
        ]
        annotate_verdicts(results)
        ac = next(r for r in results if r.probe == "aircraft")
        self.assertEqual(ac.verdict, "LEAK")

    # ───────── 2026-06-05 — PAYLOAD-TOO-LARGE verdict ─────────

    def _result_with_excerpt(self, probe, status, body_excerpt):
        """413 verdict logic reads body_excerpt, which _r does not surface.
        Build a Result directly for these tests."""
        return Result(
            probe=probe, host="https://wdgwars.pl", auth="valid",
            method="POST", url="https://wdgwars.pl/" + probe, status=status,
            elapsed_ms=10, body_len=200, body_md5="payload",
            content_type="application/json", cf_cache_status="", x_request_id="",
            server="", body_excerpt=body_excerpt,
        )

    def test_payload_too_large_fires_on_413_with_envelope(self):
        envelope = (
            '{"ok":false,"error":"payload-too-large","http_status":413,'
            '"max_bytes":15728640,"received":31457480}'
        )
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            self._result_with_excerpt("upload-csv", 413, envelope),
        ]
        annotate_verdicts(results)
        up = next(r for r in results if r.probe == "upload-csv")
        self.assertEqual(up.verdict, "PAYLOAD-TOO-LARGE")

    def test_bare_413_without_envelope_falls_back_to_bare_status(self):
        """A 413 from CF or any non-LOCOSP layer with no payload-too-large
        body must keep the generic '413' verdict, not the structured one."""
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            self._result_with_excerpt("upload-csv", 413, "<html>nope</html>"),
        ]
        annotate_verdicts(results)
        up = next(r for r in results if r.probe == "upload-csv")
        self.assertEqual(up.verdict, "413")

    def test_stats_leak_check_with_login_redirect_does_not_fire_leak(self):
        # The 2026-05-30 false-positive case in one test: stats returns
        # 200/HTML (login page) without the LSWS fingerprint → must not
        # be labeled LEAK. AUTH-REDIRECT is the right call when the 302
        # is preserved; OK is acceptable if urllib followed silently.
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="d"),
            _r("api-sentinel-404-b", status=404, body_md5="d"),
            _r("api-sentinel-404-c", status=404, body_md5="d"),
            _r("stats-leak-check", auth="none", status=302, body_md5="",
                location="/login/?next=%2Fendpoint%2Fstats"),
        ]
        annotate_verdicts(results)
        stats = next(r for r in results if r.probe == "stats-leak-check")
        self.assertEqual(stats.verdict, "AUTH-REDIRECT")
        self.assertNotIn("LEAK", [r.verdict for r in results])


class TestSummary(unittest.TestCase):
    def test_outage_when_valid_me_dead(self):
        results = _outage_fixture()
        annotate_verdicts(results)
        s = summary(results)
        self.assertTrue(s["overall"].startswith("OUTAGE"))
        self.assertIn("+LEAK", s["overall"])

    def test_degraded_when_dead_but_no_valid_me(self):
        # Remove the valid-auth me probe so it doesn't trigger OUTAGE.
        results = [r for r in _outage_fixture()
                   if not (r.probe == "me" and r.auth == "valid")]
        annotate_verdicts(results)
        s = summary(results)
        self.assertTrue(s["overall"].startswith("DEGRADED"),
                        f"expected DEGRADED, got {s['overall']}")

    def test_healthy_when_no_dead_no_leak_no_error(self):
        # stats-leak-check carries a body_md5 distinct from the sentinel:
        # post-2026-05-30 the endpoint 302s to /login (or returns a non-
        # leak body), neither of which matches the /api/ 404 fingerprint.
        # The pre-v0.6.1 fixture had this probe's body matching the
        # sentinel — that's actually DEAD, not BLOCKED, and v0.6.1 now
        # surfaces it correctly. Healthy fixtures must reflect a real
        # post-fix shape.
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="sent"),
            _r("api-sentinel-404-b", status=404, body_md5="sent"),
            _r("api-sentinel-404-c", status=404, body_md5="sent"),
            _r("non-api-sentinel-404", status=404, body_md5="bare"),
            _r("me", auth="valid", status=200, body_md5="real"),
            _r("stats-leak-check", status=302, body_md5="login-page",
                location="/login/?next=%2Fendpoint%2Fstats"),
        ]
        annotate_verdicts(results)
        s = summary(results)
        self.assertEqual(s["overall"], "HEALTHY")

    def test_sentinel_diverged_suffix(self):
        results = [
            _r("api-sentinel-404-a", status=404, body_md5="a"),
            _r("api-sentinel-404-b", status=404, body_md5="b"),
            _r("api-sentinel-404-c", status=404, body_md5="c"),
        ]
        annotate_verdicts(results)
        s = summary(results)
        self.assertIn("+SENTINEL-DIVERGED", s["overall"])


class TestStateSignature(unittest.TestCase):
    def test_same_inputs_same_hash(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture()
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        self.assertEqual(state_signature(r1), state_signature(r2))

    def test_body_md5_difference_does_not_affect_signature(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture()
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        # Mutate body_md5 on a probe in r2 (simulates /api/stats counter drift).
        for r in r2:
            if r.probe == "stats-leak-check":
                r.body_md5 = "completely-different-counter-snapshot"
        self.assertEqual(state_signature(r1), state_signature(r2),
                         "state_signature must ignore body_md5 — "
                         "dynamic bodies like /api/stats would otherwise "
                         "fire spurious state-change alerts in --watch")

    def test_verdict_change_does_change_signature(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture()
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        # Flip one verdict to simulate API recovery.
        for r in r2:
            if r.probe == "me" and r.auth == "valid":
                r.verdict = "OK"
                r.status = 200
        self.assertNotEqual(state_signature(r1), state_signature(r2))


class TestProbeDeltas(unittest.TestCase):
    def test_no_change_returns_empty(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture()
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        self.assertEqual(_probe_deltas(r1, r2), [])

    def test_verdict_flip_appears_in_deltas(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture()
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        # Simulate /api/me coming back online (DEAD/404 -> OK/200).
        for r in r2:
            if r.probe == "me" and r.auth == "valid":
                r.verdict = "OK"
                r.status = 200
        deltas = _probe_deltas(r1, r2)
        self.assertEqual(len(deltas), 1)
        self.assertIn("me/valid", deltas[0])
        self.assertIn("DEAD/404 -> OK/200", deltas[0])

    def test_new_probe_flagged(self):
        r1 = _outage_fixture()
        r2 = _outage_fixture() + [_r("brand-new", status=200, body_md5="x")]
        annotate_verdicts(r1)
        annotate_verdicts(r2)
        deltas = _probe_deltas(r1, r2)
        self.assertTrue(any("brand-new" in d and "NEW ->" in d for d in deltas))


class TestTelegramFormatter(unittest.TestCase):
    def test_regression_uses_alarm_prefix(self):
        text = _format_telegram_text(
            "HEALTHY", "OUTAGE+LEAK",
            ["wdgwars.pl me/valid    OK/200 -> DEAD/404"],
            {"DEAD": 10, "LEAK": 1, "OK": 1},
        )
        self.assertIn("🚨", text)
        self.assertIn("OUTAGE+LEAK", text)
        self.assertIn("HEALTHY → OUTAGE+LEAK", text)
        self.assertIn("DEAD=10", text)

    def test_recovery_uses_checkmark_prefix(self):
        text = _format_telegram_text(
            "OUTAGE+LEAK", "HEALTHY",
            ["wdgwars.pl me/valid    DEAD/404 -> OK/200"],
            {"OK": 11, "AUTH-REQUIRED": 4},
        )
        self.assertIn("✅", text)
        self.assertIn("recovered", text)
        self.assertNotIn("🚨", text)
        self.assertNotIn("🔧", text)

    def test_sentinel_diverged_uses_wrench_prefix(self):
        text = _format_telegram_text(
            "DEGRADED+LEAK", "DEGRADED+LEAK+SENTINEL-DIVERGED",
            [],
            {"DEAD": 5, "LEAK": 1, "SENTINEL-DIVERGED": 3},
        )
        self.assertIn("🔧", text)
        self.assertIn("diagnostic broken", text)
        self.assertNotIn("🚨", text)

    def test_long_delta_list_truncated(self):
        deltas = [f"line-{i}" for i in range(TELEGRAM_DELTA_LIMIT + 10)]
        text = _format_telegram_text("HEALTHY", "DEGRADED", deltas, {})
        self.assertIn(f"… and 10 more", text)
        # Only first N delta lines included
        self.assertIn("line-0", text)
        self.assertIn(f"line-{TELEGRAM_DELTA_LIMIT - 1}", text)
        self.assertNotIn(f"line-{TELEGRAM_DELTA_LIMIT}</code>", text)

    def test_overall_length_capped_at_telegram_limit(self):
        # Force a giant verdicts dict to trigger truncation.
        big_verdicts = {f"VERDICT_{i}": i for i in range(1000)}
        text = _format_telegram_text("HEALTHY", "DEGRADED", [], big_verdicts)
        self.assertLessEqual(len(text), TELEGRAM_TEXT_LIMIT)

    def test_html_tags_used_for_formatting(self):
        text = _format_telegram_text("HEALTHY", "DEGRADED", ["foo"], {"OK": 1})
        # Telegram HTML parse_mode requires <b>, <code>, <i>.
        self.assertIn("<b>", text)
        self.assertIn("<code>", text)


class TestWebhookFormatter(unittest.TestCase):
    def test_payload_has_slack_and_discord_keys(self):
        p = _format_webhook_payload(
            "HEALTHY", "OUTAGE+LEAK",
            ["wdgwars.pl me/valid    OK/200 -> DEAD/404"],
            {"DEAD": 10, "LEAK": 1},
        )
        # Discord webhooks read `content` — v0.10.0 carries human-readable
        # prose here instead of the raw jargon string.
        self.assertIn("content", p)
        self.assertIn("main API endpoint down", p["content"])
        self.assertIn("leaking", p["content"])
        # Slack incoming webhooks read `text` — same human-readable string.
        self.assertIn("text", p)
        self.assertIn("main API endpoint down", p["text"])
        # The old jargon string is preserved as `text_machine` for any
        # tooling that depended on it.
        self.assertIn("OUTAGE+LEAK", p["text_machine"])
        # Generic / structured consumers — unchanged from v0.9.0.
        self.assertEqual(p["overall"], "OUTAGE+LEAK")
        self.assertEqual(p["prev_overall"], "HEALTHY")
        self.assertEqual(p["kind"], "regression")
        self.assertEqual(p["tool"], "wdgwars-api-tester")
        self.assertEqual(p["by_verdict"], {"DEAD": 10, "LEAK": 1})

    def test_kind_classification(self):
        recov = _format_webhook_payload(
            "OUTAGE+LEAK", "HEALTHY", [], {"OK": 11})
        self.assertEqual(recov["kind"], "recovery")

        diag = _format_webhook_payload(
            "DEGRADED+LEAK", "DEGRADED+LEAK+SENTINEL-DIVERGED", [], {})
        self.assertEqual(diag["kind"], "diagnostic-broken")

        regr = _format_webhook_payload(
            "HEALTHY", "DEGRADED", [], {"DEAD": 5})
        self.assertEqual(regr["kind"], "regression")

    def test_payload_is_json_serializable(self):
        import json as _json
        p = _format_webhook_payload(
            "HEALTHY", "DEGRADED+LEAK",
            ["a/b/c  OK/200 -> DEAD/404"],
            {"DEAD": 1, "LEAK": 1},
        )
        # Must round-trip cleanly — no datetime, no bytes, no custom types.
        encoded = _json.dumps(p)
        decoded = _json.loads(encoded)
        self.assertEqual(decoded["overall"], "DEGRADED+LEAK")

    def test_emoji_prefix_per_kind(self):
        self.assertIn("✅", _format_webhook_payload("DEGRADED", "HEALTHY", [], {})["title"])
        self.assertIn("🔧", _format_webhook_payload("DEGRADED", "DEGRADED+SENTINEL-DIVERGED", [], {})["title"])
        self.assertIn("🚨", _format_webhook_payload("HEALTHY", "OUTAGE", [], {})["title"])


class TestClassifySeverity(unittest.TestCase):
    """v0.12.2: severity mapping for mod-channel readability.

    Reader contract: most posts should be low. Medium = "look when you
    can". High = "API genuinely broken or data leaking".
    """

    # ───── high ─────

    def test_outage_state_is_high(self):
        self.assertEqual(
            _classify_severity("HEALTHY", "OUTAGE", _dsum(regressed=5)),
            "high",
        )

    def test_unreachable_state_is_high(self):
        self.assertEqual(
            _classify_severity("HEALTHY", "UNREACHABLE", _dsum(regressed=10)),
            "high",
        )

    def test_leak_anywhere_in_overall_is_high(self):
        self.assertEqual(
            _classify_severity("HEALTHY", "DEGRADED+LEAK", _dsum(regressed=2)),
            "high",
        )
        # Even steady-state, severity follows current state, not delta.
        self.assertEqual(
            _classify_severity("OUTAGE+LEAK", "OUTAGE+LEAK", _dsum()),
            "high",
        )

    def test_steady_state_outage_is_still_high(self):
        # An ongoing outage with no movement this tick is still HIGH.
        # Severity is "what is the API like right now", not "did something
        # just change".
        self.assertEqual(
            _classify_severity("OUTAGE", "OUTAGE", _dsum()),
            "high",
        )

    # ───── medium ─────

    def test_fresh_degraded_from_healthy_is_medium(self):
        self.assertEqual(
            _classify_severity("HEALTHY", "DEGRADED", _dsum(regressed=3)),
            "medium",
        )

    def test_sentinel_diverged_first_time_is_medium(self):
        self.assertEqual(
            _classify_severity("HEALTHY", "HEALTHY+SENTINEL-DIVERGED",
                                _dsum()),
            "medium",
        )

    def test_net_regression_without_upstream_flap_is_medium(self):
        # More regressed than improved, NOT covered by upstream-flap.
        self.assertEqual(
            _classify_severity("DEGRADED", "DEGRADED",
                                _dsum(improved=1, regressed=3)),
            "medium",
        )

    # ───── low ─────

    def test_recovery_to_healthy_is_low(self):
        self.assertEqual(
            _classify_severity("OUTAGE", "HEALTHY",
                                _dsum(improved=8)),
            "low",
        )

    def test_steady_state_degraded_no_movement_is_low(self):
        # Sat in DEGRADED, nothing moved. Not new. No action needed.
        self.assertEqual(
            _classify_severity("DEGRADED", "DEGRADED", _dsum()),
            "low",
        )

    def test_upstream_flap_only_is_low(self):
        # Net regression but ALL deltas are upstream flap → CDN, not
        # server, not actionable on operator's side.
        self.assertEqual(
            _classify_severity("DEGRADED", "DEGRADED",
                                _dsum(improved=1, regressed=3,
                                      upstream_flap_count=4)),
            "low",
        )

    def test_partial_recovery_within_degraded_is_low(self):
        self.assertEqual(
            _classify_severity("DEGRADED", "DEGRADED",
                                _dsum(improved=3, regressed=0)),
            "low",
        )

    def test_sideways_shuffle_is_low(self):
        self.assertEqual(
            _classify_severity("DEGRADED", "DEGRADED",
                                _dsum(improved=2, regressed=2)),
            "low",
        )

    # ───── ordering / precedence ─────

    def test_leak_beats_degraded_severity(self):
        # If both rules could apply, LEAK wins (high > medium).
        self.assertEqual(
            _classify_severity("HEALTHY", "DEGRADED+LEAK",
                                _dsum(regressed=2)),
            "high",
        )

    def test_persisting_sentinel_diverged_falls_to_low(self):
        # Same sentinel-diverged state both ticks → not "just broke", no
        # new bad news. Falls through to default low. The point is to
        # avoid re-alerting mods every sweep tick about a known issue.
        self.assertEqual(
            _classify_severity("HEALTHY+SENTINEL-DIVERGED",
                                "HEALTHY+SENTINEL-DIVERGED",
                                _dsum()),
            "low",
        )


class TestWebhookHeadlineHasSeverityTag(unittest.TestCase):
    """v0.12.2: every headline is prefixed with [low|medium|high]."""

    def test_severity_field_in_payload(self):
        p = _format_webhook_payload(
            "HEALTHY", "OUTAGE",
            ["wdgwars.pl me/valid    OK/200 -> DEAD/404"],
            {"DEAD": 10},
        )
        self.assertEqual(p["severity"], "high")

    def test_human_headline_carries_severity_bracket(self):
        p = _format_webhook_payload(
            "HEALTHY", "OUTAGE",
            ["wdgwars.pl me/valid    OK/200 -> DEAD/404"],
            {"DEAD": 10},
        )
        self.assertTrue(
            p["content"].startswith("[high]") or "[high]" in p["title"],
            f"expected [high] prefix in title/content, got: {p['title']!r}",
        )

    def test_low_severity_prefix_on_recovery(self):
        p = _format_webhook_payload(
            "OUTAGE", "HEALTHY", [],
            {"OK": 25},
        )
        self.assertEqual(p["severity"], "low")
        self.assertIn("[low]", p["title"])

    def test_singular_probe_word_in_partial_recovery(self):
        # Was the visible bug in screenshots: "1 probes recovered".
        p = _format_webhook_payload(
            "DEGRADED", "DEGRADED",
            ["wdgwars.pl team-me/valid    ERROR/- -> OK/200"],
            {"OK": 15, "DEAD": 2},
        )
        # Should say "1 probe recovered" not "1 probes recovered".
        self.assertIn("1 probe recovered", p["content"])
        self.assertNotIn("1 probes recovered", p["content"])


class TestRedactWebhookUrl(unittest.TestCase):
    """v0.12.0: when multiple --alert-webhook URLs are configured, journal
    log lines print the URL so multi-destination fan-out is debuggable.
    The secret token portion must be masked so the journal isn't a
    credential leak vector.
    """

    def test_discord_webhook_token_is_masked(self):
        url = "https://discord.com/api/webhooks/1510817125537943602/abc123secret"
        out = _redact_webhook_url(url)
        self.assertIn("discord.com", out)
        self.assertIn("1510817125537943602", out)
        self.assertNotIn("abc123secret", out)
        self.assertIn("<token>", out)

    def test_slack_incoming_webhook_token_is_masked(self):
        # Slack URL shape: hooks.slack.com/services/T.../B.../<secret>
        url = "https://hooks.slack.com/services/TAAAAAA/BBBBBBB/secretXYZ"
        out = _redact_webhook_url(url)
        self.assertNotIn("secretXYZ", out)
        self.assertIn("<token>", out)

    def test_short_url_falls_back_to_redacted_path(self):
        url = "https://example.com/onlyone"
        out = _redact_webhook_url(url)
        self.assertIn("example.com", out)
        self.assertIn("<redacted>", out)

    def test_unparseable_does_not_raise(self):
        # Empty-ish or weird inputs must not blow up the watch loop.
        for bad in ("", "not a url at all", "://broken"):
            out = _redact_webhook_url(bad)
            self.assertIsInstance(out, str)


class TestBuildProbes2026_06_03Surface(unittest.TestCase):
    """Coverage for the 2026-06-03 LOCOSP-shipped probes (v0.8.0).

    These tests are pure-logic — they assert the probe list shape and the
    ``team_id`` parameterization without touching the network.
    """

    NEW_PROBES_2026_06_03 = (
        "badge-catalog",
        "team-id",
        "team-me",
        "member-territories-compact",
        "member-territories-bbox",
        "member-territories-zoom-skip",
    )

    def test_all_new_probes_present_in_default_list(self):
        names = {p.name for p in build_probes()}
        for n in self.NEW_PROBES_2026_06_03:
            self.assertIn(n, names, f"probe {n!r} missing from default build_probes()")

    def test_team_id_default_is_1(self):
        probes = {p.name: p for p in build_probes()}
        self.assertEqual(probes["team-id"].path, "/api/team/1")

    def test_team_id_override_threads_into_probe_path(self):
        probes = {p.name: p for p in build_probes(team_id=20)}
        self.assertEqual(probes["team-id"].path, "/api/team/20")

    def test_team_id_override_does_not_affect_other_probes(self):
        default = {p.name: p.path for p in build_probes()}
        overridden = {p.name: p.path for p in build_probes(team_id=999)}
        # Every probe except team-id and the random sentinels (which embed a
        # per-build secrets.token_hex(8) cache-buster) should have an
        # identical path.
        random_probes = set(SENTINEL_PROBES) | {"non-api-sentinel-404"}
        for name in default:
            if name == "team-id" or name in random_probes:
                continue
            self.assertEqual(
                default[name], overridden[name],
                f"probe {name!r} path drifted when team_id changed",
            )

    def test_new_probes_all_require_auth(self):
        # The 2026-06-03 surface is all key-gated. If LOCOSP ever opens any
        # of these to anonymous reads, the probe should be re-evaluated.
        probes = {p.name: p for p in build_probes()}
        for n in self.NEW_PROBES_2026_06_03:
            self.assertTrue(
                probes[n].needs_auth,
                f"probe {n!r} unexpectedly does not require auth",
            )

    def test_map_variant_probes_target_member_territories(self):
        probes = {p.name: p for p in build_probes()}
        for n in ("member-territories-compact",
                  "member-territories-bbox",
                  "member-territories-zoom-skip"):
            self.assertIn(
                "/api/member-territories", probes[n].path,
                f"probe {n!r} should target /api/member-territories, got {probes[n].path!r}",
            )


if __name__ == "__main__":
    unittest.main()
