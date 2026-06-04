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
    _format_telegram_text,
    _format_webhook_payload,
    _probe_deltas,
    annotate_verdicts,
    build_probes,
    state_signature,
    summary,
)


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
        # for the WDGoWars-specific auth-redirect pattern.
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
        # Discord webhooks read `content`
        self.assertIn("content", p)
        self.assertIn("OUTAGE+LEAK", p["content"])
        # Slack incoming webhooks read `text`
        self.assertIn("text", p)
        self.assertIn("OUTAGE+LEAK", p["text"])
        # Generic / structured consumers
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
