"""Tests for upstream-flap classification + alert suppression restored in v0.9.0.

These helpers were dropped during the v0.7.0 outage-backoff squash-merge on
2026-06-03. Without them, --silent-webhook plumbing in main() argparses but
does nothing, and every state-change tick fires the loud webhook even when
all deltas are LOCOSP CDN 5xx flap (which the operator considers noise).

See: BrainVault/Meta/Bugs/2026-06-04-wdgwars-api-tester-silent-webhook-regression.md
"""
from __future__ import annotations

import unittest

from wdgwars_api_tester import (
    _annotate_deltas,
    _classify_delta,
    _is_upstream_5xx,
    _parse_delta_line,
    _should_suppress_alert,
    _verdict_rank,
)


class TestVerdictRank(unittest.TestCase):
    def test_5xx_string_ranks_below_dead(self):
        # DEAD is in VERDICT_PRIORITY; explicit 5xx string ranks at 2 (worse).
        self.assertEqual(_verdict_rank("502", 502), 2)
        self.assertEqual(_verdict_rank("524", 524), 2)

    def test_numeric_5xx_status_ranks_at_2(self):
        self.assertEqual(_verdict_rank("OTHER", 503), 2)

    def test_unknown_verdict_falls_back_to_99(self):
        self.assertEqual(_verdict_rank("WAT", 200), 99)

    def test_case_insensitive(self):
        self.assertEqual(_verdict_rank("502", 0), 2)


class TestIsUpstream5xx(unittest.TestCase):
    def test_explicit_cf_codes(self):
        for code in ("502", "503", "504", "522", "524"):
            self.assertTrue(_is_upstream_5xx(code, int(code)))

    def test_numeric_status_only(self):
        self.assertTrue(_is_upstream_5xx("OTHER", 500))
        self.assertTrue(_is_upstream_5xx("OTHER", 599))

    def test_not_5xx(self):
        self.assertFalse(_is_upstream_5xx("OK", 200))
        self.assertFalse(_is_upstream_5xx("DEAD", 404))
        self.assertFalse(_is_upstream_5xx("AUTH-REQUIRED", 401))


class TestClassifyDelta(unittest.TestCase):
    def test_upstream_flap_either_side(self):
        c = _classify_delta("OK", 200, "502", 502)
        self.assertTrue(c["upstream_flap"])
        c = _classify_delta("524", 524, "OK", 200)
        self.assertTrue(c["upstream_flap"])

    def test_non_upstream_no_flap(self):
        c = _classify_delta("OK", 200, "DEAD", 404)
        self.assertFalse(c["upstream_flap"])

    def test_direction_improved_when_curr_better_ranked(self):
        # 502 (rank 2) -> OK (rank in VERDICT_PRIORITY > 2) is improved.
        c = _classify_delta("502", 502, "OK", 200)
        self.assertEqual(c["direction"], "improved")

    def test_direction_regressed(self):
        c = _classify_delta("OK", 200, "502", 502)
        self.assertEqual(c["direction"], "regressed")

    def test_direction_sideways_same_rank(self):
        c = _classify_delta("502", 502, "503", 503)
        self.assertEqual(c["direction"], "sideways")


class TestParseDeltaLine(unittest.TestCase):
    def test_new_returns_none(self):
        self.assertIsNone(_parse_delta_line("wdgwars.pl  some-probe/none NEW -> OK/200"))

    def test_gone_returns_none(self):
        self.assertIsNone(_parse_delta_line("wdgwars.pl  some-probe/none GONE OK/200"))

    def test_unparseable_returns_none(self):
        self.assertIsNone(_parse_delta_line("no arrow here"))

    def test_basic_parse(self):
        line = "wdgwars.pl  me-aps/garbage     AUTH-REQUIRED/401 -> 502/502"
        p = _parse_delta_line(line)
        self.assertIsNotNone(p)
        self.assertEqual(p["prev_verdict"], "AUTH-REQUIRED")
        self.assertEqual(p["prev_status"], 401)
        self.assertEqual(p["curr_verdict"], "502")
        self.assertEqual(p["curr_status"], 502)

    def test_non_numeric_status_coerces_to_zero(self):
        line = "wdgwars.pl  p/none OK/abc -> ERROR/xyz"
        p = _parse_delta_line(line)
        self.assertIsNotNone(p)
        self.assertEqual(p["prev_status"], 0)
        self.assertEqual(p["curr_status"], 0)


class TestAnnotateDeltas(unittest.TestCase):
    def test_empty(self):
        annotated, summary = _annotate_deltas([])
        self.assertEqual(annotated, [])
        self.assertEqual(summary["total_classified"], 0)
        self.assertEqual(summary["unclassified"], 0)

    def test_all_flap(self):
        deltas = [
            "wdgwars.pl  a/valid OK/200 -> 502/502",
            "wdgwars.pl  b/valid OK/200 -> 524/524",
        ]
        annotated, summary = _annotate_deltas(deltas)
        self.assertEqual(len(annotated), 2)
        self.assertTrue(all(line.startswith("↓") for line in annotated))
        self.assertEqual(summary["regressed"], 2)
        self.assertEqual(summary["upstream_flap_count"], 2)
        self.assertEqual(summary["total_classified"], 2)
        self.assertEqual(summary["unclassified"], 0)

    def test_new_line_unclassified(self):
        deltas = ["wdgwars.pl  newprobe/none NEW -> OK/200"]
        annotated, summary = _annotate_deltas(deltas)
        self.assertTrue(annotated[0].startswith("·"))
        self.assertEqual(summary["unclassified"], 1)
        self.assertEqual(summary["total_classified"], 0)


class TestShouldSuppressAlert(unittest.TestCase):
    """The boundary cases the operator called out explicitly."""

    def _summary(self, **kw) -> dict:
        base = {"improved": 0, "regressed": 0, "sideways": 0,
                "upstream_flap_count": 0, "total_classified": 0,
                "unclassified": 0}
        base.update(kw)
        return base

    def test_overall_state_changed_never_suppresses(self):
        # Even if every delta is upstream flap, a state change is real signal.
        s = self._summary(upstream_flap_count=3, total_classified=3, improved=3)
        suppress, reason = _should_suppress_alert("HEALTHY", "DEGRADED", s)
        self.assertFalse(suppress)
        self.assertIn("overall", reason)

    def test_all_flaps_no_net_regression_suppresses(self):
        s = self._summary(upstream_flap_count=4, total_classified=4,
                          improved=2, regressed=2)
        suppress, reason = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertTrue(suppress)
        self.assertIn("upstream flap", reason)

    def test_all_flaps_more_improved_than_regressed_suppresses(self):
        s = self._summary(upstream_flap_count=3, total_classified=3,
                          improved=3, regressed=0)
        suppress, _ = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertTrue(suppress)

    def test_mixed_flap_plus_non_flap_does_not_suppress(self):
        # 2 of 3 are flap — the third (e.g. probe DEAD->OK) is real signal.
        s = self._summary(upstream_flap_count=2, total_classified=3,
                          improved=2, regressed=1)
        suppress, reason = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertFalse(suppress)
        self.assertIn("non-upstream-flap", reason)

    def test_net_regression_with_flap_does_not_suppress(self):
        # All 4 are flap, but 3 regressed vs 1 improved — net getting worse.
        s = self._summary(upstream_flap_count=4, total_classified=4,
                          improved=1, regressed=3)
        suppress, reason = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertFalse(suppress)
        self.assertIn("net regression", reason)

    def test_zero_classifiable_deltas_does_not_suppress(self):
        # Nothing to classify — fall through to "real signal" (caller decides
        # what to do with no deltas + no state change).
        s = self._summary()
        suppress, reason = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertFalse(suppress)
        self.assertIn("no classifiable", reason)

    def test_unclassified_present_does_not_suppress(self):
        # NEW/GONE lines are always real signal.
        s = self._summary(unclassified=1, upstream_flap_count=2,
                          total_classified=2, improved=2)
        suppress, reason = _should_suppress_alert("DEGRADED", "DEGRADED", s)
        self.assertFalse(suppress)
        self.assertIn("unclassified", reason)


if __name__ == "__main__":
    unittest.main()
