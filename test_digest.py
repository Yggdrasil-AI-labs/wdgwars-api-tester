"""Tests for the morning-digest + state-log added in v0.10.0.

Run with: python -m unittest test_digest
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from wdgwars_api_tester import (
    _append_state_log,
    _read_state_log_window,
    _summarize_state_log_window,
    _format_digest_payload,
)


def _mk_results(by_verdict: dict, total: int = None):
    """Build a minimal {"overall", "by_verdict", "total"} dict for the
    digest formatter.it doesn't read individual Result fields."""
    if total is None:
        total = sum(by_verdict.values())
    return {"overall": "HEALTHY", "by_verdict": by_verdict, "total": total}


class TestAppendStateLog(unittest.TestCase):
    def test_append_creates_parents(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "deep" / "nested" / "state-log.jsonl"
            _append_state_log(p, "HEALTHY", "DEGRADED",
                              ["wdgwars.pl x  OK/200 -> DEAD/404"],
                              {"DEAD": 1, "OK": 10},
                              False, "")
            self.assertTrue(p.exists())
            content = p.read_text(encoding="utf-8").strip()
            rec = json.loads(content)
            self.assertEqual(rec["prev_overall"], "HEALTHY")
            self.assertEqual(rec["curr_overall"], "DEGRADED")
            self.assertEqual(rec["by_verdict"]["DEAD"], 1)
            self.assertFalse(rec["suppressed"])
            self.assertIn("ts", rec)
            self.assertIn("ts_iso", rec)

    def test_suppressed_record(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state-log.jsonl"
            _append_state_log(p, "HEALTHY", "HEALTHY", ["foo"], {"OK": 5},
                              True, "all flap, no net regression")
            rec = json.loads(p.read_text(encoding="utf-8").strip())
            self.assertTrue(rec["suppressed"])
            self.assertEqual(rec["suppress_reason"],
                             "all flap, no net regression")

    def test_multiple_appends(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state-log.jsonl"
            for i in range(3):
                _append_state_log(p, "HEALTHY", f"S{i}", [], {}, False, "")
            lines = p.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 3)


class TestReadStateLogWindow(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        self.assertEqual(_read_state_log_window(Path("/nope/nada"), 0), [])

    def test_window_filters_by_ts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state-log.jsonl"
            now = int(time.time())
            old = {"ts": now - 7200, "prev_overall": "X", "curr_overall": "Y"}
            fresh = {"ts": now - 60, "prev_overall": "A", "curr_overall": "B"}
            p.write_text(json.dumps(old) + "\n" + json.dumps(fresh) + "\n",
                         encoding="utf-8")
            # 1h window.old falls outside, fresh stays
            recs = _read_state_log_window(p, now - 3600)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["curr_overall"], "B")

    def test_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "state-log.jsonl"
            now = int(time.time())
            good = {"ts": now, "prev_overall": "H", "curr_overall": "D"}
            p.write_text("not json\n" + json.dumps(good) + "\n",
                         encoding="utf-8")
            recs = _read_state_log_window(p, now - 3600)
            self.assertEqual(len(recs), 1)


class TestSummarizeStateLogWindow(unittest.TestCase):
    def test_empty(self):
        out = _summarize_state_log_window([])
        self.assertEqual(out["total_events"], 0)
        self.assertEqual(out["loud_events"], 0)
        self.assertEqual(out["suppressed_events"], 0)
        self.assertEqual(out["transitions"], {})
        self.assertEqual(out["probes_touched"], {})

    def test_mixed_loud_suppressed(self):
        records = [
            {"prev_overall": "HEALTHY", "curr_overall": "DEGRADED",
             "deltas": ["wdgwars.pl team-me/valid OK/200 -> ERROR/-"],
             "suppressed": False},
            {"prev_overall": "DEGRADED", "curr_overall": "DEGRADED",
             "deltas": ["wdgwars.pl team-me/valid OK/200 -> 524/524"],
             "suppressed": True},
            {"prev_overall": "DEGRADED", "curr_overall": "HEALTHY",
             "deltas": ["wdgwars.pl team-me/valid ERROR/- -> OK/200"],
             "suppressed": False},
        ]
        out = _summarize_state_log_window(records)
        self.assertEqual(out["total_events"], 3)
        self.assertEqual(out["loud_events"], 2)
        self.assertEqual(out["suppressed_events"], 1)
        self.assertEqual(out["transitions"]["HEALTHY → DEGRADED"], 1)
        self.assertEqual(out["transitions"]["DEGRADED → HEALTHY"], 1)
        self.assertEqual(out["probes_touched"]["team-me/valid"], 3)


class TestFormatDigestPayload(unittest.TestCase):
    def test_healthy_digest_with_no_events(self):
        results = []
        s = _mk_results({"OK": 13, "AUTH-REQUIRED": 27, "DEAD": 2}, total=42)
        window = _summarize_state_log_window([])
        p = _format_digest_payload(results, s, window, records=[], window_hours=24)
        # Log-shaped header.
        self.assertIn("Nightly report", p["content"])
        # Empty window says so explicitly.no surprise blank section.
        self.assertIn("no state changes", p["content"])
        self.assertIn("Steady all night", p["content"])
        # Tail snapshot.single line, not a bullet list.
        self.assertIn("API status at report time", p["content"])
        self.assertIn("all endpoints healthy", p["content"])
        self.assertIn("No action needed", p["content"])
        self.assertEqual(p["kind"], "digest")
        self.assertEqual(p["total_probes"], 42)

    def test_digest_with_events_has_chronological_log(self):
        results = []
        s = _mk_results({"OK": 13, "DEAD": 2}, total=15)
        records = [
            {"ts": 100, "ts_iso": "2026-06-04T02:24:00Z",
             "prev_overall": "HEALTHY", "curr_overall": "DEGRADED",
             "deltas": ["wdgwars.pl team-me/valid                        OK/200 -> ERROR/-"],
             "by_verdict": {}, "suppressed": False, "suppress_reason": ""},
            {"ts": 200, "ts_iso": "2026-06-04T03:25:00Z",
             "prev_overall": "DEGRADED", "curr_overall": "HEALTHY",
             "deltas": ["wdgwars.pl team-me/valid                        ERROR/- -> OK/200"],
             "by_verdict": {}, "suppressed": False, "suppress_reason": ""},
            {"ts": 300, "ts_iso": "2026-06-04T05:43:00Z",
             "prev_overall": "HEALTHY", "curr_overall": "HEALTHY",
             "deltas": ["wdgwars.pl team-me/valid                        OK/200 -> 524/524"],
             "by_verdict": {}, "suppressed": True, "suppress_reason": "all flap, no net regression"},
        ]
        window = _summarize_state_log_window(records)
        p = _format_digest_payload(results, s, window, records=records, window_hours=24)
        content = p["content"]
        # Header is log-y, not summary-y.
        self.assertIn("Activity log", content)
        # Each event renders as its own timestamped block.
        self.assertIn("02:24 UTC", content)
        self.assertIn("03:25 UTC", content)
        self.assertIn("05:43 UTC", content)
        # Transition labels appear in the headers.
        self.assertIn("HEALTHY → DEGRADED", content)
        self.assertIn("DEGRADED → HEALTHY", content)
        # Per-event deltas show up humanized.
        self.assertIn("was healthy", content)
        self.assertIn("timing out", content)
        self.assertIn("recovered", content)
        # Suppressed event is tagged in its header.
        self.assertIn("suppressed", content)
        # Tally line at the bottom.
        self.assertIn("2 loud transitions", content)
        self.assertIn("1 suppressed", content)
        self.assertIn("Most-flapped probes", content)

    def test_digest_log_is_chronological(self):
        """Records out of order get sorted by ts before rendering."""
        s = _mk_results({"OK": 5}, total=5)
        records = [
            {"ts": 300, "ts_iso": "2026-06-04T03:00:00Z",
             "prev_overall": "DEGRADED", "curr_overall": "HEALTHY",
             "deltas": [], "by_verdict": {}, "suppressed": False},
            {"ts": 100, "ts_iso": "2026-06-04T01:00:00Z",
             "prev_overall": "HEALTHY", "curr_overall": "DEGRADED",
             "deltas": [], "by_verdict": {}, "suppressed": False},
        ]
        window = _summarize_state_log_window(records)
        p = _format_digest_payload([], s, window, records=records, window_hours=24)
        content = p["content"]
        i_first = content.index("01:00 UTC")
        i_second = content.index("03:00 UTC")
        self.assertLess(i_first, i_second)

    def test_digest_payload_carries_structured_fields(self):
        s = _mk_results({"OK": 5}, total=5)
        window = _summarize_state_log_window([])
        p = _format_digest_payload([], s, window, records=[], window_hours=24)
        self.assertEqual(p["kind"], "digest")
        self.assertEqual(p["overall"], "HEALTHY")
        self.assertEqual(p["overall_human"], "all endpoints healthy")
        self.assertEqual(p["window_hours"], 24)
        self.assertEqual(p["window_summary"]["total_events"], 0)


class TestFormatEventBlock(unittest.TestCase):
    def test_single_delta_event(self):
        from wdgwars_api_tester import _format_event_block
        rec = {"ts_iso": "2026-06-04T02:24:00Z",
               "prev_overall": "HEALTHY", "curr_overall": "DEGRADED",
               "deltas": ["wdgwars.pl team-me/valid                        OK/200 -> ERROR/-"],
               "suppressed": False, "suppress_reason": ""}
        block = _format_event_block(rec)
        self.assertEqual(block[0], "02:24 UTC: HEALTHY → DEGRADED (1 change)")
        # Indented delta line with direction marker.
        self.assertTrue(block[1].startswith("  "))
        self.assertIn("↓", block[1])
        self.assertIn("team-me/valid", block[1])
        self.assertIn("was healthy", block[1])

    def test_suppressed_event_tagged(self):
        from wdgwars_api_tester import _format_event_block
        rec = {"ts_iso": "2026-06-04T05:43:00Z",
               "prev_overall": "HEALTHY", "curr_overall": "HEALTHY",
               "deltas": ["wdgwars.pl team-me/valid                        OK/200 -> 524/524"],
               "suppressed": True, "suppress_reason": "all flap, no net regression"}
        block = _format_event_block(rec)
        # No-state-change suppressed: header reads 'still HEALTHY' + suppressed tag.
        self.assertIn("still HEALTHY", block[0])
        self.assertIn("suppressed: all flap", block[0])

    def test_missing_ts_iso_falls_back_to_ts(self):
        from wdgwars_api_tester import _format_event_block
        rec = {"ts": 0, "prev_overall": "H", "curr_overall": "D", "deltas": []}
        block = _format_event_block(rec)
        # Epoch 0 → "00:00" via gmtime, so fallback at least renders.
        self.assertTrue(block[0].endswith("(0 changes)"))


if __name__ == "__main__":
    unittest.main()
