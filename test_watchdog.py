"""Tests for the watch-loop heartbeat + wedge watchdog added in v0.13.0."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from wdgwars_api_tester import (
    _check_stale,
    _format_wedge_payload,
    _read_heartbeat,
    _write_heartbeat,
    main,
)


class HeartbeatRoundTrip(unittest.TestCase):
    def test_write_then_read(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            _write_heartbeat(hb, "DEGRADED", 1234, "ok")
            rec = _read_heartbeat(hb)
            self.assertIsNotNone(rec)
            assert rec is not None
            self.assertEqual(rec["overall"], "DEGRADED")
            self.assertEqual(rec["sweep_ms"], 1234)
            self.assertEqual(rec["status"], "ok")
            self.assertEqual(rec["tool"], "wdgwars-api-tester")
            self.assertIn("ts", rec)

    def test_read_missing_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(_read_heartbeat(Path(d) / "nope.json"))

    def test_read_garbage_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            hb.write_text("{not json", encoding="utf-8")
            self.assertIsNone(_read_heartbeat(hb))


class CheckStale(unittest.TestCase):
    def _hb(self, d: str, age_s: int, status: str = "ok") -> Path:
        hb = Path(d) / "hb.json"
        hb.write_text(json.dumps({
            "ts": int(time.time()) - age_s,
            "overall": "DEGRADED", "status": status,
        }), encoding="utf-8")
        return hb

    def test_fresh_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_check_stale(self._hb(d, 30), 300, None), 0)

    def test_old_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_check_stale(self._hb(d, 9000), 300, None), 1)

    def test_missing_file_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(_check_stale(Path(d) / "absent.json", 300, None), 1)

    def test_no_path_is_stale(self) -> None:
        self.assertEqual(_check_stale(None, 300, None), 1)


class WedgePayload(unittest.TestCase):
    def test_payload_has_discord_content(self) -> None:
        p = _format_wedge_payload(Path("/x/hb.json"), 9000, 300.0,
                                  {"status": "ok", "overall": "DEGRADED"})
        self.assertIn("content", p)
        self.assertIn("text", p)
        self.assertIn("STALLED", p["content"])
        # tool-neutral: no host identifiers leak into the alert body
        self.assertNotIn("zhn", p["content"].lower())

    def test_payload_handles_missing_heartbeat(self) -> None:
        p = _format_wedge_payload(None, None, 300.0, None)
        self.assertIn("content", p)


class CheckStaleViaMain(unittest.TestCase):
    def test_main_fresh_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            _write_heartbeat(hb, "DEGRADED", 10, "ok")
            rc = main(["--check-stale", "300", "--heartbeat-file", str(hb)])
            self.assertEqual(rc, 0)

    def test_main_stale_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            hb.write_text(json.dumps({"ts": int(time.time()) - 9000,
                                      "overall": "DEGRADED", "status": "ok"}),
                          encoding="utf-8")
            rc = main(["--check-stale", "300", "--heartbeat-file", str(hb)])
            self.assertEqual(rc, 1)

    def test_main_check_stale_rejects_watch(self) -> None:
        rc = main(["--check-stale", "300", "--watch", "60"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
