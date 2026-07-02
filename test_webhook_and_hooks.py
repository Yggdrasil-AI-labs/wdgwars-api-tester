"""Tests for _post_webhook, the _exec_on_change error branches, the
_check_stale webhook fan-out, and diff_against_baseline.

These paths are exercised only on the happy path (or not at all) elsewhere:
test_security.py drives _exec_on_change's rc=0 success path to lock in the
env-var transport contract, but never its failure branches; test_watchdog.py
drives _check_stale with webhook_urls=None, never the alert fan-out; and
nothing calls _post_webhook or diff_against_baseline directly. Kept pure/
offline — urllib.request.urlopen and subprocess.run are mocked, never called
for real.

Run with: python -m unittest test_webhook_and_hooks
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from wdgwars_api_tester import (
    DISCORD_CONTENT_LIMIT,
    _check_stale,
    _exec_on_change,
    _post_webhook,
    diff_against_baseline,
)


class _FakeResponse:
    """Minimal context-manager stand-in for urllib's HTTPResponse."""

    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestPostWebhook(unittest.TestCase):
    def test_2xx_status_returns_true(self) -> None:
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        return_value=_FakeResponse(204)):
            self.assertTrue(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_200_status_returns_true(self) -> None:
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        return_value=_FakeResponse(200)):
            self.assertTrue(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_non_2xx_status_returns_false(self) -> None:
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        return_value=_FakeResponse(500)):
            self.assertFalse(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_http_error_returns_false(self) -> None:
        import urllib.error
        err = urllib.error.HTTPError(
            "https://example.com/hook", 429, "Too Many Requests", {}, None)
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen", side_effect=err):
            self.assertFalse(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_url_error_returns_false(self) -> None:
        import urllib.error
        err = urllib.error.URLError("connection refused")
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen", side_effect=err):
            self.assertFalse(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_generic_exception_returns_false(self) -> None:
        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        side_effect=OSError("boom")):
            self.assertFalse(_post_webhook("https://example.com/hook", {"content": "hi"}))

    def test_long_content_is_truncated_to_discord_limit(self) -> None:
        long_content = "line one\n" * 400  # well past DISCORD_CONTENT_LIMIT
        self.assertGreater(len(long_content), DISCORD_CONTENT_LIMIT)
        captured = {}

        def _fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(204)

        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        side_effect=_fake_urlopen):
            ok = _post_webhook("https://example.com/hook",
                               {"content": long_content, "text": long_content})
        self.assertTrue(ok)
        sent_content = captured["body"]["content"]
        self.assertLessEqual(len(sent_content), DISCORD_CONTENT_LIMIT)
        self.assertIn("truncated", sent_content)
        # `text` is left full-length for non-Discord consumers.
        self.assertEqual(captured["body"]["text"], long_content)

    def test_long_content_with_no_newline_still_truncates(self) -> None:
        # No '\n' anywhere in the truncation window: rfind returns -1, so the
        # cut falls back to DISCORD_CONTENT_LIMIT - 12 instead of a line break.
        long_content = "x" * (DISCORD_CONTENT_LIMIT + 500)
        captured = {}

        def _fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(204)

        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        side_effect=_fake_urlopen):
            _post_webhook("https://example.com/hook", {"content": long_content})
        sent_content = captured["body"]["content"]
        self.assertLessEqual(len(sent_content), DISCORD_CONTENT_LIMIT)
        self.assertIn("truncated", sent_content)

    def test_short_content_is_not_truncated(self) -> None:
        captured = {}

        def _fake_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(200)

        with mock.patch("wdgwars_api_tester.urllib.request.urlopen",
                        side_effect=_fake_urlopen):
            _post_webhook("https://example.com/hook", {"content": "short and sweet"})
        self.assertEqual(captured["body"]["content"], "short and sweet")
        self.assertNotIn("truncated", captured["body"]["content"])


class TestExecOnChangeErrorBranches(unittest.TestCase):
    def _run(self, mock_result=None, side_effect=None):
        with mock.patch("wdgwars_api_tester.subprocess.run",
                        return_value=mock_result, side_effect=side_effect) as m:
            rc = _exec_on_change("irrelevant-cmd", "HEALTHY", "BROKEN",
                                 ["x: UP -> DOWN"], {"DOWN": 1}, timeout=5.0)
            return rc, m

    def test_nonzero_returncode_is_false_and_logs_stderr(self) -> None:
        fake = mock.Mock(returncode=1, stderr="hook script failed\n")
        with self.assertLogs(level="WARNING") as cm:
            rc, _ = self._run(mock_result=fake)
        self.assertFalse(rc)
        self.assertIn("exec-on-change rc=1", " ".join(cm.output))

    def test_zero_returncode_is_true(self) -> None:
        fake = mock.Mock(returncode=0, stderr="")
        rc, _ = self._run(mock_result=fake)
        self.assertTrue(rc)

    def test_timeout_expired_returns_false(self) -> None:
        with self.assertLogs(level="WARNING") as cm:
            rc, _ = self._run(side_effect=subprocess.TimeoutExpired("irrelevant-cmd", 5.0))
        self.assertFalse(rc)
        self.assertIn("timed out", " ".join(cm.output))

    def test_generic_exception_returns_false(self) -> None:
        with self.assertLogs(level="WARNING") as cm:
            rc, _ = self._run(side_effect=OSError("no shell available"))
        self.assertFalse(rc)
        self.assertIn("exec-on-change failed", " ".join(cm.output))

    def test_env_is_built_before_subprocess_call(self) -> None:
        fake = mock.Mock(returncode=0, stderr="")
        _, m = self._run(mock_result=fake)
        _, kwargs = m.call_args
        env = kwargs["env"]
        self.assertEqual(env["WDGWARS_OVERALL"], "BROKEN")
        self.assertEqual(env["WDGWARS_PREV_OVERALL"], "HEALTHY")
        self.assertEqual(env["WDGWARS_RECOVERY"], "0")
        self.assertIn("WDGWARS_SEVERITY", env)


class TestCheckStaleWebhookFanout(unittest.TestCase):
    def _stale_hb(self, d: str) -> Path:
        hb = Path(d) / "hb.json"
        hb.write_text(json.dumps({
            "ts": int(time.time()) - 9000,
            "overall": "DEGRADED", "status": "ok",
        }), encoding="utf-8")
        return hb

    def test_stale_posts_to_each_webhook_url(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = self._stale_hb(d)
            urls = ["https://example.com/hook-a", "https://example.com/hook-b"]
            with mock.patch("wdgwars_api_tester._post_webhook",
                            return_value=True) as m:
                rc = _check_stale(hb, 300, urls)
            self.assertEqual(rc, 1)
            self.assertEqual(m.call_count, 2)
            called_urls = [c.args[0] for c in m.call_args_list]
            self.assertEqual(called_urls, urls)

    def test_fresh_heartbeat_never_calls_webhook(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            hb.write_text(json.dumps({"ts": int(time.time()),
                                      "overall": "HEALTHY", "status": "ok"}),
                          encoding="utf-8")
            with mock.patch("wdgwars_api_tester._post_webhook") as m:
                rc = _check_stale(hb, 300, ["https://example.com/hook"])
            self.assertEqual(rc, 0)
            m.assert_not_called()

    def test_failed_webhook_post_still_logs_failed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = self._stale_hb(d)
            with mock.patch("wdgwars_api_tester._post_webhook", return_value=False):
                with self.assertLogs(level="INFO") as cm:
                    _check_stale(hb, 300, ["https://example.com/hook"])
            self.assertIn("FAILED", " ".join(cm.output))


class TestDiffAgainstBaseline(unittest.TestCase):
    def _result(self, host="wdgwars.pl", probe="me", auth="valid",
               verdict="OK", status=200):
        return mock.Mock(host=host, probe=probe, auth=auth,
                         verdict=verdict, status=status)

    def test_missing_baseline_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "absent.json"
            self.assertEqual(diff_against_baseline([self._result()], p), [])

    def test_unreadable_baseline_reports_error(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.json"
            p.write_text("{not valid json", encoding="utf-8")
            diffs = diff_against_baseline([self._result()], p)
            self.assertEqual(len(diffs), 1)
            self.assertIn("baseline unreadable", diffs[0])

    def test_new_key_not_in_baseline_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.json"
            p.write_text(json.dumps({"results": []}), encoding="utf-8")
            diffs = diff_against_baseline([self._result()], p)
            self.assertEqual(len(diffs), 1)
            self.assertIn("NEW", diffs[0])

    def test_changed_verdict_or_status_is_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.json"
            p.write_text(json.dumps({"results": [
                {"host": "wdgwars.pl", "probe": "me", "auth": "valid",
                 "verdict": "OK", "status": 200},
            ]}), encoding="utf-8")
            diffs = diff_against_baseline(
                [self._result(verdict="DEAD", status=404)], p)
            self.assertEqual(len(diffs), 1)
            self.assertIn("CHANGE", diffs[0])
            self.assertIn("OK/200", diffs[0])
            self.assertIn("DEAD/404", diffs[0])

    def test_unchanged_result_produces_no_diff(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "baseline.json"
            p.write_text(json.dumps({"results": [
                {"host": "wdgwars.pl", "probe": "me", "auth": "valid",
                 "verdict": "OK", "status": 200},
            ]}), encoding="utf-8")
            diffs = diff_against_baseline([self._result()], p)
            self.assertEqual(diffs, [])


if __name__ == "__main__":
    unittest.main()
