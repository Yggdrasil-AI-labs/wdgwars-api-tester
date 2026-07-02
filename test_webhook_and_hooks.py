"""Tests for _post_webhook, the _exec_on_change error branches, the
_check_stale webhook fan-out, diff_against_baseline, and a handful of small
pure helpers (_write_heartbeat's OSError branch, _redact_webhook_url's
exception branch, load_key, and the no-arg branch of
_seconds_to_next_midnight_utc) that were still gaps after the first pass.

These paths are exercised only on the happy path (or not at all) elsewhere:
test_security.py drives _exec_on_change's rc=0 success path to lock in the
env-var transport contract, but never its failure branches; test_watchdog.py
drives _check_stale with webhook_urls=None, never the alert fan-out, and
covers _write_heartbeat/_read_heartbeat/_format_wedge_payload's normal
paths but not _write_heartbeat's OSError branch; test_outage_backoff.py
covers _seconds_to_next_midnight_utc but always passes an explicit `now`,
never exercising the `now is None -> time.time()` branch; and nothing calls
_post_webhook, diff_against_baseline, or load_key directly. Kept pure/
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
    _read_heartbeat,
    _redact_webhook_url,
    _seconds_to_next_midnight_utc,
    _write_heartbeat,
    diff_against_baseline,
    load_key,
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


class TestWriteHeartbeatOSError(unittest.TestCase):
    def test_write_failure_is_caught_and_logged(self) -> None:
        # path.with_suffix()/write_text()/replace() all live on the real
        # Path object; patch Path.write_text so the write itself raises,
        # proving the OSError branch swallows the error instead of
        # propagating it and killing the watch loop.
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            with mock.patch("pathlib.Path.write_text",
                            side_effect=OSError("disk full")):
                with self.assertLogs(level="WARNING") as cm:
                    _write_heartbeat(hb, "HEALTHY", 42, "ok")
            self.assertIn("heartbeat write failed", " ".join(cm.output))
            # No partial/garbage file left behind by the failed write.
            self.assertFalse(hb.exists())


class TestRedactWebhookUrlExceptionBranch(unittest.TestCase):
    def test_urlparse_raising_falls_back_to_unparseable(self) -> None:
        # The existing edge-case tests (empty string, "not a url", etc.)
        # never actually hit the except branch because urllib.parse is
        # lenient about garbage strings. Force the branch directly.
        with mock.patch("wdgwars_api_tester.urllib.parse.urlparse",
                        side_effect=ValueError("boom")):
            out = _redact_webhook_url("https://example.com/hook")
        self.assertEqual(out, "<unparseable-url>")


class TestLoadKey(unittest.TestCase):
    def test_cli_key_takes_priority(self) -> None:
        self.assertEqual(load_key("  cli-key  "), "cli-key")

    def test_env_var_used_when_no_cli_key(self) -> None:
        with mock.patch.dict("os.environ",
                             {"WDGWARS_API_KEY": " env-key "}, clear=False):
            self.assertEqual(load_key(None), "env-key")

    def test_config_file_used_when_no_cli_or_env(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake_home = Path(d)
            cfg_dir = fake_home / ".config" / "wigle-to-wdgwars"
            cfg_dir.mkdir(parents=True)
            (cfg_dir / "wdgwars.key").write_text(" file-key \n", encoding="utf-8")
            with mock.patch.dict("os.environ", {}, clear=True):
                with mock.patch("wdgwars_api_tester.Path.home",
                                return_value=fake_home):
                    self.assertEqual(load_key(None), "file-key")

    def test_returns_none_when_nothing_configured(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            fake_home = Path(d)  # no .config/wigle-to-wdgwars/wdgwars.key
            with mock.patch.dict("os.environ", {}, clear=True):
                with mock.patch("wdgwars_api_tester.Path.home",
                                return_value=fake_home):
                    self.assertIsNone(load_key(None))


class TestSecondsToNextMidnightDefaultNow(unittest.TestCase):
    def test_no_arg_uses_current_time(self) -> None:
        # test_outage_backoff.py always passes an explicit `now`; this
        # covers the `now is None -> time.time()` branch specifically.
        fixed = 1_800_000_000.0  # arbitrary fixed epoch, not near midnight
        with mock.patch("wdgwars_api_tester.time.time", return_value=fixed):
            via_default = _seconds_to_next_midnight_utc()
        via_explicit = _seconds_to_next_midnight_utc(fixed)
        self.assertEqual(via_default, via_explicit)


if __name__ == "__main__":
    unittest.main()
