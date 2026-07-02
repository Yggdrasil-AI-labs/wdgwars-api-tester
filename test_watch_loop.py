"""Integration tests for the --watch loop inside main() (the while True:
loop at roughly wdgwars_api_tester.py:2041-2164).

This is the last block of new code without coverage: --check-stale,
--digest, and the one-shot path are covered elsewhere, but nothing drove
the watch loop itself end-to-end. These tests patch `time.sleep` to raise
KeyboardInterrupt after one iteration (the loop's own
`except KeyboardInterrupt: return 0` then unwinds main() cleanly), and
mock `run_once` so no network call is ever attempted. `time.monotonic` is
left real since the loop uses it for sweep timing.

Run with: python -m pytest -q test_watch_loop.py
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import wdgwars_api_tester as wat


def _mk_result(verdict: str = "OK", status: int = 200,
               probe: str = "changelog-control",
               auth: str = "none") -> wat.Result:
    """Minimal real Result for tests that need summary()/state_signature()
    (or _outage_share()) to run on real objects instead of being mocked.

    Defaults deliberately avoid probe="me"/auth="valid" -- summary()
    escalates a DEAD verdict on that specific (probe, auth) pair straight
    to OUTAGE instead of DEGRADED (see wdgwars_api_tester.py:713)."""
    return wat.Result(
        probe=probe,
        host="https://wdgwars.pl",
        auth=auth,
        method="GET",
        url="https://wdgwars.pl/api/me",
        status=status,
        elapsed_ms=10,
        body_len=2,
        body_md5="deadbeef",
        content_type="application/json",
        cf_cache_status="",
        x_request_id="",
        server="",
        verdict=verdict,
    )


class TestWatchLoopNormalPath(unittest.TestCase):
    """First pass + normal-cadence sleep (no sweep-deadline pool, no
    outage backoff)."""

    def test_one_iteration_then_keyboard_interrupt_returns_0(self) -> None:
        with mock.patch.object(wat, "run_once", return_value=[]) as m_run, \
             mock.patch.object(wat, "summary",
                               return_value={"overall": "HEALTHY",
                                             "by_verdict": {"OK": 1},
                                             "total": 1}), \
             mock.patch.object(wat, "state_signature", return_value="sig"), \
             mock.patch.object(wat.time, "sleep",
                               side_effect=KeyboardInterrupt):
            rc = wat.main(["--watch", "1", "--quiet", "--key", "x"])
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(m_run.call_count, 1)

    def test_run_once_called_with_expected_hosts_and_key(self) -> None:
        with mock.patch.object(wat, "run_once", return_value=[]) as m_run, \
             mock.patch.object(wat, "summary",
                               return_value={"overall": "HEALTHY",
                                             "by_verdict": {}, "total": 0}), \
             mock.patch.object(wat, "state_signature", return_value="sig"), \
             mock.patch.object(wat.time, "sleep",
                               side_effect=KeyboardInterrupt):
            wat.main(["--watch", "1", "--quiet", "--key", "x"])
        args, kwargs = m_run.call_args
        self.assertEqual(args[0], wat.DEFAULT_HOSTS)
        self.assertEqual(kwargs.get("team_id"), 1)

    def test_state_change_on_second_pass_triggers_delta_log(self) -> None:
        # Two passes: HEALTHY -> DEGRADED, then interrupt. Exercises the
        # "state change" branch (not just first-pass) before the sleep.
        results_seq = [[], [_mk_result(verdict="DEAD", status=404)]]
        summaries_seq = [
            {"overall": "HEALTHY", "by_verdict": {}, "total": 0},
            {"overall": "DEGRADED", "by_verdict": {"DEAD": 1}, "total": 1},
        ]

        def _run_once(*a, **kw):
            return results_seq.pop(0) if results_seq else []

        def _summary(_results):
            return summaries_seq.pop(0) if summaries_seq else summaries_seq[-1]

        sleep_calls = {"n": 0}

        def _sleep(_seconds):
            sleep_calls["n"] += 1
            if sleep_calls["n"] >= 2:
                raise KeyboardInterrupt
            return None

        with mock.patch.object(wat, "run_once", side_effect=_run_once), \
             mock.patch.object(wat, "summary", side_effect=_summary), \
             mock.patch.object(wat, "state_signature", return_value="sig"), \
             mock.patch.object(wat.time, "sleep", side_effect=_sleep):
            with self.assertLogs(level="INFO") as cm:
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x"])
        self.assertEqual(rc, 0)
        self.assertTrue(any("state change" in line for line in cm.output))


class TestWatchLoopOutageBackoff(unittest.TestCase):
    """Drives the outage-backoff branch (~2135-2157): a sweep whose
    bad-verdict share clears --outage-backoff-threshold extends the sleep
    instead of using the normal --watch cadence."""

    def test_outage_share_over_threshold_takes_backoff_branch(self) -> None:
        bad_results = [_mk_result(verdict="429", status=429) for _ in range(5)]
        with mock.patch.object(wat, "run_once", return_value=bad_results), \
             mock.patch.object(wat.time, "sleep",
                               side_effect=KeyboardInterrupt) as m_sleep:
            with self.assertLogs(level="INFO") as cm:
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x"])
        self.assertEqual(rc, 0)
        self.assertTrue(any("outage-backoff" in line for line in cm.output))
        # The backoff branch still ultimately calls time.sleep (with the
        # extended duration) -- that's what raises the KeyboardInterrupt.
        m_sleep.assert_called()

    def test_outage_clears_after_healthy_sweep_logs_resume(self) -> None:
        # First sweep: all 429 (enters backoff, streak=1). Second sweep:
        # clean, so the "outage-backoff: clear" log line fires before the
        # normal-cadence sleep raises the interrupt.
        results_seq = [
            [_mk_result(verdict="429", status=429) for _ in range(5)],
            [_mk_result(verdict="OK", status=200)],
        ]

        def _run_once(*a, **kw):
            return results_seq.pop(0) if results_seq else [_mk_result()]

        sleep_calls = {"n": 0}

        def _sleep(_seconds):
            sleep_calls["n"] += 1
            if sleep_calls["n"] >= 2:
                raise KeyboardInterrupt
            return None

        with mock.patch.object(wat, "run_once", side_effect=_run_once), \
             mock.patch.object(wat.time, "sleep", side_effect=_sleep):
            with self.assertLogs(level="INFO") as cm:
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x",
                              "--outage-backoff-threshold", "0.5"])
        self.assertEqual(rc, 0)
        joined = " ".join(cm.output)
        self.assertIn("outage-backoff:", joined)
        self.assertIn("clear", joined)


class TestWatchLoopHeartbeatFile(unittest.TestCase):
    """Covers the pre-loop STARTING heartbeat write (~2039) and the
    in-loop post-sweep heartbeat write (~2134-2137)."""

    def test_heartbeat_file_written_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            with mock.patch.object(wat, "run_once", return_value=[]), \
                 mock.patch.object(wat, "summary",
                                   return_value={"overall": "HEALTHY",
                                                 "by_verdict": {},
                                                 "total": 0}), \
                 mock.patch.object(wat, "state_signature", return_value="sig"), \
                 mock.patch.object(wat.time, "sleep",
                                   side_effect=KeyboardInterrupt):
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x",
                              "--heartbeat-file", str(hb)])
            self.assertEqual(rc, 0)
            self.assertTrue(hb.exists())
            rec = json.loads(hb.read_text(encoding="utf-8"))
            # Written at least once post-sweep with status "ok" (the
            # pre-loop STARTING write is overwritten by the real pass).
            self.assertEqual(rec["status"], "ok")
            self.assertEqual(rec["overall"], "HEALTHY")


class TestWatchLoopAlertFanout(unittest.TestCase):
    """Drives the state-change alert fanout (~2089-2131): telegram,
    alert-webhook (multi-URL), exec-on-change, and state-log all fire when
    overall changes and _should_suppress_alert says "overall state
    changed" (never suppressed)."""

    def _two_pass_then_interrupt(self, second_results):
        results_seq = [[_mk_result(verdict="OK", status=200)], second_results]

        def _run_once(*a, **kw):
            return results_seq.pop(0) if results_seq else second_results

        sleep_calls = {"n": 0}

        def _sleep(_seconds):
            sleep_calls["n"] += 1
            if sleep_calls["n"] >= 2:
                raise KeyboardInterrupt
            return None

        return _run_once, _sleep

    def test_alert_webhook_fanout_and_state_log_and_exec_on_change(self) -> None:
        second = [_mk_result(verdict="DEAD", status=404)]
        _run_once, _sleep = self._two_pass_then_interrupt(second)
        with tempfile.TemporaryDirectory() as d:
            state_log = Path(d) / "state.jsonl"
            with mock.patch.object(wat, "run_once", side_effect=_run_once), \
                 mock.patch.object(wat.time, "sleep", side_effect=_sleep), \
                 mock.patch.object(wat, "_post_webhook",
                                   return_value=True) as m_webhook, \
                 mock.patch.object(wat, "_exec_on_change",
                                   return_value=True) as m_exec:
                rc = wat.main([
                    "--watch", "1", "--quiet", "--key", "x",
                    "--alert-webhook", "https://example.com/hook-a",
                    "--alert-webhook", "https://example.com/hook-b",
                    "--exec-on-change", "irrelevant-cmd",
                    "--state-log", str(state_log),
                ])
            self.assertEqual(rc, 0)
            # Fanned out to both --alert-webhook URLs independently.
            self.assertEqual(m_webhook.call_count, 2)
            called_urls = [c.args[0] for c in m_webhook.call_args_list]
            self.assertEqual(called_urls,
                             ["https://example.com/hook-a",
                              "https://example.com/hook-b"])
            m_exec.assert_called_once()
            self.assertTrue(state_log.exists())
            lines = state_log.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["prev_overall"], "HEALTHY")
            self.assertEqual(rec["curr_overall"], "DEGRADED")
            self.assertFalse(rec["suppressed"])

    def test_alert_telegram_posts_on_state_change(self) -> None:
        second = [_mk_result(verdict="DEAD", status=404)]
        _run_once, _sleep = self._two_pass_then_interrupt(second)
        with mock.patch.object(wat, "run_once", side_effect=_run_once), \
             mock.patch.object(wat.time, "sleep", side_effect=_sleep), \
             mock.patch.object(wat, "_post_telegram",
                               return_value=True) as m_tg:
            rc = wat.main([
                "--watch", "1", "--quiet", "--key", "x",
                "--alert-telegram",
                "--telegram-bot-token", "tok",
                "--telegram-chat-id", "123",
            ])
        self.assertEqual(rc, 0)
        m_tg.assert_called_once()

    def test_recovery_transition_logs_recovery_header(self) -> None:
        # DEGRADED -> HEALTHY is the "recovery" branch (~2074-2086), which
        # also re-emits the full table even in non-quiet mode.
        results_seq = [[_mk_result(verdict="DEAD", status=404)],
                       [_mk_result(verdict="OK", status=200)]]

        def _run_once(*a, **kw):
            return results_seq.pop(0) if results_seq else results_seq[-1]

        sleep_calls = {"n": 0}

        def _sleep(_seconds):
            sleep_calls["n"] += 1
            if sleep_calls["n"] >= 2:
                raise KeyboardInterrupt
            return None

        with mock.patch.object(wat, "run_once", side_effect=_run_once), \
             mock.patch.object(wat.time, "sleep", side_effect=_sleep):
            with self.assertLogs(level="INFO") as cm:
                rc = wat.main(["--watch", "1", "--key", "x"])
        self.assertEqual(rc, 0)
        self.assertTrue(any("RECOVERY" in line for line in cm.output))


class TestWatchLoopSweepDeadline(unittest.TestCase):
    """Drives the --sweep-deadline pool path (~2033-2064): sweeps run in a
    ThreadPoolExecutor with a hard wall-clock ceiling."""

    def test_sweep_completes_within_deadline_via_pool(self) -> None:
        with mock.patch.object(wat, "run_once", return_value=[]), \
             mock.patch.object(wat.time, "sleep",
                               side_effect=KeyboardInterrupt):
            rc = wat.main(["--watch", "1", "--quiet", "--key", "x",
                          "--sweep-deadline", "5"])
        self.assertEqual(rc, 0)

    def test_sweep_exceeding_deadline_is_abandoned_and_pool_recreated(self) -> None:
        # one_pass() is built from run_once/summary/state_signature inside
        # main(), so to force the pool's fut.result() to time out we make
        # run_once block past the deadline via a real (short) sleep in the
        # worker thread -- time.sleep is patched module-wide, so use
        # threading.Event.wait instead, which is unaffected by the patch.
        # A fresh Event per call (never .set()) means every submitted sweep
        # blocks for the full 2s wait, so every pass times out at the 0.05s
        # deadline -- the abandonment branch, not the happy path.
        import threading

        def _slow_run_once(*a, **kw):
            threading.Event().wait(timeout=2.0)
            return []

        with mock.patch.object(wat, "run_once", side_effect=_slow_run_once), \
             mock.patch.object(wat.time, "sleep",
                               side_effect=KeyboardInterrupt):
            with self.assertLogs(level="ERROR") as cm:
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x",
                              "--sweep-deadline", "0.05"])
        self.assertEqual(rc, 0)
        self.assertTrue(any("sweep-deadline" in line for line in cm.output))

    def test_deadline_abandonment_writes_stalled_heartbeat(self) -> None:
        import threading

        def _slow_run_once(*a, **kw):
            threading.Event().wait(timeout=2.0)
            return []

        with tempfile.TemporaryDirectory() as d:
            hb = Path(d) / "hb.json"
            with mock.patch.object(wat, "run_once", side_effect=_slow_run_once), \
                 mock.patch.object(wat.time, "sleep",
                                   side_effect=KeyboardInterrupt):
                rc = wat.main(["--watch", "1", "--quiet", "--key", "x",
                              "--sweep-deadline", "0.05",
                              "--heartbeat-file", str(hb)])
            self.assertEqual(rc, 0)
            rec = json.loads(hb.read_text(encoding="utf-8"))
            self.assertEqual(rec["status"], "stalled")


if __name__ == "__main__":
    unittest.main()
