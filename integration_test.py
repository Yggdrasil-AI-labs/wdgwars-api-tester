#!/usr/bin/env python3
"""Integration test harness for wdgwars-api-tester.

Offline by default — spawns mock_wdgwars HTTP servers on local ports and
runs the tool against them. Does NOT hit the real wdgwars.pl in default
mode (we just reported a hosting-telemetry bug to them and shouldn't be
adding tenant traffic).

Run:

    python3 integration_test.py             # offline, fast, safe
    python3 integration_test.py --live      # also runs the live-API
                                            # schema-validation tests
    INTEGRATION_LIVE=1 python3 integration_test.py    # env var also works

Exit 0 = all green. Exit 1 = at least one scenario failed.
"""
from __future__ import annotations

import http.server
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = ROOT / "wdgwars_api_tester.py"
PY = sys.executable
sys.path.insert(0, str(ROOT))
from mock_wdgwars import serve_in_thread  # noqa: E402

LIVE = "--live" in sys.argv or os.environ.get("INTEGRATION_LIVE") == "1"
if "--live" in sys.argv:
    sys.argv.remove("--live")

VALID_OVERALL_TOKENS = {"HEALTHY", "DEGRADED", "OUTAGE", "UNREACHABLE"}
VALID_OVERALL_SUFFIXES = ("+LEAK", "+SENTINEL-DIVERGED", "")


def _is_valid_overall(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    for base in VALID_OVERALL_TOKENS:
        if s == base:
            return True
        for suf1 in VALID_OVERALL_SUFFIXES:
            for suf2 in VALID_OVERALL_SUFFIXES:
                if s == base + suf1 + suf2:
                    return True
    return False


def run_tool(*argv: str, timeout: float = 30.0,
              env: dict | None = None) -> tuple[int, str, str]:
    cmd = [PY, str(TOOL), *argv]
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    r = subprocess.run(cmd, capture_output=True, text=True,
                        timeout=timeout, env=full_env)
    return r.returncode, r.stdout, r.stderr


# ─────────────────────── Webhook capture (for end-to-end notification) ─────


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    captured: queue.Queue = queue.Queue()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            parsed = None
        CaptureHandler.captured.put({
            "path": self.path,
            "body_raw": body.decode("utf-8", errors="replace"),
            "body_json": parsed,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, fmt, *args):
        pass


def start_capture_server() -> tuple[http.server.HTTPServer, int]:
    srv = http.server.HTTPServer(("127.0.0.1", 0), CaptureHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


# ─────────────────────── Integration scenarios ─────────────────────────────


class IntegrationTests(unittest.TestCase):
    """Each test exercises a documented capability against a local mock."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="wdgwars-integ-")
        # Spin up one mock server per scenario. Cheap — pure stdlib.
        cls.mocks = {}
        for scenario in ("outage", "healthy", "partial", "diverged"):
            srv, port = serve_in_thread(scenario)
            cls.mocks[scenario] = (srv, port, f"http://127.0.0.1:{port}")
        print(f"\n[integration] tmpdir: {cls.tmpdir}", file=sys.stderr)
        print(f"[integration] mock ports: "
              f"{ {k: v[1] for k, v in cls.mocks.items()} }",
              file=sys.stderr)

    @classmethod
    def tearDownClass(cls):
        for srv, _, _ in cls.mocks.values():
            srv.shutdown()

    def mock_url(self, scenario: str) -> str:
        return self.mocks[scenario][2]

    # ──────────── Basic invocation (mock URL — fast, safe) ───────────────

    def test_01_version_flag(self):
        rc, out, err = run_tool("--version")
        self.assertEqual(rc, 0)
        self.assertRegex((out + err).strip(), r"\d+\.\d+\.\d+")

    def test_02_help_lists_all_documented_flags(self):
        rc, out, err = run_tool("--help")
        self.assertEqual(rc, 0)
        text = out + err
        for flag in ("--hosts", "--variants", "--key", "--timeout",
                     "--json", "--no-table", "--quiet", "--watch",
                     "--baseline", "--alert-telegram",
                     "--telegram-bot-token", "--telegram-chat-id",
                     "--alert-webhook", "--exec-on-change", "--version"):
            self.assertIn(flag, text, f"--help missing {flag}")

    def test_03_default_oneshot_against_mock_outage(self):
        rc, out, err = run_tool("--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1, f"outage should exit 1, got {rc}; err={err}")
        self.assertIn("verdict", err)
        self.assertIn("DEGRADED", err)
        self.assertIn("LEAK", err)

    def test_04_quiet_against_mock_outage(self):
        rc, out, err = run_tool("--quiet",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "DEGRADED+LEAK",
                          f"expected DEGRADED+LEAK, got {out!r}")

    def test_05_json_schema_matches_documented(self):
        rc, out, err = run_tool("--json", "--no-table",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        snap = json.loads(out)
        for key in ("tool", "version", "timestamp", "hosts",
                     "variants", "summary", "results"):
            self.assertIn(key, snap)
        self.assertEqual(snap["tool"], "wdgwars-api-tester")
        probe_names = {r["probe"] for r in snap["results"]}
        for documented in ("api-root", "me", "upload-history",
                            "upload-csv", "v2-upload-csv", "signed-upload",
                            "me-aps", "aircraft", "meshcore",
                            "territories", "member-territories",
                            "leaderboard", "bounties",
                            "team-messages", "team-messages-id",
                            "health-asked-for", "stats-leak-check",
                            "non-api-sentinel-404", "changelog-control",
                            "api-sentinel-404-a", "api-sentinel-404-b",
                            "api-sentinel-404-c"):
            self.assertIn(documented, probe_names)

    def test_06_no_table_suppresses_table_only(self):
        rc, out, err = run_tool("--no-table",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertIn(rc, (0, 1))
        self.assertNotIn("verdict          status", err)
        self.assertEqual(out, "")

    # ──────────── Scenario-specific verdict assertions ───────────────────

    def test_07_healthy_scenario_produces_HEALTHY(self):
        rc, out, err = run_tool("--quiet",
                                "--hosts", self.mock_url("healthy"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 0,
                          f"healthy mock should exit 0, got {rc}; err={err}")
        self.assertEqual(out.strip(), "HEALTHY",
                          f"expected HEALTHY, got {out!r}")

    def test_08_partial_scenario_produces_HEALTHY_plus_LEAK(self):
        rc, out, err = run_tool("--quiet",
                                "--hosts", self.mock_url("partial"),
                                "--variants", "none,garbage")
        # HEALTHY+LEAK — API up but stats still leaking. Non-zero exit
        # because LEAK is in the suffix.
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "HEALTHY+LEAK",
                          f"expected HEALTHY+LEAK, got {out!r}")

    def test_09_diverged_scenario_produces_SENTINEL_DIVERGED_suffix(self):
        rc, out, err = run_tool("--quiet",
                                "--hosts", self.mock_url("diverged"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("SENTINEL-DIVERGED", out,
                       f"expected +SENTINEL-DIVERGED in overall, got {out!r}")

    def test_10_outage_with_valid_key_marks_OUTAGE_not_DEGRADED(self):
        # The `me` valid-key probe being DEAD is the OUTAGE trigger.
        # Include `none` in variants so the sentinel probes run (they
        # don't take auth, and without them there's no canonical
        # fingerprint and DEAD detection is disabled).
        rc, out, err = run_tool("--quiet",
                                "--key", "x" * 64,
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,valid")
        self.assertEqual(rc, 1)
        self.assertTrue(out.strip().startswith("OUTAGE"),
                         f"expected OUTAGE... with valid key + outage mock, "
                         f"got {out!r}")

    # ──────────── Validation + guard rails ───────────────────────────────

    def test_11_invalid_variant_rejected(self):
        rc, out, err = run_tool("--hosts", self.mock_url("outage"),
                                "--variants", "nope")
        self.assertEqual(rc, 2)
        self.assertIn("Unknown auth variants", err)

    def test_12_invalid_hosts_rejected(self):
        rc, out, err = run_tool("--hosts", "ftp://nope",
                                "--variants", "none")
        self.assertEqual(rc, 2)
        self.assertIn("invalid --hosts", err)

    def test_13_alert_telegram_without_watch_warns(self):
        rc, out, err = run_tool("--quiet", "--alert-telegram",
                                "--telegram-bot-token", "fake",
                                "--telegram-chat-id", "fake",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("requires --watch", err)

    def test_14_alert_webhook_without_watch_warns(self):
        rc, out, err = run_tool("--quiet",
                                "--alert-webhook", "https://example.com/x",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("require --watch", err)

    def test_15_exec_on_change_without_watch_warns(self):
        rc, out, err = run_tool("--quiet",
                                "--exec-on-change", "true",
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("require --watch", err)

    # ──────────── Baseline mode ──────────────────────────────────────────

    def test_16_baseline_creates_file_first_run(self):
        baseline = Path(self.tmpdir) / "test16-baseline.json"
        rc, out, err = run_tool("--no-table",
                                "--baseline", str(baseline),
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertTrue(baseline.exists())
        self.assertIn("baseline written", err)
        data = json.loads(baseline.read_text(encoding="utf-8"))
        self.assertIn("results", data)

    def test_17_baseline_diffs_on_second_run(self):
        baseline = Path(self.tmpdir) / "test17-baseline.json"
        # Seed with a fabricated baseline that disagrees with current.
        fake = {"results": [
            {"host": "https://wdgwars.pl", "probe": "me", "auth": "none",
             "verdict": "OK", "status": 200},
        ]}
        baseline.write_text(json.dumps(fake), encoding="utf-8")
        rc, out, err = run_tool("--no-table",
                                "--baseline", str(baseline),
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("baseline diffs", err)

    # ──────────── Cross-scenario verdict transition (recovery) ──────────

    def test_18_baseline_stable_against_same_scenario(self):
        """Run twice against the same mock — second run should report no
        diff. This proves the verdict pipeline is deterministic across
        successive runs given identical API behavior."""
        baseline = Path(self.tmpdir) / "test18-baseline.json"
        rc, _, _ = run_tool("--no-table", "--baseline", str(baseline),
                              "--hosts", self.mock_url("outage"),
                              "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        # Second run against same mock.
        rc, out, err = run_tool("--no-table", "--baseline", str(baseline),
                                  "--hosts", self.mock_url("outage"),
                                  "--variants", "none,garbage")
        self.assertEqual(rc, 1)
        self.assertIn("no diff vs baseline", err,
                       f"expected stable verdicts run-over-run, got: {err[:500]}")

    # ──────────── End-to-end notification dispatch ──────────────────────

    def test_19_webhook_post_against_capture_server(self):
        """Verify _post_webhook + _format_webhook_payload talk to a mock
        receiver and the payload shape matches what the README documents.
        Driver receives root + webhook URL via argv (no path-embedding)."""
        while not CaptureHandler.captured.empty():
            try:
                CaptureHandler.captured.get_nowait()
            except queue.Empty:
                break
        srv, port = start_capture_server()
        try:
            webhook_url = f"http://127.0.0.1:{port}/hook"
            driver = Path(self.tmpdir) / "driver19.py"
            driver.write_text(
                "import sys\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "from wdgwars_api_tester import "
                "_post_webhook, _format_webhook_payload\n"
                "deltas = ['wdgwars.pl me/valid OK/200 -> DEAD/404']\n"
                "verdicts = {'DEAD': 10, 'LEAK': 1, 'OK': 1}\n"
                "payload = _format_webhook_payload("
                "'HEALTHY', 'OUTAGE+LEAK', deltas, verdicts)\n"
                "ok = _post_webhook(sys.argv[2], payload)\n"
                "print(f'ok={ok}')\n",
                encoding="utf-8",
            )
            r = subprocess.run(
                [PY, str(driver), str(ROOT), webhook_url],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(r.returncode, 0, f"driver: {r.stderr}")
            self.assertIn("ok=True", r.stdout)

            captured = CaptureHandler.captured.get(timeout=5.0)
            body = captured["body_json"]
            self.assertEqual(body["overall"], "OUTAGE+LEAK")
            self.assertEqual(body["prev_overall"], "HEALTHY")
            self.assertEqual(body["kind"], "regression")
            self.assertIn("text", body)
            self.assertIn("content", body)
            self.assertEqual(body["tool"], "wdgwars-api-tester")
        finally:
            srv.shutdown()

    def test_20_exec_on_change_env_vars_set_correctly(self):
        """Cross-platform env-capture test for _exec_on_change.

        Pass paths via argv to the driver rather than embedding them in
        source (Windows backslash paths break Python unicode-escape
        parsing when inlined as string literals).
        """
        exec_sink = Path(self.tmpdir) / "test20-sink.txt"
        capture = Path(self.tmpdir) / "capture_env.py"
        capture.write_text(
            "import os, sys\n"
            "with open(sys.argv[1], 'w', encoding='utf-8') as f:\n"
            "    for k in sorted(os.environ):\n"
            "        if k.startswith('WDGWARS_'):\n"
            "            f.write(f'{k}={os.environ[k]}\\n')\n",
            encoding="utf-8",
        )
        driver = Path(self.tmpdir) / "driver20.py"
        # The driver reads argv: [root_dir, python_exe, capture_script, sink].
        # It constructs the exec command at runtime from those args, avoiding
        # any string-literal embedding of OS paths.
        driver.write_text(
            "import sys, shlex\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from wdgwars_api_tester import _exec_on_change\n"
            "py, cap, sink = sys.argv[2], sys.argv[3], sys.argv[4]\n"
            # Quote each path defensively — works on both Win cmd.exe and POSIX sh.
            "cmd = f'\"{py}\" \"{cap}\" \"{sink}\"'\n"
            "deltas = ['foo OK/200 -> DEAD/404']\n"
            "verdicts = {'DEAD': 1}\n"
            "ok = _exec_on_change(cmd, 'HEALTHY', 'OUTAGE+LEAK', deltas, verdicts)\n"
            "print(f'ok={ok}')\n",
            encoding="utf-8",
        )
        r = subprocess.run(
            [PY, str(driver), str(ROOT), PY, str(capture), str(exec_sink)],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(r.returncode, 0,
                          f"driver rc={r.returncode}\n"
                          f"stdout={r.stdout}\nstderr={r.stderr}")
        self.assertIn("ok=True", r.stdout)
        self.assertTrue(exec_sink.exists())
        text = exec_sink.read_text(encoding="utf-8")
        self.assertIn("WDGWARS_OVERALL=OUTAGE+LEAK", text)
        self.assertIn("WDGWARS_PREV_OVERALL=HEALTHY", text)
        self.assertIn("WDGWARS_KIND=regression", text)
        self.assertIn("WDGWARS_RECOVERY=0", text)

    # ──────────── v2-upload-csv async round-trip ─────────────────────────

    def test_21_v2_upload_csv_round_trip_against_healthy(self):
        """Healthy mock: POST 202 → poll → done → status rewritten to 200,
        verdict OK, no error. Proves the custom_runner dispatch + the full
        async pipeline work end-to-end against a mock that follows the
        documented two-step contract.
        """
        rc, out, err = run_tool("--json", "--no-table",
                                "--key", "x" * 64,
                                "--hosts", self.mock_url("healthy"),
                                "--variants", "valid",
                                timeout=60.0)
        self.assertIn(rc, (0, 1))
        snap = json.loads(out)
        v2 = [r for r in snap["results"]
              if r["probe"] == "v2-upload-csv" and r["auth"] == "valid"]
        self.assertEqual(len(v2), 1, f"expected one v2 valid result, got {v2}")
        r = v2[0]
        self.assertEqual(r["status"], 200,
                          f"v2 round-trip should rewrite status to 200 on done; "
                          f"got {r}")
        self.assertEqual(r["verdict"], "OK", f"verdict should be OK; got {r}")
        self.assertEqual(r["error"], "")

    def test_22_v2_upload_csv_marked_dead_during_outage(self):
        """Outage mock: POST hits the styled-404 fallthrough; custom_runner
        short-circuits without polling because status != 2xx. The shared
        body_md5 lines up with the sentinel fingerprint so DEAD verdict
        fires — same blast radius as a v1 endpoint going dark.

        `none` is included in variants so the sentinel probes (which are
        needs_auth=False) actually run and establish the canonical /api/
        404 fingerprint. Without that, DEAD detection is disabled and the
        v2 result falls through to a plain 404 verdict — see test_10.
        """
        rc, out, err = run_tool("--json", "--no-table",
                                "--key", "x" * 64,
                                "--hosts", self.mock_url("outage"),
                                "--variants", "none,valid",
                                timeout=60.0)
        self.assertEqual(rc, 1)
        snap = json.loads(out)
        v2 = [r for r in snap["results"]
              if r["probe"] == "v2-upload-csv" and r["auth"] == "valid"]
        self.assertEqual(len(v2), 1)
        self.assertEqual(v2[0]["verdict"], "DEAD",
                          f"v2 should be DEAD when styled-404 fingerprint "
                          f"matches; got {v2[0]}")


# ──────────── Live-only tests (opt-in via --live or INTEGRATION_LIVE=1) ──


@unittest.skipUnless(LIVE,
    "Live tests skipped. Pass --live or INTEGRATION_LIVE=1 to enable.")
class LiveTests(unittest.TestCase):
    """Schema-validation against the real wdgwars.pl. Opt-in — these hit
    the actual API and shouldn't run on every developer push."""

    def test_live_probe_schema(self):
        rc, out, err = run_tool("--json", "--no-table",
                                "--variants", "none,garbage",
                                "--timeout", "20", timeout=60.0)
        self.assertIn(rc, (0, 1))
        snap = json.loads(out)
        probe_names = {r["probe"] for r in snap["results"]}
        for documented in ("api-root", "me", "upload-history",
                            "upload-csv", "v2-upload-csv", "signed-upload",
                            "me-aps", "aircraft", "meshcore",
                            "territories", "member-territories",
                            "leaderboard", "bounties",
                            "team-messages", "team-messages-id",
                            "health-asked-for", "stats-leak-check",
                            "non-api-sentinel-404", "changelog-control",
                            "api-sentinel-404-a", "api-sentinel-404-b",
                            "api-sentinel-404-c"):
            self.assertIn(documented, probe_names,
                           f"README documents '{documented}' but it's "
                           "missing from live output")
        sentinels = [r for r in snap["results"]
                      if r["probe"].startswith("api-sentinel-404-")
                      and not r["probe"].endswith("nonapi")]
        self.assertEqual(len(sentinels), 3)


def main():
    print("=" * 70)
    print(f"wdgwars-api-tester integration test loop  "
           f"({'OFFLINE+LIVE' if LIVE else 'OFFLINE'})")
    print("=" * 70)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(IntegrationTests),
        loader.loadTestsFromTestCase(LiveTests),
    ])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print()
    print("=" * 70)
    print(f"Ran {result.testsRun} integration scenarios "
           f"({'OFFLINE+LIVE' if LIVE else 'OFFLINE'})")
    print(f"Failures: {len(result.failures)}   "
           f"Errors: {len(result.errors)}   "
           f"Skipped: {len(result.skipped)}")
    print("=" * 70)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
