"""Security-posture regression tests.

wdgwars-api-tester had no SonarCloud SAST findings to remediate when its CI
quality gate was added (see SECURITY-FINDINGS.md). Its one security-sensitive
construct is `_exec_on_change`, which runs an operator-authored shell command
on state change via `subprocess.run(..., shell=True)`. That is acceptable by
design — the command is authored by the operator (like a cron command or git
hook) — *and* it is only safe because the dynamic, potentially attacker-
influenced state data (deltas, verdicts, overall status) is passed to that
command through **environment variables**, never interpolated into the command
string.

This test LOCKS IN that contract: if a future refactor ever started splicing
delta/verdict text into the command, a shell-metacharacter payload in a delta
would execute, and `test_delta_payload_travels_as_env_data_not_code` would fail.

Run: python -m unittest test_security
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import wdgwars_api_tester as t  # noqa: E402


# A helper script that records the WDGWARS_* env vars handed to the hook into
# a JSON file (argv[1]). Invoked through the same shell=True path the tool uses.
_RECORDER = (
    "import os, json, sys\n"
    "keys = ['WDGWARS_OVERALL', 'WDGWARS_PREV_OVERALL', 'WDGWARS_DELTAS',\n"
    "        'WDGWARS_VERDICTS', 'WDGWARS_RECOVERY', 'WDGWARS_KIND',\n"
    "        'WDGWARS_SEVERITY']\n"
    "json.dump({k: os.environ.get(k) for k in keys}, open(sys.argv[1], 'w'))\n"
)


class ExecOnChangeEnvTransportTests(unittest.TestCase):

    def _run_hook(self, deltas, by_verdict, prev="HEALTHY", curr="BROKEN"):
        with tempfile.TemporaryDirectory() as d:
            recorder = Path(d) / "recorder.py"
            recorder.write_text(_RECORDER, encoding="utf-8")
            out = Path(d) / "env.json"
            # shell=True command, exactly as an operator would supply one.
            cmd = f'"{sys.executable}" "{recorder}" "{out}"'
            rc_ok = t._exec_on_change(cmd, prev, curr, deltas, by_verdict,
                                      timeout=30.0)
            self.assertTrue(rc_ok, "hook command should exit 0")
            return json.loads(out.read_text())

    def test_state_is_exported_as_env_vars(self):
        env = self._run_hook(["wdgwars.pl: HEALTHY -> DOWN"], {"DOWN": 1})
        self.assertEqual(env["WDGWARS_OVERALL"], "BROKEN")
        self.assertEqual(env["WDGWARS_PREV_OVERALL"], "HEALTHY")
        self.assertEqual(json.loads(env["WDGWARS_VERDICTS"]), {"DOWN": 1})

    def test_delta_payload_travels_as_env_data_not_code(self):
        # A delta line carrying a shell-injection payload must arrive verbatim
        # in WDGWARS_DELTAS (proving it went via the environment), and must not
        # have been executed as part of the command.
        payload = "; touch PWNED && echo $(reboot)"
        env = self._run_hook([payload, "host b: UP -> DOWN"], {"DOWN": 1})
        self.assertEqual(env["WDGWARS_DELTAS"], payload + "\nhost b: UP -> DOWN")
        # The payload's side effect (a PWNED file) must not exist anywhere we
        # ran — it was data, never code.
        self.assertFalse(Path("PWNED").exists())
        self.assertFalse((Path.cwd() / "PWNED").exists())

    def test_verdicts_payload_is_json_encoded_not_interpolated(self):
        # by_verdict values are server-influenced; they must be JSON in an env
        # var, not spliced into the command.
        env = self._run_hook(["x: UP -> DOWN"], {"DOWN`whoami`": 2})
        self.assertEqual(json.loads(env["WDGWARS_VERDICTS"]), {"DOWN`whoami`": 2})


if __name__ == "__main__":
    unittest.main()
