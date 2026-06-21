# Security review — findings & disposition

On **2026-06-21**, as part of bringing the WDGoWars feeder family onto a common
gated CI pipeline (pytest + coverage → SonarCloud → Snyk), `wdgwars_api_tester.py`
was reviewed for the same classes of issue that SonarCloud's SAST flagged in the
sibling **adsb-to-wdgwars (Muninn)** repo — path traversal, command/argument
injection, insecure temp-directory use, and unsafe database opens.

**Outcome: no remediation needed.** This tool has one genuinely
security-sensitive construct — a `shell=True` exec-on-change hook — and it is
acceptable by design, with the dynamic data passed safely. The disposition is
recorded below and the safe behavior is now pinned by a regression test
([`test_security.py`](test_security.py)).

## Disposition

| Muninn finding class | Status here |
|---|---|
| **S6350 / S8705** — command / OS-command from untrusted data (`subprocess.run(cmd, shell=True)` in `_exec_on_change`) | **Acceptable by design.** `--exec-on-change "<cmd>"` runs a command the **operator** authored (the same trust model as a cron command or git hook). Crucially, the dynamic, network-influenced state (deltas, verdict counts, overall status) is passed to that command via **environment variables** (`WDGWARS_OVERALL`, `WDGWARS_DELTAS`, `WDGWARS_VERDICTS`, …), **never interpolated into the command string** — so server-side data cannot inject shell code. This matches the threat model already documented in `SECURITY.md` → "Exec-on-change", and is now locked by `test_security.py` (`test_delta_payload_travels_as_env_data_not_code`). |
| **S8707 / S6549** — path construction from CLI args (`--baseline`, `--state-log`) | **Accept-by-design.** Both are operator-chosen file paths: `--state-log` is appended to (JSONL), `--baseline` is read/written for snapshot comparison. The state-log path is a fixed operator-supplied location, never derived from network data, so there is no traversal vector. As with the rest of the family, this is a local operator CLI with no sandbox root to confine to. |
| **S2083** — path traversal into a watch state file | **N/A** — the `--state-log` path is operator-supplied, not built from a watched directory's contents. |
| **S5443** — publicly-writable / `/tmp` directory | **N/A** — no `tempfile`/`gettempdir`/`/tmp` use in the tool. |
| **S8706** — SQLite connection from a filename | **N/A** — no SQLite. |

## What the regression test pins

`test_security.py` runs `_exec_on_change` through the real `shell=True` path with
a delta line carrying a shell-injection payload (`; touch PWNED && echo
$(reboot)`) and asserts:

- the payload arrives **verbatim** in `WDGWARS_DELTAS` (proving it travelled as
  environment *data*, not command text), and
- its side effect (a `PWNED` file) never materialises (proving it was never
  executed),
- and that server-influenced verdict keys are JSON-encoded in an env var rather
  than spliced into the command.

If a future change ever starts interpolating delta/verdict text into the
command string, that test fails.

## A note for when SonarCloud is enabled

This repo is not yet imported into SonarCloud. Once it is (and the `SONAR_TOKEN`
/ `SNYK_TOKEN` secrets are added — see [CI.md](CI.md)), the scanner will almost
certainly raise a hotspot on the `shell=True` call in `_exec_on_change`. Mark it
**Safe** with the rationale above: the command is operator-authored and the
untrusted state reaches it only through environment variables. The tool is pure
stdlib, so the Snyk stage is effectively a no-op (kept for family parity).
