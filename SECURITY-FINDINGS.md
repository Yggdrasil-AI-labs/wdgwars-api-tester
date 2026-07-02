# Security review — findings & disposition

On **2026-06-21**, as part of bringing the WDGoWars feeder family onto a common
gated CI pipeline (pytest + coverage → SonarCloud → Snyk), `wdgwars_api_tester.py`
was reviewed for the same classes of issue that SonarCloud's SAST flagged in the
sibling **adsb-to-wdgwars (Muninn)** repo — path traversal, command/argument
injection, insecure temp-directory use, and unsafe database opens.

**Outcome: no code remediation needed; findings accepted-by-design in SonarCloud.**
This tool has one genuinely security-sensitive construct — a `shell=True`
exec-on-change hook — and it is acceptable by design, with the dynamic data
passed safely. The disposition is recorded below and the safe behavior is pinned
by regression tests ([`test_security.py`](test_security.py)).

**Update (2026-07-02):** the first green SonarCloud analysis (once a valid org
token was in place) flagged **8 vulnerabilities**, all reviewed and marked
**Accepted** in SonarCloud with the rationale below:
`pythonsecurity:S8707` × 6 (operator file paths: `--baseline`, `--state-log`,
etc.), `pythonsecurity:S8703` × 1 (webhook SSRF), `pythonsecurity:S8701` × 1
(the `shell=True` hook). Each is operator-controlled input on a local CLI — see
[the 2026-07-02 disposition](#2026-07-02--sonarcloud-sast-review) at the bottom.

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

## 2026-07-02 — SonarCloud SAST review

With a valid org `SONAR_TOKEN` in place, the scanner ran clean and flagged 8
vulnerabilities. Each was reviewed against the family threat model (a local
operator CLI: the operator's own argv is not the privilege boundary) and marked
**Accepted** in SonarCloud:

| Rule | Count | Where | Disposition |
|---|---|---|---|
| `pythonsecurity:S8707` | 6 | `_post_webhook`/state/baseline file paths (L1380, 1387, 1462, 1475, 1729, 2194) | **Accept-by-design.** Operator-chosen file paths (`--baseline`, `--state-log`); no traversal vector — the paths come from the operator's own argv, never from network data. No sandbox root to confine to. |
| `pythonsecurity:S8703` | 1 | `_post_webhook` request (L1327) | **Accept-by-design.** The webhook URL is the operator's own `--alert-webhook` / `--silent-webhook` / `--digest` value. There is no untrusted source of the URL, so this is not a server-side request forgery vector — it is the operator sending their own notifications. |
| `pythonsecurity:S8701` | 1 | `_exec_on_change` `subprocess.run(cmd, shell=True)` (L1666) | **Accept-by-design.** `--exec-on-change "<cmd>"` runs a command the operator authored (cron/git-hook trust model). Network-influenced state travels via env vars (`WDGWARS_*`), never interpolated into the command string. Pinned by `test_security.py`. |

Coverage was raised to clear the 80% new-code gate at the same time
(`test_webhook_and_hooks.py`). The tool is pure stdlib, so the Snyk stage is a
no-op (kept for family parity).
