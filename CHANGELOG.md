# Changelog

All notable changes to `wdgwars-api-tester`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-06-03 — Outage-aware backoff in `--watch` mode

`--watch` mode now detects LOCOSP-side outage (daily cap, per-IP rate
limit, or transport-level failure) and progressively extends the
inter-sweep sleep instead of hammering through the outage at the
operator-chosen cadence. Resets to normal cadence on the first clean
sweep. Triggered live by the 2026-06-03 outage when LOCOSP's documented
midnight-UTC daily quota tripped and the wider player base lost map
rendering + biscuit uploads.

### Added

- `--outage-backoff-threshold FLOAT` (default `0.30`): if at least this
  fraction of a sweep's results are `verdict=429` or `verdict=ERROR`
  (`status=0` transport failure), the next sleep is extended. Set
  `1.01` to disable the feature entirely.
- `--outage-backoff-cap-seconds FLOAT` (default `3600.0`): maximum
  sleep when in backoff. Capped further by time-to-next-midnight-UTC,
  since LOCOSP's daily quota documentedly resets at 00:00 UTC — no
  point sleeping past it.
- Three new public-ish helpers (importable for tests / external use):
  `_outage_share`, `_seconds_to_next_midnight_utc`,
  `_backoff_sleep_seconds`. Plus module-level constant
  `OUTAGE_VERDICT_TAGS = {"ERROR", "429"}` so the verdict set the
  feature treats as outage signal is one obvious source of truth.
- `test_outage_backoff.py`: 21 new unit tests covering threshold
  detection, midnight-UTC math (incl. edge cases at exactly midnight
  and one minute before), and the backoff sleep schedule (doubling,
  cap clamping, midnight clamping, never-below-base safety).

### Behavior

Streak doubles per consecutive outage sweep: `2x, 4x, 8x, 16x, 32x`
base, capping at the smaller of `--outage-backoff-cap-seconds` and
time-to-next-midnight-UTC. The streak resets to 0 on the first clean
sweep, with a log line announcing recovery. `DEAD`, `AUTH-REQUIRED`,
`AUTH-REDIRECT`, and other expected non-OK verdicts do NOT count
toward the outage share — only `429` and `ERROR` (transport-level).

### Why now

Triggered by a real 2026-06-03 incident where the WDGoWars API hit its
global daily cap (confirmed in Discord by WDGW staff: "The API is at
it's daily limit again. It'll reset at midnight UTC"). During the
~5-hour outage, this tool kept sweeping every 30 minutes, contributing
non-zero traffic to a quota that was already burned and producing only
all-429 noise. The feature is the structured fix.

## [0.6.3] — 2026-06-03 — Security Notes catch-up

Pure documentation release. Brings the family's documented security
posture to api-tester. No code changes.

### Added

- `SECURITY.md`: documents the probe's outbound footprint, key
  handling, the `--exec-on-change` threat model, and the alert payload
  shapes. Ported from Heimdall and adapted for the probe-tool surface
  (api-tester reads keys, never saves them; has alert paths the
  uploaders don't).

### Notes on what's intentionally NOT ported

- `scripts/check_readme_examples.py` (the venv-form README linter the
  three uploaders ship) is N/A for api-tester. The linter exists to
  catch the post-PEP-668 footgun where users follow `python3
  <script>.py` examples and hit `ModuleNotFoundError` because deps
  live in `.venv/`. api-tester is single-file stdlib-only — no deps,
  no venv requirement, no footgun. If a runtime dep is ever added,
  port the linter at the same time.
- `pages.yml` (the GitHub Pages workflow Muninn and Heimdall ship) is
  N/A for api-tester. It publishes the `web/` Pyodide frontend those
  two repos carry; api-tester has no browser-frontend surface.
- `--setup` / `--update` / `--schedule` from the uploader family are
  N/A here. api-tester reads keys from the shared family config path
  (`~/.config/wigle-to-wdgwars/wdgwars.key`); it does not manage its
  own. Scheduled monitoring is already covered by `--watch`, which is
  designed for continuous probing rather than daily snapshots.

## [0.6.2] — 2026-06-03

First family-alignment release. Pure housekeeping — no behavior changes
to the probe itself. Brings wdgwars-api-tester to repo-hygiene parity
with the other public feeders in the WDGoWars family.

### Added

- `CHANGELOG.md` (this file), back-filled from git history.
- `run.sh` / `run.bat` — double-clickable forward to `python3 wdgwars_api_tester.py "$@"`.
- `update.sh` / `update.bat` — fetch the latest single-file script from `main`.
- `scripts/smoke.sh` — pre-release smoke (import + `--version` + `--help` + offline tests + mock-server roundtrip).
- README `## Updating` section.

## [0.6.1] — 2026-05-30

### Changed

- `LEAK` verdict now fires when the body carries the LiteSpeed-admin telemetry
  fingerprint (`lsphp_processes` / `top_domains` / `lsphp`), not just when
  `/api/stats` returns HTTP 200. Tightened after the upstream `/api/stats` fix
  landed: the endpoint now `302`s to `/login`, which the old bare-status rule
  would have false-positived.
- `AUTH-REDIRECT` added as a first-class verdict. A `3xx` whose `Location`
  points at `/login` is the auth gate working, but the endpoint is wired
  through the web-session flow rather than returning `401` JSON — a routing
  shape regression for an API caller, but not a security/availability issue.
  Does **not** escalate to `DEGRADED`.
- Redirect-follow disabled for probes (we report the redirect target now, not
  the body the auth wall would have served us).

## [0.6.0] — 2026-05-30

### Added

- 8 new probes covering the full published REST surface (territories,
  member-territories, leaderboard, bounties, signed-upload, me-aps, aircraft,
  meshcore).

## [0.5.0] — 2026-05-30

### Added

- Offline-by-default integration tests (`integration_test.py`).
- `mock_wdgwars.py` standalone scenario server.

## [0.4.0] — 2026-05-29

### Added

- `--alert-webhook URL` — universal JSON POST on state change. Payload carries
  both `text` and `content` keys so Discord / Slack / n8n / PagerDuty consume
  the same URL without per-service flags.
- `--exec-on-change CMD` — arbitrary shell command on state change with
  `WDGWARS_*` env vars exported.

## [0.3.0] — 2026-05-29

### Added

- `--alert-telegram` — native Telegram self-paging in `--watch` mode. No
  external bridge required; pure stdlib `urllib` to the Bot API.

## [0.2.0] — 2026-05-29

### Added

- Quorum-sentinel logic (3 random /api/ paths, 2-of-3 majority required) so a
  single CDN-cache slip can't disable DEAD detection.
- `--quiet` summary mode.
- `--watch SECONDS` polling with compact state-change deltas.
- Unit test suite.

## [0.1.0] — 2026-05-29

### Added

- Initial release. Probes apex with the `(none, garbage, valid)` auth-variant
  matrix; reports per-probe verdicts and an overall summary.

[0.6.2]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.6.2
[0.6.1]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.6.1
[0.6.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.6.0
[0.5.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.5.0
[0.4.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.4.0
[0.3.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.3.0
[0.2.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.2.0
[0.1.0]: https://github.com/HiroAlleyCat/wdgwars-api-tester/releases/tag/v0.1.0
