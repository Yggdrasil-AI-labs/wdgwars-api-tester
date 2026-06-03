# Changelog

All notable changes to `wdgwars-api-tester`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
