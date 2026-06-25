# Changelog

All notable changes to `wdgwars-api-tester`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.13.2] - Watchdog log wording

`--check-stale`'s healthy log line reused the staleness phrasing, reading e.g.
`last heartbeat 3s ago (>16200s)` on success — confusing. It now reads `(within
16200s threshold)` when fresh and `(over … threshold)` when stale. Log text
only; no behavior change.

## [0.13.1] - Startup heartbeat

`--watch` now writes a `status=starting` heartbeat before the first sweep when
`--heartbeat-file` is set. Without it, a fresh start (or restart) had no
heartbeat for the duration of the first sweep (~30s), so a `--check-stale`
watchdog firing in that window would false-alarm on a missing file. Now a
heartbeat always exists once the loop is up.

## [0.13.0] - Watch-loop wedge protection

The `--watch` loop could freeze indefinitely without dying. `--timeout` is a
per-socket-read timeout, not a total deadline, so a response that trickles
bytes (or a half-open connection a CDN keeps warm) blocks `resp.read()`
forever. The single-threaded loop then stops sweeping while the process stays
`active (running)` — alerting silently dies but `systemctl is-active` looks
healthy. Observed in the field: a watch instance went silent for 8 days after
wedging mid-sweep, with `is-active` reporting `active` the whole time.

Two defenses, plus an external watchdog hook:

### Added

- `--sweep-deadline SECONDS` (default 180, 0 disables) — hard wall-clock ceiling
  on a single sweep in `--watch` mode. A sweep that exceeds it is abandoned and
  the loop continues; the stuck worker is left to drain and the internal
  one-slot executor is recreated so the next sweep is never queued behind it.
- `--heartbeat-file PATH` — in `--watch` mode, atomically writes a JSON
  heartbeat (`ts`, `overall`, `sweep_ms`, `status`, `pid`) after every sweep,
  including abandoned ones (`status=stalled`). Lets an external watchdog tell a
  healthy-but-quiet loop from a wedged one — state-log freshness can't, since it
  only grows on transitions.
- `--check-stale SECONDS` — one-shot watchdog mode. Reads `--heartbeat-file` and
  exits 1 if the newest heartbeat is older than `SECONDS` (or missing), else 0.
  With `--alert-webhook`, also POSTs a wedge alert. Mutually exclusive with
  `--watch`/`--digest`; intended for a short systemd timer guarding the loop.

### Tests

- `test_watchdog.py` — heartbeat round-trip, staleness thresholds, missing-file
  handling, wedge-payload shape (asserts no host identifiers leak), and the
  `--check-stale` exit-code contract via `main()`.

## [Unreleased] - CI quality gates + security review

Tooling and CI only — no change to `wdgwars_api_tester.py` behavior, so no
version bump.

Brings wdgwars-api-tester onto the same gated CI pipeline as the sibling
feeder repos (Muninn, Heimdall, wigle-to-wdgwars): pytest + coverage →
SonarCloud quality gate → Snyk dependency scan → gated release-artifact build.
The `sonarcloud` / `snyk` jobs stay red until the repo is imported into
SonarCloud and the `SONAR_TOKEN` / `SNYK_TOKEN` secrets are added (see CI.md);
the test + coverage stage is independent and passes on its own. (The tool is
pure stdlib, so the Snyk stage is effectively a no-op — kept for parity.)

A review against the SonarCloud SAST finding classes found nothing to
remediate. The one security-sensitive construct — the `shell=True`
exec-on-change hook — is acceptable by design: the command is operator-authored
and the network-influenced state reaches it only via environment variables,
never interpolated into the command string. See SECURITY-FINDINGS.md.

### Added

- `.github/workflows/ci-quality-gates.yml` — gated quality + security pipeline.
- `pyproject.toml` (new — pytest collection scoped to `test_*.py`, plus a
  coverage config with a 50% regression floor; baseline ~55%),
  `sonar-project.properties`, `requirements.txt` (placeholder — no runtime
  deps), `requirements-dev.txt`, and `CI.md`.
- `test_security.py` — pins the exec-on-change env-var contract: a
  shell-injection payload in a delta must arrive as environment *data*
  (`WDGWARS_DELTAS`), never as executed command text.
- `SECURITY-FINDINGS.md` — the security review write-up; pointer added to
  `SECURITY.md`.

## [0.12.2] - 2026-06-05 - Severity tag (low/medium/high) on every post + plural fixes

State-change posts are now prefixed with `[low]` / `[medium]` / `[high]`
so a mod-channel reader can scan and triage without parsing the verdict
jargon. Designed to make the feed *useful knowledge*, not alarming.

### Added

- `_classify_severity(prev_overall, curr_overall, dsum)` helper. Maps a
  state transition + delta summary to one of low | medium | high:
  - **high** when current overall carries `+LEAK` (security exposure)
    or is `OUTAGE`/`UNREACHABLE`. Steady-state outage stays high every
    tick — severity follows current state, not delta direction.
  - **medium** when fresh `DEGRADED` from `HEALTHY`, when sentinel
    quorum just broke (`+SENTINEL-DIVERGED` new this tick), or when
    there's a net regression NOT covered by upstream-flap.
  - **low** for everything else: recoveries, steady-state DEGRADED with
    no movement, upstream/CDN flap, sideways shuffle, partial
    recoveries, new probes added. Persisting sentinel-diverged falls
    through to low so mods don't get re-alerted about a known issue.
- `severity` field in the structured payload alongside `kind`.
- `WDGWARS_SEVERITY` env var exported to `--exec-on-change` callbacks.
  Downstream consumers (`severity-router.sh` etc.) can route by
  severity instead of inferring from KIND + OVERALL.
- 16 new unit tests in `TestClassifySeverity` covering all three tiers,
  precedence (LEAK beats DEGRADED), and the steady-state cases.
- 4 new headline-shape tests in `TestWebhookHeadlineHasSeverityTag`.

### Changed

- Every headline (both jargon `text_machine` and human `text`/`content`)
  now starts with `[low] ` / `[medium] ` / `[high] ` after any leading
  emoji.
- Singular/plural fixed in partial-recovery, partial-regression, and
  sideways-shuffle headlines. "1 probes recovered" was the visible
  eyesore in mod-channel screenshots; now "1 probe recovered" /
  "2 probes recovered" depending on count.
- `SENTINEL` and `SENTINEL-OUTLIER` snapshot bullets correctly
  pluralize "sentinel" → "sentinels" for n > 1. The 3-probe quorum
  always fires three so this is `n=3` in practice, but the rule was
  off-by-default and reads as a typo.
- `AUTH-REDIRECT` snapshot bullet rephrased from
  "rejecting via login redirect" to
  "wired through web-session login (working, not API-shape)". The old
  text read like the endpoints were rejecting auth; the new text makes
  it clear the auth gate IS working, the response shape just isn't
  API-clean.

### Operational

- No systemd unit changes needed. `--exec-on-change` callers see one
  extra env var; existing callers ignore unknown vars cleanly.
- The Asgard severity-router.sh can be simplified in a future commit to
  read `WDGWARS_SEVERITY` directly instead of mapping KIND + OVERALL.

## [0.12.1] - 2026-06-05 - PAYLOAD-TOO-LARGE verdict for the 15 MB upload cap

LOCOSP rolled out a temporary 15 MB body cap on every wdgwars.pl upload
endpoint on 2026-06-05 with a structured 413 envelope. Adds a dedicated
verdict so future sweeps surface the cap cleanly instead of burying it
under the generic "413" label. The tester does not POST large bodies in
normal operation, so the verdict is defensive coverage rather than a
path that fires today.

### Added

- `PAYLOAD-TOO-LARGE` verdict in `annotate_verdicts`. Fires when
  `r.status == 413` AND `r.body_excerpt` contains the
  `"error":"payload-too-large"` substring. Bare 413s from CF or other
  upstream layers (no envelope) keep the generic "413" verdict so the
  rule is precise. Priority slot 7, same tier as METHOD.
- 2 new tests in `test_wdgwars_api_tester.py`: envelope-fires-verdict
  and bare-413-falls-back-to-bare-status.

### Notes

- Cap is expected to be removed in roughly two weeks after LOCOSP's
  host migration, at which point the branch goes cold. The verdict
  itself can stay — it costs nothing and may catch any future
  hosting-tier limit that returns the same envelope shape.

## [0.12.0] — 2026-06-05 — Repeatable --alert-webhook for multi-destination fan-out

Single polling instance, multiple Discord/Slack/etc. destinations. Use when
you want the same rich state-change payload mirrored into a partner's
channel without doubling the API polling load (relevant given LOCOSP's
midnight-UTC daily cap on `/api/*` traffic).

### Changed

- `--alert-webhook` is now `action="append"`. Pass it once for the
  existing behavior; pass it N times to fan out the same payload to N
  URLs. Each URL is POSTed independently; one failing does not block the
  others (a partner's channel being down should not silence your own ops
  channel).
- Default changed from `None` to `None` (unchanged in absence) but the
  attribute is a list once any flag is passed. Existing systemd units
  with a single `--alert-webhook URL` need no edit; behavior is
  byte-identical.
- Journal log lines now print the redacted URL (`/<token>` masked) so
  multi-URL deploys are debuggable without leaking the webhook secret.

### Added

- `_redact_webhook_url(url)` helper. Parses the URL and masks the last
  path segment as `<token>`. Discord-shape webhooks (the secret token is
  the last segment) come out fully redacted; other shapes fall back to
  `https://host/<redacted>`.

### Operational

- For a multi-destination deploy, store URLs in an EnvironmentFile (mode
  0600) and reference both in `ExecStart`:

      EnvironmentFile=%h/lab/webhooks.env
      ExecStart=... --alert-webhook ${ASGARD_URL} --alert-webhook ${PARTNER_URL}

  Both URLs see the same payload on the same sweep tick; one polling
  process, one state machine.

## [0.11.0] — 2026-06-04 — Team-messages probes + bounties cascade-fix note

LOCOSP confirmed in #🛡️-mod-reports that the CF-Transform-Rule + REQUEST_URI
regex cascade was wider than the original five handlers. `bounties.php` and
`shop_activate.php` had the same miss and were patched in the same pass at
~10:00 ET on 2026-06-04. Separately, `GET /api/team/messages/{id}` now
returns 405 with `Allow: DELETE` instead of silently dropping the id and
returning the gang messages list — the original spec at the top of
`team_messages.php` was always "trailing `/N` is DELETE-only".

### Added

- `team-messages` probe — `GET /api/team/messages`, expects 200 (caller's
  gang messages list, no id).
- `team-messages-id` probe — `GET /api/team/messages/1`, expects 405 (the
  METHOD verdict labels this as "responding with 405 wrong-verb (endpoint
  healthy)", which is the post-fix healthy state for the DELETE-only
  route).
- `build_probes` docstring now lists the state-mutating endpoints
  intentionally NOT probed, including `POST /api/shop/activate/{id}`
  (same regex-cascade fix, but unsafe to probe because POST would
  side-effect on production).

### Changed

- `bounties` probe note updated to record the 2026-06-04 fix. The
  2026-05-30 observation `"also returns 404 with valid key — undeployed?"`
  was the same regex bug, not an undeployed route. The probe already
  expected 200; the live signal just starts firing OK now.
- Mock server (`mock_wdgwars.py`) routes `/api/team/messages` (200 list)
  and `/api/team/messages/{id}` (405 on GET, 200 on DELETE). Ordered
  before the `/api/team/` catchall so the existing `/api/team/{id}` probe
  still works.
- Integration test `test_live_probe_schema` + `test_05_probe_coverage`
  assert the two new probe names are present in output.

### Operational

- No webhook / digest format changes. The two new probes flow through the
  existing verdict + humanization paths (`OK` for the list, `METHOD` for
  the /N variant) so no downstream consumer touches were needed.

## [0.10.1] — 2026-06-04 — Log-shaped nightly report

Reframed the digest from a summary-shaped morning report to a log-shaped
nightly report. Aimed at a debugging audience (LOCOSP correlating with
their own server logs): leads with a timestamped chronological event log
so the reader can match probe-side observations against server-side
events.

### Changed

- `_format_digest_payload` rewritten. Output now leads with an Activity
  log section (one block per state-log record, chronological order),
  followed by a one-line tally and a single-line current-state snapshot.
  Previous shape (snapshot-first, transitions counted) is removed.
- Header is now "Nightly report for YYYY-MM-DD" instead of "Morning
  report".
- Each event block has the shape:

      HH:MM UTC: PREV -> CURR (N changes[, suppressed: reason])
        marker probe/auth: humanized delta line

- The `records` arg is now forwarded into the payload so consumers can
  reconstruct the event timeline from the structured fields too.

### Added

- `_format_event_block(record)` helper. Pure function, independently
  testable. Picks HH:MM from `ts_iso`, falls back to `gmtime(ts)`, and
  delegates per-delta rendering to `_humanize_delta_line` so the log
  inherits the same plain-English mapping as the loud-channel posts.

### Tests

- `test_digest.py`: added `TestFormatEventBlock` (3 tests) + updated
  `TestFormatDigestPayload` for the new log shape. Full suite: 128/128
  pass.

### Operational

- The `wdgwars-api-tester-digest.service` unit's `--digest` URL should
  point at the new dedicated `#api-tester-log` Discord channel (separate
  webhook from the loud `#api-tester` channel) so the nightly report
  doesn't blur with the live state-change alerts.

### Style

- Em-dashes scrubbed from all user-visible strings (headlines, delta
  prose, summary bullets) per the lab style rule.

## [0.10.0] — 2026-06-04 — Plain-English webhook output + morning digest

State-change webhook posts now read as plain English instead of jargon, and a
new oneshot `--digest URL` mode emits a daily summary suitable for a community
channel. Aimed at making the tool's Discord/Slack output legible to non-dev
readers (mods, community members, anyone who isn't reading the source).

### Added

- Plain-English layer in `_format_webhook_payload`. The `text` + `content`
  fields now carry human-readable prose ("API status changed: all endpoints
  healthy → some endpoints down" / "team-me/valid: was healthy (HTTP 200),
  now timing out (>15s) or unreachable" / "13 endpoints healthy, 2 timed
  out"). The previous jargon string is preserved as `text_machine` for any
  tooling that depended on parsing it.
- New helpers: `_humanize_verdict`, `_humanize_overall`, `_humanize_delta_line`,
  `_humanize_verdict_summary`. Each is independently unit-tested.
- New payload fields: `text_machine`, `overall_human`, `prev_overall_human`,
  `deltas_human`, `by_verdict_human`.
- `--digest URL` oneshot mode. Runs all probes once, reads the last 24h from
  the `--state-log` file, and POSTs a single readable morning summary. Pair
  with a systemd timer firing at 08:00 local time. Mutually exclusive with
  `--watch`.
- `--state-log PATH` flag. In `--watch` mode, appends every state change
  (including suppressed ones) to a JSONL log. Used by `--digest` for the
  rolling 24h summary. Records carry `ts`, `ts_iso`, `prev_overall`,
  `curr_overall`, `deltas`, `by_verdict`, `suppressed`, `suppress_reason`.
- `--digest-window-hours` flag (default 24). How far back the digest reads.

### Changed

- `_format_webhook_payload`'s `text` + `content` fields are now human-readable
  prose. Tools that consumed the old jargon should read `text_machine`. All
  other structured fields (`deltas`, `by_verdict`, `delta_summary`, `action`,
  `kind`, `overall`, `prev_overall`, `tool`, `version`) are unchanged.

### Tests

- `test_humanize.py` (15 tests) covering verdict / overall / delta-line /
  summary humanizers and the updated payload formatter.
- `test_digest.py` (10 tests) covering state-log append, windowed read,
  malformed-line skipping, summarization, and digest payload shape.
- `test_payload_has_slack_and_discord_keys` updated to assert on the new
  human-readable strings + the preserved `text_machine` field.
- Full suite: 124/124 pass.

### Operational

- The systemd user unit `~/.config/systemd/user/wdgwars-api-tester.service`
  should add `--state-log ~/wdgwars-api-tester/lab/state-log.jsonl` to its
  ExecStart so the digest has data to summarize.
- A new timer + service pair `wdgwars-api-tester-digest.{timer,service}` runs
  the digest at 08:00 America/New_York (handles DST automatically).

## [0.9.0] — 2026-06-04 — Restore upstream-flap suppression + `--silent-webhook`

The v0.7.0 outage-backoff squash-merge (PR #4, commit 9b32b7f) collapsed a
parallel local branch that carried six helpers and a CLI flag. Those didn't
make it into the squash. This release restores them on top of v0.8.0. No
existing behavior changes — the helpers gate a new code path that only fires
in `--watch` mode when `--silent-webhook` is set.

### Added

- `--silent-webhook URL` CLI flag. In `--watch` mode, POSTs suppressed alerts
  (LOCOSP upstream flap, no net regression) to this URL instead of dropping
  them. Same payload as `--alert-webhook` with a `[suppressed: <reason>]`
  prefix on `content` + `text` so a channel reader can tell at a glance.
- `_verdict_rank(verdict, status)` — 5xx ranks below DEAD so we don't
  mis-call an upstream gateway failure as a probe regression.
- `_is_upstream_5xx(verdict, status)` — single source of truth for
  "is this transition a CDN/origin flap rather than a probe-side change."
  Matches explicit CF codes (502/503/504/522/524) and any numeric 5xx.
- `_classify_delta(...)` — labels each delta `improved` / `regressed` /
  `sideways` by verdict-rank, tags it `upstream_flap` if either side is 5xx.
- `_parse_delta_line(line)` — inverse of `_probe_deltas` line format,
  returns None for `NEW` / `GONE` (those are always real signal).
- `_annotate_deltas(deltas)` — runs the above over a list, returns
  (annotated_lines_with_↑↓↔_markers, summary_dict).
- `_should_suppress_alert(prev_overall, curr_overall, summary)` — the
  suppression policy. Suppress only when overall state didn't change AND
  every classified delta is upstream-flap AND `regressed <= improved`.

### Changed

- `_format_webhook_payload(...)` rewritten to use the new annotation helpers.
  Directional `↑`/`↓`/`↔` markers in the delta block, partial-recovery /
  upstream-flap headlines when `overall` doesn't change, and a `→ action`
  footer ("LOCOSP upstream is flapping. No local action." etc.). The payload
  now also carries `delta_summary` + `action` fields for structured consumers.
- `--watch` loop wraps the alert-emit block with the suppression check.
  When suppressed: log `alert SUPPRESSED: <reason>` and (if configured)
  POST to `--silent-webhook` instead of `--alert-webhook` / `--exec-on-change`.

### Tests

- `test_suppression.py` (27 new tests) covering `_verdict_rank`,
  `_is_upstream_5xx`, `_classify_delta`, `_parse_delta_line`,
  `_annotate_deltas`, and all six `_should_suppress_alert` boundary cases:
  overall changed, all-flap-no-net-regression, all-flap-net-improved,
  mixed flap + non-flap, net regression with flap, zero classifiable
  deltas, and unclassified (NEW/GONE) present.

### Operational

- The systemd user unit `~/.config/systemd/user/wdgwars-api-tester.service`
  on the prod host had `--silent-webhook ${ASGARD_WEBHOOK_LAB_SILENT}` in
  its ExecStart, so it failed to start with argparse exit 2 every 30s
  between the v0.7.0 squash-merge and the hotfix that stripped the flag.
  Bug log: `BrainVault/Meta/Bugs/2026-06-04-wdgwars-api-tester-silent-webhook-regression.md`.

## [0.8.0] — 2026-06-03 — Probes for the 2026-06-03 LOCOSP-shipped surface

Six new probes covering the API additions LOCOSP shipped on 2026-06-03 in
response to the bug + perf writeups. The probes give LOCOSP the usage data
he asked for before committing to the next tier of map-perf work (vector
tiles / PMTiles), and pin contract regressions on the new endpoints.

### Added

- `badge-catalog` probe — `GET /api/badge-catalog`. Curated 51-badge
  dictionary, 24h server cache. Response shape:
  `{ok, count, categories, badges:[{id, label, category, criteria}]}`.
- `team-id` probe — `GET /api/team/{id}` with `id` configurable via the
  new `--team-id` CLI flag (default `1`). Top-level shape:
  `{id, name, color, rank, created_at, members[]}`.
- `team-me` probe — `GET /api/team/me`. The 400 "usage" error from
  2026-06-03 morning was fixed in LOCOSP's CF-Transform-Rule batch, but
  the `/me` variant currently 524s (CF origin timeout). Probe accepts
  200 so the upstream timeout surfaces as a `524` verdict until fully
  shipped.
- `member-territories-compact` probe — `GET /api/member-territories?compact=1`.
  Strips redundant `gang/color/logo` from every row; adds top-level
  `gangs` lookup keyed by `gang_id`. Cuts payload ~20-30%.
- `member-territories-bbox` probe — `GET /api/member-territories?compact=1&bbox=W,S,E,N&zoom=8`.
  Server-side spatial filter. Accepts Leaflet `bounds.toBBoxString()`
  format. Probe uses a sample bounding window.
- `member-territories-zoom-skip` probe — `GET /api/member-territories?zoom=5`.
  At zoom<6 the server returns `gang_hulls` only with
  `zoom_skipped_cells:true` and an empty `cells[]`. Verifies the
  low-zoom render-perf path.
- `--team-id INT` CLI flag (default `1`) for the `team-id` probe.
  Override when probing a fork/staging instance where id 1 doesn't
  exist, or to vary the probed team across runs.

### Tests

- Six new unit tests (`TestBuildProbes2026_06_03Surface` in
  `test_wdgwars_api_tester.py`) covering: every new probe is present
  in the default probe list; `team_id` defaults to `1`; the override
  flows into `team-id`'s path; other probes' paths are stable across
  `team_id` changes; every new probe requires auth (the 2026-06-03
  surface is fully key-gated); the three map-variant probes target
  `/api/member-territories`.

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
