# wdgwars-api-tester

Systematic probe of the **[WDGoWars](https://wdgwars.pl/)** HTTP API surface.

Built 2026-05-29 during the mass `/api/*` 404 outage. The point of this tool is
to answer, in one command, the questions that took an hour of curl that day:

- Which endpoints are alive vs returning the styled 404 page?
- Does an unauthenticated `/api/me` return 401 (the expected behavior) or 404
  (route-not-bound)?
- Is `/api/stats` exposing the LiteSpeed admin telemetry leak?
- Did anything change since the last snapshot?

Stdlib-only Python 3. No `pip install`. Single file.

## Family

Sibling repos in the WDGoWars feeder family:

- [Muninn](https://github.com/HiroAlleyCat/adsb-to-wdgwars) — ADS-B feeder
- [Heimdall](https://github.com/HiroAlleyCat/meshcore-to-wdgwars) — MeshCore LoRa feeder
- [wigle-to-wdgwars](https://github.com/HiroAlleyCat/wigle-to-wdgwars) — WiGLE Wi-Fi/BLE feeder
- [gungnir](https://github.com/HiroAlleyCat/gungnir) — shared HMAC transport library

## Quick start

```bash
# Probe apex with all three auth variants (none, garbage, valid)
python3 wdgwars_api_tester.py

# Add www. and api. subdomains
python3 wdgwars_api_tester.py --hosts all

# Probe a custom host (staging, fork, local mock) — anything starting with
# http:// or https:// becomes the target instead of wdgwars.pl.
python3 wdgwars_api_tester.py --hosts http://127.0.0.1:9999 --variants none

# Machine-readable
python3 wdgwars_api_tester.py --json > snapshot.json

# Just the overall verdict word + exit code (good for shell / CI)
python3 wdgwars_api_tester.py --quiet --variants none,garbage
# → prints `HEALTHY` / `DEGRADED` / `OUTAGE` / `UNREACHABLE`
#   plus optional `+LEAK` or `+SENTINEL-DIVERGED` suffix.

# Poll every 60s, print compact deltas on state change.
# Full table is printed on the recovery moment (first transition into HEALTHY).
python3 wdgwars_api_tester.py --watch 60

# Snapshot once, then diff future runs against it
python3 wdgwars_api_tester.py --baseline baseline.json

# Watch + Telegram self-page on state change (no bridge needed)
export TELEGRAM_BOT_TOKEN=123456:ABC...
export TELEGRAM_CHAT_ID=-1001234567890
python3 wdgwars_api_tester.py --watch 60 --alert-telegram

# Watch + Discord / Slack / n8n / PagerDuty (any webhook URL)
python3 wdgwars_api_tester.py --watch 60 \
   --alert-webhook https://discord.com/api/webhooks/.../...

# Watch + arbitrary shell command on state change
python3 wdgwars_api_tester.py --watch 60 \
   --exec-on-change 'echo "$WDGWARS_PREV_OVERALL → $WDGWARS_OVERALL" | mail -s "wdgwars alert" me@example.com'
```

## API key

Same precedence as [wigle-to-wdgwars](https://github.com/HiroAlleyCat/wigle-to-wdgwars):

1. `--key` CLI flag
2. `$WDGWARS_API_KEY`
3. `~/.config/wigle-to-wdgwars/wdgwars.key`

If no key is found, the `valid` variant is dropped automatically and only the
`none` and `garbage` variants run.

## What it probes

| Probe | Method | Path | Auth | Notes |
|---|---|---|---|---|
| `api-root` | GET | `/api/` | no | Baseline shape of the /api/ subtree. |
| `me` | GET | `/api/me` | yes | Identity. Unauth → 401, not 404. |
| `upload-history` | GET | `/api/upload-history?limit=5` | yes | Added 2026-04-27. |
| `upload-csv` | POST | `/api/upload-csv` | yes | Multipart WiGLE-1.6, mixed Types. |
| `v2-upload-csv` | POST + GET | `/api/v2/upload-csv` → `/api/v2/upload-job/<id>` | yes | Async pipeline: POST 202 → poll until `done`/`failed` (6 polls @ 1s). Catches v2-parser regressions independent of v1. |
| `signed-upload` | GET | `/api/upload/` | yes | HMAC JSON endpoint. GET → 405 if healthy. |
| `me-aps` | GET | `/api/me/aps?limit=1` | yes | Caller's own AP read-back (supports `?since=` delta sync). |
| `aircraft` | GET | `/api/aircraft` | yes | ADS-B live snapshot (top-level array). |
| `meshcore` | GET | `/api/meshcore` | yes | MeshCore live snapshot (top-level array). |
| `territories` | GET | `/api/territories` | yes | Global gang convex hulls (top-level array). |
| `member-territories` | GET | `/api/member-territories` | yes | Cell-based grid + gang hulls. 5-min snapshot. |
| `leaderboard` | GET | `/api/leaderboard` | yes | 5 boards. 5-min snapshot. |
| `bounties` | GET | `/api/bounties` | yes | Open bounties (max 200). |
| `health-asked-for` | GET | `/api/health` | no | Doesn't exist yet. Asked for in bug #1. |
| `stats-leak-check` | GET | `/api/stats` | no | Fires LEAK if body carries the LSWS admin-telemetry fingerprint. (locosp's 2026-05-30 fix landed — endpoint now 302s to login; rule tightened in v0.6.1 to detect content, not just status.) |
| `api-sentinel-404-a/b/c` | GET | `/api/<random>` × 3 | no | Quorum fingerprint of the /api/ 404 page (2-of-3 majority required). |
| `non-api-sentinel-404` | GET | `/<random>` | no | Fingerprints the non-/api/ 404 page. |
| `changelog-control` | GET | `/changelog` | no | Public-page reachability control. |

## Verdicts

| Verdict | Meaning |
|---|---|
| `OK` | 2xx response, body distinct from any 404 sentinel. |
| `AUTH-REQUIRED` | 401. Endpoint is alive and rejecting the key with the spec-correct JSON shape. |
| `AUTH-REDIRECT` | 3xx whose `Location` points at `/login...`. The auth gate is working, but the endpoint is wired through the web-session flow rather than returning 401 JSON — a routing-shape regression for an API caller, but not a security/availability issue. Does NOT escalate to DEGRADED. |
| `REDIRECT-{n}` | 3xx whose `Location` does not match `/login` (catch-all so unexpected redirects don't masquerade as OK). |
| `DEAD` | Body hash matches the /api/ 404 quorum sentinel. Route not bound. |
| `DEAD-NONAPI` | Body matches the non-/api/ 404 sentinel. |
| `LEAK` | Body carries the LiteSpeed admin-telemetry fingerprint (`lsphp_processes` / `top_domains` / `lsphp`). Generalized in v0.6.1 — fires on any probe, not just `stats-leak-check`. Tightened from "stats returned 200" because the bare-status rule false-positived once locosp's 2026-05-30 fix landed and `/api/stats` started 302ing to `/login`. |
| `404` | 404 response but body distinct from sentinels. |
| `METHOD` | 405. Healthy endpoint, wrong verb. |
| `ERROR` | Network/timeout/URL error. |
| `SENTINEL` | One of the 3 /api/ quorum sentinels, in agreement with the majority. |
| `SENTINEL-OUTLIER` | The 1 of 3 sentinels that disagreed with the other 2 (CDN cache slip, e.g.). DEAD detection still works via the 2-vote majority. |
| `SENTINEL-DIVERGED` | All 3 sentinels returned distinct bodies. DEAD detection disabled for that host. Investigate the diagnostic before trusting results. |
| `SENTINEL-NONAPI` | The non-/api/ 404 fingerprint probe. |

The overall summary is one of:

- `HEALTHY` — no DEAD, no ERROR, no LEAK.
- `UNREACHABLE` — everything errored. DNS, no internet, host down.
- `DEGRADED` — at least one probe DEAD.
- `OUTAGE` — `/api/me` with a valid key is DEAD. Whole API surface is down.
- `…+LEAK` — appended to any of the above when `/api/stats` is exposed.
- `…+SENTINEL-DIVERGED` — appended when the 3 quorum sentinels couldn't agree on a fingerprint. DEAD detection is disabled for affected hosts; investigate before trusting results.

Exit code is `1` for DEGRADED/OUTAGE/UNREACHABLE/LEAK/SENTINEL-DIVERGED and `0` for HEALTHY.

## Running on a schedule

Drop it in cron, a systemd timer, or Windows Task Scheduler. Pair `--baseline`
with `--json` to log every snapshot for later trend analysis, or use `--watch`
on a long-running host to get a single state-change notification when the API
comes back up.

Cron example:

```cron
*/5 * * * * cd /opt/wdgwars-api-tester && \
  python3 wdgwars_api_tester.py --baseline /var/log/wdgwars/baseline.json \
                                --json >> /var/log/wdgwars/snapshots.jsonl
```

## Notification channels

`--watch` mode supports three independent notification paths. Use one, two, or all three at once — they don't conflict.

| Flag | Use when |
|---|---|
| `--alert-telegram` | You have a Telegram bot + chat. Easiest setup. |
| `--alert-webhook URL` | You're on Discord, Slack, n8n, PagerDuty, or any service that takes a JSON POST. |
| `--exec-on-change CMD` | None of the above fit — email, SMS, a Lambda, write to a database, pipe to logger. |

Failure in any one path logs a warning to stderr but never crashes the watch loop or blocks the others.

### Telegram self-paging

In `--watch` mode the tool can post directly to a Telegram chat on every state change. No external broker, webhook service, or alerting infrastructure required — stdlib `urllib` to the Bot API and a chat id.

### Setup

1. Talk to [@BotFather](https://t.me/BotFather) on Telegram and create a bot. Copy the token.
2. Add the bot to the chat where you want alerts (DM, group, or channel).
3. Send any message in that chat, then `GET https://api.telegram.org/bot<TOKEN>/getUpdates` and read `result[0].message.chat.id` (or `result[0].channel_post.chat.id` for channels).
4. Export both values and pass `--alert-telegram`:

```bash
export TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
export TELEGRAM_CHAT_ID=-1001234567890
python3 wdgwars_api_tester.py --watch 60 --alert-telegram
```

Or pass them inline: `--telegram-bot-token <token> --telegram-chat-id <id>`.

### Message format

| Transition | Header |
|---|---|
| Recovery (`* → HEALTHY`) | `✅ wdgwars API recovered` |
| Diagnostic broken (`+SENTINEL-DIVERGED` appears) | `🔧 wdgwars-api-tester diagnostic broken` |
| Regression (anything else worse) | `🚨 wdgwars API <new-overall>` |

Body includes the `prev_overall → curr_overall` transition, per-probe deltas (capped at 30 lines for Telegram's 4096-char message limit), and a verdict count rollup. Uses HTML parse mode so `<b>` / `<code>` render correctly.

### Generic webhook (`--alert-webhook URL`)

POSTs a JSON payload to any HTTP endpoint on state change. The payload carries multiple top-level keys so the same URL works for several services without per-service flags:

```json
{
  "text": "🚨 wdgwars-api-tester: HEALTHY → OUTAGE+LEAK\n\n<deltas>\n\nverdicts: DEAD=10, LEAK=1",
  "content": "<same as text — Discord reads this>",
  "title": "🚨 wdgwars-api-tester: HEALTHY → OUTAGE+LEAK",
  "kind": "regression",
  "overall": "OUTAGE+LEAK",
  "prev_overall": "HEALTHY",
  "deltas": ["wdgwars.pl me/valid  OK/200 -> DEAD/404", "..."],
  "by_verdict": {"DEAD": 10, "LEAK": 1, "OK": 1},
  "tool": "wdgwars-api-tester",
  "version": "0.4.0"
}
```

- **Discord** reads `content`. Drop in any channel webhook URL.
- **Slack incoming webhooks** read `text`. Same drop-in.
- **n8n / Zapier / Make** can pick the structured fields directly.
- **PagerDuty Events v2** — wrap with `--exec-on-change` (it expects a different envelope).
- **Custom HTTP handlers** — read whatever they need from the structured fields.

### Arbitrary command (`--exec-on-change CMD`)

Runs any shell command on state change. The following env vars are exported into the subprocess:

| Env var | Value |
|---|---|
| `WDGWARS_OVERALL` | New overall verdict, e.g. `DEGRADED+LEAK` |
| `WDGWARS_PREV_OVERALL` | Previous overall verdict |
| `WDGWARS_KIND` | `recovery` / `regression` / `diagnostic-broken` |
| `WDGWARS_RECOVERY` | `1` if transitioning into HEALTHY, else `0` |
| `WDGWARS_DELTAS` | Newline-joined per-probe delta lines |
| `WDGWARS_VERDICTS` | JSON-encoded `{verdict: count}` dict |

Examples:

```bash
# Email on every transition
--exec-on-change 'echo "$WDGWARS_DELTAS" | mail -s "wdgwars: $WDGWARS_OVERALL" me@example.com'

# Only page on regression (not recovery, not diagnostic)
--exec-on-change '[ "$WDGWARS_KIND" = "regression" ] && /usr/local/bin/page-me.sh "$WDGWARS_OVERALL"'

# Forward to an existing internal alerting service
--exec-on-change 'curl -X POST -H "Authorization: Bearer $MY_TOKEN" \
                  -d "{\"summary\":\"$WDGWARS_OVERALL\",\"verdicts\":$WDGWARS_VERDICTS}" \
                  https://internal.example.com/alert'
```

The command runs with `shell=True` and a 15-second timeout. Non-zero exit codes log a warning but don't crash the watch loop.

## Adapting the tool for your own service

Single-file, MIT, stdlib only — fork is encouraged. The structure is designed to make these changes easy:

- **Probe a different API.** Edit `build_probes()` to swap the endpoints, methods, and expected statuses. `DEFAULT_HOSTS` / `ALL_HOSTS` at the top change which hosts get probed.
- **Add new probes.** Append `Probe(...)` entries to `build_probes()`. Each gets the same auth-variant matrix and verdict annotation automatically.
- **Add a new verdict.** Edit `annotate_verdicts()` to add a branch, then add the verdict to `VERDICT_PRIORITY` so the table sort works, and `summary()` so it rolls up into the overall verdict if relevant.
- **Customize the sentinel mechanism.** `SENTINEL_PROBES` and `_canonical_sentinel()` define the quorum logic. Change `SENTINEL_PROBES` to use more sentinels, or rewrite `_canonical_sentinel()` to use a different agreement rule.
- **Different notification format.** Edit `_format_telegram_text()` or `_format_webhook_payload()` directly. Both are pure functions, easy to unit-test.

If you ship a fork, MIT means clone-and-rename is fine — no need to credit upstream.

## Tests

Two suites, both stdlib only.

### Unit tests (offline, fast)

```
python3 -m unittest test_wdgwars_api_tester
```

32 tests, no network. Covers verdict annotation, quorum sentinel logic, state signature stability, summary rollup, probe delta detection, Telegram message formatting, and webhook payload shape. Runs in under a second.

### Integration tests (offline by default)

```
python3 integration_test.py                # offline — fast, safe, default
python3 integration_test.py --live         # also runs the live API check
INTEGRATION_LIVE=1 python3 integration_test.py    # env var equivalent
```

21 end-to-end scenarios. Default mode is **offline** — `integration_test.py` spawns local instances of `mock_wdgwars.py` (one per scenario, on random ports) and points the tester at them. The real `wdgwars.pl` is not touched, so the suite is safe to run on every push without adding tenant traffic to a small community-hosted API.

Coverage:

- `--version`, `--help`, default one-shot, `--quiet`, `--json`, `--no-table`
- Invalid `--variants` / `--hosts` rejection
- **Scenario-specific verdict assertions** — the offline mock supports four states:
  - `outage` → tester produces `DEGRADED+LEAK` (or `OUTAGE+LEAK` with a valid key)
  - `healthy` → tester produces `HEALTHY`
  - `partial` → tester produces `HEALTHY+LEAK` (API up but stats endpoint still leaking)
  - `diverged` → tester produces something with `+SENTINEL-DIVERGED` suffix
- `--baseline` first-run creation + second-run stability (no diff against same scenario)
- All three notification guard rails (`--alert-telegram` / `--alert-webhook` / `--exec-on-change` without `--watch` warn and disable)
- End-to-end webhook dispatch — `_post_webhook` against a local capture server, payload assertions (Slack `text`, Discord `content`, structured `kind`/`overall`/`prev_overall`)
- End-to-end exec dispatch — cross-platform Python env-capture helper confirms all `WDGWARS_*` env vars set correctly
- `--live` opt-in: schema validation against the real `wdgwars.pl` (every documented probe appears in JSON output, 3-sentinel quorum produces ≤2 distinct hashes in non-diverged states)

Offline run takes ~11 seconds. `--live` adds ~10-30 seconds for one real probe of `wdgwars.pl`. Exit 0 = all green.

### Mock server (standalone use)

`mock_wdgwars.py` can also be run as a standalone HTTP server for manual exploration. Useful for learning the verdict surface or developing a fork:

```
python3 mock_wdgwars.py --scenario healthy --port 9999 &
python3 wdgwars_api_tester.py --hosts http://127.0.0.1:9999 --variants none,garbage
```

Available scenarios: `outage`, `healthy`, `partial`, `diverged`.

## Updating

Stdlib-only, so updating just refreshes the single `.py` file from `main`:

```bash
./update.sh           # Linux / Mac
update.bat            # Windows (double-click)
```

Or by hand:

```bash
curl -O https://raw.githubusercontent.com/HiroAlleyCat/wdgwars-api-tester/main/wdgwars_api_tester.py
```

## Related

- [wigle-to-wdgwars](https://github.com/HiroAlleyCat/wigle-to-wdgwars) — WiFi/BLE CSV uploader.
- [adsb-to-wdgwars (Muninn)](https://github.com/HiroAlleyCat/adsb-to-wdgwars) — ADS-B uploader.

## License

MIT.
