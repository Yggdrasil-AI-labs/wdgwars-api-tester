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

## Quick start

```bash
# Probe apex with all three auth variants (none, garbage, valid)
python3 wdgwars_api_tester.py

# Add www. and api. subdomains
python3 wdgwars_api_tester.py --hosts all

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
| `signed-upload` | GET | `/api/upload/` | yes | HMAC JSON endpoint. GET → 405 if healthy. |
| `health-asked-for` | GET | `/api/health` | no | Doesn't exist yet. Asked for in bug #1. |
| `stats-leak-check` | GET | `/api/stats` | no | 200 here = LiteSpeed admin leak. |
| `api-sentinel-404-a/b/c` | GET | `/api/<random>` × 3 | no | Quorum fingerprint of the /api/ 404 page (2-of-3 majority required). |
| `non-api-sentinel-404` | GET | `/<random>` | no | Fingerprints the non-/api/ 404 page. |
| `changelog-control` | GET | `/changelog` | no | Public-page reachability control. |

## Verdicts

| Verdict | Meaning |
|---|---|
| `OK` | 2xx response, body distinct from any 404 sentinel. |
| `AUTH-REQUIRED` | 401. Endpoint is alive and rejecting the key. |
| `DEAD` | Body hash matches the /api/ 404 quorum sentinel. Route not bound. |
| `DEAD-NONAPI` | Body matches the non-/api/ 404 sentinel. |
| `LEAK` | `/api/stats` returned 200 → LiteSpeed admin telemetry exposed. |
| `BLOCKED` | `/api/stats` returned non-200. Desired state for that endpoint, regardless of which 404 handler served it. |
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

## Telegram self-paging (optional)

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

### Failure handling

Telegram post failures (network blip, invalid token, banned bot) log a warning to stderr but never crash the watch loop. The tool keeps polling and pages on the next transition.

## Tests

```
python3 -m unittest test_wdgwars_api_tester
```

28 tests, no network, stdlib only. Covers verdict annotation, quorum sentinel logic, state signature stability, summary rollup, probe delta detection, and Telegram message formatting.

## Related

- [wigle-to-wdgwars](https://github.com/HiroAlleyCat/wigle-to-wdgwars) — WiFi/BLE CSV uploader.
- [adsb-to-wdgwars (Muninn)](https://github.com/HiroAlleyCat/adsb-to-wdgwars) — ADS-B uploader.

## License

MIT.
