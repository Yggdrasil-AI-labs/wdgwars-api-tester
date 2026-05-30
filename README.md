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

# Poll every 60s, print only when state changes
python3 wdgwars_api_tester.py --watch 60

# Snapshot once, then diff future runs against it
python3 wdgwars_api_tester.py --baseline baseline.json
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
| `api-sentinel-404` | GET | `/api/<random>` | no | Fingerprints the /api/ 404 page. |
| `non-api-sentinel-404` | GET | `/<random>` | no | Fingerprints the non-/api/ 404 page. |
| `changelog-control` | GET | `/changelog` | no | Public-page reachability control. |

## Verdicts

| Verdict | Meaning |
|---|---|
| `OK` | 2xx response, body distinct from any 404 sentinel. |
| `AUTH-REQUIRED` | 401. Endpoint is alive and rejecting the key. |
| `DEAD` | Body hash matches the /api/ 404 sentinel. Route not bound. |
| `DEAD-NONAPI` | Body matches the non-/api/ 404 sentinel. |
| `LEAK` | `/api/stats` returned 200 → LiteSpeed admin telemetry exposed. |
| `404` | 404 response but body distinct from sentinels. |
| `METHOD` | 405. Healthy endpoint, wrong verb. |
| `ERROR` | Network/timeout/URL error. |
| `SENTINEL` / `SENTINEL-NONAPI` | The fingerprint probes themselves. |

The overall summary is one of:

- `HEALTHY` — no DEAD, no ERROR, no LEAK.
- `UNREACHABLE` — everything errored. DNS, no internet, host down.
- `DEGRADED` — at least one probe DEAD.
- `OUTAGE` — `/api/me` with a valid key is DEAD. Whole API surface is down.
- `…+LEAK` — appended to any of the above when `/api/stats` is exposed.

Exit code is `1` for DEGRADED/OUTAGE/UNREACHABLE/LEAK and `0` for HEALTHY.

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

## Related

- [wigle-to-wdgwars](https://github.com/HiroAlleyCat/wigle-to-wdgwars) — WiFi/BLE CSV uploader.
- [adsb-to-wdgwars (Muninn)](https://github.com/HiroAlleyCat/adsb-to-wdgwars) — ADS-B uploader.

## License

MIT.
