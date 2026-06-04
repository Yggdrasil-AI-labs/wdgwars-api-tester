#!/usr/bin/env python3
"""wdgwars-api-tester: systematic probe of the WDGoWars HTTP API surface.

Built to detect outages (e.g. the 2026-05-29 mass /api/* 404), distinguish
"endpoint dead" from "auth rejected", and fingerprint the styled-404 page so a
broken endpoint can't masquerade as a real response.

For each (host, endpoint, auth-variant) tuple it records:
    status, content-type, body length, body md5, latency_ms,
    cf-cache-status, x-request-id, server header

Then it compares every response against the 404 sentinel response (a random
nonexistent /api/ path). Any response whose body md5 matches the sentinel is
reported as DEAD regardless of status code.

Stdlib only. No gungnir, no requests, no install step. The whole point of
this tool is that it works when everything else doesn't.

Quickstart:
    python3 wdgwars_api_tester.py                 # probe apex, all variants
    python3 wdgwars_api_tester.py --hosts all     # apex + www + api.subdomain
    python3 wdgwars_api_tester.py --json          # JSON to stdout, table to stderr
    python3 wdgwars_api_tester.py --watch 60      # poll every 60s, print on state change
    python3 wdgwars_api_tester.py --baseline snap.json   # write/diff a baseline
"""
from __future__ import annotations

__version__ = "0.9.0"
GITHUB_URL = "https://github.com/HiroAlleyCat/wdgwars-api-tester"

import argparse
import datetime
import hashlib
import io
import json
import logging
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Callable, Optional

USER_AGENT = f"wdgwars-api-tester/{__version__} (+{GITHUB_URL})"

DEFAULT_HOSTS = ["https://wdgwars.pl"]
ALL_HOSTS = ["https://wdgwars.pl", "https://www.wdgwars.pl", "https://api.wdgwars.pl"]

GARBAGE_KEY = "g" * 64
AUTH_VARIANTS = ("none", "garbage", "valid")

# Fingerprint for the LiteSpeed admin-telemetry leak that 2026-05-29's bug
# report flagged on /api/stats. The leak's distinctive content always
# carries at least one of these substrings — both are LSWS field names that
# would never appear in a normal API response or auth-redirect login page.
# This list is the LEAK verdict's gate; bare HTTP 200 on stats-leak-check
# is no longer enough (locosp's fix landed and the endpoint now 302s to
# /login, which would false-positive on a status-only rule).
LSWS_LEAK_FINGERPRINTS = ("lsphp_processes", "top_domains", "lsphp")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """urllib's default behavior is to silently follow 3xx responses, which
    would mask the route's actual shape — a /api/<endpoint> path that 302s
    to /login is meaningfully different from one that 200s directly. We
    want the 3xx to surface so verdict logic can label it AUTH-REDIRECT.

    Returning None from redirect_request signals "do not redirect"; urllib
    then raises HTTPError with the original 3xx code, which the existing
    HTTPError handler catches.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirectHandler())

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
log = logging.getLogger("api-tester")


@dataclass
class Probe:
    name: str
    method: str
    path: str
    needs_auth: bool
    expect_status: tuple  # acceptable codes if API is healthy
    body: Optional[bytes] = None
    content_type: Optional[str] = None
    notes: str = ""
    # Escape hatch for probes that need more than a single request (e.g.
    # the async v2 upload pipeline: POST → 202 + job_id → poll until
    # done). When set, `_request()` delegates to this callable instead of
    # doing its normal single-shot flow. The callable receives the same
    # arguments as `_request` and must return a fully-populated Result.
    # Keep this rare — most probes should fit the single-shot model.
    custom_runner: Optional[Callable] = None


def _csv_probe_body() -> tuple[bytes, str]:
    """Minimal multipart/form-data WiGLE CSV body for upload-csv probe.

    Five rows covering Types WIFI, BLE, GSM, LTE, NR_5G. The mixed-Type
    payload doubles as a regression check for the silent unsupported-Type
    drop (the response counters should fully account for all 5 rows).
    """
    boundary = "----wdgwars-api-tester-" + secrets.token_hex(8)
    csv = (
        "WigleWifi-1.6,appRelease=v0.0.0\n"
        "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,"
        "CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "aa:bb:cc:dd:ee:01,ProbeWifi,[WPA2-PSK-CCMP][ESS],2026-05-29 12:00:00,6,-55,41.0,-81.0,200,10,WIFI\n"
        "aa:bb:cc:dd:ee:02,ProbeBle,,2026-05-29 12:00:01,0,-60,41.0,-81.0,200,10,BLE\n"
        "aa:bb:cc:dd:ee:03,ProbeGsm,,2026-05-29 12:00:02,0,-70,41.0,-81.0,200,10,GSM\n"
        "aa:bb:cc:dd:ee:04,ProbeLte,,2026-05-29 12:00:03,0,-75,41.0,-81.0,200,10,LTE\n"
        "aa:bb:cc:dd:ee:05,ProbeNr,,2026-05-29 12:00:04,0,-80,41.0,-81.0,200,10,NR_5G\n"
    )
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(b'Content-Disposition: form-data; name="file"; filename="probe.wiglecsv"\r\n')
    body.write(b"Content-Type: text/csv\r\n\r\n")
    body.write(csv.encode())
    body.write(f"\r\n--{boundary}--\r\n".encode())
    return body.getvalue(), f"multipart/form-data; boundary={boundary}"


def build_probes(team_id: int = 1) -> list[Probe]:
    """Build the probe list. ``team_id`` selects which numeric gang id to
    probe on ``/api/team/{id}`` — defaults to 1 (typically the founder gang
    on any healthy instance). Override via ``--team-id`` for forks/staging.
    """
    csv_body, csv_ct = _csv_probe_body()
    return [
        Probe("api-root", "GET", "/api/", False, (200, 301, 302, 404),
              notes="Used as baseline for /api/ subtree shape."),
        Probe("me", "GET", "/api/me", True, (200,),
              notes="Auth + identity. With no/garbage key expect 401, not 404. "
                    "Since 2026-06-03 the response also carries `your_rank` "
                    "(top_n=100, nulls for >N) and `recent_captures` (≤20 "
                    "attacker-side). Body shape isn't asserted by the tester "
                    "— OK status is the contract — but a regression that "
                    "drops them would still surface via downstream consumers."),
        Probe("badge-catalog", "GET", "/api/badge-catalog", True, (200,),
              notes="Curated public badge dictionary (~51 entries). Shipped "
                    "2026-06-03. 24h server cache. Response: "
                    "{ok, count, categories, badges:[{id, label, category, criteria}]}."),
        Probe("team-id", "GET", f"/api/team/{team_id}", True, (200,),
              notes=f"Public team dossier for gang id {team_id}. Top-level "
                    "{id, name, color, rank, created_at, members[]}. The /me "
                    "variant currently 524s (origin timeout) post-CF-Transform "
                    "fix — see team-me probe."),
        Probe("team-me", "GET", "/api/team/me", True, (200,),
              notes="Caller's-own team dossier. Was 400 'usage' pre-2026-06-03, "
                    "fix accepted both /api/ and /endpoint/ prefixes but "
                    "/me variant now returns CF 524 (origin timeout). "
                    "Probe accepts 200 — a 524 surfaces as the verdict so "
                    "the upstream bug stays visible until LOCOSP ships the "
                    "/me-side fix."),
        Probe("upload-history", "GET", "/api/upload-history?limit=5", True, (200,),
              notes="Added 2026-04-27 per /changelog."),
        Probe("upload-csv", "POST", "/api/upload-csv", True, (200, 400),
              body=csv_body, content_type=csv_ct,
              notes="Multipart WiGLE-1.6 with mixed Types."),
        Probe("v2-upload-csv", "POST", "/api/v2/upload-csv", True, (202,),
              body=csv_body, content_type=csv_ct,
              custom_runner=_v2_upload_csv_round_trip,
              notes="Async upload. POST 202 + {job_id, poll_url}; tester "
                    "polls /api/v2/upload-job/<id> until status=done|failed "
                    "(6 polls @ 1s). Result.status is rewritten to 200 on "
                    "a clean round-trip so the OK verdict fires."),
        Probe("signed-upload", "GET", "/api/upload/", True, (200, 405),
              notes="HMAC signed JSON endpoint. GET should be 405 if healthy."),
        Probe("me-aps", "GET", "/api/me/aps?limit=1", True, (200,),
              notes="Caller's-own AP delta-sync read path. Supports "
                    "?since=ISO-Z and ?limit=N (1..500000)."),
        Probe("aircraft", "GET", "/api/aircraft", True, (200,),
              notes="ADS-B live snapshot. Top-level array (no {ok:true} "
                    "wrapper). 60s server cache."),
        Probe("meshcore", "GET", "/api/meshcore", True, (200,),
              notes="MeshCore radio nodes. Top-level array. 60s cache."),
        Probe("territories", "GET", "/api/territories", True, (200,),
              notes="Global gang convex hulls. Top-level array."),
        Probe("member-territories", "GET", "/api/member-territories", True, (200,),
              notes="Cell-based grid (0.02° × 0.03° squares) + grid-traced "
                    "gang hulls. 5-min cron snapshot."),
        Probe("member-territories-compact",
              "GET", "/api/member-territories?compact=1", True, (200,),
              notes="Compact variant shipped 2026-06-03. Strips gang/color/"
                    "logo per-cell and per-hull; adds top-level `gangs` "
                    "lookup keyed by gang_id. Cuts payload ~20-30%."),
        Probe("member-territories-bbox",
              "GET",
              "/api/member-territories?compact=1&bbox=-82,41,-81,42&zoom=8",
              True, (200,),
              notes="Server-side spatial filter shipped 2026-06-03. Accepts "
                    "Leaflet bounds.toBBoxString() (W,S,E,N) or "
                    "min_lat,min_lng,max_lat,max_lng. Response echoes parsed "
                    "bbox in [S,W,N,E] order. Probe uses a NE-Ohio window "
                    "around the operator's Lorain coordinates."),
        Probe("member-territories-zoom-skip",
              "GET", "/api/member-territories?zoom=5", True, (200,),
              notes="At zoom<6 server returns gang_hulls only with "
                    "zoom_skipped_cells:true + empty cells[]. Shipped "
                    "2026-06-03 for low-zoom map render perf."),
        Probe("leaderboard", "GET", "/api/leaderboard", True, (200,),
              notes="5 boards (today/week/all_time/gangs/hunters), top 25 "
                    "each. 5-min cron snapshot."),
        Probe("bounties", "GET", "/api/bounties", True, (200,),
              notes="Currently-open bounties (max 200, reward DESC)."),
        Probe("health-asked-for", "GET", "/api/health", False, (200, 404),
              notes="Currently does not exist. Asked for in bug report ask #2."),
        Probe("stats-leak-check", "GET", "/api/stats", False, (404,),
              notes="If 200, LiteSpeed admin telemetry is leaking through "
                    "the unbound /api/ prefix (shared-hosting tenant list, "
                    "request counters, lsphp process internals)."),
        Probe("api-sentinel-404-a",
              "GET",
              f"/api/zzz_{secrets.token_hex(8)}_definitely_not_a_route",
              False, (404,),
              notes="Fingerprints the /api/ 404 page. 3-sentinel quorum: at "
                    "least 2 of (a,b,c) must agree on body_md5 to establish "
                    "the canonical fingerprint. Endpoints matching it are DEAD."),
        Probe("api-sentinel-404-b",
              "GET",
              f"/api/zzz_{secrets.token_hex(8)}_definitely_not_a_route",
              False, (404,),
              notes="Quorum sentinel B."),
        Probe("api-sentinel-404-c",
              "GET",
              f"/api/zzz_{secrets.token_hex(8)}_definitely_not_a_route",
              False, (404,),
              notes="Quorum sentinel C."),
        Probe("non-api-sentinel-404",
              "GET",
              f"/zzz_{secrets.token_hex(8)}_definitely_not_a_route",
              False, (404,),
              notes="Fingerprints the non-/api/ 404 page for comparison."),
        Probe("changelog-control", "GET", "/changelog", False, (200,),
              notes="Public page control. Confirms host is reachable."),
    ]


@dataclass
class Result:
    probe: str
    host: str
    auth: str
    method: str
    url: str
    status: int
    elapsed_ms: int
    body_len: int
    body_md5: str
    content_type: str
    cf_cache_status: str
    x_request_id: str
    server: str
    error: str = ""
    verdict: str = ""  # set after sentinel comparison
    # New in v0.6.1. `location` is the raw Location header on 3xx responses
    # (empty on 2xx/4xx/5xx). `body_excerpt` is the first 200 chars of the
    # response body, decoded with errors="replace", for human debugging
    # from the JSON snapshot (excerpt-only — do NOT treat as the full
    # body). `leak_marker` is empty unless the LSWS admin-telemetry
    # fingerprint was found anywhere in the full body — set to the first
    # matched substring; verdict logic uses it directly to fire LEAK.
    # Decoupled from body_excerpt because the leak fingerprint may sit
    # past the first 200 chars (e.g. inside a pretty-printed JSON dict).
    location: str = ""
    body_excerpt: str = ""
    leak_marker: str = ""


def _v2_upload_csv_round_trip(probe: Probe, host: str, auth: str,
                              valid_key: Optional[str],
                              timeout: float) -> "Result":
    """Exercise the full async /api/v2/upload-csv pipeline as one probe.

    Three failure modes get cleanly distinguished:

    * Auth gate broken: POST returns the styled 404 / something other than
      a real 401 for missing/garbage keys. Reported with the actual HTTP
      status from the POST so DEAD detection still fires.
    * v2 parser regression: POST 202s + returns a job_id, but the job
      keeps reporting `queued`/`processing` past our poll cap, or comes
      back `failed`. Reported as ERROR with a descriptive `error` field.
    * Healthy: POST 202 → poll reaches `done`. Result.status is rewritten
      to 200 so the existing `OK` verdict fires (the round-trip succeeded
      end-to-end, even though the HTTP code along the way was 202).

    The single Result aggregates wall-clock across POST + every poll.
    Polling cap: 6 attempts at 1s each (7s total budget on top of the
    POST). That's generous for the documented "ideal for large files"
    pipeline without blocking the tester for minutes if the queue stalls.
    """
    url = host + probe.path
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if probe.needs_auth or auth != "none":
        if auth == "valid" and valid_key:
            headers["X-API-Key"] = valid_key
        elif auth == "garbage":
            headers["X-API-Key"] = GARBAGE_KEY
    if probe.content_type and probe.body is not None:
        headers["Content-Type"] = probe.content_type

    post_req = urllib.request.Request(url, data=probe.body, headers=headers,
                                       method="POST")
    t0 = time.monotonic()
    status = 0
    body = b""
    resp_headers: dict[str, str] = {}
    err = ""

    try:
        with _OPENER.open(post_req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(1024 * 1024)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(1024 * 1024)
        except Exception:
            body = b""
        try:
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            resp_headers = {}
    except urllib.error.URLError as e:
        err = f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001 — diagnostic tool, log anything
        err = f"{type(e).__name__}: {e}"

    # Non-2xx or no body: short-circuit, no poll. DEAD detection still
    # fires correctly because the body_md5 we return is the POST body's.
    poll_url = ""
    job_id: Optional[int] = None
    if not err and 200 <= status < 300 and body:
        try:
            parsed = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            poll_url = str(parsed.get("poll_url") or "")
            jid = parsed.get("job_id")
            if isinstance(jid, int):
                job_id = jid

    if poll_url or job_id is not None:
        if poll_url and not poll_url.startswith(("http://", "https://")):
            poll_url = host + poll_url
        elif not poll_url:
            poll_url = f"{host}/api/v2/upload-job/{job_id}"

        terminal: Optional[str] = None
        last_poll_body = body
        last_poll_status = status
        last_poll_headers = resp_headers
        for _attempt in range(6):
            time.sleep(1.0)
            poll_req = urllib.request.Request(
                poll_url, headers=headers, method="GET",
            )
            try:
                with _OPENER.open(poll_req, timeout=timeout) as resp:
                    last_poll_status = resp.status
                    last_poll_body = resp.read(1024 * 1024)
                    last_poll_headers = {k.lower(): v
                                          for k, v in resp.headers.items()}
            except urllib.error.HTTPError as e:
                last_poll_status = e.code
                try:
                    last_poll_body = e.read(1024 * 1024)
                except Exception:
                    last_poll_body = b""
                try:
                    last_poll_headers = {k.lower(): v
                                          for k, v in e.headers.items()}
                except Exception:
                    last_poll_headers = {}
                terminal = f"poll HTTP {e.code}"
                break
            except urllib.error.URLError as e:
                err = f"URLError on poll: {e.reason}"
                break

            try:
                pj = json.loads(last_poll_body.decode("utf-8", "replace"))
            except Exception:
                pj = None
            poll_status_field = (pj or {}).get("status") if isinstance(pj, dict) else None
            if poll_status_field == "done":
                terminal = "done"
                break
            if poll_status_field == "failed":
                err = "job status=failed"
                terminal = "failed"
                break
            # "queued" / "processing" / unknown → keep polling

        if terminal == "done":
            # Rewrite to 200 so the existing OK verdict fires. The
            # round-trip is what's being probed, not the literal POST code.
            status = 200
        elif terminal is None and not err:
            err = "v2 upload job did not terminate within poll budget"
            status = last_poll_status or status
        else:
            status = last_poll_status or status

        body = last_poll_body
        resp_headers = last_poll_headers

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return Result(
        probe=probe.name,
        host=host,
        auth=auth,
        method=probe.method,
        url=url,
        status=status,
        elapsed_ms=elapsed_ms,
        body_len=len(body),
        body_md5=hashlib.md5(body).hexdigest() if body else "",
        content_type=resp_headers.get("content-type", ""),
        cf_cache_status=resp_headers.get("cf-cache-status", ""),
        x_request_id=resp_headers.get("x-request-id", ""),
        server=resp_headers.get("server", ""),
        error=err,
        location=resp_headers.get("location", ""),
        body_excerpt=body[:200].decode("utf-8", "replace") if body else "",
        leak_marker=next(
            (f for f in LSWS_LEAK_FINGERPRINTS if f.encode() in body),
            "",
        ),
    )


def _request(probe: Probe, host: str, auth: str, valid_key: Optional[str],
             timeout: float) -> Result:
    if probe.custom_runner is not None:
        return probe.custom_runner(probe, host, auth, valid_key, timeout)

    url = host + probe.path
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if probe.needs_auth or auth != "none":
        if auth == "valid" and valid_key:
            headers["X-API-Key"] = valid_key
        elif auth == "garbage":
            headers["X-API-Key"] = GARBAGE_KEY
        # auth == "none" leaves the header off entirely
    if probe.content_type and probe.body is not None:
        headers["Content-Type"] = probe.content_type

    req = urllib.request.Request(url, data=probe.body, headers=headers,
                                 method=probe.method)
    t0 = time.monotonic()
    status = 0
    body = b""
    resp_headers: dict[str, str] = {}
    err = ""
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(1024 * 1024)  # cap at 1 MiB, plenty for diagnostics
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(1024 * 1024)
        except Exception:
            body = b""
        try:
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            resp_headers = {}
    except urllib.error.URLError as e:
        err = f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001 — diagnostic tool, log anything
        err = f"{type(e).__name__}: {e}"
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    return Result(
        probe=probe.name,
        host=host,
        auth=auth,
        method=probe.method,
        url=url,
        status=status,
        elapsed_ms=elapsed_ms,
        body_len=len(body),
        body_md5=hashlib.md5(body).hexdigest() if body else "",
        content_type=resp_headers.get("content-type", ""),
        cf_cache_status=resp_headers.get("cf-cache-status", ""),
        x_request_id=resp_headers.get("x-request-id", ""),
        server=resp_headers.get("server", ""),
        error=err,
        location=resp_headers.get("location", ""),
        body_excerpt=body[:200].decode("utf-8", "replace") if body else "",
        leak_marker=next(
            (f for f in LSWS_LEAK_FINGERPRINTS if f.encode() in body),
            "",
        ),
    )


def run_once(hosts: list[str], variants: tuple, valid_key: Optional[str],
             timeout: float, team_id: int = 1) -> list[Result]:
    probes = build_probes(team_id=team_id)
    results: list[Result] = []
    for host in hosts:
        for probe in probes:
            for auth in variants:
                # No-auth-only probes don't need to be repeated under garbage/valid.
                if not probe.needs_auth and auth != "none":
                    continue
                results.append(_request(probe, host, auth, valid_key, timeout))
    annotate_verdicts(results)
    return results


SENTINEL_PROBES = ("api-sentinel-404-a", "api-sentinel-404-b", "api-sentinel-404-c")


def _canonical_sentinel(results: list[Result], host: str) -> tuple[str, str]:
    """Quorum-pick the canonical /api/ 404 fingerprint for one host.

    Returns (canonical_md5, status) where status is one of:
        "unanimous"   — all 3 sentinels agreed
        "majority"    — 2 of 3 agreed (one diverged, e.g. CDN cache slip)
        "diverged"    — all 3 distinct, no canonical fingerprint
        "no-data"     — fewer than 2 sentinels returned a body

    DEAD detection only fires when status is unanimous or majority. Diverged
    sentinels disable DEAD detection for that host and emit a warning.
    """
    hashes = [r.body_md5 for r in results
              if r.probe in SENTINEL_PROBES and r.host == host and r.body_md5]
    if len(hashes) < 2:
        return ("", "no-data")
    # Count occurrences manually to stay stdlib-Counter-free in case the
    # caller wants to vendor this single file with no imports beyond top.
    counts: dict[str, int] = {}
    for h in hashes:
        counts[h] = counts.get(h, 0) + 1
    top_hash, top_count = max(counts.items(), key=lambda kv: kv[1])
    if top_count == 3:
        return (top_hash, "unanimous")
    if top_count == 2:
        return (top_hash, "majority")
    return ("", "diverged")


def annotate_verdicts(results: list[Result]) -> None:
    """Verdict-tag every result using a quorum sentinel for DEAD detection.

    Three random /api/<token> probes per run define the canonical /api/ 404
    fingerprint via 2-of-3 majority. A probe whose body_md5 matches the
    canonical fingerprint is labeled DEAD (route not bound). If the three
    sentinels diverge, DEAD detection is disabled for that host and the
    sentinels themselves are labeled SENTINEL-DIVERGED.
    """
    canonical: dict[str, tuple[str, str]] = {}
    hosts_seen = {r.host for r in results}
    for host in hosts_seen:
        canonical[host] = _canonical_sentinel(results, host)
    non_api_sentinels = {r.host: r.body_md5
                          for r in results if r.probe == "non-api-sentinel-404"}

    for r in results:
        if r.error:
            r.verdict = "ERROR"
            continue
        # LEAK fires on any probe whose body carries the LiteSpeed admin-
        # telemetry fingerprint, regardless of which endpoint received
        # the request. Was probe-specific (stats-leak-check) until v0.6.1;
        # generalized so the rule catches the case where the leak expands
        # to additional /api/* paths in the future. Tightened from
        # "stats-leak-check returned 200" because locosp's 2026-05-30 fix
        # landed and the bare-status rule was false-positiving on the
        # post-fix 302→/login redirect target.
        if r.leak_marker:
            r.verdict = "LEAK"
            continue
        api_md5, quorum_status = canonical.get(r.host, ("", "no-data"))
        nas = non_api_sentinels.get(r.host, "")

        if r.probe in SENTINEL_PROBES:
            if quorum_status == "diverged":
                r.verdict = "SENTINEL-DIVERGED"
            elif quorum_status == "majority" and r.body_md5 != api_md5:
                r.verdict = "SENTINEL-OUTLIER"  # the 1 of 3 that disagreed
            else:
                r.verdict = "SENTINEL"
        elif r.probe == "non-api-sentinel-404":
            r.verdict = "SENTINEL-NONAPI"
        if r.verdict:
            continue
        if r.body_md5 and api_md5 and r.body_md5 == api_md5:
            r.verdict = "DEAD"
        elif r.body_md5 and nas and r.body_md5 == nas:
            r.verdict = "DEAD-NONAPI"
        elif r.status in (301, 302, 303, 307, 308) and "/login" in (r.location or ""):
            # API endpoint redirecting to the web-session login flow.
            # Distinct from AUTH-REQUIRED (which is the spec-correct 401
            # JSON shape). Routing inconsistency in WDGoWars: some /api/*
            # paths return 401 JSON, others 302→login HTML. We surface it
            # without escalating to DEGRADED — the auth gate is working,
            # the response shape just isn't API-clean.
            r.verdict = "AUTH-REDIRECT"
        elif r.status in (301, 302, 303, 307, 308):
            r.verdict = f"REDIRECT-{r.status}"
        elif r.status == 401:
            r.verdict = "AUTH-REQUIRED"
        elif 200 <= r.status < 300:
            r.verdict = "OK"
        elif r.status == 404:
            r.verdict = "404"
        elif r.status == 405:
            r.verdict = "METHOD"
        elif 400 <= r.status < 500:
            r.verdict = f"{r.status}"
        elif r.status >= 500:
            r.verdict = f"{r.status}"
        else:
            r.verdict = "?"


# ───────────────────────────── Rendering ──────────────────────────────────────

VERDICT_PRIORITY = {
    "ERROR": 0, "SENTINEL-DIVERGED": 1, "LEAK": 2, "DEAD": 3, "DEAD-NONAPI": 4,
    "SENTINEL-OUTLIER": 5, "404": 6, "METHOD": 7,
    "REDIRECT-301": 8, "REDIRECT-303": 8, "REDIRECT-307": 8, "REDIRECT-308": 8,
    "AUTH-REQUIRED": 9, "AUTH-REDIRECT": 10, "OK": 11,
    "BLOCKED": 12, "SENTINEL": 13, "SENTINEL-NONAPI": 14,
}


def render_table(results: list[Result]) -> str:
    cols = ("verdict", "status", "host", "probe", "auth", "ms", "len", "ct", "md5")
    rows = []
    for r in sorted(results, key=lambda r: (r.host, VERDICT_PRIORITY.get(r.verdict, 99), r.probe, r.auth)):
        rows.append((
            r.verdict,
            str(r.status) if r.status else "-",
            r.host.replace("https://", ""),
            r.probe,
            r.auth,
            str(r.elapsed_ms),
            str(r.body_len),
            (r.content_type or "-").split(";")[0],
            (r.body_md5[:8] or "-"),
        ))
    widths = [max(len(c), max((len(row[i]) for row in rows), default=0)) for i, c in enumerate(cols)]
    out = []
    out.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(cols)))
    out.append("  ".join("-" * widths[i] for i in range(len(cols))))
    for row in rows:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(len(cols))))
    return "\n".join(out)


def summary(results: list[Result]) -> dict:
    by_verdict: dict[str, int] = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
    overall = "HEALTHY"
    if by_verdict.get("DEAD", 0) > 0:
        overall = "DEGRADED"
    if any(r.probe == "me" and r.auth == "valid" and r.verdict == "DEAD" for r in results):
        overall = "OUTAGE"
    if by_verdict.get("LEAK", 0) > 0:
        overall = overall + "+LEAK"
    if by_verdict.get("ERROR", 0) > 0 and overall == "HEALTHY":
        overall = "UNREACHABLE"
    # Sentinel quorum failure: the diagnostic itself is broken (3 random
    # /api/<token> paths returned 3 distinct bodies). DEAD detection is
    # unreliable until the operator investigates. Surface it loudly.
    if by_verdict.get("SENTINEL-DIVERGED", 0) > 0:
        overall = overall + "+SENTINEL-DIVERGED"
    return {"overall": overall, "by_verdict": by_verdict, "total": len(results)}


# ───────────────────────────── Baseline diff ─────────────────────────────────

# ───────────────────────────── Telegram alerting ─────────────────────────────
#
# Optional, stdlib-only Telegram notifier. Posts to the Bot API on state
# change in --watch mode. No dependency on any bridge, broker, or webhook
# service — drop a bot token + chat id into the env and the tool pages itself.
#
# Create a bot via @BotFather to get a token. For chat_id: send a message
# to the bot, then GET https://api.telegram.org/bot<TOKEN>/getUpdates and
# read result[0].message.chat.id (positive integer for DMs, negative for
# groups, -100... for channels).

TELEGRAM_TEXT_LIMIT = 4096  # Telegram's per-message char cap
TELEGRAM_DELTA_LIMIT = 30   # max delta lines included before truncation


def _format_telegram_text(prev_overall: str, curr_overall: str,
                           deltas: list[str], by_verdict: dict) -> str:
    """Pure formatter for a Telegram alert body. Testable without HTTP."""
    if curr_overall == "HEALTHY" and prev_overall != "HEALTHY":
        prefix = "✅ wdgwars API recovered"
    elif "SENTINEL-DIVERGED" in curr_overall:
        prefix = "🔧 wdgwars-api-tester diagnostic broken"
    else:
        prefix = "🚨 wdgwars API " + curr_overall

    lines = [f"<b>{prefix}</b>", f"<code>{prev_overall} → {curr_overall}</code>", ""]

    if deltas:
        lines.append("<b>probe deltas:</b>")
        shown = deltas[:TELEGRAM_DELTA_LIMIT]
        for d in shown:
            lines.append(f"<code>{d}</code>")
        if len(deltas) > TELEGRAM_DELTA_LIMIT:
            lines.append(f"<i>… and {len(deltas) - TELEGRAM_DELTA_LIMIT} more</i>")
        lines.append("")

    if by_verdict:
        counts = ", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items()))
        lines.append(f"<b>verdicts:</b> <code>{counts}</code>")

    text = "\n".join(lines)
    if len(text) > TELEGRAM_TEXT_LIMIT:
        text = text[:TELEGRAM_TEXT_LIMIT - 20] + "\n<i>… truncated</i>"
    return text


def _post_telegram(token: str, chat_id: str, text: str,
                    parse_mode: str = "HTML", timeout: float = 10.0) -> bool:
    """POST a sendMessage to the Telegram Bot API. Returns True on 200."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(512).decode("utf-8", errors="replace")
        except Exception:
            pass
        log.warning("telegram post failed: HTTP %s %s", e.code, body[:200])
        return False
    except Exception as e:  # noqa: BLE001
        log.warning("telegram post failed: %s", e)
        return False


# ───────────────────────────── Generic webhook ───────────────────────────────
#
# POSTs a structured JSON payload to any HTTP endpoint on state change. The
# payload carries both `text` (Slack-style) and `content` (Discord-style)
# keys so it works out of the box for both, plus structured fields for any
# generic handler (n8n, PagerDuty Events v2, custom Flask/FastAPI, etc.).


def _verdict_rank(verdict: str, status: int) -> int:
    """Lower number = worse. Numeric 5xx statuses are treated as gateway/
    upstream failures and rank below DEAD (DEAD=3, 5xx=2)."""
    v = (verdict or "").upper()
    if v in {"502", "503", "504", "522", "524"}:
        return 2
    if status and 500 <= status < 600:
        return 2
    return VERDICT_PRIORITY.get(v, 99)


def _is_upstream_5xx(verdict: str, status: int) -> bool:
    """True if this side of a transition looks like a CDN/origin gateway
    failure, not a probe-side change. Used to detect LOCOSP upstream flap."""
    v = (verdict or "").upper()
    if v in {"502", "503", "504", "522", "524"}:
        return True
    if status and 500 <= status < 600:
        return True
    return False


def _classify_delta(prev_verdict: str, prev_status: int,
                     curr_verdict: str, curr_status: int) -> dict:
    """Returns {direction: improved|regressed|sideways, upstream_flap: bool}.

    Direction is by verdict-rank: improved if curr is better-ranked than prev.
    upstream_flap is True if EITHER side is a 5xx — flagging the transition as
    LOCOSP-origin/CDN flap rather than something the probe itself controls."""
    pr = _verdict_rank(prev_verdict, prev_status)
    cr = _verdict_rank(curr_verdict, curr_status)
    if cr > pr:
        direction = "improved"
    elif cr < pr:
        direction = "regressed"
    else:
        direction = "sideways"
    return {
        "direction": direction,
        "upstream_flap": (_is_upstream_5xx(prev_verdict, prev_status)
                          or _is_upstream_5xx(curr_verdict, curr_status)),
    }


def _parse_delta_line(line: str) -> dict | None:
    """Parse a line from _probe_deltas back into structured fields.

    Format: '<host> <probe>/<auth>          <PV>/<PS> -> <CV>/<CS>'
    Returns None for NEW / GONE lines (we don't classify those — they're
    always real signal, not noise)."""
    if " NEW -> " in line or " GONE " in line:
        return None
    if " -> " not in line:
        return None
    left, _, right = line.rpartition(" -> ")
    try:
        label, prev_pair = left.rsplit(None, 1)
        curr_pair = right.strip()
        pv, ps = prev_pair.split("/", 1)
        cv, cs = curr_pair.split("/", 1)
        return {
            "label": label.strip(),
            "prev_verdict": pv, "prev_status": int(ps) if ps.isdigit() else 0,
            "curr_verdict": cv, "curr_status": int(cs) if cs.isdigit() else 0,
        }
    except Exception:
        return None


def _annotate_deltas(deltas: list[str]) -> tuple[list[str], dict]:
    """Returns (annotated_lines, summary) where summary has counts:
       {improved, regressed, sideways, upstream_flap_count, total_classified,
        unclassified}."""
    summary = {"improved": 0, "regressed": 0, "sideways": 0,
                "upstream_flap_count": 0, "total_classified": 0,
                "unclassified": 0}
    out = []
    for line in deltas:
        parsed = _parse_delta_line(line)
        if not parsed:
            out.append(f"·  {line}")
            summary["unclassified"] += 1
            continue
        c = _classify_delta(parsed["prev_verdict"], parsed["prev_status"],
                             parsed["curr_verdict"], parsed["curr_status"])
        marker = {"improved": "↑", "regressed": "↓",
                  "sideways": "↔"}[c["direction"]]
        out.append(f"{marker}  {line}")
        summary[c["direction"]] += 1
        summary["total_classified"] += 1
        if c["upstream_flap"]:
            summary["upstream_flap_count"] += 1
    return out, summary


def _should_suppress_alert(prev_overall: str, curr_overall: str,
                            delta_summary: dict) -> tuple[bool, str]:
    """Decide whether to suppress the webhook + exec-on-change for this tick.

    Suppress when:
      - overall state didn't change AND
      - all classified deltas are upstream flaps AND
      - net direction isn't getting worse (regressed <= improved)
    Returns (suppress: bool, reason: str).
    """
    if prev_overall != curr_overall:
        return False, "overall state changed"
    if delta_summary["unclassified"] > 0:
        return False, "unclassified deltas present (e.g. NEW/GONE)"
    if delta_summary["total_classified"] == 0:
        return False, "no classifiable deltas"
    if delta_summary["upstream_flap_count"] != delta_summary["total_classified"]:
        return False, "non-upstream-flap delta present"
    if delta_summary["regressed"] > delta_summary["improved"]:
        return False, "net regression (more probes worse than better)"
    return True, (f"all {delta_summary['total_classified']} deltas are "
                  f"LOCOSP upstream flap, no net regression")


def _format_webhook_payload(prev_overall: str, curr_overall: str,
                             deltas: list[str], by_verdict: dict) -> dict:
    """Formatter. Renders directional ↑/↓/↔ markers and a one-line action."""
    annotated, dsum = _annotate_deltas(deltas)

    if curr_overall == "HEALTHY" and prev_overall != "HEALTHY":
        emoji, kind = "✅", "recovery"
        headline = f"{emoji} wdgwars-api-tester: RECOVERED ({prev_overall} → {curr_overall})"
    elif "SENTINEL-DIVERGED" in curr_overall:
        emoji, kind = "🔧", "diagnostic-broken"
        headline = f"{emoji} wdgwars-api-tester: {prev_overall} → {curr_overall}"
    elif prev_overall != curr_overall:
        emoji, kind = "🚨", "regression"
        headline = f"{emoji} wdgwars-api-tester: {prev_overall} → {curr_overall}"
    else:
        if dsum["upstream_flap_count"] == dsum["total_classified"] and dsum["total_classified"] > 0:
            emoji, kind = "📡", "upstream-flap"
            shape = f"LOCOSP upstream flap, {dsum['improved']} recovered, {dsum['regressed']} regressed"
        elif dsum["improved"] > dsum["regressed"]:
            emoji, kind = "🔁", "partial-recovery"
            shape = f"{dsum['improved']} recovered, {dsum['regressed']} regressed"
        elif dsum["regressed"] > dsum["improved"]:
            emoji, kind = "⚠️", "partial-regression"
            shape = f"{dsum['regressed']} regressed, {dsum['improved']} recovered"
        else:
            emoji, kind = "🔁", "sideways"
            shape = f"{dsum['total_classified']} probes shifted, no net change"
        headline = f"{emoji} wdgwars-api-tester: still {curr_overall} ({shape})"

    if (dsum["upstream_flap_count"] == dsum["total_classified"]
            and dsum["total_classified"] > 0
            and dsum["regressed"] <= dsum["improved"]):
        action = "LOCOSP upstream is flapping. No local action."
    elif dsum["regressed"] > 0 and dsum["upstream_flap_count"] < dsum["total_classified"]:
        action = "Non-upstream probe regressed. Investigate."
    elif curr_overall == "HEALTHY" and prev_overall != "HEALTHY":
        action = "Recovered. No action."
    elif "DEGRADED" in curr_overall and dsum["total_classified"] == 0:
        action = "Steady-state DEGRADED (stable DEAD endpoints). No action."
    else:
        action = ""

    delta_block = "\n".join(annotated[:30]) if annotated else "(no per-probe deltas)"
    verdicts_str = ", ".join(f"{k}={v}" for k, v in sorted(by_verdict.items()))
    body_parts = [headline, "", delta_block, "", f"verdicts: {verdicts_str}"]
    if action:
        body_parts.append("")
        body_parts.append(f"→ {action}")
    flat = "\n".join(body_parts)

    return {
        "text": flat,
        "content": flat,
        "title": headline,
        "kind": kind,
        "overall": curr_overall,
        "prev_overall": prev_overall,
        "deltas": list(deltas),
        "by_verdict": dict(by_verdict),
        "delta_summary": dsum,
        "action": action,
        "tool": "wdgwars-api-tester",
        "version": __version__,
    }


def _post_webhook(url: str, payload: dict, timeout: float = 10.0) -> bool:
    """POST a JSON payload to an arbitrary webhook URL."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        log.warning("webhook post failed: HTTP %s", e.code)
        return False
    except Exception as e:  # noqa: BLE001
        log.warning("webhook post failed: %s", e)
        return False


# ───────────────────────────── Exec-on-change hook ───────────────────────────
#
# Runs an arbitrary shell command on state change, with env vars set so the
# operator's script has everything it needs. Use this when no webhook fits —
# send email via mail(1), trigger a Lambda via aws CLI, write to a database,
# pipe to logger, whatever. Trust model: the operator authored the command.


def _exec_on_change(cmd: str, prev_overall: str, curr_overall: str,
                     deltas: list[str], by_verdict: dict,
                     timeout: float = 15.0) -> bool:
    """Run cmd with state info exported as env vars. Returns True on rc=0."""
    env = os.environ.copy()
    env["WDGWARS_OVERALL"] = curr_overall
    env["WDGWARS_PREV_OVERALL"] = prev_overall
    env["WDGWARS_DELTAS"] = "\n".join(deltas)
    env["WDGWARS_VERDICTS"] = json.dumps(by_verdict)
    env["WDGWARS_RECOVERY"] = "1" if (curr_overall == "HEALTHY"
                                       and prev_overall != "HEALTHY") else "0"
    env["WDGWARS_KIND"] = (
        "recovery" if env["WDGWARS_RECOVERY"] == "1"
        else "diagnostic-broken" if "SENTINEL-DIVERGED" in curr_overall
        else "regression")
    try:
        r = subprocess.run(cmd, shell=True, env=env, timeout=timeout,
                            capture_output=True, text=True)
        if r.returncode != 0:
            log.warning("exec-on-change rc=%d stderr=%s",
                        r.returncode, r.stderr.strip()[:200])
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        log.warning("exec-on-change timed out after %ss", timeout)
        return False
    except Exception as e:  # noqa: BLE001
        log.warning("exec-on-change failed: %s", e)
        return False


def _probe_deltas(prev: list[Result], curr: list[Result]) -> list[str]:
    """Compact per-probe deltas between two result sets.

    Lines look like:
        wdgwars.pl me/none           DEAD/404 -> AUTH-REQUIRED/401
        wdgwars.pl stats-leak-check  LEAK/200 -> 404/404

    Only probes whose verdict OR status changed are emitted. NEW / GONE keys
    (probe added or removed between runs) are flagged explicitly.
    """
    def key(r: Result) -> tuple[str, str, str]:
        return (r.host, r.probe, r.auth)

    prev_map = {key(r): r for r in prev}
    curr_map = {key(r): r for r in curr}
    lines: list[str] = []
    all_keys = sorted(set(prev_map) | set(curr_map))
    for k in all_keys:
        p = prev_map.get(k)
        c = curr_map.get(k)
        host = k[0].replace("https://", "")
        label = f"{host} {k[1]}/{k[2]}"
        if p is None:
            lines.append(f"{label:<48} NEW -> {c.verdict}/{c.status}")
        elif c is None:
            lines.append(f"{label:<48} GONE (was {p.verdict}/{p.status})")
        elif p.verdict != c.verdict or p.status != c.status:
            lines.append(f"{label:<48} {p.verdict}/{p.status} -> {c.verdict}/{c.status}")
    return lines


def state_signature(results: list[Result]) -> str:
    """Stable hash of (probe, host, auth, verdict, status) tuples.

    Used by --watch to detect state changes. Deliberately excludes body_md5 so
    a dynamic body (e.g. /api/stats counters, or the styled 404 page being
    silently resized from 1423 to 919 bytes) doesn't register as a state change.
    The verdict is the load-bearing signal.
    """
    h = hashlib.sha256()
    for r in sorted(results, key=lambda r: (r.host, r.probe, r.auth)):
        h.update(f"{r.host}|{r.probe}|{r.auth}|{r.verdict}|{r.status}\n".encode())
    return h.hexdigest()


def diff_against_baseline(current: list[Result], baseline_path: Path) -> list[str]:
    if not baseline_path.exists():
        return []
    try:
        base = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return [f"baseline unreadable: {e}"]
    base_map = {(r["host"], r["probe"], r["auth"]): r for r in base.get("results", [])}
    diffs = []
    for r in current:
        key = (r.host, r.probe, r.auth)
        b = base_map.get(key)
        if not b:
            diffs.append(f"NEW {key} verdict={r.verdict}")
            continue
        if b.get("verdict") != r.verdict or b.get("status") != r.status:
            diffs.append(
                f"CHANGE {key}: {b.get('verdict')}/{b.get('status')} "
                f"→ {r.verdict}/{r.status}"
            )
    return diffs


# ───────────────────────────── CLI ────────────────────────────────────────────

def load_key(cli_key: Optional[str]) -> Optional[str]:
    if cli_key:
        return cli_key.strip()
    env = os.environ.get("WDGWARS_API_KEY")
    if env:
        return env.strip()
    cfg = Path.home() / ".config" / "wigle-to-wdgwars" / "wdgwars.key"
    if cfg.exists():
        return cfg.read_text(encoding="utf-8").strip()
    return None


# ───────────────────────── Outage-aware backoff ──────────────────────────────
#
# In --watch mode, when LOCOSP is at a daily-cap / global-outage state, every
# probe in our sweep starts returning 429 or status=0 (connection error). The
# default behavior is to keep sweeping at the operator-chosen cadence, which
# (a) pollutes the baseline with all-429 sweeps and (b) makes us a measurable
# contributor to whatever quota is being burned. The fix: when a sweep looks
# like an outage by share of bad verdicts, extend the sleep before the next
# sweep. Resets to normal cadence on the first clean sweep.

OUTAGE_VERDICT_TAGS = {"ERROR", "429"}


def _outage_share(results: list[Result]) -> float:
    """Fraction of results carrying a 429 or transport-error verdict."""
    if not results:
        return 0.0
    bad = sum(
        1 for r in results
        if r.verdict in OUTAGE_VERDICT_TAGS or r.status == 429
    )
    return bad / len(results)


def _seconds_to_next_midnight_utc(now: Optional[float] = None) -> float:
    """Seconds from `now` (epoch) to next 00:00:00 UTC. Min 60s for safety."""
    if now is None:
        now = time.time()
    dt = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc)
    nxt = (dt + datetime.timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0)
    return max(60.0, (nxt - dt).total_seconds())


def _backoff_sleep_seconds(base: float, streak: int,
                            cap_seconds: float,
                            now: Optional[float] = None) -> float:
    """Sleep duration for the Nth consecutive outage sweep.

    Doubles per consecutive outage sweep up to 32x base, then clamps at the
    smaller of `cap_seconds` and the time-until-next-midnight-UTC (since
    LOCOSP's documented daily quota resets at midnight UTC).
    """
    multiplier = 2 ** min(max(streak, 1), 5)  # 2,4,8,16,32
    proposed = base * multiplier
    midnight = _seconds_to_next_midnight_utc(now)
    return max(base, min(proposed, cap_seconds, midnight))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="wdgwars-api-tester",
        description="Probe the WDGoWars HTTP API surface and report verdicts.",
    )
    p.add_argument("--hosts", default="apex",
                   help="apex = wdgwars.pl only (default); all = apex + www + "
                   "api; OR a comma-separated list of full URLs (e.g. "
                   "http://127.0.0.1:9999) to probe a custom host. Use the URL "
                   "form to point at staging, a fork, or a local mock for "
                   "testing without hitting the real API.")
    p.add_argument("--variants", default="none,garbage,valid",
                   help="Comma list of auth variants to run (none,garbage,valid).")
    p.add_argument("--key", help="Override valid X-API-Key. Falls back to "
                   "$WDGWARS_API_KEY then ~/.config/wigle-to-wdgwars/wdgwars.key.")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout in seconds (default 15).")
    p.add_argument("--team-id", type=int, default=1,
                   help="Numeric gang id for the /api/team/{id} probe (default "
                   "1). Override when probing a fork/staging instance where "
                   "id 1 doesn't exist, or to vary the probed team between "
                   "runs.")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON results to stdout. Table still goes to stderr.")
    p.add_argument("--no-table", action="store_true",
                   help="Suppress the human-readable table.")
    p.add_argument("--quiet", action="store_true",
                   help="Print only the overall verdict word to stdout "
                   "(HEALTHY / DEGRADED / OUTAGE / UNREACHABLE, with optional "
                   "+LEAK or +SENTINEL-DIVERGED suffix). Implies --no-table. "
                   "Pairs with exit code 0/1 for shell pipelines and CI.")
    p.add_argument("--watch", type=float, default=0.0,
                   help="Loop every N seconds. Print compact deltas on state "
                   "change; full table only on transition into HEALTHY.")
    p.add_argument("--baseline", type=Path,
                   help="Path to a baseline JSON file. If missing, written on first "
                   "run. If present, diffs are reported.")
    p.add_argument("--alert-telegram", action="store_true",
                   help="In --watch mode, also POST a Telegram message on every "
                   "state change. Requires --telegram-bot-token (or env "
                   "$TELEGRAM_BOT_TOKEN) and --telegram-chat-id (or env "
                   "$TELEGRAM_CHAT_ID).")
    p.add_argument("--telegram-bot-token",
                   help="Override $TELEGRAM_BOT_TOKEN. Get one from @BotFather.")
    p.add_argument("--telegram-chat-id",
                   help="Override $TELEGRAM_CHAT_ID. Positive int for DMs, "
                   "negative for groups, -100... for channels.")
    p.add_argument("--alert-webhook",
                   help="In --watch mode, POST a JSON payload to this URL on "
                   "every state change. Works for Discord webhooks, Slack "
                   "incoming webhooks, n8n, PagerDuty Events v2, or any "
                   "generic HTTP endpoint — payload carries both `text` "
                   "(Slack), `content` (Discord), and structured fields.")
    p.add_argument("--silent-webhook",
                   help="POST suppressed alerts (LOCOSP upstream flap "
                   "etc.) to this URL instead of dropping them to the "
                   "journal. Same payload as --alert-webhook with a "
                   "[suppressed] tag in the header.")
    p.add_argument("--exec-on-change",
                   help="In --watch mode, run this shell command on every "
                   "state change. Env vars exported: WDGWARS_OVERALL, "
                   "WDGWARS_PREV_OVERALL, WDGWARS_DELTAS (newline-joined), "
                   "WDGWARS_VERDICTS (JSON), WDGWARS_RECOVERY (1/0), "
                   "WDGWARS_KIND (recovery|regression|diagnostic-broken).")
    p.add_argument("--outage-backoff-threshold", type=float, default=0.30,
                   help="In --watch mode, if at least this fraction of sweep "
                   "results are verdict=429 or verdict=ERROR (status=0), "
                   "treat the sweep as an LOCOSP-side outage and extend the "
                   "next sleep. Default 0.30. Set 1.01 to disable.")
    p.add_argument("--outage-backoff-cap-seconds", type=float, default=3600.0,
                   help="In --watch mode, maximum sleep when in outage "
                   "backoff. Capped further by time-to-next-midnight-UTC "
                   "since LOCOSP's documented daily quota resets at 00:00 "
                   "UTC. Default 3600 (1h).")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if args.hosts == "apex":
        hosts = DEFAULT_HOSTS
    elif args.hosts == "all":
        hosts = ALL_HOSTS
    elif args.hosts.startswith(("http://", "https://")):
        hosts = [h.strip().rstrip("/") for h in args.hosts.split(",") if h.strip()]
    else:
        log.error("invalid --hosts: %r. Use 'apex', 'all', or a "
                   "comma-separated list of http(s):// URLs.", args.hosts)
        return 2
    variants = tuple(v.strip() for v in args.variants.split(",") if v.strip())
    bad = [v for v in variants if v not in AUTH_VARIANTS]
    if bad:
        log.error("Unknown auth variants: %s. Valid: %s", bad, AUTH_VARIANTS)
        return 2

    valid_key = load_key(args.key)
    if "valid" in variants and not valid_key:
        log.warning("No valid key found. Dropping 'valid' from variants. "
                    "Set $WDGWARS_API_KEY or ~/.config/wigle-to-wdgwars/wdgwars.key.")
        variants = tuple(v for v in variants if v != "valid")

    # --quiet implies --no-table; it also suppresses --json.
    if args.quiet:
        args.no_table = True

    # Resolve Telegram credentials once at startup so we fail fast.
    tg_token = args.telegram_bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    tg_chat_id = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    if args.alert_telegram:
        if not args.watch:
            log.warning("--alert-telegram requires --watch; one-shot mode has "
                        "no state to alert on. Ignoring.")
            args.alert_telegram = False
        elif not tg_token or not tg_chat_id:
            log.warning("--alert-telegram set but TELEGRAM_BOT_TOKEN or "
                        "TELEGRAM_CHAT_ID missing. Disabling.")
            args.alert_telegram = False

    if (args.alert_webhook or args.silent_webhook or args.exec_on_change) and not args.watch:
        log.warning("--alert-webhook, --silent-webhook, and --exec-on-change "
                    "require --watch; one-shot mode has no state to alert on. "
                    "Ignoring.")
        args.alert_webhook = None
        args.silent_webhook = None
        args.exec_on_change = None

    def one_pass() -> tuple[list[Result], dict, str]:
        results = run_once(hosts, variants, valid_key, args.timeout,
                           team_id=args.team_id)
        s = summary(results)
        sig = state_signature(results)
        return results, s, sig

    def emit(results: list[Result], s: dict) -> None:
        if args.quiet:
            print(s["overall"])
            return
        if not args.no_table:
            print(render_table(results), file=sys.stderr)
            print("", file=sys.stderr)
            print(f"summary: {s['overall']}  verdicts={s['by_verdict']}  "
                  f"total={s['total']}", file=sys.stderr)
        if args.json:
            payload = {
                "tool": "wdgwars-api-tester",
                "version": __version__,
                "timestamp": int(time.time()),
                "hosts": hosts,
                "variants": list(variants),
                "summary": s,
                "results": [asdict(r) for r in results],
            }
            print(json.dumps(payload, indent=2))

    if args.watch and args.watch > 0:
        last_results: Optional[list[Result]] = None
        last_overall: str = ""
        outage_streak: int = 0
        log.info("watch mode: polling every %.0fs, printing on change", args.watch)
        log.info("outage backoff: threshold=%.0f%% bad-verdicts, cap=%.0fs "
                 "(also capped at next midnight UTC)",
                 args.outage_backoff_threshold * 100.0,
                 args.outage_backoff_cap_seconds)
        try:
            while True:
                results, s, _sig = one_pass()
                overall = s["overall"]
                if last_results is None:
                    # First pass: print full table so the operator sees the
                    # starting state, then settle into delta-only output.
                    log.info("--- initial state @ %s ---",
                             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    emit(results, s)
                elif overall != last_overall or _probe_deltas(last_results, results):
                    deltas = _probe_deltas(last_results, results)
                    recovery = (overall == "HEALTHY" and last_overall != "HEALTHY")
                    header = "RECOVERY" if recovery else "state change"
                    log.info("--- %s @ %s   (%s -> %s) ---",
                             header,
                             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             last_overall, overall)
                    for line in deltas:
                        log.info("  %s", line)
                    if recovery and not args.quiet:
                        # Full table on the recovery moment so the operator
                        # can verify the post-fix verdict surface in one shot.
                        log.info("")
                        emit(results, s)
                    elif args.quiet:
                        emit(results, s)
                    if args.alert_telegram:
                        text = _format_telegram_text(
                            last_overall, overall, deltas, s["by_verdict"])
                        ok = _post_telegram(tg_token, tg_chat_id, text)
                        log.info("  telegram: %s",
                                 "sent" if ok else "FAILED")
                    _, _dsum = _annotate_deltas(deltas)
                    suppress, reason = _should_suppress_alert(
                        last_overall, overall, _dsum)
                    if suppress:
                        log.info("  alert SUPPRESSED: %s", reason)
                        if args.silent_webhook:
                            payload = _format_webhook_payload(
                                last_overall, overall, deltas, s["by_verdict"])
                            tag = f"[suppressed: {reason}]\n"
                            payload["content"] = tag + payload["content"]
                            payload["text"] = tag + payload["text"]
                            ok = _post_webhook(args.silent_webhook, payload)
                            log.info("  silent-webhook: %s",
                                     "sent" if ok else "FAILED")
                    if args.alert_webhook and not suppress:
                        payload = _format_webhook_payload(
                            last_overall, overall, deltas, s["by_verdict"])
                        ok = _post_webhook(args.alert_webhook, payload)
                        log.info("  webhook: %s",
                                 "sent" if ok else "FAILED")
                    if args.exec_on_change and not suppress:
                        ok = _exec_on_change(
                            args.exec_on_change, last_overall, overall,
                            deltas, s["by_verdict"])
                        log.info("  exec-on-change: %s",
                                 "ok" if ok else "FAILED")
                last_results = results
                last_overall = overall

                # Outage-aware backoff: if a meaningful share of this sweep
                # came back 429 or transport-error, the LOCOSP daily quota
                # (or a per-IP CF limit) is likely tripped. Don't keep
                # hammering — extend sleep up to the next-midnight-UTC reset
                # point. Resets the streak on the first clean sweep.
                share = _outage_share(results)
                if share >= args.outage_backoff_threshold:
                    outage_streak += 1
                    sleep_for = _backoff_sleep_seconds(
                        args.watch, outage_streak,
                        args.outage_backoff_cap_seconds)
                    midnight = _seconds_to_next_midnight_utc()
                    log.info(
                        "outage-backoff: %.0f%% bad-verdicts (>=%.0f%%); "
                        "sleeping %.0fs [streak=%d, midnight-utc=%.0fs]",
                        share * 100.0,
                        args.outage_backoff_threshold * 100.0,
                        sleep_for, outage_streak, midnight)
                    time.sleep(sleep_for)
                else:
                    if outage_streak > 0:
                        log.info(
                            "outage-backoff: clear (%.0f%% bad); "
                            "resuming normal cadence", share * 100.0)
                    outage_streak = 0
                    time.sleep(args.watch)
        except KeyboardInterrupt:
            return 0

    results, s, _ = one_pass()
    if args.baseline:
        diffs = diff_against_baseline(results, args.baseline)
        if not args.baseline.exists():
            args.baseline.write_text(json.dumps(
                {"results": [asdict(r) for r in results]}, indent=2), encoding="utf-8")
            log.info("baseline written: %s", args.baseline)
        else:
            if diffs:
                log.info("baseline diffs (%d):", len(diffs))
                for d in diffs:
                    log.info("  %s", d)
            else:
                log.info("no diff vs baseline %s", args.baseline)
    emit(results, s)

    if s["overall"] in ("OUTAGE", "DEGRADED", "UNREACHABLE") or "LEAK" in s["overall"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
