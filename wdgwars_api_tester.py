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

__version__ = "0.1.0"
GITHUB_URL = "https://github.com/HiroAlleyCat/wdgwars-api-tester"

import argparse
import hashlib
import io
import json
import logging
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

USER_AGENT = f"wdgwars-api-tester/{__version__} (+{GITHUB_URL})"

DEFAULT_HOSTS = ["https://wdgwars.pl"]
ALL_HOSTS = ["https://wdgwars.pl", "https://www.wdgwars.pl", "https://api.wdgwars.pl"]

GARBAGE_KEY = "g" * 64
AUTH_VARIANTS = ("none", "garbage", "valid")

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


def build_probes() -> list[Probe]:
    csv_body, csv_ct = _csv_probe_body()
    return [
        Probe("api-root", "GET", "/api/", False, (200, 301, 302, 404),
              notes="Used as baseline for /api/ subtree shape."),
        Probe("me", "GET", "/api/me", True, (200,),
              notes="Auth + identity. With no/garbage key expect 401, not 404."),
        Probe("upload-history", "GET", "/api/upload-history?limit=5", True, (200,),
              notes="Added 2026-04-27 per /changelog."),
        Probe("upload-csv", "POST", "/api/upload-csv", True, (200, 400),
              body=csv_body, content_type=csv_ct,
              notes="Multipart WiGLE-1.6 with mixed Types."),
        Probe("signed-upload", "GET", "/api/upload/", True, (200, 405),
              notes="HMAC signed JSON endpoint. GET should be 405 if healthy."),
        Probe("health-asked-for", "GET", "/api/health", False, (200, 404),
              notes="Currently does not exist. Asked for in bug report ask #2."),
        Probe("stats-leak-check", "GET", "/api/stats", False, (404,),
              notes="If 200, LiteSpeed admin telemetry is leaking through "
                    "the unbound /api/ prefix (shared-hosting tenant list, "
                    "request counters, lsphp process internals)."),
        Probe("api-sentinel-404",
              "GET",
              f"/api/zzz_{secrets.token_hex(8)}_definitely_not_a_route",
              False, (404,),
              notes="Fingerprints the /api/ 404 page. Other endpoints "
                    "matching this body hash are DEAD."),
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


def _request(probe: Probe, host: str, auth: str, valid_key: Optional[str],
             timeout: float) -> Result:
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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    )


def run_once(hosts: list[str], variants: tuple, valid_key: Optional[str],
             timeout: float) -> list[Result]:
    probes = build_probes()
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


def annotate_verdicts(results: list[Result]) -> None:
    """Compare every result against the per-host /api/ sentinel md5.

    A result whose body md5 matches the sentinel for the same host is DEAD —
    the request didn't reach an endpoint handler.
    """
    sentinels = {r.host: r.body_md5 for r in results if r.probe == "api-sentinel-404"}
    non_api_sentinels = {r.host: r.body_md5 for r in results if r.probe == "non-api-sentinel-404"}
    for r in results:
        if r.error:
            r.verdict = "ERROR"
            continue
        s = sentinels.get(r.host, "")
        nas = non_api_sentinels.get(r.host, "")
        if r.probe == "api-sentinel-404":
            r.verdict = "SENTINEL"
        elif r.probe == "non-api-sentinel-404":
            r.verdict = "SENTINEL-NONAPI"
        elif r.probe == "stats-leak-check" and r.status == 200:
            r.verdict = "LEAK"
        elif r.body_md5 and s and r.body_md5 == s:
            r.verdict = "DEAD"
        elif r.body_md5 and nas and r.body_md5 == nas:
            r.verdict = "DEAD-NONAPI"
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
    "ERROR": 0, "LEAK": 1, "DEAD": 2, "DEAD-NONAPI": 3, "404": 4,
    "METHOD": 5, "AUTH-REQUIRED": 6, "OK": 7, "SENTINEL": 8, "SENTINEL-NONAPI": 9,
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
    return {"overall": overall, "by_verdict": by_verdict, "total": len(results)}


# ───────────────────────────── Baseline diff ─────────────────────────────────

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


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="wdgwars-api-tester",
        description="Probe the WDGoWars HTTP API surface and report verdicts.",
    )
    p.add_argument("--hosts", choices=["apex", "all"], default="apex",
                   help="apex = wdgwars.pl only (default); all = apex + www + api.")
    p.add_argument("--variants", default="none,garbage,valid",
                   help="Comma list of auth variants to run (none,garbage,valid).")
    p.add_argument("--key", help="Override valid X-API-Key. Falls back to "
                   "$WDGWARS_API_KEY then ~/.config/wigle-to-wdgwars/wdgwars.key.")
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout in seconds (default 15).")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON results to stdout. Table still goes to stderr.")
    p.add_argument("--no-table", action="store_true",
                   help="Suppress the human-readable table.")
    p.add_argument("--watch", type=float, default=0.0,
                   help="Loop every N seconds. Print only on state change.")
    p.add_argument("--baseline", type=Path,
                   help="Path to a baseline JSON file. If missing, written on first "
                   "run. If present, diffs are reported.")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    hosts = ALL_HOSTS if args.hosts == "all" else DEFAULT_HOSTS
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

    def one_pass() -> tuple[list[Result], dict, str]:
        results = run_once(hosts, variants, valid_key, args.timeout)
        s = summary(results)
        sig = state_signature(results)
        return results, s, sig

    def emit(results: list[Result], s: dict) -> None:
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
        last_sig = ""
        log.info("watch mode: polling every %.0fs, printing on change", args.watch)
        try:
            while True:
                results, s, sig = one_pass()
                if sig != last_sig:
                    log.info("--- state change @ %s ---",
                             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                    emit(results, s)
                    last_sig = sig
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
