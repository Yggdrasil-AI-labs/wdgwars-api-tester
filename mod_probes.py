"""Conformance probes for the proposed mod-visibility endpoints.

These endpoints DO NOT EXIST on wdgwars.pl yet. They are a proposal, and this
module is the half of that proposal that makes "deploy when it goes green" a
real sentence rather than a promise: the contract is written down as executable
assertions, so whoever implements the endpoints can verify them without taking
anyone's word for it.

Run against a mock first, then against a real instance once an account carries
the `is_mod` flag.

WHY THESE ASSERT BODIES, UNLIKE THE MAIN SWEEP
----------------------------------------------
The probes in ``wdgwars_api_tester.build_probes`` deliberately assert status
only. That is right for endpoints that already exist and already have consumers:
the contract is established, and a body assertion would just be a second place
to keep in sync.

These are the opposite case. Nothing has been built, so the body shape IS the
thing under negotiation, and a 200 that returns the wrong field names is a
failure the client would hit on day one. So each probe validates the fields the
client actually reads, and nothing more. Field lists come from the client's own
``src/api.js``, not from wishful thinking.

SELF-SCOPED BY DEFAULT
----------------------
``resolve_self_targets`` discovers the caller's OWN username and one of their
OWN upload ids. That is a deliberate property, not a convenience:

* A conformance run never reads another player's record, so nobody has to pick
  a subject to test against.
* It needs no arguments, so the person deploying can run it with nothing but a
  key and a base URL.
* If the endpoints leak more than intended, that surfaces against the runner's
  own data first.

Pass explicit targets only when deliberately testing cross-account access, which
is the whole point of the flag and should be done knowingly.

PATH PREFIX
-----------
Defaults to ``/endpoint``, not ``/api``. Cloudflare rewrites ``/api/X`` to
``/endpoint/X`` at the edge, so ``/endpoint/*`` is the path the origin actually
sees and the permanent contract. The per-IP cap also trips on ``/api/*`` before
the documented 120/min limit does. ``prefix`` is settable so both can be probed,
which matters because the CF rewrite has already broken seven handlers that
re-parsed ``REQUEST_URI`` with an ``/api/`` regex (team.php, shop.php,
team_messages.php, upload_job.php, user_stats.php, then bounties.php and
shop_activate.php). A new endpoint should accept both prefixes from the start,
and probing both is how you prove it does.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from wdgwars_api_tester import (
    GARBAGE_KEY,
    USER_AGENT,
    Probe,
    Result,
    _excerpt,
)

MOD_PREFIX = "/endpoint"

# Field -> accepted python types, taken from what the client reads in
# src/api.js. `None` is always tolerated: the client already handles missing
# values, and forcing non-null would make the contract stricter than the
# consumer needs.
PLAYER_FIELDS: dict[str, tuple[type, ...]] = {
    "flagged": (bool,),
    "reason": (str,),
    "tier": (str,),
    "account_age_days": (int,),
}

UPLOAD_FIELDS: dict[str, tuple[type, ...]] = {
    "imported": (int,),
    "duplicates": (int,),
    "no_gps": (int,),
    "bad_rows": (int,),
    "endpoint": (str,),
}

POINT_FIELDS: dict[str, tuple[type, ...]] = {
    "lat": (int, float),
    "lng": (int, float),
}

# How many points the sample= probe asks for. Small on purpose: the assertion
# is that the server honours the cap, and a big number would make a failure
# expensive to transfer rather than easier to see.
SAMPLE_N = 25


def _headers(auth: str, valid_key: Optional[str]) -> dict[str, str]:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if auth == "valid" and valid_key:
        h["X-API-Key"] = valid_key
    elif auth == "garbage":
        h["X-API-Key"] = GARBAGE_KEY
    return h


def _fetch(url: str, auth: str, valid_key: Optional[str],
           timeout: float) -> tuple[int, bytes, dict[str, str], str]:
    """Single GET. Returns (status, body, headers, error). Never raises."""
    req = urllib.request.Request(url, headers=_headers(auth, valid_key),
                                 method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (resp.status, resp.read(1024 * 1024),
                    {k.lower(): v for k, v in resp.headers.items()}, "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(1024 * 1024)
        except Exception:
            body = b""
        try:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
        except Exception:
            hdrs = {}
        return e.code, body, hdrs, ""
    except Exception as e:  # noqa: BLE001 - surface transport errors as data
        return 0, b"", {}, f"{type(e).__name__}: {e}"


def _check_wrapper(payload: Any) -> list[str]:
    """The {ok: true, ...} wrapper.

    Asked for explicitly because the existing surface is split: /api/me and
    /api/upload-history use the wrapper while /api/territories, /api/aircraft
    and /api/meshcore return top-level arrays, so a naive resp.json()["ok"]
    raises a TypeError on those. New endpoints should not extend that split.
    """
    if not isinstance(payload, dict):
        return [f"expected a JSON object with an 'ok' key, got {type(payload).__name__}"]
    if "ok" not in payload:
        return ["missing 'ok' key (wrapper shape, as used by /api/me)"]
    if payload["ok"] is not True:
        return [f"'ok' should be true on success, got {payload['ok']!r}"]
    return []


def _check_fields(obj: Any, spec: dict[str, tuple[type, ...]],
                  where: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(obj, dict):
        problems.append(f"{where}: expected an object, got {type(obj).__name__}")
        return problems
    for name, types in spec.items():
        if name not in obj:
            problems.append(f"{where}: missing '{name}'")
            continue
        val = obj[name]
        if val is None:
            continue  # null is tolerated; the client handles it
        # bool is a subclass of int, so an int field must not accept a bool.
        if bool not in types and isinstance(val, bool):
            problems.append(
                f"{where}: '{name}' is a bool, expected "
                f"{' or '.join(t.__name__ for t in types)}")
            continue
        if not isinstance(val, types):
            problems.append(
                f"{where}: '{name}' is {type(val).__name__}, expected "
                f"{' or '.join(t.__name__ for t in types)}")
    return problems


def _first_list(payload: dict, *candidates: str) -> Optional[list]:
    """Find the list in a wrapped response without pinning its key name.

    The key name is genuinely not worth dictating, so the probe accepts any of
    the plausible ones and reports what it found. Being strict about the shape
    of each row while relaxed about the container name keeps the ask small.
    """
    for key in candidates:
        val = payload.get(key)
        if isinstance(val, list):
            return val
    for val in payload.values():
        if isinstance(val, list):
            return val
    return None


def _contract_runner(validate):
    """Wrap a body validator into the custom_runner signature.

    Status handling mirrors the v2-upload round-trip probe: a contract failure
    on an otherwise-200 response is rewritten to 900 so it cannot be mistaken
    for a healthy OK, and the specific problems land in Result.error where the
    JSON snapshot and the table both surface them.
    """

    def runner(probe: Probe, host: str, auth: str, valid_key: Optional[str],
               timeout: float) -> Result:
        url = host + probe.path
        t0 = time.monotonic()
        status, body, hdrs, err = _fetch(url, auth, valid_key, timeout)
        elapsed = int((time.monotonic() - t0) * 1000)

        problems: list[str] = []
        if err:
            problems.append(err)
        elif status == 200:
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
            except Exception as e:  # noqa: BLE001
                problems.append(f"body is not JSON: {type(e).__name__}: {e}")
            else:
                problems.extend(_check_wrapper(payload))
                if isinstance(payload, dict):
                    problems.extend(validate(payload))

        # A bad key must be refused as an API, not by bouncing to a login page.
        # 302 is the failure mode that already exists on five endpoints and the
        # one most likely to be copied into a new handler by accident.
        if auth == "garbage" and status in (301, 302, 303, 307, 308):
            problems.append(
                f"garbage key produced a {status} redirect to "
                f"{hdrs.get('location', '?')!r}; expected 401 with a JSON body")

        return Result(
            probe=probe.name,
            host=host,
            auth=auth,
            method="GET",
            url=url,
            status=900 if (problems and status == 200) else status,
            elapsed_ms=elapsed,
            body_len=len(body),
            body_md5="",
            content_type=hdrs.get("content-type", ""),
            cf_cache_status=hdrs.get("cf-cache-status", ""),
            x_request_id=hdrs.get("x-request-id", ""),
            server=hdrs.get("server", ""),
            error="; ".join(problems),
            location=hdrs.get("location", ""),
            # Must go through _excerpt, not a raw slice. These probes run with a
            # valid key against endpoints returning player data, and excerpts
            # travel into webhook and Telegram payloads plus the JSON snapshot,
            # so an echoed key would fan out to every alert channel. _excerpt
            # scrubs before truncating so a key straddling the 200-char boundary
            # cannot survive as a recognisable prefix.
            body_excerpt=_excerpt(body, valid_key),
        )

    return runner


def _validate_player(payload: dict) -> list[str]:
    # Tolerate the fields sitting at the top level or nested under a key,
    # since that is a presentation choice rather than part of the contract.
    target = payload
    for key in ("player", "data", "result"):
        if isinstance(payload.get(key), dict):
            target = payload[key]
            break
    return _check_fields(target, PLAYER_FIELDS, "player")


def _validate_uploads(payload: dict) -> list[str]:
    rows = _first_list(payload, "uploads", "data", "results", "items")
    if rows is None:
        return ["no list of uploads found in the response"]
    if not rows:
        return []  # an account with no uploads is legitimate, not a failure
    return _check_fields(rows[0], UPLOAD_FIELDS, "uploads[0]")


def _validate_points(payload: dict) -> list[str]:
    rows = _first_list(payload, "points", "data", "results", "items")
    if rows is None:
        return ["no list of points found in the response"]
    problems: list[str] = []
    if len(rows) > SAMPLE_N:
        problems.append(
            f"sample={SAMPLE_N} was ignored: got {len(rows)} points. This "
            "endpoint must downsample server-side, like /api/me/cells does, "
            "because /api/me/aps already truncates on a wide window")
    if rows:
        problems.extend(_check_fields(rows[0], POINT_FIELDS, "points[0]"))
    return problems


def resolve_self_targets(host: str, valid_key: str,
                        timeout: float = 15.0,
                        prefix: str = MOD_PREFIX) -> tuple[Optional[str], Optional[str]]:
    """Discover the caller's own username and one of their own upload ids.

    Uses only endpoints that already exist, so this works before any mod
    endpoint is deployed. Returns (username, upload_id), either of which may be
    None; callers should skip the probes that need a missing one rather than
    substituting a guess, because a guessed username would silently probe
    somebody else's record.
    """
    username: Optional[str] = None
    upload_id: Optional[str] = None

    status, body, _, err = _fetch(f"{host}{prefix}/me", "valid", valid_key, timeout)
    if status == 200 and not err:
        try:
            me = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            me = {}
        if isinstance(me, dict):
            for key in ("username", "user", "name"):
                val = me.get(key)
                if isinstance(val, str) and val:
                    username = val
                    break
            if username is None and isinstance(me.get("profile"), dict):
                val = me["profile"].get("username")
                if isinstance(val, str) and val:
                    username = val

    status, body, _, err = _fetch(f"{host}{prefix}/upload-history?limit=1",
                                  "valid", valid_key, timeout)
    if status == 200 and not err:
        try:
            hist = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            hist = {}
        rows = None
        if isinstance(hist, dict):
            rows = _first_list(hist, "uploads", "history", "data", "results")
        elif isinstance(hist, list):
            rows = hist
        if rows:
            row = rows[0]
            if isinstance(row, dict):
                for key in ("id", "upload_id", "job_id"):
                    val = row.get(key)
                    if val is not None:
                        upload_id = str(val)
                        break

    return username, upload_id


def build_mod_probes(username: Optional[str] = None,
                     upload_id: Optional[str] = None,
                     prefix: str = MOD_PREFIX) -> list[Probe]:
    """Probes for the three proposed mod endpoints.

    ``expect_status`` includes 404 on purpose. Until the endpoints are
    deployed, 404 IS the correct healthy answer, exactly like the existing
    ``health-asked-for`` probe. That means this suite can be committed and run
    today without producing false alarms, and it flips to meaningful the moment
    an implementation lands.

    Probes whose target could not be resolved are omitted rather than filled
    with a placeholder, so a run never quietly probes an account that is not
    the caller's.
    """
    probes: list[Probe] = []

    if username:
        quoted = urllib.parse.quote(username, safe="")
        probes.append(Probe(
            "mod-player", "GET", f"{prefix}/mod/player/{quoted}",
            True, (200, 404),
            custom_runner=_contract_runner(_validate_player),
            notes="PROPOSED, not deployed. Asserts the {ok:true} wrapper plus "
                  "flagged(bool) / reason(str) / tier(str) / "
                  "account_age_days(int), which is what the client reads. "
                  "Target is the caller's own username, so a conformance run "
                  "reads nobody else's record. 404 is healthy pre-deploy."))
        probes.append(Probe(
            "mod-player-uploads", "GET",
            f"{prefix}/mod/player/{quoted}/uploads?limit=5",
            True, (200, 404),
            custom_runner=_contract_runner(_validate_uploads),
            notes="PROPOSED, not deployed. Asserts per-row imported / "
                  "duplicates / no_gps / bad_rows / endpoint. An empty list "
                  "passes: an account with no uploads is legitimate. 404 is "
                  "healthy pre-deploy."))

    if upload_id:
        quoted_id = urllib.parse.quote(str(upload_id), safe="")
        probes.append(Probe(
            "mod-upload-points", "GET",
            f"{prefix}/mod/upload/{quoted_id}/points?sample={SAMPLE_N}",
            True, (200, 404),
            custom_runner=_contract_runner(_validate_points),
            notes=f"PROPOSED, not deployed. Asserts lat/lng rows and that "
                  f"sample={SAMPLE_N} is honoured server-side. The cap is the "
                  "load-bearing assertion: this is the same shape as the "
                  "existing /api/me/cells, which exists because /api/me/aps "
                  "truncates on a wide window. Target is one of the caller's "
                  "own uploads. 404 is healthy pre-deploy."))

    return probes
