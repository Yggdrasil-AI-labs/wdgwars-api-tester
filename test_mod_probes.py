"""Tests for the proposed mod-endpoint conformance probes.

These test the ASSERTIONS, not the endpoints. The endpoints do not exist yet, so
what needs proving here is that the validators actually catch the failures they
claim to catch. A conformance suite that passes everything is worse than none at
all, because it launders a broken implementation as verified.

So every validator gets both a good case and the specific bad case it exists to
detect.
"""
from __future__ import annotations

import json

import mod_probes as mp


# ---------------------------------------------------------------------------
# wrapper
# ---------------------------------------------------------------------------

def test_wrapper_accepts_ok_true():
    assert mp._check_wrapper({"ok": True, "player": {}}) == []


def test_wrapper_rejects_top_level_array():
    # The failure mode that already exists on /api/territories, /api/aircraft
    # and /api/meshcore, where resp.json()["ok"] raises TypeError.
    problems = mp._check_wrapper([{"lat": 1, "lng": 2}])
    assert problems
    assert "expected a JSON object" in problems[0]


def test_wrapper_rejects_missing_ok():
    problems = mp._check_wrapper({"player": {}})
    assert problems and "missing 'ok'" in problems[0]


def test_wrapper_rejects_ok_false():
    problems = mp._check_wrapper({"ok": False})
    assert problems and "should be true" in problems[0]


# ---------------------------------------------------------------------------
# player
# ---------------------------------------------------------------------------

GOOD_PLAYER = {
    "ok": True,
    "flagged": True,
    "reason": "impossible geographic spread (5439 km in single upload)",
    "tier": "new",
    "account_age_days": 3,
}


def test_player_good():
    assert mp._validate_player(GOOD_PLAYER) == []


def test_player_accepts_nested():
    # Nesting is a presentation choice, not part of the contract.
    assert mp._validate_player({"ok": True, "player": {
        k: v for k, v in GOOD_PLAYER.items() if k != "ok"}}) == []


def test_player_catches_missing_field():
    payload = {k: v for k, v in GOOD_PLAYER.items() if k != "reason"}
    problems = mp._validate_player(payload)
    assert any("missing 'reason'" in p for p in problems)


def test_player_catches_wrong_type():
    payload = dict(GOOD_PLAYER, account_age_days="3")
    problems = mp._validate_player(payload)
    assert any("account_age_days" in p and "str" in p for p in problems)


def test_player_rejects_bool_for_int():
    # bool subclasses int in Python, so a naive isinstance check would let
    # account_age_days=True through. That would be a real implementation bug
    # slipping past a green suite.
    payload = dict(GOOD_PLAYER, account_age_days=True)
    problems = mp._validate_player(payload)
    assert any("account_age_days" in p and "bool" in p for p in problems)


def test_player_tolerates_null():
    # An unflagged player legitimately has no reason string.
    payload = dict(GOOD_PLAYER, reason=None)
    assert mp._validate_player(payload) == []


# ---------------------------------------------------------------------------
# uploads
# ---------------------------------------------------------------------------

GOOD_UPLOAD = {
    "imported": 0,
    "duplicates": 12,
    "no_gps": 61233,
    "bad_rows": 0,
    "endpoint": "upload-csv",
}


def test_uploads_good():
    assert mp._validate_uploads({"ok": True, "uploads": [GOOD_UPLOAD]}) == []


def test_uploads_empty_list_passes():
    # An account with no uploads is a legitimate state, not a contract failure.
    assert mp._validate_uploads({"ok": True, "uploads": []}) == []


def test_uploads_finds_list_under_any_key():
    assert mp._validate_uploads({"ok": True, "data": [GOOD_UPLOAD]}) == []


def test_uploads_catches_no_list():
    problems = mp._validate_uploads({"ok": True, "count": 3})
    assert problems and "no list of uploads" in problems[0]


def test_uploads_catches_missing_counter():
    row = {k: v for k, v in GOOD_UPLOAD.items() if k != "no_gps"}
    problems = mp._validate_uploads({"ok": True, "uploads": [row]})
    assert any("missing 'no_gps'" in p for p in problems)


# ---------------------------------------------------------------------------
# points
# ---------------------------------------------------------------------------

def _points(n: int) -> dict:
    return {"ok": True, "points": [{"lat": 41.0 + i / 1000, "lng": -81.0}
                                   for i in range(n)]}


def test_points_good():
    assert mp._validate_points(_points(mp.SAMPLE_N)) == []


def test_points_under_cap_is_fine():
    assert mp._validate_points(_points(3)) == []


def test_points_catches_ignored_sample_cap():
    # The load-bearing assertion. If the server ignores sample= and dumps every
    # row, the map review is exactly the /api/me/aps truncation problem again.
    problems = mp._validate_points(_points(mp.SAMPLE_N + 1))
    assert problems
    assert "sample" in problems[0] and "downsample" in problems[0]


def test_points_catches_missing_lng():
    payload = {"ok": True, "points": [{"lat": 41.0}]}
    problems = mp._validate_points(payload)
    assert any("missing 'lng'" in p for p in problems)


def test_points_accepts_int_coords():
    payload = {"ok": True, "points": [{"lat": 41, "lng": -81}]}
    assert mp._validate_points(payload) == []


# ---------------------------------------------------------------------------
# probe construction
# ---------------------------------------------------------------------------

def test_probes_use_endpoint_prefix_by_default():
    probes = mod = mp.build_mod_probes("AlleyCat", "42")
    assert probes
    for p in probes:
        assert p.path.startswith("/endpoint/mod/"), p.path
        assert not p.path.startswith("/api/"), p.path


def test_probes_accept_api_prefix_for_rewrite_testing():
    # Both prefixes must work post-CF-rewrite; probing both is how that gets
    # proven rather than assumed.
    probes = mp.build_mod_probes("AlleyCat", "42", prefix="/api")
    assert probes and all(p.path.startswith("/api/mod/") for p in probes)


def test_probes_tolerate_404_pre_deploy():
    # Committing a suite that alarms on a not-yet-built endpoint would train
    # everyone to ignore it.
    for p in mp.build_mod_probes("AlleyCat", "42"):
        assert 404 in p.expect_status


def test_probes_omitted_when_target_unresolved():
    # Never substitute a placeholder username: that would probe a real account
    # belonging to somebody else.
    assert mp.build_mod_probes(None, None) == []
    only_player = mp.build_mod_probes("AlleyCat", None)
    assert {p.name for p in only_player} == {"mod-player", "mod-player-uploads"}
    only_points = mp.build_mod_probes(None, "42")
    assert {p.name for p in only_points} == {"mod-upload-points"}


def test_probes_url_encode_the_username():
    probes = mp.build_mod_probes("we ird/name", "42")
    player = next(p for p in probes if p.name == "mod-player")
    assert " " not in player.path
    assert "we%20ird%2Fname" in player.path


def test_all_probes_need_auth():
    for p in mp.build_mod_probes("AlleyCat", "42"):
        assert p.needs_auth, p.name


# ---------------------------------------------------------------------------
# runner behaviour
# ---------------------------------------------------------------------------

class _FakeFetch:
    def __init__(self, status, payload, headers=None):
        self.status = status
        self.body = (json.dumps(payload).encode() if payload is not None else b"")
        self.headers = headers or {}

    def __call__(self, url, auth, valid_key, timeout):
        return self.status, self.body, self.headers, ""


def _run(monkeypatch, status, payload, auth="valid", headers=None):
    monkeypatch.setattr(mp, "_fetch", _FakeFetch(status, payload, headers))
    probe = next(p for p in mp.build_mod_probes("AlleyCat", "42")
                 if p.name == "mod-player")
    return probe.custom_runner(probe, "https://example.test", auth, "k" * 64, 5.0)


def test_runner_clean_200_has_no_error(monkeypatch):
    res = _run(monkeypatch, 200, GOOD_PLAYER)
    assert res.status == 200
    assert res.error == ""


def test_runner_rewrites_status_on_contract_failure(monkeypatch):
    # A 200 with the wrong body must not be able to read as healthy.
    res = _run(monkeypatch, 200, {"ok": True, "flagged": True})
    assert res.status == 900
    assert "missing" in res.error


def test_runner_passes_through_404(monkeypatch):
    res = _run(monkeypatch, 404, None)
    assert res.status == 404
    assert res.error == ""


def test_runner_flags_login_redirect_on_garbage_key(monkeypatch):
    # The exact failure mode on /api/aircraft, /api/meshcore, /api/territories,
    # /api/member-territories and /api/stats today.
    res = _run(monkeypatch, 302, None, auth="garbage",
               headers={"location": "/login/?next=/endpoint/mod/player/AlleyCat"})
    assert "expected 401" in res.error


def test_runner_accepts_401_on_garbage_key(monkeypatch):
    res = _run(monkeypatch, 401, {"ok": False, "error": "unauthorized"},
               auth="garbage")
    assert res.error == ""


def test_runner_reports_non_json_body(monkeypatch):
    monkeypatch.setattr(mp, "_fetch",
                        lambda *a, **k: (200, b"<html>login</html>", {}, ""))
    probe = next(p for p in mp.build_mod_probes("AlleyCat", "42")
                 if p.name == "mod-player")
    res = probe.custom_runner(probe, "https://example.test", "valid", "k" * 64, 5.0)
    assert res.status == 900
    assert "not JSON" in res.error


def test_runner_scrubs_echoed_api_key_from_excerpt(monkeypatch):
    # Regression guard. These probes run with a valid key against endpoints that
    # return player data, and excerpts travel into webhook/Telegram payloads and
    # the JSON snapshot. A raw body slice here would reintroduce the exact leak
    # that _excerpt was added upstream to close.
    key = "k" * 64
    monkeypatch.setattr(
        mp, "_fetch",
        lambda *a, **kw: (200, json.dumps(
            {"ok": True, "echoed_key": key, **{k: v for k, v in GOOD_PLAYER.items()
                                               if k != "ok"}}).encode(), {}, ""))
    probe = next(p for p in mp.build_mod_probes("AlleyCat", "42")
                 if p.name == "mod-player")
    res = probe.custom_runner(probe, "https://example.test", "valid", key, 5.0)
    assert key not in res.body_excerpt
    assert "[REDACTED-KEY]" in res.body_excerpt


def test_runner_surfaces_transport_error(monkeypatch):
    monkeypatch.setattr(mp, "_fetch",
                        lambda *a, **k: (0, b"", {}, "TimeoutError: timed out"))
    probe = next(p for p in mp.build_mod_probes("AlleyCat", "42")
                 if p.name == "mod-player")
    res = probe.custom_runner(probe, "https://example.test", "valid", "k" * 64, 5.0)
    assert res.status == 0
    assert "TimeoutError" in res.error


# ---------------------------------------------------------------------------
# self-target resolution
# ---------------------------------------------------------------------------

def test_resolve_self_targets_reads_me_and_history(monkeypatch):
    def fake(url, auth, valid_key, timeout):
        if url.endswith("/me"):
            return 200, json.dumps({"ok": True, "username": "AlleyCat"}).encode(), {}, ""
        return 200, json.dumps({"ok": True, "uploads": [{"id": 4242}]}).encode(), {}, ""

    monkeypatch.setattr(mp, "_fetch", fake)
    assert mp.resolve_self_targets("https://example.test", "k" * 64) == ("AlleyCat", "4242")


def test_resolve_self_targets_returns_none_on_failure(monkeypatch):
    monkeypatch.setattr(mp, "_fetch", lambda *a, **k: (500, b"", {}, ""))
    assert mp.resolve_self_targets("https://example.test", "k" * 64) == (None, None)


def test_resolve_self_targets_survives_nested_username(monkeypatch):
    def fake(url, auth, valid_key, timeout):
        if url.endswith("/me"):
            return 200, json.dumps(
                {"ok": True, "profile": {"username": "Nested"}}).encode(), {}, ""
        return 200, b'{"ok":true,"uploads":[]}', {}, ""

    monkeypatch.setattr(mp, "_fetch", fake)
    name, upload = mp.resolve_self_targets("https://example.test", "k" * 64)
    assert name == "Nested"
    assert upload is None
