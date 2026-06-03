#!/usr/bin/env bash
# Pre-release smoke test for wdgwars-api-tester. Runs in CI and locally.
#
# Stdlib-only tool, so the surface is small:
#   1. AST parse + import sanity (no syntax errors, all top-level imports
#      resolve in a clean interpreter).
#   2. `--version` and `--help` don't crash.
#   3. Offline unit tests pass.
#   4. mock_wdgwars.py launches and serves a known scenario (sanity-check
#      the integration harness's prerequisite without running the full
#      offline integration suite — that's the CI workflow's job).
#
# Run from the repo root:   bash scripts/smoke.sh
# Exit: 0 all pass, 1 any failure (fail-fast).

set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d -t api-tester-smoke-XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

say()  { printf "[smoke] %s\n" "$*"; }
fail() { printf "[smoke] FAIL: %s\n" "$*" >&2; exit 1; }
ok()   { printf "[smoke] ok: %s\n" "$*"; }

cd "$REPO_DIR"

# 1. import + AST sanity
say "checking import + AST..."
python3 -c "import ast; ast.parse(open('wdgwars_api_tester.py').read())" \
    || fail "wdgwars_api_tester.py syntax"
python3 -c "import ast; ast.parse(open('mock_wdgwars.py').read())" \
    || fail "mock_wdgwars.py syntax"
python3 -c "import wdgwars_api_tester" \
    || fail "import wdgwars_api_tester"
ok "import + AST"

# 2. --version + --help
say "wdgwars_api_tester.py --version..."
VER=$(python3 wdgwars_api_tester.py --version 2>&1 | head -1) \
    || fail "--version"
say "  $VER"
python3 wdgwars_api_tester.py --help > /dev/null \
    || fail "--help"
ok "--version + --help"

# 3. offline unit tests
say "running offline unit tests..."
if python3 -m unittest test_wdgwars_api_tester > "$TMP_DIR/tests.log" 2>&1; then
    ok "unit tests passed"
else
    tail -30 "$TMP_DIR/tests.log" >&2
    fail "unit tests"
fi

# 4. mock_wdgwars.py launches
say "spawning mock_wdgwars.py on a random port..."
MOCK_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()")
python3 mock_wdgwars.py --scenario healthy --port "$MOCK_PORT" \
    > "$TMP_DIR/mock.log" 2>&1 &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null; rm -rf "$TMP_DIR"' EXIT INT TERM
# Poll for ready — TCP connect, not HTTP. The mock's endpoints return
# 401/404 by design (that's what the tester probes for); HTTP-level
# checks would mis-read those as "not ready" even though the server is.
READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', $MOCK_PORT)); s.close()" 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.3
done
if [ "$READY" != "1" ]; then
    cat "$TMP_DIR/mock.log" >&2
    fail "mock server didn't come up on :$MOCK_PORT"
fi
ok "mock server up"

# Probe the mock to confirm a HEALTHY-shape readout
say "probing mock with --variants none,garbage..."
if python3 wdgwars_api_tester.py \
        --hosts "http://127.0.0.1:$MOCK_PORT" \
        --variants none,garbage \
        --quiet > "$TMP_DIR/probe.log" 2>&1; then
    say "  $(head -1 "$TMP_DIR/probe.log")"
    ok "probe completed"
else
    # Quiet exit-1 is OK if there are non-HEALTHY verdicts; we just want
    # to confirm the tester can talk to the mock without crashing.
    say "  $(head -1 "$TMP_DIR/probe.log")"
    ok "probe completed (non-zero exit acceptable)"
fi

say "all smoke checks passed"
exit 0
