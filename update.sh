#!/usr/bin/env bash
# Double-click (or run) this file to refresh wdgwars_api_tester.py from main.
# Stdlib only — no deps to refresh, just the single .py file.

set -e
cd "$(dirname "$0")"

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
    echo "wdgwars-api-tester needs Python 3.8 or newer. Your current python3 is:"
    python3 --version 2>/dev/null || echo "  (not found on PATH)"
    echo
    echo "Install Python 3.8+ from your package manager or https://python.org/downloads/."
    exit 1
fi

echo "[1/1] Refreshing wdgwars_api_tester.py from GitHub..."
python3 -c "import urllib.request as u; u.urlretrieve('https://raw.githubusercontent.com/HiroAlleyCat/wdgwars-api-tester/main/wdgwars_api_tester.py', 'wdgwars_api_tester.py')"

echo
echo "Updated. Current version:"
python3 wdgwars_api_tester.py --version

echo
if [ -t 0 ]; then
    read -n 1 -s -r -p "Press any key to close..."
    echo
fi
