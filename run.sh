#!/usr/bin/env bash
# Double-click: probe wdgwars.pl with default args.
# CLI:         forward any args to wdgwars_api_tester.py.
#
# Examples:
#   ./run.sh                                   # default probe
#   ./run.sh --hosts all                       # apex + www + api subdomain
#   ./run.sh --json > snapshot.json            # machine-readable
#   ./run.sh --watch 60 --alert-webhook URL    # poll + notify
#
# Stdlib only — no venv needed. Picks python3 from PATH.

cd "$(dirname "$0")"
python3 wdgwars_api_tester.py "$@"
echo
if [ -t 0 ]; then
    read -n 1 -s -r -p "Press any key to close..."
    echo
fi
