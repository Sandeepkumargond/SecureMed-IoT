#!/usr/bin/env bash
# start_ui.sh — Start the SecureMed-IoT demo UI
set -e
cd "$(dirname "$0")"
echo "Starting SecureMed-IoT PRESENT-80 Demo UI..."
echo "Open http://localhost:5050 in your browser"
python3 app.py
