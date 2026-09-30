#!/usr/bin/env bash
# Linux / macOS Leftover Folder Scanner Agent
SERVER_URL="${1:-http://192.168.0.139:8090}"

echo "=========================================================="
echo "  Application Leftover Folder Scanner - Linux/Mac Agent   "
echo "  Reporting to Central Dashboard: $SERVER_URL             "
echo "=========================================================="

python3 -c "import urllib.request; exec(urllib.request.urlopen('$SERVER_URL/agent/agent.py').read().decode('utf-8'))" "$SERVER_URL"
