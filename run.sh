#!/usr/bin/env bash
# ==============================================================================
# Aegis Defender Pro - Unified Launcher for macOS & Linux
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "======================================================================"
echo "    🛡️  AEGIS DEFENDER PRO - NEXT-GEN ANTIVIRUS & ENDPOINT SHIELD    "
echo "======================================================================"
echo "  Starting Core Engine & Cyber Command Dashboard..."

PORT=8787

# Find available python3
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[-] Error: Python 3 is required to run Aegis Defender Pro."
    exit 1
fi

echo "[+] Python Interpreter: $($PYTHON_CMD --version)"
echo "[+] Starting Aegis Server on http://localhost:$PORT ..."

# Launch default browser in background after short delay
(
    sleep 1.2
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "http://localhost:$PORT"
    elif command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost:$PORT"
    fi
) &

# Run server
exec $PYTHON_CMD server.py $PORT
