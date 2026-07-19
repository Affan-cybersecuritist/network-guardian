#!/bin/bash
# One-command test: checks the model works AND checks it catches a real attack
# in a real packet capture. Run this any time you want to "just check it works."
#
# Usage:  ./test.sh
# (Run this AFTER ./start.sh is already running in another terminal)

cd "$(dirname "$0")"

echo "=================================================="
echo "  Network Guardian — Quick Test"
echo "=================================================="

echo ""
echo "[1/3] Checking the API is reachable..."
if curl -s -f http://localhost:8000/health > /dev/null; then
    echo "    ✓ API is up"
else
    echo "    ✗ API is NOT running. Start it first with: ./start.sh"
    exit 1
fi

echo ""
echo "[2/3] Checking model performance numbers..."
curl -s http://localhost:8000/metrics | python3 -m json.tool

echo ""
echo "[3/3] Generating a test capture (normal traffic + a real port scan + a real SYN flood)"
echo "      and scoring it through the live model..."
python3 notebooks/generate_test_pcap.py
python3 backend/score_pcap.py | tail -15

echo ""
echo "=================================================="
echo "  Test complete. If you see mostly 'ATTACK' flags"
echo "  on the scan/flood rows above and low risk scores"
echo "  on normal traffic, everything is working."
echo "=================================================="
