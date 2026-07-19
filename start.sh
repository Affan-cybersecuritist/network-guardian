#!/bin/bash
# One-command startup for Network Guardian.
# Usage:  ./start.sh
# Then just open http://localhost:8080 in your browser.

set -e
cd "$(dirname "$0")"

echo "Checking dependencies..."
pip install -q pandas numpy scikit-learn joblib fastapi uvicorn websockets python-multipart scapy requests --break-system-packages 2>/dev/null || \
pip install -q pandas numpy scikit-learn joblib fastapi uvicorn websockets python-multipart scapy requests

if [ ! -f "models/isolation_forest.joblib" ]; then
    echo "No trained model found — training now (one-time, ~30 seconds)..."
    python3 notebooks/train_model.py
else
    echo "Trained model found, skipping training."
fi

echo "Starting backend API on port 8000..."
uvicorn backend.main:app --host 0.0.0.0 --port 8000 > /tmp/network-guardian-backend.log 2>&1 &
BACKEND_PID=$!

echo "Starting dashboard on port 8080..."
cd frontend
python3 -m http.server 8080 > /tmp/network-guardian-frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

sleep 2
echo ""
echo "=========================================="
echo "  Network Guardian is running!"
echo "  Open this in your browser:"
echo "  http://localhost:8080"
echo "=========================================="
echo ""
echo "Press Ctrl+C to stop both servers."

# Save PIDs so stop.sh can clean up
echo "$BACKEND_PID" > /tmp/network-guardian-backend.pid
echo "$FRONTEND_PID" > /tmp/network-guardian-frontend.pid

# Wait so Ctrl+C stops both
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
wait
