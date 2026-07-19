#!/bin/bash
# Stops the backend + frontend servers started by start.sh
[ -f /tmp/network-guardian-backend.pid ] && kill "$(cat /tmp/network-guardian-backend.pid)" 2>/dev/null
[ -f /tmp/network-guardian-frontend.pid ] && kill "$(cat /tmp/network-guardian-frontend.pid)" 2>/dev/null
echo "Stopped."
