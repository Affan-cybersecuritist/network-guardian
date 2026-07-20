"""
API Endpoint Testing - Validates Network Guardian REST API
Run BEFORE starting the backend server to perform functional tests
"""
import sys
import os
import json
import subprocess
import time
import requests
from pathlib import Path

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

print("\n" + "=" * 90)
print("NETWORK GUARDIAN - API ENDPOINT TESTS")
print("=" * 90)

API_URL = "http://localhost:8000"
TIMEOUT = 3

# Function to check if server is running
def is_server_running():
    try:
        resp = requests.get(f"{API_URL}/health", timeout=TIMEOUT)
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False

# Check if server is already running
if not is_server_running():
    print("\n[INFO] Starting backend server...")
    print("[INFO] This will open a terminal window. Keep it running for the tests.")
    print("[INFO] After tests complete, you can close the terminal or press Ctrl+C.\n")

    # Start the server in a new terminal
    if sys.platform == "win32":
        subprocess.Popen(
            f"cmd.exe /c cd {_THIS_DIR} && python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000",
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        subprocess.Popen(
            ["python", "-m", "uvicorn", "backend.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000"],
            cwd=_THIS_DIR
        )

    # Wait for server to start
    print("[INFO] Waiting for server to start (max 30 seconds)...")
    for i in range(30):
        time.sleep(1)
        if is_server_running():
            print(f"[OK] Server is running!\n")
            break
    else:
        print("[FAIL] Server did not start. Check the terminal window for errors.")
        sys.exit(1)
else:
    print("\n[OK] Server is already running.\n")

# ===== API TESTS =====
print("-" * 90)
print("Running API endpoint tests...\n")

test_results = []

# Test 1: Health check
print("[TEST 1] GET /health")
try:
    resp = requests.get(f"{API_URL}/health", timeout=TIMEOUT)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    print("[PASS] Server is responding\n")
    test_results.append(("Health check", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Health check", False))

# Test 2: Get metrics
print("[TEST 2] GET /metrics")
try:
    resp = requests.get(f"{API_URL}/metrics", timeout=TIMEOUT)
    assert resp.status_code == 200
    data = resp.json()
    assert "accuracy" in data
    print(f"[PASS] Model accuracy: {data.get('accuracy', 0):.1%}\n")
    test_results.append(("Get metrics", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Get metrics", False))

# Test 3: Get interfaces (may not have Npcap on Windows)
print("[TEST 3] GET /interfaces")
try:
    resp = requests.get(f"{API_URL}/interfaces", timeout=TIMEOUT)
    if resp.status_code == 200:
        interfaces = resp.json()["interfaces"]
        print(f"[PASS] Found {len(interfaces)} network interfaces\n")
        test_results.append(("List interfaces", True))
    else:
        print(f"[INFO] Interfaces endpoint returned {resp.status_code} (may require Npcap/libpcap)\n")
        test_results.append(("List interfaces", None))
except Exception as e:
    print(f"[INFO] Interfaces test skipped (requires Npcap): {type(e).__name__}\n")
    test_results.append(("List interfaces", None))

# Test 4: Get sample traffic
print("[TEST 4] GET /sample-traffic")
try:
    resp = requests.get(f"{API_URL}/sample-traffic?n=10&attack_ratio=0.3", timeout=TIMEOUT)
    assert resp.status_code == 200
    data = resp.json()
    assert "traffic" in data
    traffic = data["traffic"]
    assert len(traffic) > 0
    assert all("risk_score" in t for t in traffic)
    attacks = sum(1 for t in traffic if t["flagged"])
    print(f"[PASS] Sample traffic generated ({len(traffic)} connections, {attacks} flagged)\n")
    test_results.append(("Sample traffic", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Sample traffic", False))

# Test 5: Analyze normal traffic
print("[TEST 5] POST /analyze (normal traffic)")
try:
    payload = {
        "rows": [
            {
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 100,
                "dst_bytes": 200,
                "count": 1,
                "srv_count": 1,
                "same_srv_rate": 1.0,
                "dst_host_count": 1,
            }
        ]
    }
    resp = requests.post(f"{API_URL}/analyze", json=payload, timeout=TIMEOUT)
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert len(data["results"]) == 1
    result = data["results"][0]
    assert "risk_score" in result
    print(f"[PASS] Analysis returned (risk_score={result['risk_score']:.1f})\n")
    test_results.append(("Analyze traffic", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Analyze traffic", False))

# Test 6: Get alerts
print("[TEST 6] GET /alerts")
try:
    resp = requests.get(f"{API_URL}/alerts?limit=20", timeout=TIMEOUT)
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data
    alerts = data["alerts"]
    print(f"[PASS] Retrieved {len(alerts)} alerts\n")
    test_results.append(("Get alerts", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Get alerts", False))

# Test 7: Get alert stats
print("[TEST 7] GET /alerts/stats")
try:
    resp = requests.get(f"{API_URL}/alerts/stats", timeout=TIMEOUT)
    assert resp.status_code == 200
    data = resp.json()
    required_keys = ["scored", "flagged", "bruteforce_triggered"]
    assert all(k in data for k in required_keys)
    print(f"[PASS] Stats: scored={data['scored']}, flagged={data['flagged']}\n")
    test_results.append(("Get alert stats", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Get alert stats", False))

# Test 8: Demo attack scenario
print("[TEST 8] POST /demo/simulate-attack")
try:
    resp = requests.post(f"{API_URL}/demo/simulate-attack", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    results = data["results"]
    assert len(results) > 0
    flagged = sum(1 for r in results if r.get("flagged"))
    print(f"[PASS] Demo attack scenario analyzed ({len(results)} connections, {flagged} flagged)\n")
    test_results.append(("Demo attack scenario", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Demo attack scenario", False))

# Test 9: Webhook settings
print("[TEST 9] GET/POST /settings/webhook")
try:
    # Get current settings
    resp = requests.get(f"{API_URL}/settings/webhook", timeout=TIMEOUT)
    assert resp.status_code == 200

    # Set new settings
    settings = {"url": "https://example.com/webhook", "enabled": True}
    resp = requests.post(f"{API_URL}/settings/webhook", json=settings, timeout=TIMEOUT)
    assert resp.status_code == 200

    # Verify settings were saved
    resp = requests.get(f"{API_URL}/settings/webhook", timeout=TIMEOUT)
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://example.com/webhook"
    print("[PASS] Webhook settings working\n")
    test_results.append(("Webhook settings", True))
except Exception as e:
    print(f"[FAIL] {e}\n")
    test_results.append(("Webhook settings", False))

# Test 10: Firewall operations (may fail without admin)
print("[TEST 10] GET /firewall/blocked")
try:
    resp = requests.get(f"{API_URL}/firewall/blocked", timeout=TIMEOUT)
    if resp.status_code == 200:
        data = resp.json()
        blocked = data.get("blocked", [])
        print(f"[PASS] Firewall blocking working ({len(blocked)} blocked IPs)\n")
        test_results.append(("Firewall operations", True))
    else:
        print(f"[INFO] Firewall endpoint returned {resp.status_code} (may require Admin)\n")
        test_results.append(("Firewall operations", None))
except Exception as e:
    print(f"[INFO] Firewall test skipped: {type(e).__name__}\n")
    test_results.append(("Firewall operations", None))

# ===== SUMMARY =====
print("=" * 90)
print("API TEST SUMMARY")
print("=" * 90)

passed = sum(1 for _, result in test_results if result is True)
failed = sum(1 for _, result in test_results if result is False)
skipped = sum(1 for _, result in test_results if result is None)
total = len(test_results)

for test_name, result in test_results:
    if result is True:
        status = "[PASS]"
    elif result is False:
        status = "[FAIL]"
    else:
        status = "[SKIP]"
    print(f"{status} {test_name}")

print("\n" + "-" * 90)
print(f"Results: {passed} passed, {failed} failed, {skipped} skipped out of {total} tests")
print("-" * 90)

if failed == 0:
    print("\n[SUCCESS] All API endpoints are working correctly!")
else:
    print(f"\n[WARNING] {failed} test(s) failed. Check the output above for details.")

print("""
NEXT STEPS:
  1. The backend server is still running in another terminal
  2. Open your browser and visit: http://localhost:8000/frontend/
  3. Try the following:
     - View the dashboard
     - Run the demo attack scenario
     - Upload a PCAP file
     - Check the alerts history
  4. When done, close the server terminal or press Ctrl+C
""")
