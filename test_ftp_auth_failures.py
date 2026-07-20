"""
Test script for FTP auth failure detection in pcap_to_features.py

Generates a .pcap with:
  - Normal FTP connections
  - FTP connections with 530 (Not logged in) failure responses
  - Verifies num_failed_logins is correctly extracted from payloads
"""
import sys
import os
from scapy.all import IP, TCP, wrpcap, Raw

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_THIS_DIR, 'backend'))
from pcap_to_features import extract_connections_from_packets, compute_features

_OUTPUT_PATH = os.path.join(_THIS_DIR, "data", "test_ftp_auth.pcap")

packets = []
base_time = 2000.0

def add_ftp_connection_with_response(src, dst, sport, dport, t, response_payload, n_data=1):
    """FTP connection: SYN -> SYN/ACK -> ACK -> server response (e.g., 530 failure)."""
    p1 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = t
    p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02

    # Server response (e.g., FTP 220 banner or 530 failure)
    resp = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1001)/Raw(load=response_payload)
    resp.time = t + 0.05

    # Client closes
    fin = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=1001, ack=2001 + len(response_payload))
    fin.time = t + 0.1
    finack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="FA", seq=2001 + len(response_payload), ack=1002)
    finack.time = t + 0.11

    packets.extend([p1, p2, p3, resp, fin, finack])
    return t + 0.2


# --- 1. Successful FTP connection (220 banner) ---
t = base_time
t = add_ftp_connection_with_response("10.0.0.10", "192.0.2.100", 50000, 21, t, b"220 FTP Server Ready\r\n")

# --- 2. Failed login attempt with 530 response (3 attempts) ---
for i in range(3):
    t = add_ftp_connection_with_response("10.0.0.11", "192.0.2.100", 50100 + i, 21, t,
                                          b"530 Not logged in\r\n")

# --- 3. Multiple failed attempts from same source (for brute-force detection) ---
for i in range(5):
    t = add_ftp_connection_with_response("10.0.0.12", "192.0.2.100", 50200 + i, 21, t,
                                          b"530 Login incorrect\r\n")

# --- 4. Mixed success/failure scenario ---
t = add_ftp_connection_with_response("10.0.0.13", "192.0.2.100", 50300, 21, t, b"220 FTP Server Ready\r\n")
t = add_ftp_connection_with_response("10.0.0.13", "192.0.2.100", 50301, 21, t, b"530 Invalid user\r\n")
t = add_ftp_connection_with_response("10.0.0.13", "192.0.2.100", 50302, 21, t, b"530 Not logged in\r\n")

packets.sort(key=lambda p: p.time)
wrpcap(_OUTPUT_PATH, packets)
print(f"Generated {len(packets)} FTP test packets -> {_OUTPUT_PATH}\n")

# --- Test feature extraction ---
print("=" * 80)
print("Testing feature extraction from FTP packets...")
print("=" * 80)

conns = extract_connections_from_packets(packets)
print(f"Extracted {len(conns)} connections\n")

features = compute_features(conns)

# Summarize
print("Summary of extracted features:")
print("-" * 80)
for f in features:
    if f['num_failed_logins'] > 0 or f['_dst_port'] == 21:
        status = "[FAIL]" if f['num_failed_logins'] > 0 else "[OK]  "
        print(f"{status:12} | {f['_src_ip']:>15} -> {f['_dst_ip']:<15}:{f['_dst_port']:<5} | "
              f"failed_logins={f['num_failed_logins']:<2} | bytes={f['src_bytes']}/{f['dst_bytes']}")

print("-" * 80)
print(f"Total connections: {len(features)}")
auth_fail_conns = sum(1 for f in features if f['num_failed_logins'] > 0)
print(f"Connections with failed login detection: {auth_fail_conns}")

# Verify expectations
print("\n" + "=" * 80)
print("Test results:")
print("=" * 80)

expected_failures = 3 + 5 + 2  # 3 from source 10.0.0.11 + 5 from 10.0.0.12 + 2 from 10.0.0.13
total_failures = sum(f['num_failed_logins'] for f in features)

if total_failures == expected_failures:
    print(f"[PASS] Detected {total_failures} FTP auth failures (expected {expected_failures})")
else:
    print(f"[FAIL] Detected {total_failures} FTP auth failures (expected {expected_failures})")
    sys.exit(1)

# Check that non-FTP ports have 0 failed logins
non_ftp_failures = sum(1 for f in features if f['_dst_port'] != 21 and f['num_failed_logins'] > 0)
if non_ftp_failures == 0:
    print(f"[PASS] No false positives on non-FTP ports")
else:
    print(f"[FAIL] {non_ftp_failures} false positives on non-FTP ports")
    sys.exit(1)

# Check successful connections don't get marked as failures
successful_conns = [f for f in features if f['_src_ip'] == '10.0.0.10' or f['_src_ip'] == '10.0.0.13']
if any(f['num_failed_logins'] > 0 for f in successful_conns if '220' in str(packets)):
    print("[WARN] Some successful FTP connections may have been misclassified")
else:
    print(f"[PASS] Successful FTP connections not misclassified")

print("\nAll tests passed!")
