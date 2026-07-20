"""
Integration test: verifies FTP auth failure detection works alongside existing features
(auth_bruteforce_score for SSH, port scanning, etc.)
"""
import sys
import os
from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Raw

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_THIS_DIR, 'backend'))
from pcap_to_features import extract_connections_from_packets, compute_features

_OUTPUT_PATH = os.path.join(_THIS_DIR, "data", "test_integration.pcap")

packets = []
base_time = 3000.0

def add_normal_handshake(src, dst, sport, dport, t, n_data=3):
    """Normal completed connection."""
    p1 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = t
    p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02
    packets.extend([p1, p2, p3])

    cur_t = t + 0.03
    seq, ack = 1001, 2001
    for i in range(n_data):
        d = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)/("X" * 300)
        d.time = cur_t
        packets.append(d)
        seq += 300
        cur_t += 0.05
        r = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq)/("Y" * 150)
        r.time = cur_t
        packets.append(r)
        ack += 150
        cur_t += 0.05

    fin = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ack)
    fin.time = cur_t
    finack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=seq+1)
    finack.time = cur_t + 0.01
    packets.extend([fin, finack])
    return cur_t + 0.02

def add_ftp_with_response(src, dst, sport, dport, t, response):
    """FTP connection with server response."""
    p1 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = t
    p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02
    resp = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="PA", seq=2001, ack=1001)/Raw(load=response)
    resp.time = t + 0.05
    fin = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=1001, ack=2001 + len(response))
    fin.time = t + 0.1
    finack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="FA", seq=2001 + len(response), ack=1002)
    finack.time = t + 0.11
    packets.extend([p1, p2, p3, resp, fin, finack])
    return t + 0.2

def add_syn_only(src, dst, sport, dport, t):
    """Port scan attempt (no reply)."""
    p = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=5000)
    p.time = t
    packets.append(p)

def add_brute_force_ssh(src, dst, sport, dport, t, count=15):
    """SSH brute-force attempts (throttled)."""
    for i in range(count):
        p1 = IP(src=src, dst=dst)/TCP(sport=sport+i, dport=dport, flags="S", seq=1000+i*100)
        p1.time = t
        p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport+i, flags="SA", seq=2000+i*100, ack=1001+i*100)
        p2.time = t + 0.01
        p3 = IP(src=src, dst=dst)/TCP(sport=sport+i, dport=dport, flags="A", seq=1001+i*100, ack=2001+i*100)
        p3.time = t + 0.02
        rst = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport+i, flags="RA", seq=2001+i*100, ack=1001+i*100)
        rst.time = t + 0.15
        packets.extend([p1, p2, p3, rst])
        t += 2.1
    return t

# === 1. Normal traffic (HTTP/HTTPS) ===
t = base_time
for i in range(3):
    t = add_normal_handshake("10.0.0.5", "93.184.216.34", 40000+i, 443, t)
    t += 0.5

# === 2. Successful FTP connection ===
t = add_ftp_with_response("10.0.0.20", "192.0.2.100", 50000, 21, t, b"220 FTP Server Ready\r\n")

# === 3. FTP auth failures (multiple sources) ===
for i in range(4):
    t = add_ftp_with_response("10.0.0.21", "192.0.2.100", 50100+i, 21, t, b"530 Not logged in\r\n")

for i in range(3):
    t = add_ftp_with_response("10.0.0.22", "192.0.2.100", 50200+i, 21, t, b"530 Login incorrect\r\n")

# === 4. Port scan ===
t += 0.5
scan_start = t
for port in range(1, 15):
    add_syn_only("10.0.0.99", "192.0.2.50", 55000, port, scan_start)
    scan_start += 0.01
t = scan_start + 0.2

# === 5. SSH brute-force ===
t = add_brute_force_ssh("203.0.113.66", "192.0.2.88", 50000, 22, t, count=12)

packets.sort(key=lambda p: p.time)
wrpcap(_OUTPUT_PATH, packets)
print(f"Generated {len(packets)} test packets -> {_OUTPUT_PATH}\n")

# === Test extraction ===
print("=" * 90)
print("INTEGRATION TEST: Feature Extraction")
print("=" * 90)

conns = extract_connections_from_packets(packets)
features = compute_features(conns)

print(f"Total connections: {len(features)}\n")

# Summary stats
ftp_success = sum(1 for f in features if f['_dst_port'] == 21 and f['num_failed_logins'] == 0)
ftp_failures = sum(1 for f in features if f['_dst_port'] == 21 and f['num_failed_logins'] > 0)
ssh_bruteforce = sum(1 for f in features if f['_dst_port'] == 22 and f['auth_bruteforce_score'] >= 5)
port_scans = sum(1 for f in features if f['flag'] == 'S0')

print(f"Detection Summary:")
print(f"  - Successful FTP connections: {ftp_success}")
print(f"  - FTP auth failures: {ftp_failures} (expected 7)")
print(f"  - SSH brute-force attempts: {ssh_bruteforce}")
print(f"  - Port scans (S0 flag): {port_scans}")

print("\nDetailed results:")
print("-" * 90)

for f in features:
    flags = []
    if f['_dst_port'] == 21 and f['num_failed_logins'] > 0:
        flags.append(f"FTP-FAIL({f['num_failed_logins']})")
    if f['auth_bruteforce_score'] >= 5:
        flags.append(f"SSH-BF({f['auth_bruteforce_score']:.0f})")
    if f['flag'] == 'S0':
        flags.append("SCAN")

    if flags:
        flag_str = ", ".join(flags)
        print(f"[{flag_str:20}] {f['_src_ip']:>15} -> {f['_dst_ip']:<15}:{f['_dst_port']:<5} "
              f"flag={f['flag']:<3} bytes={f['src_bytes']}/{f['dst_bytes']}")

print("-" * 90)

# Verify results
print("\n" + "=" * 90)
print("TEST RESULTS")
print("=" * 90)

errors = []

if ftp_success != 1:
    errors.append(f"Successful FTP connections: {ftp_success} (expected 1)")
if ftp_failures != 7:
    errors.append(f"FTP auth failures: {ftp_failures} (expected 7)")
if ssh_bruteforce < 1:
    errors.append(f"SSH brute-force detection: {ssh_bruteforce} (expected > 0)")
if port_scans < 1:
    errors.append(f"Port scan detection: {port_scans} (expected > 0)")

if errors:
    print("[FAIL] Some checks failed:")
    for err in errors:
        print(f"  - {err}")
    sys.exit(1)
else:
    print("[PASS] All integration tests passed!")
    print("  - FTP auth failures detected correctly")
    print("  - SSH brute-force detection still working")
    print("  - Port scan detection still working")
    print("  - New and old features coexist without conflicts")
