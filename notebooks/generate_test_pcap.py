"""
Generates a test .pcap containing:
  - Normal-looking HTTP/HTTPS connections (completed handshakes, reasonable byte counts)
  - A SYN port-scan against one host (many ports, no completed handshakes) -- classic 'satan'/'ipsweep'-style behavior
  - A SYN flood against one port (many SYNs, no ACKs) -- classic 'neptune'-style behavior
  - An SSH password brute-force: one source repeatedly opening short-lived
    connections to port 22 on one victim, throttled to ~1 attempt every 2s so
    it's invisible to the 2-second "count"/"srv_count" window but still catches
    the auth_bruteforce_score behavioral feature (see backend/pcap_to_features.py)

This exists purely so we can prove the pcap -> feature -> model pipeline works on
ACTUAL PACKET DATA, not just the static NSL-KDD CSV rows.
"""
from scapy.all import IP, TCP, wrpcap
import random
import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
_OUTPUT_PATH = os.path.join(_PROJECT_ROOT, "data", "test_traffic.pcap")

packets = []
base_time = 1000.0

def add_completed_handshake(src, dst, sport, dport, t, n_data_packets=4, bytes_per_pkt=400):
    """SYN -> SYN/ACK -> ACK -> some data -> FIN (a normal, successful connection)."""
    p1 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = t
    p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02
    packets.extend([p1, p2, p3])
    cur_t = t + 0.03
    seq, ack = 1001, 2001
    for i in range(n_data_packets):
        d = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)/("X" * bytes_per_pkt)
        d.time = cur_t
        packets.append(d)
        seq += bytes_per_pkt
        cur_t += 0.05
        r = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="A", seq=ack, ack=seq)/("Y" * (bytes_per_pkt // 2))
        r.time = cur_t
        packets.append(r)
        ack += bytes_per_pkt // 2
        cur_t += 0.05
    fin = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA", seq=seq, ack=ack)
    fin.time = cur_t
    finack = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="FA", seq=ack, ack=seq+1)
    finack.time = cur_t + 0.01
    packets.extend([fin, finack])
    return cur_t + 0.02


def add_failed_login_attempt(src, dst, sport, dport, t):
    """SYN -> SYN/ACK -> ACK -> immediate RST (connects, auth fails, resets --
    a single password-guess attempt against ssh/telnet/ftp)."""
    p1 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000)
    p1.time = t
    p2 = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001)
    p2.time = t + 0.01
    p3 = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
    p3.time = t + 0.02
    rst = IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="RA", seq=2001, ack=1001)
    rst.time = t + 0.15
    packets.extend([p1, p2, p3, rst])


def add_syn_only(src, dst, sport, dport, t):
    """Just a SYN with no reply -- looks like a probe/scan against a closed or filtered port."""
    p = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1000, 9000))
    p.time = t
    packets.append(p)


# --- 1. Normal traffic: a handful of legit-looking web sessions ---
t = base_time
for i in range(6):
    t = add_completed_handshake("10.0.0.5", "93.184.216.34", 40000 + i, 443, t, n_data_packets=5, bytes_per_pkt=500)
    t += 0.5

for i in range(4):
    t = add_completed_handshake("10.0.0.5", "192.0.2.10", 41000 + i, 80, t, n_data_packets=3, bytes_per_pkt=300)
    t += 0.3

# --- 2. Port scan: single source rapidly hitting many ports on one target, no completed handshakes ---
scan_start = t
for port in range(1, 60):
    add_syn_only("10.0.0.99", "192.0.2.50", 55000, port, scan_start)
    scan_start += 0.01  # very fast, sequential ports = classic scan signature
t = scan_start + 0.2

# --- 3. SYN flood: many SYNs at one victim port from spoofed-looking varying source ports, no replies ---
flood_start = t
for i in range(80):
    add_syn_only(f"10.0.0.{100 + (i % 20)}", "192.0.2.77", 60000 + i, 80, flood_start)
    flood_start += 0.005
t = flood_start

# --- 4. SSH brute-force: throttled to one attempt every ~2.2s (past the 2s
# window) but 20 attempts land inside the 60s auth_bruteforce_score window ---
bf_start = t
for i in range(20):
    add_failed_login_attempt("203.0.113.66", "192.0.2.88", 50000 + i, 22, bf_start)
    bf_start += 2.2
t = bf_start

packets.sort(key=lambda p: p.time)
wrpcap(_OUTPUT_PATH, packets)
print(f"Generated {len(packets)} packets -> data/test_traffic.pcap")
print(f"Time span: {packets[0].time:.2f}s to {packets[-1].time:.2f}s")
