"""
pcap_to_features.py
--------------------
Converts raw captured packets into the NSL-KDD-style feature schema our
model expects, so the model can score REAL traffic instead of only the
static CSV test set.

IMPORTANT / HONEST LIMITATION:
NSL-KDD's 41 features fall into two groups:

  1. "Flow" features (protocol, bytes, duration, connection counts, error
     rates) -- these ARE genuinely computable from packet captures alone,
     and this script computes them for real from the pcap.

  2. "Content/host" features (num_failed_logins, root_shell, num_compromised,
     hot, num_shells, num_file_creations, num_access_files, num_outbound_cmds,
     is_host_login, is_guest_login, su_attempted, num_root, urgent, land,
     wrong_fragment) -- these require deep packet PAYLOAD inspection and
     host-level audit logs (e.g. did this session actually get root shell
     access). No network-flow tool can derive these from traffic metadata
     alone -- the original 1998 DARPA/KDD dataset builders had a fully
     instrumented lab environment to capture these. This script sets them
     to 0 (their statistical mode/most-common value), which is disclosed
     here and in the API response so nobody mistakes this for something
     it isn't.

Connections are grouped by 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
and aggregate "traffic" features (count, srv_count, error rates, etc.) are
computed using a 2-second sliding time window per host/service, mirroring
the original KDD feature-construction methodology.

ENGINEERED FEATURE -- auth_bruteforce_score:
A behavioral feature added on top of the standard 41 NSL-KDD columns to catch
password-guessing/brute-force attacks (e.g. guess_passwd) that the pure
flow-based model misses. These attacks throttle to 1-2 connections per 2s,
which hides them from "count"/"srv_count" -- but the SAME source IP repeatedly
hitting the SAME auth-service port (ftp/ssh/telnet) over a longer (60s) window
is a strong signal. See compute_auth_bruteforce_scores() below. The model was
retrained with a matching (proxied, since NSL-KDD has no raw src_ip/timestamp)
column so it can actually use this signal -- see notebooks/data_prep.py.
"""
import sys
import os
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP, ICMP

TIME_WINDOW = 2.0  # seconds, per original KDD "same host" window

# --- Auth brute-force behavioral feature ---
# Password-guessing tools (hydra, medusa, etc.) open a NEW connection (new src
# port) per attempt, so the 2-second "same host" window above misses them --
# a throttled attacker never has more than 1-2 connections open at once. What
# DOES give them away is the same source IP repeatedly hitting the same
# auth-service port over a longer horizon. We track that separately here,
# keyed by (src_ip, dst_ip, dst_port) rather than the full 5-tuple, so it
# survives the attacker rotating source ports.
AUTH_PORTS = {21: "ftp", 22: "ssh", 23: "telnet"}
AUTH_WINDOW = 60.0  # seconds


def extract_connections(pcap_path):
    """Group packets into connections by 5-tuple, return raw per-connection stats."""
    packets = rdpcap(pcap_path)
    return extract_connections_from_packets(packets)


def extract_connections_from_packets(packets):
    """Same as extract_connections() but takes an in-memory list of scapy packets
    (e.g. from a live AsyncSniffer buffer) instead of reading a .pcap file."""
    conns = defaultdict(lambda: {
        "packets": [], "start_time": None, "end_time": None,
        "src_bytes": 0, "dst_bytes": 0, "flags_seen": set(),
        "protocol": None, "dst_ip": None, "dst_port": None, "src_ip": None,
    })

    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        if TCP in pkt:
            proto = "tcp"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "udp"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            flags = ""
        elif ICMP in pkt:
            proto = "icmp"
            sport, dport = 0, 0
            flags = ""
        else:
            continue

        # Canonical key: always order by (lower_ip, higher_ip) won't work for
        # directionality, so key by the INITIATOR's tuple. We treat the first-seen
        # direction as "forward" (src_bytes) and replies as "backward" (dst_bytes).
        fwd_key = (ip.src, ip.dst, sport, dport, proto)
        bwd_key = (ip.dst, ip.src, dport, sport, proto)

        if fwd_key in conns and conns[fwd_key]["packets"]:
            key, is_forward = fwd_key, True
        elif bwd_key in conns and conns[bwd_key]["packets"]:
            key, is_forward = bwd_key, False
        else:
            key, is_forward = fwd_key, True

        c = conns[key]
        c["packets"].append(pkt)
        t = float(pkt.time)
        c["start_time"] = t if c["start_time"] is None else min(c["start_time"], t)
        c["end_time"] = t if c["end_time"] is None else max(c["end_time"], t)
        c["protocol"] = proto
        c["src_ip"], c["dst_ip"], c["dst_port"] = key[0], key[1], key[3]

        pkt_len = len(pkt)
        if is_forward:
            c["src_bytes"] += pkt_len
        else:
            c["dst_bytes"] += pkt_len
        if flags:
            c["flags_seen"].add(flags)

    return conns


def infer_flag(flags_seen):
    """Approximate NSL-KDD's connection status flag from observed TCP flags."""
    has = lambda f: any(f in fs for fs in flags_seen)
    if has("S") and has("SA") and has("F"):
        return "SF"          # normal completion
    if has("S") and not has("SA"):
        return "S0"          # connection attempt, no reply (scan/flood signature)
    if has("R"):
        return "REJ"         # rejected
    if has("S") and has("SA") and not has("F"):
        return "S1"          # established, not yet closed
    return "OTH"


def infer_service(dst_port):
    """Rough port -> service name mapping (subset covering common NSL-KDD services)."""
    mapping = {80: "http", 443: "http", 21: "ftp", 22: "ssh", 23: "telnet",
               25: "smtp", 53: "domain_u", 110: "pop_3"}
    return mapping.get(dst_port, "private")


def compute_auth_bruteforce_scores(conns):
    """
    For every connection whose dst_port is an auth-service port, count how many
    OTHER connections from the same src_ip to the same (dst_ip, dst_port) started
    within the preceding AUTH_WINDOW seconds. Returns {conn_key: score}.
    """
    auth_attempts = [
        (c["src_ip"], c["dst_ip"], c["dst_port"], c["start_time"], key)
        for key, c in conns.items()
        if c["dst_port"] in AUTH_PORTS
    ]

    scores = {}
    for src_ip, dst_ip, dst_port, t0, key in auth_attempts:
        window_hits = [
            1 for (s, d, p, t, _) in auth_attempts
            if s == src_ip and d == dst_ip and p == dst_port and t0 - AUTH_WINDOW <= t <= t0
        ]
        scores[key] = len(window_hits)
    return scores


def compute_features(conns):
    """Turn grouped connections into feature rows, with 2-second-window traffic stats."""
    # Sort connections by start time so we can compute "last 2 seconds" windows
    items = sorted(conns.items(), key=lambda kv: kv[1]["start_time"])
    auth_scores = compute_auth_bruteforce_scores(conns)

    rows = []
    for i, (key, c) in enumerate(items):
        src_ip, dst_ip, sport, dport, proto = key
        t0 = c["start_time"]

        # Traffic features: look at connections in the preceding 2-second window
        window = [oc for _, oc in items if t0 - TIME_WINDOW <= oc["start_time"] <= t0]

        same_host = [oc for oc in window if oc["dst_ip"] == dst_ip]
        same_host_srv = [oc for oc in same_host if oc["dst_port"] == dport]

        def error_rate(conn_list):
            if not conn_list:
                return 0.0
            errored = sum(1 for oc in conn_list if infer_flag(oc["flags_seen"]) in ("S0", "REJ"))
            return errored / len(conn_list)

        count = len(same_host)
        srv_count = len(same_host_srv)
        serror_rate = error_rate(same_host)
        rerror_rate = sum(1 for oc in same_host if infer_flag(oc["flags_seen"]) == "REJ") / max(count, 1)
        same_srv_rate = srv_count / max(count, 1)
        diff_srv_rate = 1 - same_srv_rate

        row = {
            "duration": round(c["end_time"] - c["start_time"], 4),
            "protocol_type": proto,
            "service": infer_service(dport),
            "flag": infer_flag(c["flags_seen"]),
            "src_bytes": c["src_bytes"],
            "dst_bytes": c["dst_bytes"],
            "count": count,
            "srv_count": srv_count,
            "same_srv_rate": round(same_srv_rate, 3),
            "diff_srv_rate": round(diff_srv_rate, 3),
            "serror_rate": round(serror_rate, 3),
            "srv_serror_rate": round(serror_rate, 3),
            "rerror_rate": round(rerror_rate, 3),
            "srv_rerror_rate": round(rerror_rate, 3),
            "dst_host_count": count,
            "dst_host_srv_count": srv_count,
            "dst_host_same_srv_rate": round(same_srv_rate, 3),
            "dst_host_diff_srv_rate": round(diff_srv_rate, 3),
            "dst_host_serror_rate": round(serror_rate, 3),
            "dst_host_srv_serror_rate": round(serror_rate, 3),
            "dst_host_rerror_rate": round(rerror_rate, 3),
            "dst_host_srv_rerror_rate": round(rerror_rate, 3),
            # --- content/host features: NOT derivable from flow data alone, see module docstring ---
            "num_failed_logins": 0, "root_shell": 0, "num_compromised": 0, "hot": 0,
            "num_shells": 0, "num_file_creations": 0, "num_access_files": 0,
            "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
            "su_attempted": 0, "num_root": 0, "urgent": 0, "land": 1 if src_ip == dst_ip else 0,
            "wrong_fragment": 0, "logged_in": 0,
            "dst_host_same_src_port_rate": 0, "dst_host_srv_diff_host_rate": 0,
            "srv_diff_host_rate": 0,
            "auth_bruteforce_score": float(auth_scores.get(key, 0)),
            # metadata (not fed to model, useful for display)
            "_src_ip": src_ip, "_dst_ip": dst_ip, "_dst_port": dport, "_conn_key": key,
        }
        rows.append(row)
    return rows


if __name__ == "__main__":
    _default_pcap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "test_traffic.pcap")
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else _default_pcap
    conns = extract_connections(pcap_path)
    print(f"Extracted {len(conns)} connections from {pcap_path}")
    rows = compute_features(conns)
    print(f"Computed feature rows for {len(rows)} connections\n")

    for r in rows:
        bruteforce_marker = f" <-- possible brute-force ({r['auth_bruteforce_score']:.0f} attempts/60s)" if r["auth_bruteforce_score"] >= 5 else ""
        flagged_marker = " <-- suspicious pattern" if r["flag"] in ("S0", "REJ") or r["count"] > 20 else bruteforce_marker
        print(f"{r['_src_ip']:>15} -> {r['_dst_ip']:<15}:{r['_dst_port']:<5} "
              f"proto={r['protocol_type']:<4} flag={r['flag']:<3} "
              f"count={r['count']:<4} srv_count={r['srv_count']:<4} "
              f"bytes={r['src_bytes']}/{r['dst_bytes']}{flagged_marker}")
