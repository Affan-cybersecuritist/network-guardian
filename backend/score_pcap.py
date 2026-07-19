"""
Feeds pcap-extracted features into the live /analyze API endpoint and
prints the model's risk scores -- proving the full pipeline (raw packets
-> real feature extraction -> trained model -> risk score) works end to end.
"""
import sys
import os
import json
import requests

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.append(_THIS_DIR)
from pcap_to_features import extract_connections, compute_features

API = "http://localhost:8000/analyze"

MODEL_FIELDS = [
    "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count",
    "srv_count", "same_srv_rate", "dst_host_count", "duration", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

pcap_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_PROJECT_ROOT, "data", "test_traffic.pcap")
conns = extract_connections(pcap_path)
rows = compute_features(conns)

payload = []
meta = []
for r in rows:
    payload.append({k: r[k] for k in MODEL_FIELDS if k in r})
    meta.append((r["_src_ip"], r["_dst_ip"], r["_dst_port"]))

resp = requests.post(API, json=payload, timeout=30)
resp.raise_for_status()
results = resp.json()["results"]

print(f"{'SRC':>15} -> {'DST':<15}:{'PORT':<6} {'RISK':>6}  {'FLAGGED':<8} REASONS")
print("-" * 100)
for (src, dst, port), r in zip(meta, results):
    marker = "\033[91m*ATTACK*\033[0m" if r["flagged"] else ""
    print(f"{src:>15} -> {dst:<15}:{port:<6} {r['risk_score']:>6.1f}  {str(r['flagged']):<8} {', '.join(r['reasons'])} {marker}")

# Summary
n_flagged = sum(1 for r in results if r["flagged"])
print(f"\n{n_flagged}/{len(results)} connections flagged as anomalous")
