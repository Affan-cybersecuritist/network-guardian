# Network Guardian — AI-Powered Intrusion Detection

**[Live demo →](https://network-guardian-2.onrender.com/)**
*(free-tier hosting — sleeps after 15 min idle, first load after that takes ~30-50s to wake up)*


An anomaly-based network intrusion detector that flags compromised systems **without relying only on known Indicators of Compromise (IoCs)** — built in response to a real Smart India Hackathon-style problem statement from India's National Technical Research Organisation (NTRO).

## Why this approach matters

Traditional intrusion detection matches traffic against known attack signatures (IoCs). That means it's blind to anything new. This project instead:

1. Trains an **Isolation Forest** model exclusively on *normal* traffic behavior.
2. Flags anything that statistically deviates from that learned baseline as anomalous — regardless of whether it matches a known attack signature.

## Results (on NSL-KDD held-out test set)

| Metric | Score |
|---|---|
| ROC-AUC | **0.943** |
| Precision (attack class) | **97.5%** |
| Recall (attack class) | 67.3% |
| **Detection rate on completely unseen attack types** | **71.2%** |

That last number is the key result: it proves the model generalizes to attack patterns it never saw during training — the entire point of the problem statement.

The model now also uses an engineered `auth_bruteforce_score` feature (repeated connection
attempts to an auth-service port — ftp/ssh/telnet — from the same source within a short
window) to catch throttled password-guessing attacks that the pure flow-based model used
to miss. See "Catching brute-force attacks" below.

## Project structure

```
network-guardian/
├── data/                   # NSL-KDD dataset (train/test)
├── notebooks/
│   ├── data_prep.py        # Loading, cleaning, encoding, scaling
│   └── train_model.py      # Trains Isolation Forest + evaluates + saves model
├── models/                 # Saved model + preprocessing artifacts (generated)
├── backend/
│   ├── main.py              # FastAPI: predictions, pcap upload, live capture control + WebSocket
│   ├── pcap_to_features.py  # pcap/live packets -> NSL-KDD-style features (+ brute-force feature)
│   └── live_capture.py      # Real-time interface sniffing (scapy AsyncSniffer) + rolling scoring
├── frontend/
│   ├── index.html          # Dashboard UI
│   ├── styles.css
│   └── app.js               # Fetches from API, drives live visualizations
└── README.md
```

## Running it locally (the easy way)

One process serves both the API and the dashboard — `backend/main.py` mounts `frontend/`
as static files, so there's a single port and no CORS to think about.

**If you're on Windows**, use the `.bat` files (double-click them, or run from Command Prompt):
```
start.bat     <- installs deps, trains the model if needed, starts the server, opens the browser
test.bat      <- checks everything is working
stop.bat      <- stops the server
```

**If you're on Mac or Linux**, use the `.sh` files from a terminal:
```bash
./start.sh    # installs deps + trains model first time, then launches the server
```
Then open **http://localhost:8000** in your browser. That's it — the dashboard is your test. Watch the live feed, click rows to see why things get flagged, or use the "Analyze Real Traffic" upload button.

When you're done:
```bash
./stop.sh     # stops the server cleanly
```

Any time you want to double-check everything still works without opening the dashboard (e.g. after changing code), run this in a **second terminal** while the server is still running in the first:
```bash
./test.sh     # checks the API, prints model accuracy, and scores a real test capture
```

You'll never need to type the commands below unless something breaks and you want to debug manually — `start.sh`/`start.bat` already does all of it for you.

<details>
<summary>Manual step-by-step (only needed for debugging)</summary>

```bash
pip install -r requirements.txt
python notebooks/train_model.py
uvicorn backend.main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```
</details>

## Deploying your own copy for free

The whole app is one Docker container (`Dockerfile` at the repo root) — API and
dashboard together, no separate frontend host needed.

**Render.com** (free Web Service tier, no credit card):
1. New → Web Service → connect your GitHub repo → Environment = **Docker**.
2. Instance type = **Free**. Nothing else to configure — Render injects `$PORT` and the `Dockerfile` picks it up automatically.

(Hugging Face Spaces looks like a natural fit for an ML demo like this, but as of
this writing Docker-based Spaces require a paid PRO plan — only their zero-backend
"Static" SDK is free, which can't run this app. Render's free tier is the one
that's actually free.)

The free tier sleeps after ~15 minutes of inactivity and wakes on the next visit
(expect a ~30-50s cold start on the first request after idling).

### What won't work on a cloud deployment (by design, not a bug)

**Live packet capture** and **firewall blocking** need a real, addressable network
interface and OS-level privileges (Npcap + Administrator on Windows) that no
container on a shared cloud host has or should have. Everything else —
model metrics, SHAP explainability, pcap upload/analysis, the WAF/threat-intel/
brute-force detection layers, and the one-click "Simulate an attack" demo — runs
identically in the cloud, since those only need the uploaded/canned packet data,
not a live NIC. This mirrors real-world IDS deployment: sensors run on the
network they're protecting, not on a random cloud VM.

## Live packet capture (real-time, not just uploaded files)

The "01 / Live Packet Capture" section on the dashboard sniffs an actual network
interface continuously, groups packets into connections in a rolling window, and
streams scored results to the dashboard over a WebSocket (`/ws/live`) as they happen
— no polling, no pre-recorded file.

**Requirements (Windows):**
1. Install [Npcap](https://npcap.com/#download) (check "WinPcap API-compatible mode").
2. Run the backend (`uvicorn`/`start.bat`) **as Administrator** — raw packet capture needs elevated privileges.

Pick an interface from the dropdown and click **Start Live Capture**. If it fails, the
status line will say why (almost always missing Npcap or missing admin rights).

Under the hood: `backend/live_capture.py` runs a `scapy.AsyncSniffer` in a background
thread, keeps the last 65 seconds of packets, and every 3 seconds re-extracts and scores
newly-completed connections using the exact same feature pipeline as pcap uploads
(`backend/pcap_to_features.py`) — so live traffic and uploaded captures are scored
identically.

## Catching brute-force attacks (auth_bruteforce_score)

Password-guessing tools throttle themselves to avoid the classic "too many connections
too fast" detection — often just 1 attempt every couple of seconds. That's exactly why
the existing `count`/`srv_count` features (2-second window) miss them.

To catch this, both the live-capture and pcap-upload pipelines now track, per source IP,
how many connection attempts hit the same auth-service port (ftp/21, ssh/22, telnet/23)
within a rolling **60-second** window (`AUTH_WINDOW` in `pcap_to_features.py`). That count
becomes the `auth_bruteforce_score` feature:

- The Isolation Forest was retrained with this feature (NSL-KDD has no raw per-source
  timestamps, so training data uses a documented proxy — see the comment in
  `notebooks/data_prep.py`).
- Independently of the model's own verdict, `backend/main.py` force-flags any connection
  with `auth_bruteforce_score >= 15` and explains why in the "reasons" shown when you
  click a row — the same layered approach real security tools use (rules on top of ML).

`notebooks/generate_test_pcap.py` includes a synthetic SSH brute-force scenario (20
throttled login attempts from one source) you can regenerate and test against with
`python notebooks/generate_test_pcap.py` followed by uploading `data/test_traffic.pcap`.

## Analyzing real captured traffic (not just the sample dataset)

This is the part that makes the project genuinely work on "outside data," not just the static NSL-KDD test set.

**Easiest way:** open the dashboard (`./start.sh`, then `http://localhost:8000`) and click **"Upload Capture"** in the "Analyze Real Traffic" section. Pick any `.pcap`/`.pcapng` file.

You can capture your own traffic with `tcpdump -w capture.pcap` or Wireshark.

**Don't have a real capture handy?** `./test.sh` already generates and scores a synthetic one for you automatically (normal HTTPS/HTTP sessions + a real port scan + a real SYN flood) — no extra steps needed.

### The honest limitation (read this before demoing to anyone technical)

NSL-KDD's 41 features split into two groups:

| Feature type | Examples | Computable from real traffic? |
|---|---|---|
| **Flow features** | protocol, bytes, duration, connection counts, error rates | **Yes** — `backend/pcap_to_features.py` computes these for real from captured packets, using the same 2-second sliding-window methodology as the original dataset |
| **Content/host features** | `num_failed_logins`, `root_shell`, `num_compromised`, `num_file_creations` | **No** — these need deep packet payload inspection and host-level audit logs (e.g. did this session get root access). No network-flow tool can derive these from traffic metadata alone. They default to 0, and the API discloses this in every `/analyze-pcap` response. |

This isn't a shortcut specific to this project — it's a well-documented, known constraint of every flow-based IDS built on KDD-style features. Say this plainly if you present this project; it's far more credible than claiming full feature parity with the original dataset.

## What's simulated vs. real (summary)

- **The model, its accuracy numbers, and the pcap/live feature extraction are all 100% real.**
- The `/sample-traffic` feed used by "02 / Live Traffic Pulse" **simulates** real-time monitoring by sampling from held-out NSL-KDD test data (clearly disclosed in the UI).
- The `/analyze-pcap` endpoint and the "01 / Live Packet Capture" section both run on **actual packets** — captured live or uploaded — this is the real "outside data" pathway.
- Content/host features in pcap- and live-derived rows are 0 by design (see table above) — disclosed via the `note` field in the API response and in the dashboard UI.

## Beyond the core model

A few layers now sit on top of the Isolation Forest, all visible in the dashboard header:

- **SHAP** (`shap.TreeExplainer`) — per-connection feature attribution, so every flag comes with *which* features drove it, not just a score.
- **WAF engine** (`backend/waf_engine.py`) — inspects HTTP request content for injection/XSS-style payloads independently of the flow-based model.
- **Threat intel lookup** — checks source IPs against AbuseIPDB reputation data.
- **Auto-response engine** (`backend/response_engine.py`) — policy-driven simulated response actions on high-risk detections.
- **SQLite persistence** (`backend/db.py`) — alert history and live-capture results survive restarts and page reloads, not just in-memory.

## Next steps to extend this

- Swap Isolation Forest for an autoencoder to compare performance
- Add authentication + role-based access if deploying beyond a demo
- Real firewall auto-blocking currently requires local Windows Administrator — a Linux/iptables equivalent would let it run unattended on a real network sensor
