# Network Guardian — AI-Powered Intrusion Detection

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

**If you're on Windows**, use the `.bat` files (double-click them, or run from Command Prompt):
```
start.bat     <- starts everything (two new windows will open, keep them open)
test.bat      <- checks everything is working
stop.bat      <- stops both servers
```

**If you're on Mac or Linux**, use the `.sh` files from a terminal:
```bash
./start.sh    # starts everything (installs deps + trains model first time, then launches both servers)
```
Then open **http://localhost:8080** in your browser. That's it — the dashboard is your test. Watch the live feed, click rows to see why things get flagged, or use the "Analyze Real Traffic" upload button.

When you're done:
```bash
./stop.sh     # stops both servers cleanly
```

Any time you want to double-check everything still works without opening the dashboard (e.g. after changing code), run this in a **second terminal** while `start.sh` is still running in the first:
```bash
./test.sh     # checks the API, prints model accuracy, and scores a real test capture
```

You'll never need to type the long multi-line commands below unless something breaks and you want to debug manually — `start.sh`/`start.bat` already does all of it for you.

<details>
<summary>Manual step-by-step (only needed for debugging)</summary>

```bash
pip install pandas numpy scikit-learn joblib fastapi uvicorn websockets python-multipart scapy requests shap
python notebooks/train_model.py
uvicorn backend.main:app --host 0.0.0.0 --port 8000   # terminal 1
cd frontend && python -m http.server 8080              # terminal 2
```
</details>

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

**Easiest way:** open the dashboard (`./start.sh`, then `http://localhost:8080`) and click **"Upload Capture"** in the "Analyze Real Traffic" section. Pick any `.pcap`/`.pcapng` file.

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

## Next steps to extend this

- Swap Isolation Forest for an autoencoder to compare performance
- Add SHAP-based explainability instead of the current rule-based "reasons"
- Persist live-captured connections (currently in-memory only) for later review
- Add authentication + role-based access if deploying beyond a demo
