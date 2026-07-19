"""
Network Guardian API
---------------------
Serves the Isolation Forest anomaly detector. Exposes:
  - GET  /health
  - GET  /metrics            -> model performance stats (for the dashboard header)
  - GET  /sample-traffic     -> pulls N random rows from the test set (simulates a live feed)
  - POST /analyze            -> scores a batch of traffic rows, returns risk + explanation
"""
import sys
import os
import uuid
import random
import asyncio
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
NOTEBOOKS_DIR = os.path.join(PROJECT_ROOT, "notebooks")

sys.path.append(NOTEBOOKS_DIR)
sys.path.append(BACKEND_DIR)
from data_prep import load_raw, transform
from pcap_to_features import extract_connections, compute_features
from live_capture import LiveCapture, list_interfaces

MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

app = FastAPI(title="Network Guardian API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Load model + preprocessing artifacts once at startup ---
model = joblib.load(f"{MODEL_DIR}/isolation_forest.joblib")
encoders = joblib.load(f"{MODEL_DIR}/encoders.joblib")
scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")
feature_cols = joblib.load(f"{MODEL_DIR}/feature_cols.joblib")
numeric_cols = joblib.load(f"{MODEL_DIR}/numeric_cols.joblib")
metrics = joblib.load(f"{MODEL_DIR}/metrics.joblib")

test_df = load_raw(f"{DATA_DIR}/KDDTest.txt")
# Pre-transform full test set once so we can slice quickly per request
X_test_full, _ = transform(test_df, encoders, numeric_cols, scaler, fit_scaler=False)

RAW_DISPLAY_COLS = [
    "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "count", "srv_count", "same_srv_rate", "dst_host_count", "label",
]


class TrafficRow(BaseModel):
    protocol_type: str
    service: str
    flag: str
    src_bytes: float = Field(ge=0, le=1e10, description="Bytes sent, must be non-negative")
    dst_bytes: float = Field(ge=0, le=1e10, description="Bytes received, must be non-negative")
    count: float = Field(ge=0, le=100000)
    srv_count: float = Field(ge=0, le=100000)
    same_srv_rate: float = Field(ge=0, le=1, description="Rate fields must be between 0 and 1")
    dst_host_count: float = Field(ge=0, le=100000)
    # remaining features default to 0 if not provided by a simplified UI form
    duration: float = Field(default=0, ge=0)
    land: float = Field(default=0, ge=0, le=1)
    wrong_fragment: float = Field(default=0, ge=0)
    urgent: float = Field(default=0, ge=0)
    hot: float = Field(default=0, ge=0)
    num_failed_logins: float = Field(default=0, ge=0)
    logged_in: float = Field(default=0, ge=0, le=1)
    num_compromised: float = Field(default=0, ge=0)
    root_shell: float = Field(default=0, ge=0, le=1)
    su_attempted: float = Field(default=0, ge=0)
    num_root: float = Field(default=0, ge=0)
    num_file_creations: float = Field(default=0, ge=0)
    num_shells: float = Field(default=0, ge=0)
    num_access_files: float = Field(default=0, ge=0)
    num_outbound_cmds: float = Field(default=0, ge=0)
    is_host_login: float = Field(default=0, ge=0, le=1)
    is_guest_login: float = Field(default=0, ge=0, le=1)
    serror_rate: float = Field(default=0, ge=0, le=1)
    srv_serror_rate: float = Field(default=0, ge=0, le=1)
    rerror_rate: float = Field(default=0, ge=0, le=1)
    srv_rerror_rate: float = Field(default=0, ge=0, le=1)
    diff_srv_rate: float = Field(default=0, ge=0, le=1)
    srv_diff_host_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_count: float = Field(default=0, ge=0, le=100000)
    dst_host_same_srv_rate: float = Field(default=0, ge=0, le=1)
    dst_host_diff_srv_rate: float = Field(default=0, ge=0, le=1)
    dst_host_same_src_port_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_diff_host_rate: float = Field(default=0, ge=0, le=1)
    dst_host_serror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_serror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_rerror_rate: float = Field(default=0, ge=0, le=1)
    dst_host_srv_rerror_rate: float = Field(default=0, ge=0, le=1)
    auth_bruteforce_score: float = Field(
        default=0, ge=0,
        description="Repeated connection attempts to an auth-service port (ftp/ssh/telnet) "
                    "from the same source within a short window. See backend/pcap_to_features.py.",
    )


# Real-world brute-force bursts (e.g. hydra/medusa against ssh/telnet/ftp) commonly
# produce >=15 connection attempts from one source within the 60s tracking window --
# see AUTH_WINDOW in pcap_to_features.py. The Isolation Forest was retrained with this
# feature and often isolates these on its own, but since it's an unsupervised global
# anomaly score, a clear behavioral signal like this is force-flagged directly too,
# the same way security tools layer rule-based detections on top of ML scores.
AUTH_BRUTEFORCE_THRESHOLD = 15


def score_rows(df: pd.DataFrame):
    X, _ = transform(df, encoders, numeric_cols, scaler, fit_scaler=False)
    raw_score = -model.decision_function(X)  # higher = more anomalous
    is_attack = (model.predict(X) == -1)

    # Normalize anomaly score to a friendly 0-100 "risk score"
    # decision_function roughly in [-0.5, 0.5]; clip + rescale
    risk = np.clip((raw_score + 0.2) / 0.4, 0, 1) * 100

    results = []
    for i in range(len(df)):
        row = df.iloc[i]
        auth_bruteforce_score = float(row.get("auth_bruteforce_score", 0))
        is_bruteforce = bool(auth_bruteforce_score >= AUTH_BRUTEFORCE_THRESHOLD)

        # crude "why flagged" explanation: which numeric features are most
        # extreme relative to training distribution (z-score style via scaler)
        reasons = []
        if is_bruteforce:
            reasons.append(
                f"possible password brute-force: {int(auth_bruteforce_score)} connection "
                f"attempts to an auth-service port (ftp/ssh/telnet) from the same source"
            )
        if row.get("serror_rate", 0) > 0.5:
            reasons.append("high SYN error rate (possible SYN flood/scan)")
        if row.get("count", 0) > 200:
            reasons.append("unusually high connection count in short window")
        if row.get("num_failed_logins", 0) > 0:
            reasons.append("failed login attempts detected")
        if row.get("dst_host_diff_srv_rate", 0) > 0.5:
            reasons.append("connections spread across many services (scan-like behavior)")
        if not reasons:
            reasons.append("statistical deviation from learned normal traffic baseline")

        risk_i = max(float(risk[i]), 70.0) if is_bruteforce else float(risk[i])

        results.append({
            "risk_score": round(risk_i, 1),
            "flagged": bool(is_attack[i]) or is_bruteforce,
            "true_label": row.get("label", None),
            "protocol_type": row.get("protocol_type", None),
            "service": row.get("service", None),
            "flag": row.get("flag", None),
            "src_bytes": float(row.get("src_bytes", 0)),
            "dst_bytes": float(row.get("dst_bytes", 0)),
            "reasons": reasons,
        })
    return results


class LiveBroadcaster:
    """Bridges the background capture thread (sync) to connected WebSocket
    clients (async) using run_coroutine_threadsafe."""

    def __init__(self):
        self.clients: List[WebSocket] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop):
        self.loop = loop

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.clients:
            self.clients.remove(ws)

    async def _broadcast(self, payload):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def on_capture_results(self, feature_rows):
        """Called from the capture's background thread with new raw feature rows."""
        if not self.clients or self.loop is None:
            return
        try:
            results = score_feature_rows(feature_rows)
        except Exception as e:
            results = [{"error": f"{type(e).__name__}: {e}"}]

        asyncio.run_coroutine_threadsafe(
            self._broadcast({"type": "results", "results": results}), self.loop
        )


broadcaster = LiveBroadcaster()
live_capture = LiveCapture(on_results=broadcaster.on_capture_results)


@app.on_event("startup")
async def on_startup():
    broadcaster.set_loop(asyncio.get_event_loop())


@app.on_event("shutdown")
def on_shutdown():
    if live_capture.running:
        live_capture.stop()


def score_feature_rows(feature_rows):
    """Shared by /analyze-pcap and the live capture broadcaster: takes raw rows
    from pcap_to_features.compute_features() (still carrying _src_ip/_dst_ip/
    _dst_port/_conn_key metadata) and returns scored results with that metadata
    merged back in."""
    df = pd.DataFrame(feature_rows)
    df["label"] = "unknown"
    meta = df[["_src_ip", "_dst_ip", "_dst_port"]].to_dict("records")
    df_model = df.drop(columns=["_src_ip", "_dst_ip", "_dst_port", "_conn_key"])
    results = score_rows(df_model)
    for r, m in zip(results, meta):
        r["src_ip"] = m["_src_ip"]
        r["dst_ip"] = m["_dst_ip"]
        r["dst_port"] = m["_dst_port"]
    return results


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/interfaces")
def get_interfaces():
    """List network interfaces available for live capture (requires Npcap on Windows)."""
    try:
        return {"interfaces": list_interfaces()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not list interfaces: {type(e).__name__}: {e}") from e


class LiveStartRequest(BaseModel):
    interface: Optional[str] = None
    bpf_filter: Optional[str] = Field(default=None, description="Optional BPF filter, e.g. 'tcp'")


@app.post("/live/start")
def live_start(req: LiveStartRequest):
    try:
        live_capture.start(interface=req.interface, bpf_filter=req.bpf_filter)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return live_capture.status()


@app.post("/live/stop")
def live_stop():
    live_capture.stop()
    return live_capture.status()


@app.get("/live/status")
def live_status():
    return live_capture.status()


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    """Streams newly-scored connections from the running live capture as they happen."""
    await broadcaster.connect(websocket)
    try:
        while True:
            # We don't expect client messages; just keep the connection open
            # and detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)


@app.get("/metrics")
def get_metrics():
    return metrics


@app.get("/sample-traffic")
def sample_traffic(
    n: int = Query(default=20, ge=1, le=200),
    attack_ratio: float = Query(default=0.3, ge=0.0, le=1.0),
):
    """Simulate a live traffic feed by sampling from the held-out test set."""
    n_attack = int(n * attack_ratio)
    n_normal = n - n_attack

    normal_pool = test_df[test_df["binary_label"] == "normal"]
    attack_pool = test_df[test_df["binary_label"] == "attack"]

    sample = pd.concat([
        normal_pool.sample(min(n_normal, len(normal_pool))),
        attack_pool.sample(min(n_attack, len(attack_pool))),
    ]).sample(frac=1).reset_index(drop=True)  # shuffle

    results = score_rows(sample)
    return {"traffic": results}


@app.post("/analyze")
def analyze(rows: List[TrafficRow]):
    if len(rows) == 0:
        return {"results": []}
    if len(rows) > 500:
        raise HTTPException(status_code=413, detail="Max 500 rows per request. Split into smaller batches.")

    try:
        df = pd.DataFrame([r.model_dump() for r in rows])
        df["label"] = "unknown"
        results = score_rows(df)
    except Exception as e:
        # Don't leak stack traces to the client; log server-side instead.
        raise HTTPException(status_code=500, detail=f"Scoring failed: {type(e).__name__}") from e

    return {"results": results}


@app.post("/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """
    Accepts a real .pcap/.pcapng file, extracts NSL-KDD-style flow features
    from the ACTUAL captured packets, and scores each connection.

    HONEST LIMITATION (also see backend/pcap_to_features.py docstring):
    Only flow-level features (bytes, duration, protocol, connection/error
    rates) are computed from the real packets. Content/host features
    (num_failed_logins, root_shell, etc.) cannot be derived from network
    traffic alone and default to 0 -- this is disclosed per-result below.
    """
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")

    tmp_path = f"/tmp/{uuid.uuid4().hex}.pcap"
    try:
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Max pcap size is 50MB for this demo")
        with open(tmp_path, "wb") as f:
            f.write(content)

        conns = extract_connections(tmp_path)
        if len(conns) == 0:
            return {"results": [], "note": "No TCP/UDP/ICMP connections found in this capture."}

        feature_rows = compute_features(conns)
        results = score_feature_rows(feature_rows)

        return {
            "results": results,
            "note": ("Flow features (bytes, duration, error rates, protocol) computed from "
                     "actual packets. Content/host features (failed logins, root shell, etc.) "
                     "default to 0 -- not derivable from network traffic alone."),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pcap processing failed: {type(e).__name__}: {e}") from e
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
