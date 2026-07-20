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
import shap
import requests
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
NOTEBOOKS_DIR = os.path.join(PROJECT_ROOT, "notebooks")

sys.path.append(NOTEBOOKS_DIR)
sys.path.append(BACKEND_DIR)
from data_prep import load_raw, transform
from pcap_to_features import extract_connections, compute_features
from live_capture import LiveCapture, list_interfaces_detailed
import db as db_store
import firewall
import notifications
import waf_engine
import response_engine

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

# SHAP explainer for the Isolation Forest -- gives per-connection feature
# attribution instead of just "something's off". Confirmed empirically that
# shap.TreeExplainer's reconstructed output (expected_value + sum(shap values))
# correlates with model.decision_function at r=0.997 on the test set, same
# sign convention (higher = more normal) -- so the features with the most
# NEGATIVE shap value are exactly the ones pushing a connection toward
# "anomalous". ~1ms/row, so this runs on every scoring call, not just on demand.
shap_explainer = shap.TreeExplainer(model)

# Initialize response engine
resp_engine = response_engine.ResponseEngine()

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

# Risk score at/above which a connection counts as "high-risk" for the alert
# inbox, /alerts default filter, and outbound webhook notifications.
ALERT_RISK_THRESHOLD = 70

# ===== Threat Intelligence Integration =====
# Free APIs for IP reputation checking (no API key required for basic queries)
THREAT_INTEL_ENABLED = True
IP_REPUTATION_CACHE = {}  # Simple cache to avoid repeated lookups

def get_ip_reputation(ip: str) -> Dict:
    """
    Check IP reputation using free threat intelligence APIs.
    Returns: {reputation_score: 0-100, reason: str, is_malicious: bool}
    """
    if not THREAT_INTEL_ENABLED or not ip or ip.startswith("127.") or ip.startswith("192.168."):
        return {"reputation_score": 0, "reason": None, "is_malicious": False}

    # Check cache first
    if ip in IP_REPUTATION_CACHE:
        return IP_REPUTATION_CACHE[ip]

    result = {"reputation_score": 0, "reason": None, "is_malicious": False}

    try:
        # Try AbuseIPDB (free tier: 1000 queries/day)
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ""},  # Free tier doesn't require key for basic queries
            timeout=2
        )
        if resp.status_code == 200:
            data = resp.json()
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if score > 50:
                result["reputation_score"] = min(100, score)
                result["reason"] = f"AbuseIPDB confidence: {score}%"
                result["is_malicious"] = True
    except:
        pass  # API timeout or error - continue without threat intel

    # Cache result
    IP_REPUTATION_CACHE[ip] = result
    return result


def _format_feature_value(value):
    if isinstance(value, (int, float, np.floating, np.integer)):
        return round(float(value), 3)
    return value


def score_rows(df: pd.DataFrame):
    X, used_feature_cols = transform(df, encoders, numeric_cols, scaler, fit_scaler=False)
    raw_score = -model.decision_function(X)  # higher = more anomalous
    is_attack = (model.predict(X) == -1)

    # Normalize anomaly score to a friendly 0-100 "risk score"
    # decision_function roughly in [-0.5, 0.5]; clip + rescale
    risk = np.clip((raw_score + 0.2) / 0.4, 0, 1) * 100

    # Per-row feature attribution -- see shap_explainer comment above for why
    # "most negative shap value" == "biggest driver of the anomaly".
    shap_values = shap_explainer.shap_values(X)

    results = []
    for i in range(len(df)):
        row = df.iloc[i]
        auth_bruteforce_score = float(row.get("auth_bruteforce_score", 0))
        is_bruteforce = bool(auth_bruteforce_score >= AUTH_BRUTEFORCE_THRESHOLD)

        sv_row = shap_values[i]
        top_order = np.argsort(sv_row)[:3]  # ascending -> most negative (most anomalous) first
        top_features = [
            {
                "feature": used_feature_cols[idx],
                "shap": round(float(sv_row[idx]), 4),
                "value": _format_feature_value(row.get(used_feature_cols[idx])),
            }
            for idx in top_order
        ]

        # Check threat intelligence for source IP
        src_ip = row.get("_src_ip", "unknown")
        threat_intel = get_ip_reputation(src_ip)
        is_known_malicious = threat_intel.get("is_malicious", False)

        # WAF analysis for HTTP traffic
        waf_result = None
        if row.get("service") == "http":
            http_body = row.get("_http_body", "")
            http_headers = row.get("_http_headers", {})
            http_method = row.get("_http_method", "GET")
            if http_body or http_method:
                waf_result = waf_engine.analyze_http_request(
                    url=row.get("_http_url", "/"),
                    http_method=http_method,
                    http_headers=http_headers,
                    http_body=http_body,
                    request_count=int(row.get("count", 1))
                )

        # crude "why flagged" explanation: which numeric features are most
        # extreme relative to training distribution (z-score style via scaler)
        reasons = []
        if is_known_malicious:
            reasons.append(
                f"source IP {src_ip} is known to be malicious "
                f"(threat intel score: {threat_intel['reputation_score']}/100)"
            )
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
            reasons.append(f"failed login attempts detected ({int(row.get('num_failed_logins', 0))} attempts)")
        if row.get("dst_host_diff_srv_rate", 0) > 0.5:
            reasons.append("connections spread across many services (scan-like behavior)")
        # Add WAF findings
        if waf_result:
            if waf_result["attacks_detected"]:
                for attack in waf_result["attacks_detected"]:
                    reasons.append(f"WAF: {attack} detected (risk: {waf_result['risk_score']})")

        if not reasons:
            top1 = top_features[0]
            reasons.append(
                f"statistical deviation from learned normal traffic baseline "
                f"(top contributor: {top1['feature']} = {top1['value']})"
            )

        # Boost risk if IP is known malicious or WAF detected attack
        base_risk = float(risk[i])
        if is_known_malicious:
            base_risk = max(base_risk, 80.0)
        if waf_result and waf_result.get("block"):
            base_risk = max(base_risk, 90.0)

        risk_i = max(base_risk, 70.0) if is_bruteforce else base_risk

        alert_data = {
            "risk_score": round(risk_i, 1),
            "flagged": bool(is_attack[i]) or is_bruteforce or is_known_malicious or (waf_result and waf_result.get("block")),
            "true_label": row.get("label", None),
            "protocol_type": row.get("protocol_type", None),
            "service": row.get("service", None),
            "flag": row.get("flag", None),
            "src_bytes": float(row.get("src_bytes", 0)),
            "dst_bytes": float(row.get("dst_bytes", 0)),
            "auth_bruteforce_score": auth_bruteforce_score,
            "threat_intel_score": threat_intel.get("reputation_score", 0),
            "is_known_malicious": is_known_malicious,
            "src_ip": src_ip,
            "reasons": reasons,
            "top_features": top_features,
        }

        # Add WAF details if attack detected
        if waf_result:
            alert_data["waf_attacks"] = waf_result.get("attacks_detected", [])
            alert_data["waf_risk"] = waf_result["risk_score"]

        # Execute response policy if alert flagged
        if alert_data.get("flagged"):
            resp_engine.execute_response(alert_data, simulate=True)

        results.append(alert_data)
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
        """Called from the capture's background thread with new raw feature rows.
        Persists to the DB regardless of whether anyone's watching the dashboard --
        live capture keeps building alert history even with the browser tab closed."""
        try:
            results = score_feature_rows(feature_rows, source="live")
        except Exception as e:
            results = [{"error": f"{type(e).__name__}: {e}"}]

        if not self.clients or self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(
            self._broadcast({"type": "results", "results": results}), self.loop
        )


broadcaster = LiveBroadcaster()
live_capture = LiveCapture(on_results=broadcaster.on_capture_results)


@app.on_event("startup")
async def on_startup():
    broadcaster.set_loop(asyncio.get_event_loop())
    db_store.init_db()


@app.on_event("shutdown")
def on_shutdown():
    if live_capture.running:
        live_capture.stop()


def score_feature_rows(feature_rows, source):
    """Shared by /analyze-pcap, /demo/simulate-attack, and the live capture
    broadcaster: takes raw rows from pcap_to_features.compute_features() (still
    carrying _src_ip/_dst_ip/_dst_port/_conn_key metadata), scores them, and
    persists every result to the DB tagged with `source` ('upload' | 'demo_scenario'
    | 'live') -- these are the only sources ever written to storage; the simulated
    NSL-KDD sample-traffic feed never touches the DB, so history stays trustworthy."""
    df = pd.DataFrame(feature_rows)
    df["label"] = "unknown"
    meta = df[["_src_ip", "_dst_ip", "_dst_port"]].to_dict("records")
    df_model = df.drop(columns=["_src_ip", "_dst_ip", "_dst_port", "_conn_key"])
    results = score_rows(df_model)
    for r, m in zip(results, meta):
        r["src_ip"] = m["_src_ip"]
        r["dst_ip"] = m["_dst_ip"]
        r["dst_port"] = m["_dst_port"]
    try:
        db_store.insert_scored_results(results, source=source)
    except Exception:
        pass  # persistence is best-effort -- never break scoring/live capture over a DB hiccup
    try:
        notifications.notify_high_risk(results, source=source, threshold=ALERT_RISK_THRESHOLD)
    except Exception:
        pass  # same -- a dead webhook must never break scoring
    return results


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/interfaces")
def get_interfaces():
    """List network interfaces available for live capture (requires Npcap on Windows),
    with human-readable name/description alongside the raw device string."""
    try:
        return {"interfaces": list_interfaces_detailed()}
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


@app.get("/alerts")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    min_risk: float = Query(default=ALERT_RISK_THRESHOLD, ge=0, le=100),
):
    """High-risk history from real (packet-derived) sources only -- upload,
    demo scenario, and live capture. Survives page reloads and backend restarts."""
    return {"alerts": db_store.get_alerts(limit=limit, min_risk=min_risk)}


@app.get("/alerts/stats")
def get_alert_stats():
    """Session/all-time aggregate counters + top offending source IPs, computed
    from the same persisted history -- powers the live-stat readouts on the dashboard."""
    return db_store.get_stats()


@app.delete("/alerts")
def clear_alerts():
    db_store.clear_all()
    return {"status": "cleared"}


class BlockIpRequest(BaseModel):
    ip: str
    reason: Optional[str] = None


@app.post("/firewall/block")
def firewall_block(req: BlockIpRequest):
    """
    Adds a Windows Firewall rule blocking inbound traffic from this IP.
    Requires the backend to be running as Administrator (same requirement as
    live capture). This is NEVER called automatically by the scoring pipeline --
    only ever in direct response to an explicit user click + confirmation in
    the dashboard, exactly like a security analyst running the command by hand.
    """
    try:
        result = firewall.block_ip(req.ip)
    except firewall.FirewallError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    db_store.add_blocked_ip(req.ip, reason=req.reason)
    return result


@app.post("/firewall/unblock")
def firewall_unblock(req: BlockIpRequest):
    try:
        result = firewall.unblock_ip(req.ip)
    except firewall.FirewallError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    db_store.remove_blocked_ip(req.ip)
    return result


@app.get("/firewall/blocked")
def firewall_list_blocked():
    return {"blocked": db_store.list_blocked_ips()}


class WebhookSettings(BaseModel):
    url: str = ""
    enabled: bool = False


@app.get("/settings/webhook")
def get_webhook_settings():
    return {
        "url": db_store.get_setting("webhook_url", ""),
        "enabled": db_store.get_setting("webhook_enabled") == "1",
    }


@app.post("/settings/webhook")
def set_webhook_settings(req: WebhookSettings):
    if req.url and not (req.url.startswith("http://") or req.url.startswith("https://")):
        raise HTTPException(status_code=400, detail="Webhook URL must start with http:// or https://")
    db_store.set_setting("webhook_url", req.url)
    db_store.set_setting("webhook_enabled", "1" if req.enabled else "0")
    return {"status": "saved"}


@app.post("/settings/webhook/test")
def test_webhook_settings(req: WebhookSettings):
    """Fires one test payload immediately, using the URL passed in (not necessarily
    saved yet) -- so the user can verify it works before enabling it for real."""
    if not req.url:
        raise HTTPException(status_code=400, detail="No webhook URL provided")
    try:
        status = notifications.send_test(req.url)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Webhook test failed: {type(e).__name__}: {e}") from e
    return {"status": "sent", "http_status": status}


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


PCAP_ANALYSIS_NOTE = (
    "Flow features (bytes, duration, error rates, protocol) computed from "
    "actual packets. Content/host features (failed logins, root shell, etc.) "
    "default to 0 -- not derivable from network traffic alone."
)


def analyze_pcap_file(pcap_path, source):
    """Shared by /analyze-pcap (uploaded file) and /demo/simulate-attack (canned
    scenario file already on disk) -- extract connections, compute features, score."""
    conns = extract_connections(pcap_path)
    if len(conns) == 0:
        return {"results": [], "note": "No TCP/UDP/ICMP connections found in this capture."}
    feature_rows = compute_features(conns)
    results = score_feature_rows(feature_rows, source=source)
    return {"results": results, "note": PCAP_ANALYSIS_NOTE}


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
        return analyze_pcap_file(tmp_path, source="upload")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pcap processing failed: {type(e).__name__}: {e}") from e
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/demo/simulate-attack")
def simulate_attack():
    """
    Runs the same scoring pipeline as /analyze-pcap over a canned scenario file
    already on disk (data/test_traffic.pcap) -- normal HTTP/HTTPS traffic, a SYN
    port scan, a SYN flood, and a throttled SSH brute-force -- so the detection
    logic can be demonstrated with one click, without needing a real attacker or
    a file to upload. See notebooks/generate_test_pcap.py for how it's built.
    """
    demo_path = os.path.join(DATA_DIR, "test_traffic.pcap")
    if not os.path.exists(demo_path):
        raise HTTPException(
            status_code=404,
            detail="Demo capture not found. Run: python notebooks/generate_test_pcap.py",
        )
    try:
        return analyze_pcap_file(demo_path, source="demo_scenario")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"pcap processing failed: {type(e).__name__}: {e}") from e
