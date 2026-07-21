"""
db.py
-----
Lightweight persistence for scored connections, using stdlib sqlite3 (no new
dependency). Without this, every alert and stat lived only in the browser's
JS memory -- a page refresh or backend restart lost all history, and there
was no way to ask "has this source hit us before?" or see trends over time.

Only REAL, packet-derived results are stored (pcap upload, the demo/attack
scenario, and live capture) -- the simulated NSL-KDD sample-traffic feed is
never written here, so history stays trustworthy (see main.py score_feature_rows).
"""
import json
import os
import sqlite3
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "guardian.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scored_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    source TEXT NOT NULL,          -- 'upload' | 'demo_scenario' | 'live' | 'replay'
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol_type TEXT,
    service TEXT,
    flag TEXT,
    src_bytes REAL,
    dst_bytes REAL,
    risk_score REAL NOT NULL,
    flagged INTEGER NOT NULL,
    auth_bruteforce_score REAL DEFAULT 0,
    is_bruteforce INTEGER DEFAULT 0,
    reasons TEXT NOT NULL,          -- JSON array
    top_features TEXT               -- JSON array of {feature, shap, value} from SHAP, nullable
);
CREATE INDEX IF NOT EXISTS idx_scored_created_at ON scored_connections(created_at);
CREATE INDEX IF NOT EXISTS idx_scored_risk ON scored_connections(risk_score);
CREATE INDEX IF NOT EXISTS idx_scored_src_ip ON scored_connections(src_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    blocked_at REAL NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn):
    """CREATE TABLE IF NOT EXISTS won't add new columns to a table that
    already existed from an earlier version of this app -- handle that here
    so upgrading never requires deleting your existing guardian.db."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(scored_connections)")}
    if "top_features" not in cols:
        conn.execute("ALTER TABLE scored_connections ADD COLUMN top_features TEXT")


def insert_scored_results(results, source):
    """results: list of dicts as produced by main.score_rows()/score_feature_rows()."""
    if not results:
        return
    now = time.time()
    rows = [
        (
            now,
            source,
            r.get("src_ip"),
            r.get("dst_ip"),
            r.get("dst_port"),
            r.get("protocol_type"),
            r.get("service"),
            r.get("flag"),
            r.get("src_bytes"),
            r.get("dst_bytes"),
            r.get("risk_score"),
            1 if r.get("flagged") else 0,
            r.get("auth_bruteforce_score", 0),
            1 if any("brute-force" in x for x in r.get("reasons", [])) else 0,
            json.dumps(r.get("reasons", [])),
            json.dumps(r.get("top_features", [])),
        )
        for r in results
    ]
    with _connect() as conn:
        conn.executemany(
            """INSERT INTO scored_connections
               (created_at, source, src_ip, dst_ip, dst_port, protocol_type, service, flag,
                src_bytes, dst_bytes, risk_score, flagged, auth_bruteforce_score, is_bruteforce, reasons, top_features)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )


def get_alerts(limit=50, min_risk=70):
    with _connect() as conn:
        cur = conn.execute(
            """SELECT * FROM scored_connections
               WHERE risk_score >= ? OR is_bruteforce = 1
               ORDER BY created_at DESC LIMIT ?""",
            (min_risk, limit),
        )
        return [_row_to_dict(row) for row in cur.fetchall()]


def get_stats():
    with _connect() as conn:
        row = conn.execute(
            """SELECT
                 COUNT(*) AS scored,
                 SUM(flagged) AS flagged,
                 SUM(is_bruteforce) AS bruteforce_triggered,
                 SUM(CASE WHEN service IN ('ftp','ssh','telnet') THEN 1 ELSE 0 END) AS auth_observed,
                 COALESCE(MAX(auth_bruteforce_score), 0) AS auth_max,
                 SUM(CASE WHEN risk_score >= 70 OR is_bruteforce = 1 THEN 1 ELSE 0 END) AS high_risk_count
               FROM scored_connections"""
        ).fetchone()
        by_source = conn.execute(
            "SELECT source, COUNT(*) AS n FROM scored_connections GROUP BY source"
        ).fetchall()
        top_sources = conn.execute(
            """SELECT src_ip, COUNT(*) AS n, MAX(risk_score) AS max_risk
               FROM scored_connections
               WHERE src_ip IS NOT NULL AND (risk_score >= 70 OR is_bruteforce = 1)
               GROUP BY src_ip ORDER BY n DESC LIMIT 10"""
        ).fetchall()
        return {
            "scored": row["scored"] or 0,
            "flagged": row["flagged"] or 0,
            "bruteforce_triggered": row["bruteforce_triggered"] or 0,
            "auth_observed": row["auth_observed"] or 0,
            "auth_max": row["auth_max"] or 0,
            "high_risk_count": row["high_risk_count"] or 0,
            "by_source": {r["source"]: r["n"] for r in by_source},
            "top_offenders": [dict(r) for r in top_sources],
        }


def clear_all():
    with _connect() as conn:
        conn.execute("DELETE FROM scored_connections")


def add_blocked_ip(ip, reason=None):
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?, ?, ?)",
            (ip, time.time(), reason),
        )


def remove_blocked_ip(ip):
    with _connect() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def list_blocked_ips():
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
        return [dict(row) for row in cur.fetchall()]


def is_blocked(ip):
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        return row is not None


def get_setting(key, default=None):
    with _connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with _connect() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


def _row_to_dict(row):
    d = dict(row)
    d["reasons"] = json.loads(d["reasons"])
    d["top_features"] = json.loads(d["top_features"]) if d.get("top_features") else []
    d["flagged"] = bool(d["flagged"])
    d["is_bruteforce"] = bool(d["is_bruteforce"])
    return d
