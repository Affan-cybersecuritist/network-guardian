"""
db_postgres.py
--------------
PostgreSQL adapter for Network Guardian.
Use this instead of SQLite for enterprise/production environments.

INSTALLATION:
  1. Install PostgreSQL: https://www.postgresql.org/download/
  2. Create a database: createdb network_guardian
  3. Set environment variables:
     export DB_TYPE=postgres
     export DATABASE_URL=postgresql://user:password@localhost:5432/network_guardian
  4. Run python with these vars set

BENEFITS over SQLite:
  - Scales to billions of connections
  - Supports concurrent writes
  - Supports replication and clustering
  - Better indexing performance
  - Full ACID compliance
  - Backup/restore capabilities
"""
import json
import os
import time
import psycopg2
from psycopg2.extras import RealDictCursor

DB_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/network_guardian")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scored_connections (
    id SERIAL PRIMARY KEY,
    created_at REAL NOT NULL,
    source TEXT NOT NULL,
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
    threat_intel_score REAL DEFAULT 0,
    is_known_malicious INTEGER DEFAULT 0,
    reasons TEXT NOT NULL,
    top_features TEXT
);

CREATE INDEX IF NOT EXISTS idx_scored_created_at ON scored_connections(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scored_risk ON scored_connections(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_scored_src_ip ON scored_connections(src_ip);
CREATE INDEX IF NOT EXISTS idx_scored_flagged ON scored_connections(flagged);

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
    """Create a PostgreSQL connection."""
    try:
        conn = psycopg2.connect(DB_URL)
        conn.set_session(autocommit=False)
        return conn
    except psycopg2.Error as e:
        raise Exception(f"Could not connect to PostgreSQL: {e}")


def init_db():
    """Initialize database schema."""
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA)
            conn.commit()
        print("PostgreSQL database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise


def insert_scored_results(results, source):
    """Insert scored results into PostgreSQL."""
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
            r.get("threat_intel_score", 0),
            1 if r.get("is_known_malicious", False) else 0,
            json.dumps(r.get("reasons", [])),
            json.dumps(r.get("top_features", [])),
        )
        for r in results
    ]

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(
                    """INSERT INTO scored_connections
                       (created_at, source, src_ip, dst_ip, dst_port, protocol_type, service, flag,
                        src_bytes, dst_bytes, risk_score, flagged, auth_bruteforce_score, is_bruteforce,
                        threat_intel_score, is_known_malicious, reasons, top_features)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    rows,
                )
            conn.commit()
    except psycopg2.Error as e:
        print(f"Error inserting results: {e}")


def get_alerts(limit=50, min_risk=70):
    """Retrieve high-risk alerts."""
    try:
        with _connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """SELECT * FROM scored_connections
                       WHERE risk_score >= %s OR is_bruteforce = 1 OR is_known_malicious = 1
                       ORDER BY created_at DESC LIMIT %s""",
                    (min_risk, limit),
                )
                rows = cur.fetchall()
                return [dict(row) for row in rows]
    except psycopg2.Error as e:
        print(f"Error retrieving alerts: {e}")
        return []


def get_stats():
    """Get statistics from database."""
    try:
        with _connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """SELECT
                         COUNT(*) AS scored,
                         SUM(flagged) AS flagged,
                         SUM(is_bruteforce) AS bruteforce_triggered,
                         SUM(is_known_malicious) AS known_malicious,
                         SUM(CASE WHEN service IN ('ftp','ssh','telnet') THEN 1 ELSE 0 END) AS auth_observed,
                         COALESCE(MAX(auth_bruteforce_score), 0) AS auth_max,
                         SUM(CASE WHEN risk_score >= 70 OR is_bruteforce = 1 THEN 1 ELSE 0 END) AS high_risk_count
                       FROM scored_connections"""
                )
                row = cur.fetchone()

            cur.execute(
                "SELECT source, COUNT(*) AS n FROM scored_connections GROUP BY source"
            )
            by_source_rows = cur.fetchall()

            cur.execute(
                """SELECT src_ip, COUNT(*) AS n, MAX(risk_score) AS max_risk
                   FROM scored_connections
                   WHERE src_ip IS NOT NULL AND (risk_score >= 70 OR is_bruteforce = 1 OR is_known_malicious = 1)
                   GROUP BY src_ip ORDER BY n DESC LIMIT 10"""
            )
            top_offenders_rows = cur.fetchall()

            return {
                "scored": row["scored"] or 0,
                "flagged": row["flagged"] or 0,
                "bruteforce_triggered": row["bruteforce_triggered"] or 0,
                "known_malicious": row["known_malicious"] or 0,
                "auth_observed": row["auth_observed"] or 0,
                "auth_max": row["auth_max"] or 0,
                "high_risk_count": row["high_risk_count"] or 0,
                "by_source": {r["source"]: r["n"] for r in by_source_rows},
                "top_offenders": [dict(r) for r in top_offenders_rows],
            }
    except psycopg2.Error as e:
        print(f"Error getting stats: {e}")
        return {}


def clear_all():
    """Clear all alerts."""
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scored_connections")
            conn.commit()
    except psycopg2.Error as e:
        print(f"Error clearing alerts: {e}")


def add_blocked_ip(ip, reason=None):
    """Add IP to blocked list."""
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO blocked_ips (ip, blocked_at, reason) VALUES (%s, %s, %s) "
                    "ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason",
                    (ip, time.time(), reason)
                )
            conn.commit()
    except psycopg2.Error as e:
        print(f"Error blocking IP: {e}")


def list_blocked_ips():
    """List blocked IPs."""
    try:
        with _connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
                rows = cur.fetchall()
                return [dict(row) for row in rows]
    except psycopg2.Error as e:
        print(f"Error listing blocked IPs: {e}")
        return []


def remove_blocked_ip(ip):
    """Remove IP from blocked list."""
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
            conn.commit()
    except psycopg2.Error as e:
        print(f"Error unblocking IP: {e}")


def get_setting(key, default=None):
    """Get a setting value."""
    try:
        with _connect() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
                row = cur.fetchone()
                return row["value"] if row else default
    except psycopg2.Error:
        return default


def set_setting(key, value):
    """Set a setting value."""
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO settings (key, value) VALUES (%s, %s) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (key, value)
                )
            conn.commit()
    except psycopg2.Error as e:
        print(f"Error setting value: {e}")
