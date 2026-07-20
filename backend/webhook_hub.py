"""
webhook_hub.py
--------------
Central aggregation point for multiple Network Guardian sensors.

Enables:
- Multi-machine monitoring from one dashboard
- Alert deduplication across sensors
- Correlation detection (same attacker hitting multiple servers)
- Lateral movement detection
- Network-wide statistics
- Centralized blocking policies
"""
import json
import time
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict

HUB_DB_PATH = "data/webhook_hub.db"

HUB_SCHEMA = """
CREATE TABLE IF NOT EXISTS hub_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at REAL NOT NULL,
    sensor_id TEXT NOT NULL,
    sensor_ip TEXT,
    alert_data TEXT NOT NULL,
    risk_score REAL,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    flagged INTEGER,
    correlation_group INTEGER
);

CREATE INDEX IF NOT EXISTS idx_hub_received ON hub_alerts(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_hub_sensor ON hub_alerts(sensor_id);
CREATE INDEX IF NOT EXISTS idx_hub_src_ip ON hub_alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_hub_correlation ON hub_alerts(correlation_group);

CREATE TABLE IF NOT EXISTS hub_sensors (
    sensor_id TEXT PRIMARY KEY,
    sensor_ip TEXT,
    name TEXT,
    last_seen REAL,
    alerts_received INTEGER DEFAULT 0,
    high_risk_alerts INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hub_correlations (
    correlation_group INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT,
    src_ip TEXT,
    created_at REAL,
    sensor_count INTEGER,
    total_alerts INTEGER,
    severity TEXT
);
"""


def init_hub_db():
    """Initialize webhook hub database."""
    with sqlite3.connect(HUB_DB_PATH) as conn:
        conn.executescript(HUB_SCHEMA)
        conn.commit()


def receive_alert(sensor_id: str, sensor_ip: str, alert_data: Dict) -> Dict:
    """
    Receive alert from a remote Network Guardian sensor.

    Args:
        sensor_id: Unique identifier for the sensor
        sensor_ip: IP address of the sensor
        alert_data: Alert dict from sensor's score_rows()

    Returns:
        {success: bool, correlation_group: int, network_alert: bool}
    """
    now = time.time()

    with sqlite3.connect(HUB_DB_PATH) as conn:
        # Register sensor
        conn.execute(
            """INSERT OR REPLACE INTO hub_sensors
               (sensor_id, sensor_ip, last_seen, alerts_received)
               VALUES (?, ?, ?,
                       (SELECT COALESCE(alerts_received, 0) + 1
                        FROM hub_sensors WHERE sensor_id = ?))""",
            (sensor_id, sensor_ip, now, sensor_id)
        )

        # Store alert
        correlation_group = None
        src_ip = alert_data.get("src_ip")

        # Check for correlation with recent alerts from same source
        if src_ip:
            existing = conn.execute(
                """SELECT DISTINCT correlation_group FROM hub_alerts
                   WHERE src_ip = ? AND received_at > ?
                   LIMIT 1""",
                (src_ip, now - 3600)  # 1 hour window
            ).fetchone()

            if existing:
                correlation_group = existing[0]
            else:
                # Create new correlation group
                result = conn.execute(
                    "INSERT INTO hub_correlations (attack_type, src_ip, created_at, sensor_count) "
                    "VALUES (?, ?, ?, 1) RETURNING correlation_group",
                    ("multi_vector", src_ip, now)
                )
                correlation_group = result.fetchone()[0] if result else None

        conn.execute(
            """INSERT INTO hub_alerts
               (received_at, sensor_id, sensor_ip, alert_data, risk_score,
                src_ip, dst_ip, dst_port, flagged, correlation_group)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                sensor_id,
                sensor_ip,
                json.dumps(alert_data),
                alert_data.get("risk_score", 0),
                alert_data.get("src_ip"),
                alert_data.get("dst_ip"),
                alert_data.get("dst_port"),
                1 if alert_data.get("flagged") else 0,
                correlation_group
            )
        )

        # Update high-risk count
        if alert_data.get("flagged"):
            conn.execute(
                "UPDATE hub_sensors SET high_risk_alerts = high_risk_alerts + 1 WHERE sensor_id = ?",
                (sensor_id,)
            )

        conn.commit()

        # Check if this is a network-wide alert (same attacker on multiple sensors)
        network_alert = check_network_alert(conn, src_ip, now)

        return {
            "success": True,
            "correlation_group": correlation_group,
            "network_alert": network_alert
        }


def check_network_alert(conn, src_ip: str, timeframe_seconds: int = 300) -> bool:
    """
    Detect if an attacker is hitting multiple sensors.

    Returns True if same source IP has alerts on 2+ sensors in recent timeframe.
    """
    if not src_ip:
        return False

    result = conn.execute(
        """SELECT COUNT(DISTINCT sensor_id) FROM hub_alerts
           WHERE src_ip = ? AND received_at > ? AND flagged = 1""",
        (src_ip, time.time() - timeframe_seconds)
    ).fetchone()

    sensor_count = result[0] if result else 0
    return sensor_count >= 2


def get_network_overview() -> Dict:
    """Get overview of entire network security posture."""
    with sqlite3.connect(HUB_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # Sensor status
        sensors = conn.execute(
            "SELECT * FROM hub_sensors ORDER BY last_seen DESC"
        ).fetchall()

        # Recent high-risk alerts
        high_risk = conn.execute(
            """SELECT * FROM hub_alerts WHERE flagged = 1
               ORDER BY received_at DESC LIMIT 20"""
        ).fetchall()

        # Top offending IPs
        top_offenders = conn.execute(
            """SELECT src_ip, COUNT(*) as count, MAX(risk_score) as max_risk
               FROM hub_alerts WHERE flagged = 1
               GROUP BY src_ip ORDER BY count DESC LIMIT 10"""
        ).fetchall()

        # Correlations (multi-sensor attacks)
        correlations = conn.execute(
            """SELECT * FROM hub_correlations
               WHERE created_at > ? ORDER BY created_at DESC
               LIMIT 20""",
            (time.time() - 86400,)  # Last 24 hours
        ).fetchall()

        return {
            "sensors": [dict(s) for s in sensors],
            "high_risk_alerts": [dict(a) for a in high_risk],
            "top_offenders": [dict(o) for o in top_offenders],
            "correlations": [dict(c) for c in correlations],
            "stats": {
                "total_sensors": len(sensors),
                "active_sensors": sum(1 for s in sensors if time.time() - s["last_seen"] < 3600),
                "total_alerts_24h": conn.execute(
                    "SELECT COUNT(*) FROM hub_alerts WHERE received_at > ?",
                    (time.time() - 86400,)
                ).fetchone()[0],
                "network_alerts": conn.execute(
                    "SELECT COUNT(*) FROM hub_correlations WHERE created_at > ?",
                    (time.time() - 86400,)
                ).fetchone()[0]
            }
        }


def get_sensor_alerts(sensor_id: str, limit: int = 50) -> List[Dict]:
    """Get alerts for a specific sensor."""
    with sqlite3.connect(HUB_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM hub_alerts WHERE sensor_id = ? ORDER BY received_at DESC LIMIT ?",
            (sensor_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]


def detect_lateral_movement() -> List[Dict]:
    """
    Detect lateral movement: same source IP hitting different destinations on different sensors.
    """
    with sqlite3.connect(HUB_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        results = conn.execute(
            """SELECT src_ip,
                      GROUP_CONCAT(DISTINCT sensor_id) as sensors_hit,
                      GROUP_CONCAT(DISTINCT dst_ip) as targets,
                      COUNT(*) as total_alerts,
                      MAX(risk_score) as max_risk
               FROM hub_alerts
               WHERE received_at > ? AND flagged = 1
               GROUP BY src_ip
               HAVING COUNT(DISTINCT sensor_id) >= 2
               ORDER BY total_alerts DESC""",
            (time.time() - 3600,)  # Last hour
        ).fetchall()

        return [dict(r) for r in results]


def block_ip_network_wide(ip: str, duration_minutes: int = 60) -> Dict:
    """
    Coordinate blocking an IP across all sensors in the network.

    Sends block command to all sensors.
    """
    with sqlite3.connect(HUB_DB_PATH) as conn:
        sensors = conn.execute(
            "SELECT DISTINCT sensor_id, sensor_ip FROM hub_alerts WHERE src_ip = ?"
        ).fetchall()

        return {
            "ip": ip,
            "blocked_on_sensors": sensors,
            "duration_minutes": duration_minutes,
            "status": "pending"  # Should call API on each sensor
        }
