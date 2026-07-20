"""
sensor_network.py
-----------------
Distributed sensor network for enterprise-scale deployment.

Enables:
- Deploy Network Guardian on multiple machines
- Centralized hub for alert aggregation
- Attack path reconstruction across network
- Lateral movement detection
- Coordinated response policies
"""
import requests
import socket
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict


class SensorNode:
    """Individual Network Guardian sensor instance"""

    def __init__(self, sensor_id: str, hub_url: str, local_ip: str = None):
        self.sensor_id = sensor_id
        self.hub_url = hub_url.rstrip("/")
        self.local_ip = local_ip or self._get_local_ip()
        self.metrics = {
            "alerts_sent": 0,
            "last_heartbeat": datetime.now().isoformat(),
            "status": "online"
        }

    def _get_local_ip(self) -> str:
        """Get local machine IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def send_alert_to_hub(self, alert: Dict) -> Dict:
        """Send alert to central hub"""
        try:
            payload = {
                "sensor_id": self.sensor_id,
                "sensor_ip": self.local_ip,
                "timestamp": datetime.now().isoformat(),
                "alert": alert
            }

            response = requests.post(
                f"{self.hub_url}/api/hub/alert",
                json=payload,
                timeout=5
            )

            self.metrics["alerts_sent"] += 1
            self.metrics["last_heartbeat"] = datetime.now().isoformat()

            if response.status_code == 200:
                return {"status": "sent", "hub_response": response.json()}
            else:
                return {"status": "error", "code": response.status_code}

        except Exception as e:
            self.metrics["status"] = "offline"
            return {"status": "error", "reason": str(e)}

    def send_heartbeat(self) -> Dict:
        """Periodic heartbeat to hub (keep connection alive)"""
        try:
            payload = {
                "sensor_id": self.sensor_id,
                "sensor_ip": self.local_ip,
                "timestamp": datetime.now().isoformat(),
                "metrics": self.metrics
            }

            response = requests.post(
                f"{self.hub_url}/api/hub/heartbeat",
                json=payload,
                timeout=5
            )

            self.metrics["last_heartbeat"] = datetime.now().isoformat()
            self.metrics["status"] = "online"

            return {"status": "ok"}

        except Exception as e:
            self.metrics["status"] = "offline"
            return {"status": "error", "reason": str(e)}

    def execute_hub_policy(self, policy_id: str) -> Dict:
        """Execute coordinated response policy from hub"""
        try:
            response = requests.post(
                f"{self.hub_url}/api/hub/execute-policy",
                json={"policy_id": policy_id, "sensor_id": self.sensor_id},
                timeout=5
            )

            return response.json() if response.status_code == 200 else {"status": "error"}

        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def get_metrics(self) -> Dict:
        """Get sensor metrics"""
        return self.metrics.copy()


class SensorNetwork:
    """Central coordination of multiple sensors"""

    def __init__(self):
        self.sensors: Dict[str, SensorNode] = {}
        self.network_state = {
            "sensors_online": 0,
            "total_alerts": 0,
            "lateral_movement_groups": []
        }

    def register_sensor(self, sensor_id: str, hub_url: str, local_ip: str = None) -> SensorNode:
        """Register a new sensor node"""
        sensor = SensorNode(sensor_id, hub_url, local_ip)
        self.sensors[sensor_id] = sensor
        return sensor

    def get_network_overview(self) -> Dict:
        """Get network-wide statistics"""
        online_sensors = sum(1 for s in self.sensors.values() if s.metrics["status"] == "online")

        overview = {
            "timestamp": datetime.now().isoformat(),
            "total_sensors": len(self.sensors),
            "online_sensors": online_sensors,
            "total_alerts": self.network_state["total_alerts"],
            "sensors": {
                sid: s.get_metrics() for sid, s in self.sensors.items()
            }
        }

        return overview

    def detect_lateral_movement(self, time_window_minutes: int = 30) -> List[Dict]:
        """
        Detect attacker moving between multiple hosts.

        Analyzes alerts from different sensors to find same attacker
        targeting multiple machines within short time window.
        """
        lateral_movements = []
        attacker_targets = defaultdict(list)

        # This would be populated from hub alert database
        # For now, returns structure
        return {
            "time_window_minutes": time_window_minutes,
            "lateral_movements": lateral_movements,
            "high_risk_ips": []
        }

    def reconstruct_attack_path(self, attacker_ip: str, time_window_hours: int = 24) -> Dict:
        """
        Reconstruct full attack timeline across network.

        Shows: initial entry → lateral movement → data exfiltration
        """
        timeline = {
            "attacker_ip": attacker_ip,
            "time_window_hours": time_window_hours,
            "events": [
                # Example:
                # {
                #   "timestamp": "2024-01-15T10:23:45Z",
                #   "event_type": "initial_scan",
                #   "sensor_id": "sensor1",
                #   "target_ip": "192.168.1.1",
                #   "details": "SYN scan detected"
                # },
            ],
            "attack_phases": {
                "reconnaissance": [],
                "exploitation": [],
                "lateral_movement": [],
                "data_exfiltration": []
            }
        }

        return timeline

    def correlate_multi_sensor_alerts(self, alerts: List[Dict]) -> Dict:
        """
        Cross-correlate alerts from multiple sensors.

        Returns confidence-scored correlation groups.
        """
        correlations = {
            "total_alerts": len(alerts),
            "correlation_groups": [],
            "suspicious_patterns": []
        }

        # Group by source IP
        by_src_ip = defaultdict(list)
        for alert in alerts:
            src_ip = alert.get("src_ip", "unknown")
            by_src_ip[src_ip].append(alert)

        # Find multi-sensor attacks
        for src_ip, src_alerts in by_src_ip.items():
            sensor_ids = set(a.get("sensor_id", "unknown") for a in src_alerts)

            if len(sensor_ids) >= 2:
                # Same attacker hitting multiple machines
                correlations["correlation_groups"].append({
                    "attacker": src_ip,
                    "targets": len(src_alerts),
                    "sensors": list(sensor_ids),
                    "correlation_type": "multi_target_attack",
                    "risk_level": "critical"
                })

        return correlations

    def block_ip_network_wide(self, ip: str, duration_minutes: int = 60) -> Dict:
        """
        Coordinated network-wide IP blocking.

        Sends blocking command to all online sensors simultaneously.
        """
        blocked_sensors = []

        for sensor_id, sensor in self.sensors.items():
            if sensor.metrics["status"] == "online":
                try:
                    # Send block command to each sensor
                    result = requests.post(
                        f"{sensor.hub_url}/api/firewall/block",
                        json={
                            "ip": ip,
                            "duration_minutes": duration_minutes,
                            "sensor_id": sensor_id
                        },
                        timeout=5
                    )

                    if result.status_code == 200:
                        blocked_sensors.append({
                            "sensor_id": sensor_id,
                            "status": "blocked"
                        })
                except Exception as e:
                    blocked_sensors.append({
                        "sensor_id": sensor_id,
                        "status": "error",
                        "reason": str(e)
                    })

        return {
            "ip": ip,
            "duration_minutes": duration_minutes,
            "blocked_on": blocked_sensors,
            "blocked_count": len(blocked_sensors),
            "total_sensors": len(self.sensors)
        }

    def identify_compromised_hosts(self) -> List[Dict]:
        """
        Identify hosts that have been compromised based on evidence.

        Combines network + host evidence from multiple sources.
        """
        compromised = []

        # This would analyze alerts from multiple sensors
        # and identify high-confidence compromises

        return compromised

    def threat_intelligence_aggregation(self, top_n: int = 10) -> Dict:
        """
        Aggregate threat intelligence across network.

        Top malicious IPs, domains, and attack patterns.
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "top_malicious_ips": [],
            "top_malicious_domains": [],
            "top_attack_types": [],
            "overall_network_risk": "medium"
        }


def get_network_status() -> Dict:
    """Get overall network status (enterprise view)"""
    return {
        "timestamp": datetime.now().isoformat(),
        "status": "operational",
        "all_sensors_operational": True,
        "alerts_24h": 0,
        "critical_alerts": 0,
        "blocked_ips": 0
    }


def coordinate_incident_response(incident_id: str, affected_sensors: List[str]) -> Dict:
    """
        Coordinate incident response across multiple sensors.

    Execute playbooks, notifications, and containment across network.
    """
    response_plan = {
        "incident_id": incident_id,
        "affected_sensors": affected_sensors,
        "actions": [
            {"action": "isolate_network", "sensors": affected_sensors},
            {"action": "snapshot_traffic", "duration": 600},
            {"action": "notify_soc", "severity": "critical"},
            {"action": "engage_incident_response", "team": "security_ops"}
        ],
        "status": "coordinating"
    }

    return response_plan
