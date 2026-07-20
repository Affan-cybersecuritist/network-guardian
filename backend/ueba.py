"""
ueba.py
-------
User & Entity Behavior Analytics - detect insider threats and compromised accounts.

Detects:
- Unusual login times/locations
- Abnormal data access patterns
- Privilege abuse
- Mass file downloads
- Access to sensitive resources
- Lateral movement by legitimate user
"""
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import math


class UserBehaviorAnalyzer:
    """Analyze user behavior for insider threats"""

    def __init__(self):
        self.user_profiles = {}  # Baseline behavior for each user
        self.risk_scores = {}    # Current risk for each user

    def create_user_profile(self, username: str, historical_events: List[Dict]) -> Dict:
        """
        Learn normal behavior for a user from historical data.

        Baseline includes: login times, accessed resources, data volume, locations
        """
        profile = {
            "username": username,
            "login_hours": [],
            "login_locations": set(),
            "accessed_resources": set(),
            "typical_data_volume": 0,
            "typical_network_peers": set(),
            "role": "unknown",
            "sensitivity_level": "low",
            "sample_size": len(historical_events)
        }

        if not historical_events:
            return profile

        total_bytes = 0
        for event in historical_events:
            # Collect login patterns
            if event.get("event_type") == "login":
                profile["login_hours"].append(event.get("hour", 0))
                profile["login_locations"].add(event.get("source_ip", "unknown"))

            # Collect resource access
            if event.get("event_type") == "file_access":
                profile["accessed_resources"].add(event.get("resource", "unknown"))
                total_bytes += event.get("bytes", 0)

            # Collect network peers
            if event.get("event_type") == "network_connection":
                profile["network_peers"].add(event.get("destination", "unknown"))

        profile["typical_data_volume"] = total_bytes / len(historical_events) if historical_events else 0

        return profile

    def detect_anomalous_login(self, username: str, event: Dict) -> Tuple[float, Optional[str]]:
        """
        Detect unusual login: wrong time, wrong location, wrong device.

        Returns: (risk_score, reason)
        """
        if username not in self.user_profiles:
            return 0.0, None

        profile = self.user_profiles[username]
        risk_score = 0.0
        reasons = []

        # Check 1: Login time anomaly
        current_hour = event.get("hour", -1)
        if profile["login_hours"] and current_hour >= 0:
            typical_hours = set(profile["login_hours"])
            if current_hour not in typical_hours:
                # Unusual time
                if current_hour < 6 or current_hour > 22:
                    risk_score += 0.3
                    reasons.append(f"Login at unusual time: {current_hour}:00 (typical: {sorted(typical_hours)})")

        # Check 2: Location anomaly
        source_ip = event.get("source_ip", "unknown")
        if profile["login_locations"] and source_ip not in profile["login_locations"]:
            # Unusual location
            risk_score += 0.4
            reasons.append(f"Login from new location: {source_ip} (typical: {profile['login_locations']})")

        # Check 3: Device anomaly
        device_id = event.get("device_id", "unknown")
        if profile.get("typical_devices") and device_id not in profile.get("typical_devices", set()):
            risk_score += 0.2
            reasons.append(f"Login from new device: {device_id}")

        reason = " | ".join(reasons) if reasons else None
        return min(risk_score, 1.0), reason

    def detect_data_exfiltration(self, username: str, event: Dict) -> Tuple[float, Optional[str]]:
        """
        Detect abnormal data access/download.

        Mass file access or access to sensitive resources is suspicious.
        """
        if username not in self.user_profiles:
            return 0.0, None

        profile = self.user_profiles[username]
        risk_score = 0.0
        reasons = []

        bytes_accessed = event.get("bytes", 0)
        typical_volume = profile.get("typical_data_volume", 0)

        # Check 1: Data volume spike
        if typical_volume > 0:
            ratio = bytes_accessed / typical_volume
            if ratio > 10:  # 10x normal
                risk_score += 0.6
                reasons.append(f"Data volume spike: {ratio:.0f}x normal ({bytes_accessed} bytes)")
            elif ratio > 5:
                risk_score += 0.4
                reasons.append(f"Data volume elevated: {ratio:.0f}x normal")

        # Check 2: Accessing sensitive resources
        resource = event.get("resource", "")
        sensitive_keywords = ["password", "secret", "confidential", "financial", "customer", "database"]
        if any(keyword in resource.lower() for keyword in sensitive_keywords):
            if resource not in profile["accessed_resources"]:
                risk_score += 0.5
                reasons.append(f"Access to sensitive resource: {resource}")

        # Check 3: Mass file operations
        file_count = event.get("file_count", 1)
        if file_count > 100:
            risk_score += 0.7
            reasons.append(f"Mass file operation: {file_count} files")

        reason = " | ".join(reasons) if reasons else None
        return min(risk_score, 1.0), reason

    def detect_privilege_abuse(self, username: str, event: Dict) -> Tuple[float, Optional[str]]:
        """
        Detect privilege escalation or abuse.

        Admin using credentials they shouldn't have.
        """
        risk_score = 0.0
        reasons = []

        # Check 1: Privilege escalation
        if event.get("escalation_detected"):
            risk_score += 0.8
            reasons.append("Privilege escalation attempt")

        # Check 2: Root/admin activity from non-admin user
        user_role = event.get("user_role", "user")
        target_role = event.get("target_role", "user")

        if user_role != "admin" and target_role == "admin":
            risk_score += 0.7
            reasons.append(f"Non-admin user accessing admin resources")

        # Check 3: Unusual commands for user
        command = event.get("command", "")
        dangerous_commands = ["sudo", "chmod", "chown", "rm -rf", "dd", "dd if=/dev/urandom"]

        if user_role == "user" and any(cmd in command for cmd in dangerous_commands):
            risk_score += 0.9
            reasons.append(f"High-risk command from non-privileged user: {command}")

        reason = " | ".join(reasons) if reasons else None
        return min(risk_score, 1.0), reason

    def detect_lateral_movement_by_user(
        self, username: str, current_hosts: List[str]
    ) -> Tuple[float, Optional[str]]:
        """
        Detect if compromised account is moving laterally through network.

        Legitimate user in one part of network suddenly in different part = suspicious.
        """
        if username not in self.user_profiles:
            return 0.0, None

        profile = self.user_profiles[username]
        typical_hosts = profile.get("network_peers", set())

        new_hosts = set(current_hosts) - typical_hosts

        if len(new_hosts) == 0:
            return 0.0, None

        # One new host = maybe legitimate, multiple = suspicious
        risk_score = min(len(new_hosts) * 0.15, 0.9)
        reason = f"Lateral movement: accessing new hosts {new_hosts}"

        return risk_score, reason

    def detect_account_takeover(
        self,
        username: str,
        login_event: Dict,
        file_events: List[Dict]
    ) -> Tuple[float, Optional[str]]:
        """
        Detect account takeover (compromised credentials).

        Combination of: unusual login + unusual activity = account stolen.
        """
        risk_score = 0.0
        reasons = []

        # Check login anomaly
        login_risk, login_reason = self.detect_anomalous_login(username, login_event)
        if login_risk > 0.5:
            risk_score += login_risk * 0.5
            reasons.append(login_reason)

        # Check file access patterns
        for file_event in file_events:
            file_risk, file_reason = self.detect_data_exfiltration(username, file_event)
            if file_risk > 0.5:
                risk_score += file_risk * 0.5
                reasons.append(file_reason)
                break

        # Only flag if BOTH login + activity are suspicious
        if risk_score > 0.6:
            reason = f"ACCOUNT TAKEOVER: {' | '.join(reasons)}"
            return min(risk_score, 1.0), reason

        return 0.0, None

    def generate_user_risk_report(self, username: str, recent_events: List[Dict]) -> Dict:
        """
        Generate comprehensive risk report for user.

        Combines all behavior analysis into single risk score.
        """
        if username not in self.user_profiles:
            self.create_user_profile(username, [])

        report = {
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0.0,
            "risk_level": "LOW",
            "findings": [],
            "recommendations": []
        }

        for event in recent_events:
            # Check each behavior type
            if event.get("event_type") == "login":
                login_risk, login_reason = self.detect_anomalous_login(username, event)
                if login_risk > 0.3:
                    report["findings"].append({
                        "type": "Anomalous Login",
                        "risk": login_risk,
                        "detail": login_reason
                    })
                    report["risk_score"] = max(report["risk_score"], login_risk)

            elif event.get("event_type") == "file_access":
                exfil_risk, exfil_reason = self.detect_data_exfiltration(username, event)
                if exfil_risk > 0.3:
                    report["findings"].append({
                        "type": "Data Exfiltration",
                        "risk": exfil_risk,
                        "detail": exfil_reason
                    })
                    report["risk_score"] = max(report["risk_score"], exfil_risk)

            elif event.get("event_type") == "privilege_change":
                priv_risk, priv_reason = self.detect_privilege_abuse(username, event)
                if priv_risk > 0.3:
                    report["findings"].append({
                        "type": "Privilege Abuse",
                        "risk": priv_risk,
                        "detail": priv_reason
                    })
                    report["risk_score"] = max(report["risk_score"], priv_risk)

        # Determine risk level
        if report["risk_score"] >= 0.8:
            report["risk_level"] = "CRITICAL"
            report["recommendations"].append("Disable account immediately")
            report["recommendations"].append("Initiate incident response")
        elif report["risk_score"] >= 0.6:
            report["risk_level"] = "HIGH"
            report["recommendations"].append("Monitor account closely")
            report["recommendations"].append("Review account permissions")
        elif report["risk_score"] >= 0.4:
            report["risk_level"] = "MEDIUM"
            report["recommendations"].append("Investigate findings")
        else:
            report["risk_level"] = "LOW"

        return report

    def get_top_risky_users(self, all_users: Dict[str, List[Dict]], top_n: int = 10) -> List[Dict]:
        """
        Identify top risky users in organization.

        Returns: List of users ranked by risk score
        """
        user_risks = []

        for username, events in all_users.items():
            report = self.generate_user_risk_report(username, events)
            user_risks.append({
                "username": username,
                "risk_score": report["risk_score"],
                "risk_level": report["risk_level"],
                "finding_count": len(report["findings"])
            })

        # Sort by risk
        user_risks.sort(key=lambda x: x["risk_score"], reverse=True)

        return user_risks[:top_n]
