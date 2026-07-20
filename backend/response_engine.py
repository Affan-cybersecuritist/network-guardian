"""
response_engine.py
------------------
Automated response policy execution.

Policies define: if X attack detected → execute Y response

Supports:
- Auto-block IPs
- Auto-notify SIEM
- Auto-create incidents
- Run playbooks (Ansible)
- Coordinated network-wide responses
"""
import yaml
import json
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta

# Default policies
DEFAULT_POLICIES = {
    "ssh_bruteforce": {
        "trigger": "auth_bruteforce_score >= 15",
        "actions": ["block_ip:3600", "notify_siem:high"],
        "enabled": True
    },
    "dns_exfiltration": {
        "trigger": "dns_tunneling_detected",
        "actions": ["block_domain", "snapshot_traffic:600", "notify_siem:critical"],
        "enabled": True
    },
    "sql_injection": {
        "trigger": "waf_sql_injection_detected",
        "actions": ["block_ip:86400", "notify_siem:critical", "create_incident"],
        "enabled": True
    },
    "xss_attack": {
        "trigger": "waf_xss_detected",
        "actions": ["block_ip:3600", "notify_siem:high"],
        "enabled": True
    },
    "command_injection": {
        "trigger": "waf_command_injection_detected",
        "actions": ["block_ip:86400", "notify_siem:critical"],
        "enabled": True
    },
    "active_breach": {
        "trigger": "is_active_breach",
        "actions": ["block_ip:86400", "notify_siem:critical", "create_incident:emergency", "isolate_host"],
        "enabled": True
    }
}


class ResponseEngine:
    def __init__(self, config_path: Optional[str] = None):
        self.policies = DEFAULT_POLICIES
        self.action_history = []
        self.blocked_ips = {}  # {ip: expiry_time}

        if config_path:
            self.load_policies(config_path)

    def load_policies(self, config_path: str):
        """Load policies from YAML file."""
        try:
            with open(config_path, 'r') as f:
                custom_policies = yaml.safe_load(f)
                if custom_policies:
                    self.policies.update(custom_policies)
        except Exception as e:
            print(f"Error loading policies: {e}")

    def execute_response(self, alert: Dict, simulate: bool = False) -> Dict:
        """
        Execute response policy for an alert.

        Args:
            alert: The security alert
            simulate: If True, don't actually execute (for testing)

        Returns: {actions_taken, results}
        """
        execution_log = {
            "alert": alert,
            "timestamp": time.time(),
            "actions_executed": [],
            "results": {},
            "simulated": simulate
        }

        # Find matching policies
        matching_policies = self._find_matching_policies(alert)

        if not matching_policies:
            return {"message": "No matching policies", "actions": []}

        # Execute actions from matching policies
        for policy_name, policy in matching_policies:
            for action in policy.get("actions", []):
                result = self._execute_action(alert, action, simulate=simulate)
                execution_log["actions_executed"].append(action)
                execution_log["results"][action] = result

        # Store in history
        self.action_history.append(execution_log)

        return execution_log

    def _find_matching_policies(self, alert: Dict) -> List[tuple]:
        """Find policies triggered by this alert."""
        matching = []

        for policy_name, policy in self.policies.items():
            if not policy.get("enabled"):
                continue

            trigger = policy.get("trigger", "")

            # Simple trigger matching
            if self._matches_trigger(alert, trigger):
                matching.append((policy_name, policy))

        return matching

    def _matches_trigger(self, alert: Dict, trigger: str) -> bool:
        """Check if alert matches trigger condition."""
        # Simple trigger format: "field >= value" or "field_exists"

        if "auth_bruteforce_score >= 15" in trigger:
            return alert.get("auth_bruteforce_score", 0) >= 15

        if "dns_tunneling_detected" in trigger:
            return "DNS Tunneling" in alert.get("threats_detected", [])

        if "is_active_breach" in trigger:
            return alert.get("is_active_breach", False)

        if "waf_sql_injection_detected" in trigger:
            return "SQL Injection" in alert.get("waf_attacks", [])

        if "waf_xss_detected" in trigger:
            return "XSS" in alert.get("waf_attacks", [])

        if "waf_command_injection_detected" in trigger:
            return "Command Injection" in alert.get("waf_attacks", [])

        return False

    def _execute_action(self, alert: Dict, action: str, simulate: bool = False) -> Dict:
        """Execute a single response action."""
        result = {
            "action": action,
            "status": "executed",
            "simulated": simulate
        }

        # Parse action: "action_name:param"
        parts = action.split(":")
        action_type = parts[0]
        param = parts[1] if len(parts) > 1 else None

        try:
            if action_type == "block_ip":
                duration = int(param) if param else 3600
                src_ip = alert.get("src_ip")
                result["details"] = self._action_block_ip(src_ip, duration, simulate)

            elif action_type == "notify_siem":
                severity = param or "high"
                result["details"] = self._action_notify_siem(alert, severity, simulate)

            elif action_type == "create_incident":
                priority = param or "high"
                result["details"] = self._action_create_incident(alert, priority, simulate)

            elif action_type == "block_domain":
                domain = alert.get("domain")
                result["details"] = self._action_block_domain(domain, simulate)

            elif action_type == "snapshot_traffic":
                duration = int(param) if param else 600
                result["details"] = self._action_snapshot_traffic(alert, duration, simulate)

            elif action_type == "isolate_host":
                src_ip = alert.get("src_ip")
                result["details"] = self._action_isolate_host(src_ip, simulate)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result

    def _action_block_ip(self, ip: str, duration: int, simulate: bool) -> Dict:
        """Block IP address."""
        expiry = time.time() + duration

        if not simulate:
            self.blocked_ips[ip] = expiry
            # In production: call firewall.block_ip(ip, duration)

        return {
            "ip": ip,
            "duration_seconds": duration,
            "expiry_time": datetime.fromtimestamp(expiry).isoformat()
        }

    def _action_notify_siem(self, alert: Dict, severity: str, simulate: bool) -> Dict:
        """Notify SIEM system."""
        notification = {
            "severity": severity,
            "alert_id": alert.get("src_ip"),
            "timestamp": datetime.now().isoformat(),
            "alert_summary": alert.get("reasons", [])
        }

        if not simulate:
            # In production: call siem.send_alert(notification)
            pass

        return notification

    def _action_create_incident(self, alert: Dict, priority: str, simulate: bool) -> Dict:
        """Create incident ticket."""
        incident = {
            "title": f"Security Alert: {alert.get('src_ip')}",
            "priority": priority,
            "description": "\n".join(alert.get("reasons", [])),
            "assigned_to": "security_team",
            "created_at": datetime.now().isoformat()
        }

        if not simulate:
            # In production: call ticketing_system.create(incident)
            pass

        return incident

    def _action_block_domain(self, domain: str, simulate: bool) -> Dict:
        """Block a domain."""
        if not simulate:
            # In production: update DNS/firewall rules
            pass

        return {
            "domain": domain,
            "action": "blocked"
        }

    def _action_snapshot_traffic(self, alert: Dict, duration: int, simulate: bool) -> Dict:
        """Capture network traffic for forensics."""
        if not simulate:
            # In production: start tcpdump or equivalent
            pass

        return {
            "src_ip": alert.get("src_ip"),
            "capture_duration": duration,
            "saved_to": f"/forensics/{alert.get('src_ip')}_capture.pcap"
        }

    def _action_isolate_host(self, ip: str, simulate: bool) -> Dict:
        """Isolate compromised host from network."""
        if not simulate:
            # In production: disconnect host / quarantine
            pass

        return {
            "host_ip": ip,
            "action": "isolated",
            "timestamp": datetime.now().isoformat()
        }

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs."""
        now = time.time()
        active_blocks = {ip: expiry for ip, expiry in self.blocked_ips.items() if expiry > now}
        return list(active_blocks.keys())

    def get_action_history(self, limit: int = 100) -> List[Dict]:
        """Get recent action history."""
        return self.action_history[-limit:]
