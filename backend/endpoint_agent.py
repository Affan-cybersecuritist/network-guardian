"""
endpoint_agent.py
-----------------
Endpoint Detection & Response (EDR) - detect malware and suspicious processes on hosts.

Detects:
- Malware (signature + behavior)
- Ransomware (file encryption patterns)
- Privilege escalation attempts
- Suspicious process creation
- Process injection/hollowing
- Lateral movement from endpoint
"""
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib
import re


class EndpointAgent:
    """Lightweight agent for endpoint security"""

    def __init__(self, endpoint_id: str, os_type: str = "windows"):
        self.endpoint_id = endpoint_id
        self.os_type = os_type.lower()
        self.process_baseline = {}
        self.detected_threats = []

    def scan_process_list(self, processes: List[Dict]) -> Dict:
        """
        Scan running processes for malware indicators.

        Returns: threats found + risk score
        """
        findings = {
            "suspicious_processes": [],
            "risk_score": 0,
            "threat_count": 0
        }

        for proc in processes:
            pid = proc.get("pid")
            name = proc.get("name", "").lower()
            path = proc.get("path", "").lower()
            parent_pid = proc.get("parent_pid")
            user = proc.get("user", "system")

            # Check 1: Known malware process names
            malware_processes = {
                "svchost.exe": "commonly_abused",
                "explorer.exe": "commonly_abused",
                "rundll32.exe": "dll_injection",
                "powershell.exe": "script_execution",
                "cmd.exe": "command_execution",
                "wmic.exe": "system_reconnaissance"
            }

            for malware_proc, category in malware_processes.items():
                if name == malware_proc and category == "dll_injection":
                    findings["suspicious_processes"].append({
                        "pid": pid,
                        "name": name,
                        "reason": f"{malware_proc} used for DLL injection",
                        "risk": 70
                    })
                    findings["risk_score"] += 0.3
                    findings["threat_count"] += 1

            # Check 2: Process in suspicious location
            suspicious_paths = [
                "\\appdata\\",
                "\\temp\\",
                "\\windows\\temp\\",
                "\\programdata\\",
                "\\recycle.bin\\"
            ]

            for susp_path in suspicious_paths:
                if susp_path in path:
                    findings["suspicious_processes"].append({
                        "pid": pid,
                        "name": name,
                        "reason": f"Executable in suspicious location: {path}",
                        "risk": 60
                    })
                    findings["risk_score"] += 0.25
                    findings["threat_count"] += 1
                    break

            # Check 3: System process from non-system user
            system_processes = ["svchost", "lsass", "services", "smss"]
            for sys_proc in system_processes:
                if sys_proc in name.lower() and user.lower() != "system":
                    findings["suspicious_processes"].append({
                        "pid": pid,
                        "name": name,
                        "reason": f"System process {name} running as {user}",
                        "risk": 85
                    })
                    findings["risk_score"] += 0.4
                    findings["threat_count"] += 1
                    break

            # Check 4: Hidden process detection
            if proc.get("hidden", False):
                findings["suspicious_processes"].append({
                    "pid": pid,
                    "name": name,
                    "reason": "Hidden process detected",
                    "risk": 90
                })
                findings["risk_score"] += 0.5
                findings["threat_count"] += 1

        findings["risk_score"] = min(findings["risk_score"], 1.0)
        return findings

    def detect_ransomware(self, file_operations: List[Dict]) -> Tuple[float, Optional[str]]:
        """
        Detect ransomware by file operation patterns.

        Ransomware: rapid file encryption, specific extensions, mass operations.
        """
        risk_score = 0.0
        reasons = []

        # Count file operations by type
        rename_count = sum(1 for f in file_operations if f.get("operation") == "rename")
        write_count = sum(1 for f in file_operations if f.get("operation") == "write")
        delete_count = sum(1 for f in file_operations if f.get("operation") == "delete")

        # Check 1: Mass file renames (common ransomware behavior)
        if rename_count > 100:
            risk_score += 0.7
            reasons.append(f"Mass file rename operations: {rename_count} files")

        # Check 2: Specific file extensions being created (ransom note)
        extensions = [f.get("extension", "") for f in file_operations if f.get("operation") == "create"]
        ransom_extensions = [".encryptojon", ".cerber", ".locky", ".cryptowall", ".ransomware"]

        ransom_found = [ext for ext in ransom_extensions if ext in extensions]
        if ransom_found:
            risk_score += 0.8
            reasons.append(f"Ransom note extensions detected: {ransom_found}")

        # Check 3: Rapid encryption pattern
        write_speed = write_count / len(file_operations) if file_operations else 0
        if write_speed > 0.5:  # >50% of operations are writes
            risk_score += 0.6
            reasons.append(f"Rapid file write pattern detected: {write_speed:.0%} writes")

        reason = " | ".join(reasons) if reasons else None
        return min(risk_score, 1.0), reason

    def detect_process_injection(self, process_events: List[Dict]) -> Tuple[float, Optional[str]]:
        """
        Detect process injection/hollowing attacks.

        Parent process spawning child with unusual characteristics.
        """
        risk_score = 0.0
        reasons = []

        for event in process_events:
            parent = event.get("parent_name", "").lower()
            child = event.get("child_name", "").lower()

            # Check 1: Unusual parent-child combinations
            suspicious_spawns = {
                "explorer.exe": ["powershell", "cmd", "rundll32", "regsvcs", "csc"],
                "svchost.exe": ["cmd", "powershell", "taskmgr"],
                "winlogon.exe": ["cmd", "powershell", "explorer"],
            }

            for parent_proc, children in suspicious_spawns.items():
                if parent == parent_proc:
                    for child_proc in children:
                        if child_proc in child:
                            risk_score += 0.6
                            reasons.append(f"Suspicious spawn: {parent} → {child}")

            # Check 2: Process memory anomaly
            memory_diff = abs(event.get("memory_size", 0) - event.get("expected_memory", 0))
            if memory_diff > 50_000_000:  # 50MB difference from expected
                risk_score += 0.5
                reasons.append(f"Unusual memory size for {child}")

            # Check 3: Process hollow/replacement
            if event.get("hollowed", False):
                risk_score += 0.9
                reasons.append(f"Process hollowing detected in {child}")

        reason = " | ".join(reasons[:3]) if reasons else None  # Top 3 reasons
        return min(risk_score, 1.0), reason

    def detect_privilege_escalation(self, priv_events: List[Dict]) -> Tuple[float, Optional[str]]:
        """
        Detect privilege escalation on endpoint.

        User → Admin, LocalService → System, etc.
        """
        risk_score = 0.0
        reasons = []

        for event in priv_events:
            from_priv = event.get("from_privilege", "user")
            to_priv = event.get("to_privilege", "user")
            method = event.get("method", "unknown")

            # Check 1: Elevation to SYSTEM
            if to_priv == "system" and from_priv != "system":
                risk_score += 0.8
                reasons.append(f"Privilege escalation to SYSTEM via {method}")

            # Check 2: Unusual elevation method
            suspicious_methods = ["exploiting", "registry", "vulnerable_driver", "token_impersonation"]
            if method in suspicious_methods:
                risk_score += 0.7
                reasons.append(f"Suspicious elevation method: {method}")

            # Check 3: UAC bypass
            if event.get("uac_bypassed", False):
                risk_score += 0.9
                reasons.append("UAC bypass detected")

        reason = " | ".join(reasons) if reasons else None
        return min(risk_score, 1.0), reason

    def scan_file_hash(self, file_path: str, file_hash: str) -> Dict:
        """
        Check file hash against known malware database (VirusTotal-like).

        Returns: threat info if malware found
        """
        # Simulated malware hash database
        malware_hashes = {
            "5d41402abc4b2a76b9719d911017c592": "trojan_generic",
            "6512bd43d9caa6e02c990b0a82652dca": "ransomware_generic",
            "c20ad4d76fe97759aa27a0c99bff6710": "worm_generic",
        }

        if file_hash in malware_hashes:
            return {
                "detected": True,
                "malware_family": malware_hashes[file_hash],
                "risk_score": 95,
                "recommendation": "QUARANTINE"
            }

        return {"detected": False, "risk_score": 0}

    def analyze_network_connections(self, connections: List[Dict]) -> Dict:
        """
        Analyze endpoint's network connections for C2 communication.

        Looks for: known malicious IPs, unusual ports, encrypted channels.
        """
        findings = {
            "suspicious_connections": [],
            "risk_score": 0
        }

        # Known C2 infrastructure
        known_malicious_ips = {
            "203.0.113.1": "known_c2_server",
            "198.51.100.50": "botnet_command",
        }

        # Unusual ports for common services
        unusual_ports = {
            22: "ssh",  # If not from server team
            3389: "rdp",
            5985: "winrm",
            4444: "known_backdoor"
        }

        for conn in connections:
            dest_ip = conn.get("destination_ip")
            dest_port = conn.get("destination_port")
            protocol = conn.get("protocol", "tcp")

            # Check 1: Known malicious IP
            if dest_ip in known_malicious_ips:
                findings["suspicious_connections"].append({
                    "destination": f"{dest_ip}:{dest_port}",
                    "reason": f"Known C2: {known_malicious_ips[dest_ip]}",
                    "risk": 95
                })
                findings["risk_score"] += 0.5

            # Check 2: Unusual port
            if dest_port in unusual_ports and dest_port != 443:  # Not HTTPS
                findings["suspicious_connections"].append({
                    "destination": f"{dest_ip}:{dest_port}",
                    "reason": f"Unusual port for {unusual_ports[dest_port]}",
                    "risk": 70
                })
                findings["risk_score"] += 0.3

        findings["risk_score"] = min(findings["risk_score"], 1.0)
        return findings

    def generate_endpoint_report(self, endpoint_data: Dict) -> Dict:
        """
        Comprehensive endpoint security report.

        Combines all threat detections into single risk assessment.
        """
        report = {
            "endpoint_id": self.endpoint_id,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0.0,
            "threat_level": "CLEAN",
            "threats_found": [],
            "recommendations": []
        }

        # Run all detections
        process_risk = self.scan_process_list(endpoint_data.get("processes", []))
        ransomware_risk, ransomware_reason = self.detect_ransomware(
            endpoint_data.get("file_operations", [])
        )
        injection_risk, injection_reason = self.detect_process_injection(
            endpoint_data.get("process_events", [])
        )
        priv_risk, priv_reason = self.detect_privilege_escalation(
            endpoint_data.get("privilege_events", [])
        )
        network_risk = self.analyze_network_connections(endpoint_data.get("connections", []))

        # Aggregate risks
        all_risks = [
            process_risk.get("risk_score", 0),
            ransomware_risk,
            injection_risk,
            priv_risk,
            network_risk.get("risk_score", 0)
        ]

        report["risk_score"] = max(all_risks)

        # Add findings
        if process_risk.get("threat_count", 0) > 0:
            report["threats_found"].append(f"Suspicious processes: {process_risk['threat_count']}")

        if ransomware_risk > 0.5:
            report["threats_found"].append(f"Ransomware indicators: {ransomware_reason}")

        if injection_risk > 0.5:
            report["threats_found"].append(f"Process injection: {injection_reason}")

        if priv_risk > 0.5:
            report["threats_found"].append(f"Privilege escalation: {priv_reason}")

        if len(network_risk.get("suspicious_connections", [])) > 0:
            report["threats_found"].append(f"C2 connections: {len(network_risk['suspicious_connections'])}")

        # Determine threat level
        if report["risk_score"] >= 0.8:
            report["threat_level"] = "CRITICAL"
            report["recommendations"] = [
                "Isolate endpoint immediately",
                "Initiate incident response",
                "Collect forensics",
                "Disable user accounts"
            ]
        elif report["risk_score"] >= 0.6:
            report["threat_level"] = "HIGH"
            report["recommendations"] = [
                "Isolate if possible",
                "Investigate threats",
                "Run full scan"
            ]
        elif report["risk_score"] >= 0.4:
            report["threat_level"] = "MEDIUM"
            report["recommendations"] = ["Monitor closely", "Run scans"]
        else:
            report["threat_level"] = "CLEAN"

        return report
