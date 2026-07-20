"""
event_log_analyzer.py
---------------------
Correlates network alerts with host-level events from Windows/Linux.

Bridges the gap between:
- Network detection (alert fired)
- Host confirmation (attack actually worked)

Detects:
- Failed login attempts on same IP as network alert
- Successful breach after failed attempts
- Privilege escalation attempts
- Suspicious process execution
"""
import subprocess
import json
import time
from typing import Dict, List, Optional
import platform
import os

# Windows Event Log event IDs
WINDOWS_FAILED_LOGIN = 4625
WINDOWS_SUCCESS_LOGIN = 4624
WINDOWS_PRIVILEGE_ESCALATION = 4672
WINDOWS_PROCESS_CREATION = 4688


def query_windows_event_log(event_id: int, ip: str = None, minutes: int = 5) -> List[Dict]:
    """
    Query Windows Security Event Log for specific events.

    Requires: Event Log Reader permission (usually Administrator)
    """
    if platform.system() != "Windows":
        return []

    try:
        import wmi
    except ImportError:
        return []  # wmi not available

    try:
        c = wmi.WMI(moniker="//./root/cimv2")

        # Build WQL query
        if event_id == WINDOWS_FAILED_LOGIN:
            query = f"""
            SELECT * FROM Win32_NTLogEvent
            WHERE LogFile='Security' AND EventCode={WINDOWS_FAILED_LOGIN}
            AND TimeGenerated>'{get_wmi_time(minutes)}'
            """
        else:
            query = f"""
            SELECT * FROM Win32_NTLogEvent
            WHERE LogFile='Security' AND EventCode={event_id}
            AND TimeGenerated>'{get_wmi_time(minutes)}'
            """

        events = c.query(query)

        results = []
        for event in events:
            results.append({
                "event_id": event_id,
                "timestamp": event.TimeGenerated,
                "source": event.SourceName,
                "message": event.Message or "",
                "user": event.User or "",
                "computer": event.ComputerName
            })

        return results
    except Exception as e:
        print(f"Error querying Windows Event Log: {e}")
        return []


def query_linux_auth_logs(ip: str, minutes: int = 5) -> Dict:
    """
    Query Linux authentication logs for failed/successful logins.

    Requires: read access to /var/log/auth.log
    """
    if platform.system() != "Linux":
        return {"failed": 0, "successful": 0}

    try:
        # Get auth log path (varies by distro)
        auth_log = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"

        if not os.path.exists(auth_log):
            return {"failed": 0, "successful": 0}

        # grep for failed logins from IP
        result = subprocess.run(
            ["grep", f"from {ip}", auth_log],
            capture_output=True,
            text=True,
            timeout=5
        )

        lines = result.stdout.split('\n')
        failed = sum(1 for line in lines if "Failed password" in line or "Invalid user" in line)
        successful = sum(1 for line in lines if "Accepted" in line)

        return {
            "failed": failed,
            "successful": successful,
            "total": len([l for l in lines if l.strip()])
        }
    except Exception as e:
        print(f"Error querying auth logs: {e}")
        return {"failed": 0, "successful": 0}


def correlate_network_and_host(network_alert: Dict) -> Dict:
    """
    Correlate network alert with host-level evidence.

    Returns correlation data and risk boost.
    """
    src_ip = network_alert.get("src_ip", "")
    if not src_ip:
        return {"correlation_found": False, "risk_boost": 0}

    correlation = {
        "src_ip": src_ip,
        "network_alert": network_alert.get("reason", ""),
        "host_evidence": {},
        "correlation_found": False,
        "risk_boost": 0,
        "confidence": "low"
    }

    # Query host logs
    if platform.system() == "Windows":
        host_logs = query_windows_event_log(WINDOWS_FAILED_LOGIN, src_ip, minutes=30)

        if host_logs:
            correlation["host_evidence"]["failed_logins"] = len(host_logs)
            correlation["host_evidence"]["failed_accounts"] = list(set(
                log.get("user", "unknown") for log in host_logs
            ))
            correlation["correlation_found"] = True

            # Check for successful login after failed attempts
            success_logs = query_windows_event_log(WINDOWS_SUCCESS_LOGIN, src_ip, minutes=30)
            if success_logs:
                correlation["host_evidence"]["successful_logins"] = len(success_logs)
                correlation["risk_boost"] = 40  # MAJOR BOOST - breach succeeded
                correlation["confidence"] = "very_high"
            else:
                correlation["risk_boost"] = 20  # Moderate boost - attempts detected
                correlation["confidence"] = "high"

    else:  # Linux
        host_logs = query_linux_auth_logs(src_ip, minutes=30)

        if host_logs["failed"] > 0:
            correlation["host_evidence"]["failed_logins"] = host_logs["failed"]
            correlation["correlation_found"] = True

            if host_logs["successful"] > 0:
                correlation["host_evidence"]["successful_logins"] = host_logs["successful"]
                correlation["risk_boost"] = 40
                correlation["confidence"] = "very_high"
            else:
                correlation["risk_boost"] = 20
                correlation["confidence"] = "high"

    return correlation


def detect_privilege_escalation(ip: str = None) -> Dict:
    """
    Detect if attacker attempted/succeeded with privilege escalation.
    """
    escalation = {
        "detected": False,
        "type": None,
        "severity": "low"
    }

    if platform.system() == "Windows":
        try:
            # Event ID 4672 = Special privileges assigned
            events = query_windows_event_log(WINDOWS_PRIVILEGE_ESCALATION, minutes=30)

            if events:
                escalation["detected"] = True
                escalation["type"] = "windows_privilege_assignment"
                escalation["severity"] = "high"
                escalation["event_count"] = len(events)
        except:
            pass

    else:  # Linux
        try:
            # Check for sudo usage or su commands
            result = subprocess.run(
                ["grep", "-E", "sudo.*COMMAND|su\\[", "/var/log/auth.log"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.stdout:
                escalation["detected"] = True
                escalation["type"] = "linux_privilege_escalation"
                escalation["severity"] = "high"
        except:
            pass

    return escalation


def detect_breach_completion(network_alert: Dict, host_correlation: Dict) -> bool:
    """
    Determine if this is an active breach (network attack + successful host compromise).

    Returns True if attack succeeded on the host.
    """
    # Strong indicators of breach:
    # 1. SSH/HTTP brute-force detected (network)
    # 2. Failed logins detected on same IP (host)
    # 3. Successful login after failures (host)

    if not host_correlation.get("correlation_found"):
        return False

    if host_correlation.get("confidence") == "very_high":
        return True

    # Also check for post-exploitation indicators
    if "privilege_escalation" in network_alert.get("reasons", []):
        return True

    return False


def get_wmi_time(minutes_ago: int) -> str:
    """Convert minutes ago to WMI timestamp format."""
    import datetime
    past = datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)
    return past.strftime("%Y%m%d%H%M%S")


def analyze_alert_with_host_context(network_alert: Dict) -> Dict:
    """
    Main function: Take network alert and enrich with host context.

    Returns enhanced alert with host evidence and boosted risk score.
    """
    # Get host evidence
    correlation = correlate_network_and_host(network_alert)
    escalation = detect_privilege_escalation()
    is_breach = detect_breach_completion(network_alert, correlation)

    # Build enriched alert
    enhanced_alert = network_alert.copy()
    enhanced_alert["host_correlation"] = correlation
    enhanced_alert["privilege_escalation"] = escalation
    enhanced_alert["is_active_breach"] = is_breach

    # Boost risk score based on host evidence
    original_risk = enhanced_alert.get("risk_score", 0)
    risk_boost = correlation.get("risk_boost", 0)

    if escalation["detected"]:
        risk_boost += 15

    if is_breach:
        enhanced_alert["severity"] = "CRITICAL"
        enhanced_alert["risk_score"] = min(100, original_risk + risk_boost)
    else:
        enhanced_alert["risk_score"] = original_risk + risk_boost

    # Add evidence to reasons
    if correlation["correlation_found"]:
        enhanced_alert["reasons"] = enhanced_alert.get("reasons", []) + [
            f"Host correlation confirmed: {correlation['host_evidence']}"
        ]

    if escalation["detected"]:
        enhanced_alert["reasons"].append(f"Privilege escalation detected: {escalation['type']}")

    if is_breach:
        enhanced_alert["reasons"].append("ACTIVE BREACH IN PROGRESS - successful host compromise detected")

    return enhanced_alert
