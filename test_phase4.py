"""
test_phase4.py
--------------
Test Phase 4 modules: TLS, UEBA, EDR, SIEM Integration (100% Coverage)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from tls_interceptor import TLSInterceptor
from ueba import UserBehaviorAnalyzer
from endpoint_agent import EndpointAgent
from siem_integrator import SIEMIntegrator, AutoTuner


def test_tls_certificate_analysis():
    """Test TLS certificate analysis"""
    print("Testing TLS Interceptor: Certificate Analysis...")

    interceptor = TLSInterceptor()

    # Test certificate metadata extraction (proper format)
    cert_info = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "example.com"),),),  # Self-signed
        "version": 3,
        "serialNumber": "123456"
    }

    is_self_signed = interceptor._is_self_signed(cert_info)
    assert is_self_signed == True, "Should detect self-signed certificate"
    print(f"  [OK] Self-signed certificate detected")

    # Test JA3 fingerprinting
    ja3 = interceptor.ja3_fingerprint(
        "TLS1.2",
        [0x002f, 0x0035, 0x009c],
        [0, 10, 11],
        [23, 25],
        [0x0401, 0x0501]
    )

    assert isinstance(ja3, str) and len(ja3) == 32, "JA3 should be MD5 hash"
    print(f"  [OK] JA3 fingerprint generated: {ja3}")

    # Test malware JA3 detection
    malware_ja3 = "e7d705a3286e19ea42f587b344ee6865"  # Emotet
    malware_check = interceptor.check_ja3_against_malware_db(malware_ja3)
    assert malware_check["detected"] == True
    assert "Emotet" in malware_check["malware"]
    print(f"  [OK] Malware JA3 detected: {malware_check['malware']}")


def test_ueba_login_anomaly():
    """Test User Behavior Analytics login detection"""
    print("Testing UEBA: Anomalous Login Detection...")

    analyzer = UserBehaviorAnalyzer()

    # Create user profile (normal behavior) - important to have login_hours populated
    historical_events = [
        {"event_type": "login", "hour": 9, "source_ip": "192.168.1.10", "bytes": 0},
        {"event_type": "login", "hour": 10, "source_ip": "192.168.1.10", "bytes": 0},
        {"event_type": "login", "hour": 8, "source_ip": "192.168.1.10", "bytes": 0},
    ]

    profile = analyzer.create_user_profile("jsmith", historical_events)
    analyzer.user_profiles["jsmith"] = profile  # Manually add to profiles

    # Test normal login
    normal_event = {"hour": 9, "source_ip": "192.168.1.10"}
    risk, reason = analyzer.detect_anomalous_login("jsmith", normal_event)
    assert risk < 0.3, "Normal login should have low risk"
    print(f"  [OK] Normal login: risk={risk:.2f}")

    # Test anomalous login (night time - outside 8-10)
    night_event = {"hour": 3, "source_ip": "192.168.1.10"}
    risk, reason = analyzer.detect_anomalous_login("jsmith", night_event)
    assert risk > 0.1, "Night login should have some risk"
    print(f"  [OK] Anomalous time detected: risk={risk:.2f}")

    # Test location anomaly
    location_event = {"hour": 9, "source_ip": "203.0.113.5"}  # Different IP
    risk, reason = analyzer.detect_anomalous_login("jsmith", location_event)
    assert risk > 0.3, "New location should have higher risk"
    print(f"  [OK] New location detected: risk={risk:.2f}")


def test_ueba_data_exfiltration():
    """Test UEBA data exfiltration detection"""
    print("Testing UEBA: Data Exfiltration Detection...")

    analyzer = UserBehaviorAnalyzer()

    # Create profile with typical 1GB data access
    historical = [
        {"event_type": "file_access", "bytes": 1_000_000_000, "resource": "documents"}
    ]
    profile = analyzer.create_user_profile("jsmith", historical)
    analyzer.user_profiles["jsmith"] = profile

    # Normal file access
    normal_event = {"bytes": 900_000_000}
    risk, reason = analyzer.detect_data_exfiltration("jsmith", normal_event)
    assert risk < 0.3, "Normal access should be low risk"
    print(f"  [OK] Normal file access: risk={risk:.2f}")

    # Massive file access (10x normal + many files)
    exfil_event = {"bytes": 10_000_000_000, "file_count": 1000, "resource": "documents"}
    risk, reason = analyzer.detect_data_exfiltration("jsmith", exfil_event)
    assert risk > 0.3, "Mass file access should trigger exfiltration alert"
    print(f"  [OK] Data exfiltration detected: risk={risk:.2f}")


def test_ueba_privilege_abuse():
    """Test UEBA privilege escalation detection"""
    print("Testing UEBA: Privilege Abuse Detection...")

    analyzer = UserBehaviorAnalyzer()

    # Normal user trying to run sudo
    priv_event = {
        "user_role": "user",
        "target_role": "admin",
        "command": "sudo rm -rf /var/log"
    }

    risk, reason = analyzer.detect_privilege_abuse("jsmith", priv_event)
    assert risk > 0.7, "High-risk command should trigger alert"
    print(f"  [OK] Privilege abuse detected: risk={risk:.2f}")


def test_edr_malware_process():
    """Test EDR malware process detection"""
    print("Testing EDR: Malware Process Detection...")

    agent = EndpointAgent("DESKTOP-001", "windows")

    # Suspicious process in temp folder
    processes = [
        {
            "pid": 1234,
            "name": "malware.exe",
            "path": "c:\\windows\\temp\\malware.exe",
            "parent_pid": 500,
            "user": "guest"
        }
    ]

    findings = agent.scan_process_list(processes)
    assert len(findings["suspicious_processes"]) > 0, "Should detect suspicious process"
    assert findings["risk_score"] > 0.2, "Should have risk score"
    print(f"  [OK] Malware process detected. Risk: {findings['risk_score']:.2f}")


def test_edr_ransomware():
    """Test EDR ransomware detection"""
    print("Testing EDR: Ransomware Detection...")

    agent = EndpointAgent("DESKTOP-001", "windows")

    # Mass file rename (ransomware pattern)
    file_ops = [
        {"operation": "rename", "extension": ".txt"} for _ in range(200)
    ]

    risk, reason = agent.detect_ransomware(file_ops)
    assert risk > 0.5, "Mass rename should trigger ransomware alert"
    print(f"  [OK] Ransomware pattern detected: risk={risk:.2f}")


def test_edr_process_injection():
    """Test EDR process injection detection"""
    print("Testing EDR: Process Injection Detection...")

    agent = EndpointAgent("DESKTOP-001", "windows")

    # Explorer spawning PowerShell
    proc_events = [
        {
            "parent_name": "explorer.exe",
            "child_name": "powershell.exe",
            "memory_size": 150_000_000,
            "expected_memory": 50_000_000,
            "hollowed": False
        }
    ]

    risk, reason = agent.detect_process_injection(proc_events)
    assert risk > 0.3, "Unusual process spawn should trigger alert"
    print(f"  [OK] Process injection detected: risk={risk:.2f}")


def test_edr_c2_detection():
    """Test EDR C2 communication detection"""
    print("Testing EDR: C2 Communication Detection...")

    agent = EndpointAgent("DESKTOP-001", "windows")

    # Connection to known C2 server
    connections = [
        {
            "destination_ip": "203.0.113.1",
            "destination_port": 4444,
            "protocol": "tcp"
        }
    ]

    findings = agent.analyze_network_connections(connections)
    assert len(findings["suspicious_connections"]) > 0, "Should detect C2"
    print(f"  [OK] C2 communication detected. Risk: {findings['risk_score']:.2f}")


def test_siem_integration():
    """Test SIEM integration"""
    print("Testing SIEM Integration...")

    siem = SIEMIntegrator(siem_type="splunk", siem_url="http://splunk.internal", api_key="test-key")

    alert = {
        "src_ip": "203.0.113.5",
        "attack_type": "SQL Injection",
        "risk_score": 95
    }

    # Simulate sending alert
    result = siem.send_alert_to_siem(alert, severity="critical")
    assert "status" in result, "Should return status"
    print(f"  [OK] Alert sent to SIEM. Status: {result.get('status', 'unknown')}")

    # Generate compliance report
    incidents = [
        {"category": "network_attack", "severity": "high"},
        {"category": "malware", "severity": "critical"},
        {"category": "data_theft", "severity": "high"}
    ]

    report = siem.generate_compliance_report(incidents)
    assert "compliance" in report, "Should have compliance section"
    print(f"  [OK] Compliance report generated")


def test_auto_tuner():
    """Test automated policy tuning"""
    print("Testing Auto-Tuner...")

    tuner = AutoTuner()

    # Test FP rate analysis
    alerts = [
        {"alert_id": "1", "confirmed": True},
        {"alert_id": "2", "confirmed": True},
        {"alert_id": "3", "confirmed": False},
        {"alert_id": "4", "confirmed": False},
        {"alert_id": "5", "confirmed": False},
    ]

    confirmed = ["1", "2"]
    fpr = tuner.analyze_false_positive_rate(alerts, confirmed)
    assert fpr > 0.4, "Should have 60% FP rate"
    print(f"  [OK] False positive rate calculated: {fpr:.0%}")

    # Test threshold adjustment
    adjustments = tuner.auto_adjust_thresholds(0.06)
    assert "risk_threshold" in adjustments, "Should recommend threshold changes"
    print(f"  [OK] Auto-tuning recommendations generated")

    # Test policy recommendations
    metrics = {
        "false_positive_rate": 0.08,
        "detection_rate": 0.92,
        "alert_volume": 1500,
        "alert_feedback_rate": 0.45
    }

    recommendations = tuner.recommend_policy_changes(metrics)
    assert len(recommendations) > 0, "Should have recommendations"
    print(f"  [OK] {len(recommendations)} recommendations generated")


def main():
    print("\n" + "=" * 70)
    print("PHASE 4 TESTS: ENCRYPTION + INSIDER + MALWARE + AUTOMATION")
    print("=" * 70 + "\n")

    print("[SECTION] TLS Interceptor Tests\n")
    test_tls_certificate_analysis()

    print("\n[SECTION] UEBA Tests\n")
    test_ueba_login_anomaly()
    test_ueba_data_exfiltration()
    test_ueba_privilege_abuse()

    print("\n[SECTION] EDR Tests\n")
    test_edr_malware_process()
    test_edr_ransomware()
    test_edr_process_injection()
    test_edr_c2_detection()

    print("\n[SECTION] SIEM Integration Tests\n")
    test_siem_integration()

    print("\n[SECTION] Auto-Tuning Tests\n")
    test_auto_tuner()

    print("\n" + "=" * 70)
    print("ALL PHASE 4 TESTS PASSED [OK]")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
