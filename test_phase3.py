"""
test_phase3.py
--------------
Test Phase 3 modules: Model Retraining + Distributed Sensors
"""
import sys
import os
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from model_trainer import ModelTrainer
from sensor_network import SensorNode, SensorNetwork


def test_model_trainer_baseline():
    """Test baseline learning"""
    print("Testing Model Trainer: Baseline Creation...")

    trainer = ModelTrainer()

    # Simulate historical data
    data = pd.DataFrame({
        "protocol_type": ["tcp", "udp", "tcp", "icmp"],
        "service": ["http", "dns", "ssh", "icmp"],
        "src_bytes": [1000, 500, 2000, 100],
        "dst_bytes": [2000, 100, 1000, 50],
        "count": [5, 3, 10, 1],
        "duration": [60, 30, 120, 5]
    })

    baseline = trainer.create_baseline_profile(data)

    assert "sample_size" in baseline
    assert baseline["sample_size"] == 4
    assert "protocols" in baseline
    assert "services" in baseline
    print(f"  [OK] Baseline created. Sample size: {baseline['sample_size']}, Protocols: {baseline['protocols']}")


def test_model_trainer_drift_detection():
    """Test concept drift detection"""
    print("Testing Model Trainer: Drift Detection...")

    trainer = ModelTrainer()

    # Create baseline from normal data
    baseline_data = pd.DataFrame({
        "protocol_type": ["tcp"] * 5,
        "service": ["http"] * 5,
        "src_bytes": [1000] * 5,
        "dst_bytes": [2000] * 5,
        "count": [5] * 5,
        "duration": [60] * 5
    })

    baseline = trainer.create_baseline_profile(baseline_data)

    # Create "drifted" data with HIGH byte volume change
    drifted_data = pd.DataFrame({
        "protocol_type": ["tcp", "udp", "icmp", "tcp", "igmp"],  # New protocols!
        "service": ["http", "dns", "icmp", "http", "igmp"],
        "src_bytes": [5000, 4000, 4500, 5500, 4800],  # WAY higher than baseline (1000)
        "dst_bytes": [6000, 5000, 5500, 6500, 5800],
        "count": [50, 40, 45, 55, 48],  # 10x higher than baseline (5)
        "duration": [60, 30, 5, 120, 1]
    })

    drift_score, reason = trainer.detect_concept_drift(drifted_data, baseline)

    # With high byte volume change (5x+) we should get drift detection
    assert drift_score > 0.1, f"Should detect some drift, got {drift_score}"
    print(f"  [OK] Drift detection working. Score: {drift_score:.2f}, Reason: {str(reason)[:50] if reason else 'N/A'}...")


def test_model_trainer_retrain_decision():
    """Test retrain decision logic"""
    print("Testing Model Trainer: Retrain Decision...")

    trainer = ModelTrainer()

    # High drift → should retrain
    should_retrain_drift = trainer.should_retrain(drift_score=0.6, days_since_retrain=1)
    assert should_retrain_drift == True
    print(f"  [OK] High drift triggers retrain: {should_retrain_drift}")

    # Time-based → should retrain
    should_retrain_time = trainer.should_retrain(drift_score=0.1, days_since_retrain=7)
    assert should_retrain_time == True
    print(f"  [OK] Weekly retrain triggers: {should_retrain_time}")

    # No trigger
    should_retrain_none = trainer.should_retrain(drift_score=0.1, days_since_retrain=1)
    assert should_retrain_none == False
    print(f"  [OK] No retrain when drift low and time short: {should_retrain_none}")


def test_model_trainer_health_check():
    """Test model health monitoring"""
    print("Testing Model Trainer: Health Check...")

    trainer = ModelTrainer()

    # Create alert data
    alerts = [
        {"flagged": True, "risk_score": 75},
        {"flagged": True, "risk_score": 65},
        {"flagged": False, "risk_score": 20},
        {"flagged": False, "risk_score": 15},
        {"flagged": False, "risk_score": 10},
    ] * 20  # 100 alerts total, ~8% flagged rate

    health = trainer.periodic_health_check(alerts)

    assert "status" in health
    assert health["total_alerts"] == 100
    assert health["alert_rate"] > 0
    print(f"  [OK] Health check complete. Status: {health['status']}, Alert rate: {health['alert_rate']:.2%}")


def test_sensor_node_creation():
    """Test individual sensor node"""
    print("Testing Sensor Network: Node Creation...")

    sensor = SensorNode(sensor_id="office-main-01", hub_url="http://security-hub.internal")

    assert sensor.sensor_id == "office-main-01"
    assert sensor.local_ip is not None
    assert sensor.metrics["status"] == "online"
    print(f"  [OK] Sensor created. ID: {sensor.sensor_id}, Local IP: {sensor.local_ip}")


def test_sensor_network_registration():
    """Test multi-sensor registration"""
    print("Testing Sensor Network: Registration...")

    network = SensorNetwork()

    # Register multiple sensors
    s1 = network.register_sensor("office-1", "http://hub.internal", "192.168.1.10")
    s2 = network.register_sensor("office-2", "http://hub.internal", "192.168.1.20")
    s3 = network.register_sensor("dmz-1", "http://hub.internal", "10.0.0.5")

    assert len(network.sensors) == 3
    assert "office-1" in network.sensors
    print(f"  [OK] Registered {len(network.sensors)} sensors")


def test_sensor_network_overview():
    """Test network-wide overview"""
    print("Testing Sensor Network: Overview...")

    network = SensorNetwork()

    s1 = network.register_sensor("office-1", "http://hub.internal", "192.168.1.10")
    s2 = network.register_sensor("office-2", "http://hub.internal", "192.168.1.20")

    # Mark one as online
    s1.metrics["status"] = "online"
    s2.metrics["status"] = "offline"

    overview = network.get_network_overview()

    assert overview["total_sensors"] == 2
    assert overview["online_sensors"] == 1
    print(f"  [OK] Network overview: {overview['total_sensors']} total, {overview['online_sensors']} online")


def test_lateral_movement_detection():
    """Test lateral movement detection"""
    print("Testing Sensor Network: Lateral Movement Detection...")

    network = SensorNetwork()

    # Register 3 sensors in different subnets
    network.register_sensor("s1", "http://hub", "192.168.1.1")
    network.register_sensor("s2", "http://hub", "192.168.2.1")
    network.register_sensor("s3", "http://hub", "10.0.0.1")

    # Detect lateral movement
    lateral = network.detect_lateral_movement(time_window_minutes=30)

    assert "lateral_movements" in lateral
    print(f"  [OK] Lateral movement detection enabled")


def test_attack_path_reconstruction():
    """Test attack timeline reconstruction"""
    print("Testing Sensor Network: Attack Path Reconstruction...")

    network = SensorNetwork()

    timeline = network.reconstruct_attack_path("203.0.113.5", time_window_hours=24)

    assert "attacker_ip" in timeline
    assert "attack_phases" in timeline
    assert "reconnaissance" in timeline["attack_phases"]
    print(f"  [OK] Attack path reconstructed for {timeline['attacker_ip']}")


def test_multi_sensor_correlation():
    """Test cross-sensor alert correlation"""
    print("Testing Sensor Network: Multi-Sensor Correlation...")

    network = SensorNetwork()

    # Simulate alerts from multiple sensors
    alerts = [
        {"src_ip": "203.0.113.5", "sensor_id": "s1", "risk_score": 75},
        {"src_ip": "203.0.113.5", "sensor_id": "s2", "risk_score": 68},
        {"src_ip": "203.0.113.5", "sensor_id": "s3", "risk_score": 70},
        {"src_ip": "10.0.0.1", "sensor_id": "s1", "risk_score": 30},
    ]

    correlation = network.correlate_multi_sensor_alerts(alerts)

    assert correlation["total_alerts"] == 4
    assert len(correlation["correlation_groups"]) >= 1
    print(f"  [OK] Found {len(correlation['correlation_groups'])} correlation groups")


def test_network_wide_blocking():
    """Test coordinated IP blocking"""
    print("Testing Sensor Network: Network-Wide Blocking...")

    network = SensorNetwork()

    # Register 3 online sensors
    for i in range(1, 4):
        s = network.register_sensor(f"sensor-{i}", "http://hub", f"192.168.1.{i}")
        s.metrics["status"] = "online"

    # Test block command structure (doesn't actually block)
    block_result = network.block_ip_network_wide("203.0.113.5", duration_minutes=60)

    assert block_result["ip"] == "203.0.113.5"
    assert "blocked_count" in block_result
    print(f"  [OK] Block coordinated across {block_result['total_sensors']} sensors")


def main():
    print("\n" + "=" * 70)
    print("PHASE 3 TESTS: MODEL RETRAINING + DISTRIBUTED SENSORS")
    print("=" * 70 + "\n")

    print("[SECTION] Model Trainer Tests\n")
    test_model_trainer_baseline()
    test_model_trainer_drift_detection()
    test_model_trainer_retrain_decision()
    test_model_trainer_health_check()

    print("\n[SECTION] Sensor Network Tests\n")
    test_sensor_node_creation()
    test_sensor_network_registration()
    test_sensor_network_overview()
    test_lateral_movement_detection()
    test_attack_path_reconstruction()
    test_multi_sensor_correlation()
    test_network_wide_blocking()

    print("\n" + "=" * 70)
    print("ALL PHASE 3 TESTS PASSED [OK]")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
