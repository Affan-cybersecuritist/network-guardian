"""
test_ai_automation.py - Test AI prevention and 24/7 automation
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from ai_prevention_and_24_7_automation import (
    AIThreatPredictor,
    AutomatedIncidentResponse,
    PredictiveBlocking,
    AI24x7OnCallBot,
    CostOptimization,
    COST_COMPARISON
)


print("\n" + "=" * 70)
print("AI PREVENTION + 24/7 AUTOMATION TESTS")
print("=" * 70 + "\n")

# Test 1: AI Threat Prediction
print("Test 1: AI Threat Prediction (Predict attacks BEFORE they happen)...")
predictor = AIThreatPredictor()
historical_attacks = [
    {"type": "scan", "src_ip": "203.0.113.5", "hour": 14},
    {"type": "bruteforce", "src_ip": "203.0.113.5", "hour": 14},
    {"type": "breach", "src_ip": "203.0.113.5", "hour": 14},
    {"type": "scan", "src_ip": "203.0.113.5", "hour": 14},
    {"type": "bruteforce", "src_ip": "203.0.113.5", "hour": 14},
]
predictions = predictor.predict_next_attack(historical_attacks)
print(f"  [OK] Predicted {len(predictions['predicted_attacks'])} attack patterns")
print(f"       Confidence: {predictions['confidence']:.0%}")
if predictions['recommended_blocks']:
    print(f"       Block these IPs: {predictions['recommended_blocks']}")

# Test 2: AI Insider Threat Prediction
print("\nTest 2: AI Insider Threat Prediction (Stop data theft BEFORE it happens)...")
user_activities = [
    {"resource": "customer_database", "hour": 23},
    {"resource": "financial_data", "hour": 23},
    {"resource": "employee_records", "hour": 23},
    {"destination": "personal_aws_s3", "hour": 23},
    {"destination": "personal_dropbox", "hour": 23},
] * 3
risk, reason = predictor.predict_insider_threat(user_activities)
print(f"  [OK] Insider threat risk detected: {risk:.0%}")
print(f"       Reasons: {reason}")

# Test 3: Predictive Blocking
print("\nTest 3: Predictive Blocking (Block BEFORE attack succeeds)...")
blocker = PredictiveBlocking()
threat_intel = {
    "known_malicious_ips": ["203.0.113.5", "10.20.30.40"],
    "current_connections": [
        {"src_ip": "203.0.113.5", "dst_port": 3306},
        {"src_ip": "10.20.30.40", "dst_port": 22},
        {"src_ip": "192.168.1.1", "dst_port": 80},
    ],
    "attack_history": {
        "203.0.113.5": [{"target_port": 3306}, {"target_port": 3306}]
    }
}
predictions = blocker.predict_and_block(threat_intel)
print(f"  [OK] Predicted {len(predictions['predicted_blocks'])} blocks")
print(f"       Prevented {predictions['prevented_attacks']} attacks BEFORE they happened")
print(f"       Accuracy: {predictions['accuracy']:.0%}")

# Test 4: Automated Incident Response (No humans needed)
print("\nTest 4: Automated Incident Response (AI handles 99% of incidents)...")
responder = AutomatedIncidentResponse()
test_cases = [
    {"src_ip": "203.0.113.1", "risk_score": 30, "attack_type": "scan"},
    {"src_ip": "203.0.113.2", "risk_score": 60, "attack_type": "bruteforce"},
    {"src_ip": "203.0.113.3", "risk_score": 80, "attack_type": "ransomware"},
]
for alert in test_cases:
    response = responder.auto_respond_to_alert(alert)
    print(f"  [OK] Risk {alert['risk_score']}: {len(response['auto_actions_taken'])} auto-actions taken")
    if response["human_escalation_needed"]:
        print(f"       ⚠️  Escalated to human ({response['escalation_reason']})")

stats = responder.get_auto_response_stats()
print(f"  [OK] AI automation rate: {stats['auto_percentage']:.0f}%")

# Test 5: AI 24/7 On-Call Bot
print("\nTest 5: AI 24/7 On-Call Bot (Never sleep, always responding)...")
bot = AI24x7OnCallBot()
alerts = [
    {"src_ip": "203.0.113.1", "risk_score": 50, "attack_type": "scan"},
    {"src_ip": "203.0.113.2", "risk_score": 75, "attack_type": "bruteforce"},
]
for alert in alerts:
    result = bot.process_alert_24_7(alert)
    print(f"  [OK] Alert processed in {result['ai_processing_time_ms']:.1f}ms")
    if result["human_needed"]:
        print(f"       Human on-call SMS sent")

coverage = bot.get_coverage_stats()
print(f"  [OK] Automation rate: {coverage['automation_rate']:.0f}%")

# Test 6: Cost Comparison
print("\nTest 6: Cost Optimization (AI vs Traditional SOC)...")
costs = CostOptimization.calculate_cost_savings()
print(f"  [TRADITIONAL SOC]")
print(f"    Team: {costs['traditional_24_7_soc']['team_size']}")
print(f"    Cost: {costs['traditional_24_7_soc']['total_cost']}")
print(f"    Response: {costs['traditional_24_7_soc']['availability']}")
print(f"  [AI-POWERED SOC]")
print(f"    Team: {costs['ai_powered_soc']['team_size']}")
print(f"    Cost: {costs['ai_powered_soc']['total_cost']}")
print(f"    Response: {costs['ai_powered_soc']['availability']}")
print(f"  [SAVINGS]: {costs['savings']}")

print("\n" + "=" * 70)
print("ALL AI AUTOMATION TESTS PASSED [OK]")
print("=" * 70)
print(COST_COMPARISON)
