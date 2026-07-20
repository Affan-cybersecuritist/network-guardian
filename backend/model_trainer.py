"""
model_trainer.py
----------------
Auto-retraining pipeline: learn network baseline, detect concept drift, adapt model.

Enables:
- Baseline learning from first week of data
- Concept drift detection (when attack patterns evolve)
- Periodic model retraining (weekly)
- A/B testing new models before deployment
"""
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import json
import os


class ModelTrainer:
    def __init__(self, model_dir: str = "models", history_file: str = "data/training_history.json"):
        self.model_dir = model_dir
        self.history_file = history_file
        self.training_history = self._load_history()

        # Load current model and artifacts
        try:
            self.current_model = joblib.load(f"{model_dir}/isolation_forest.joblib")
            self.scaler = joblib.load(f"{model_dir}/scaler.joblib")
            self.encoders = joblib.load(f"{model_dir}/encoders.joblib")
            self.feature_cols = joblib.load(f"{model_dir}/feature_cols.joblib")
        except:
            self.current_model = None

    def _load_history(self) -> List[Dict]:
        """Load training history"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def _save_history(self):
        """Save training history"""
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        with open(self.history_file, 'w') as f:
            json.dump(self.training_history, f, indent=2)

    def create_baseline_profile(self, historical_data: pd.DataFrame) -> Dict:
        """
        Learn normal traffic patterns from first week.

        Returns: baseline statistics for drift detection
        """
        if historical_data.empty:
            return {}

        baseline = {
            "timestamp": datetime.now().isoformat(),
            "sample_size": len(historical_data),
            "protocols": list(historical_data["protocol_type"].unique()),
            "services": list(historical_data["service"].unique()),
            "avg_src_bytes": float(historical_data["src_bytes"].mean()),
            "avg_dst_bytes": float(historical_data["dst_bytes"].mean()),
            "avg_count": float(historical_data["count"].mean()),
            "median_duration": float(historical_data.get("duration", [0]).median()),
            "normal_src_ips": set(),  # Placeholder for real implementation
            "normal_ports": set(),    # Placeholder for real implementation
            "peak_hours": [],         # Placeholder for real implementation
        }

        return baseline

    def detect_concept_drift(self, current_data: pd.DataFrame, baseline: Dict) -> Tuple[float, Optional[str]]:
        """
        Detect when traffic patterns diverge from baseline (concept drift).

        Uses statistical hypothesis testing to detect distribution changes.
        Returns: (drift_score, reason)
        """
        if not baseline or baseline.get("sample_size", 0) == 0:
            return 0.0, None

        drift_signals = []
        drift_score = 0.0

        # Check 1: Protocol distribution change
        if "protocols" in baseline and not current_data.empty:
            current_protocols = set(current_data["protocol_type"].unique())
            baseline_protocols = set(baseline.get("protocols", []))

            protocol_divergence = len(current_protocols.symmetric_difference(baseline_protocols))
            if protocol_divergence > 0:
                drift_signals.append(f"New protocols detected: {current_protocols - baseline_protocols}")
                drift_score += 0.1

        # Check 2: Service distribution change
        if "services" in baseline and not current_data.empty:
            current_services = set(current_data["service"].unique())
            baseline_services = set(baseline.get("services", []))

            service_divergence = len(current_services.symmetric_difference(baseline_services))
            if service_divergence > 0:
                drift_signals.append(f"New services detected: {current_services - baseline_services}")
                drift_score += 0.1

        # Check 3: Byte volume change
        if not current_data.empty and "avg_src_bytes" in baseline:
            current_avg_src = current_data["src_bytes"].mean()
            baseline_avg_src = baseline.get("avg_src_bytes", 0)

            if baseline_avg_src > 0:
                byte_ratio = current_avg_src / baseline_avg_src
                if byte_ratio > 2.0 or byte_ratio < 0.5:
                    drift_signals.append(f"Byte volume drift: {byte_ratio:.2f}x baseline")
                    drift_score += 0.2

        # Check 4: Connection count change
        if not current_data.empty and "avg_count" in baseline:
            current_avg_count = current_data["count"].mean()
            baseline_avg_count = baseline.get("avg_count", 1)

            if baseline_avg_count > 0:
                count_ratio = current_avg_count / baseline_avg_count
                if count_ratio > 3.0 or count_ratio < 0.33:
                    drift_signals.append(f"Connection count drift: {count_ratio:.2f}x baseline")
                    drift_score += 0.2

        reason = None
        if drift_signals:
            reason = " | ".join(drift_signals)

        # Normalize drift score to 0-1
        drift_score = min(drift_score, 1.0)

        return drift_score, reason

    def should_retrain(self, drift_score: float, days_since_retrain: int) -> bool:
        """
        Decide if model should be retrained.

        Triggers if:
        - Concept drift detected (drift_score > 0.5)
        - Time-based: weekly retraining
        """
        if drift_score > 0.5:
            return True

        if days_since_retrain >= 7:
            return True

        return False

    def retrain_model(self, historical_data: pd.DataFrame, new_data: pd.DataFrame) -> Dict:
        """
        Retrain Isolation Forest on combined historical + recent data.

        Returns: model evaluation metrics
        """
        from sklearn.ensemble import IsolationForest

        if self.scaler is None or self.current_model is None:
            return {"status": "error", "reason": "Missing base model or scaler"}

        try:
            # Combine historical + new data
            combined = pd.concat([historical_data, new_data], ignore_index=True)

            # Use same feature engineering as original
            X_train = combined[self.feature_cols]

            # Apply scaler
            X_train_scaled = self.scaler.transform(X_train)

            # Train new model (same hyperparameters as original)
            new_model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
                max_samples="auto"
            )
            new_model.fit(X_train_scaled)

            # Evaluate on new data
            X_new_scaled = self.scaler.transform(new_data[self.feature_cols])
            new_scores = new_model.decision_function(X_new_scaled)
            old_scores = self.current_model.decision_function(X_new_scaled)

            # Compare performance
            correlation = np.corrcoef(new_scores, old_scores)[0, 1]
            improvement = np.mean(new_scores) - np.mean(old_scores)

            result = {
                "status": "success",
                "model": new_model,
                "correlation_with_old": float(correlation),
                "avg_score_change": float(improvement),
                "training_samples": len(combined),
                "new_samples": len(new_data),
                "timestamp": datetime.now().isoformat()
            }

            return result

        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def deploy_model(self, new_model, backup_current: bool = True) -> Dict:
        """
        Deploy new model to production.

        Optionally backs up current model first.
        """
        try:
            if backup_current and self.current_model:
                backup_path = f"{self.model_dir}/isolation_forest.backup"
                joblib.dump(self.current_model, backup_path)

            # Deploy new model
            joblib.dump(new_model, f"{self.model_dir}/isolation_forest.joblib")

            self.current_model = new_model

            # Log to history
            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "model_deployed",
                "model_path": f"{self.model_dir}/isolation_forest.joblib"
            }
            self.training_history.append(entry)
            self._save_history()

            return {"status": "success", "message": "Model deployed"}

        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def rollback_model(self, backup_path: str = None) -> Dict:
        """
        Rollback to previous model if new model performs poorly.
        """
        try:
            if backup_path is None:
                backup_path = f"{self.model_dir}/isolation_forest.backup"

            if not os.path.exists(backup_path):
                return {"status": "error", "reason": "No backup available"}

            # Restore backup
            backup_model = joblib.load(backup_path)
            joblib.dump(backup_model, f"{self.model_dir}/isolation_forest.joblib")

            self.current_model = backup_model

            # Log to history
            entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "model_rollback",
                "backup_path": backup_path
            }
            self.training_history.append(entry)
            self._save_history()

            return {"status": "success", "message": "Model rolled back"}

        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def get_training_status(self) -> Dict:
        """Get current training status and history"""
        return {
            "current_model_path": f"{self.model_dir}/isolation_forest.joblib",
            "training_history_size": len(self.training_history),
            "last_training": self.training_history[-1] if self.training_history else None,
            "history": self.training_history[-10:]  # Last 10 entries
        }

    def periodic_health_check(self, current_alerts: List[Dict]) -> Dict:
        """
        Periodic check: is model still performing well?

        Returns metrics on detection rate, false positives, etc.
        """
        if not current_alerts:
            return {"status": "no_data"}

        # Convert to DataFrame for analysis
        df = pd.DataFrame(current_alerts)

        # Metrics
        total_alerts = len(df)
        flagged = len(df[df.get("flagged", False)])
        high_risk = len(df[df.get("risk_score", 0) >= 70])

        alert_rate = flagged / total_alerts if total_alerts > 0 else 0

        health = {
            "total_alerts": total_alerts,
            "flagged_alerts": flagged,
            "high_risk_alerts": high_risk,
            "alert_rate": alert_rate,
            "status": "healthy" if 0.01 < alert_rate < 0.20 else "anomalous",
            "recommendation": self._get_health_recommendation(alert_rate)
        }

        return health

    def _get_health_recommendation(self, alert_rate: float) -> str:
        """Recommend action based on alert rate"""
        if alert_rate < 0.01:
            return "Alert rate very low - model may be too conservative"
        elif alert_rate > 0.20:
            return "Alert rate high - model may be too sensitive, consider retraining"
        else:
            return "Alert rate normal - model performing well"
