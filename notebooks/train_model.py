"""
Train an Isolation Forest anomaly detector on NSL-KDD.

Approach: train ONLY on normal traffic so the model learns a baseline of
"what normal looks like." At inference time, ANY traffic (seen attack type
or brand new one) that deviates from that baseline gets flagged. This is
the behavior-based approach NTRO's SIH problem statement calls for --
not simple signature/IoC matching.
"""
import sys
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
sys.path.append(_THIS_DIR)
from data_prep import load_raw, build_preprocessor, transform

DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(_PROJECT_ROOT, "models")


def main():
    train_df = load_raw(f"{DATA_DIR}/KDDTrain.txt")
    test_df = load_raw(f"{DATA_DIR}/KDDTest.txt")

    encoders, numeric_cols, scaler = build_preprocessor(train_df)

    # Fit scaler on ALL train data (normal+attack) so scaling is stable,
    # but the MODEL itself only ever trains on normal rows.
    X_train_all, feature_cols = transform(train_df, encoders, numeric_cols, scaler, fit_scaler=True)
    train_df = train_df.reset_index(drop=True)
    normal_mask = (train_df["binary_label"] == "normal").values
    X_train_normal = X_train_all[normal_mask]

    print(f"Training Isolation Forest on {X_train_normal.shape[0]} NORMAL samples "
          f"({X_train_normal.shape[1]} features)...")

    # contamination = expected proportion of outliers baked into training data.
    # Since we filtered to normal only, we set it low -- just to regularize.
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_normal)

    # --- Evaluate on TEST set (contains both normal + attack, including
    # attack types the model has NEVER seen, since NSL-KDD test set has extras) ---
    X_test, _ = transform(test_df, encoders, numeric_cols, scaler, fit_scaler=False)
    y_true = (test_df["binary_label"] == "attack").astype(int).values  # 1 = attack

    # decision_function: higher = more normal. We flip sign so higher = more anomalous.
    anomaly_score = -model.decision_function(X_test)
    y_pred = (model.predict(X_test) == -1).astype(int)  # -1 = outlier/attack, 1 = inlier/normal

    print("\n=== Classification Report (1 = attack/anomaly) ===")
    print(classification_report(y_true, y_pred, target_names=["normal", "attack"]))

    print("=== Confusion Matrix ===")
    cm = confusion_matrix(y_true, y_pred)
    print(pd.DataFrame(cm, index=["actual_normal", "actual_attack"],
                        columns=["pred_normal", "pred_attack"]))

    auc = roc_auc_score(y_true, anomaly_score)
    print(f"\nROC-AUC: {auc:.4f}")

    # Check performance specifically on NOVEL attack types unseen in train
    train_attack_types = set(train_df["label"].unique())
    test_df_reset = test_df.reset_index(drop=True)
    novel_mask = (~test_df_reset["label"].isin(train_attack_types)) & (test_df_reset["binary_label"] == "attack")
    if novel_mask.sum() > 0:
        novel_detected = y_pred[novel_mask.values].mean()
        print(f"\nNovel/unseen attack types in test set: {novel_mask.sum()} samples")
        print(f"Detection rate on UNSEEN attack types: {novel_detected:.2%}")
        print("(This is the key number -- proves it's not just memorizing known signatures)")

    # --- Save everything the API will need ---
    joblib.dump(model, f"{MODEL_DIR}/isolation_forest.joblib")
    joblib.dump(encoders, f"{MODEL_DIR}/encoders.joblib")
    joblib.dump(scaler, f"{MODEL_DIR}/scaler.joblib")
    joblib.dump(feature_cols, f"{MODEL_DIR}/feature_cols.joblib")
    joblib.dump(numeric_cols, f"{MODEL_DIR}/numeric_cols.joblib")

    metrics = {
        "roc_auc": float(auc),
        "precision_attack": float(classification_report(y_true, y_pred, output_dict=True)["1"]["precision"]),
        "recall_attack": float(classification_report(y_true, y_pred, output_dict=True)["1"]["recall"]),
        "f1_attack": float(classification_report(y_true, y_pred, output_dict=True)["1"]["f1-score"]),
        "novel_attack_detection_rate": float(novel_detected) if novel_mask.sum() > 0 else None,
        "n_train_normal": int(X_train_normal.shape[0]),
        "n_test": int(X_test.shape[0]),
    }
    joblib.dump(metrics, f"{MODEL_DIR}/metrics.joblib")
    print(f"\nSaved model + preprocessing artifacts to {MODEL_DIR}/")
    print("Metrics:", metrics)


if __name__ == "__main__":
    main()
