"""
NSL-KDD data loading & preprocessing
-------------------------------------
Loads the NSL-KDD intrusion detection dataset, cleans it, and prepares
features for an anomaly-detection model (Isolation Forest).

Key idea: we train ONLY on 'normal' traffic patterns, then flag anything
that deviates from that learned normal-behavior baseline as a possible
compromise -- this is what makes it NOT a simple IoC (signature) matcher.
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

# NSL-KDD has 41 features + label + difficulty score (no header row in file)
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

# --- Engineered behavioral feature: auth brute-force signal ---
# Password-guessing attacks (guess_passwd, ssh/telnet/ftp scanning) throttle
# themselves to 1-3 connections per 2-second window, which is exactly why the
# existing "count"/"srv_count" (2s window) features miss them -- see
# backend/pcap_to_features.py TIME_WINDOW. The signal that DOES survive is
# many repeated connections to the same auth-service port piling up over a
# longer window.
#
# NSL-KDD rows have no raw src_ip or timestamp (each row is already a
# pre-aggregated connection summary), so this is approximated here using
# dst_host_srv_count, which is computed over the last 100 connections to the
# same host+service (a longer horizon than the 2s "count"/"srv_count" cols),
# gated to auth-service ports. Empirically this separates guess_passwd from
# normal auth traffic in NSL-KDD: guess_passwd rows on telnet/ftp/ssh average
# dst_host_srv_count ~138 vs ~34 for normal traffic on those same services.
#
# The REAL pcap pipeline (backend/pcap_to_features.py) computes the equivalent
# feature directly from actual per-source-IP timestamps over a 60s window --
# this proxy exists only so the training data has a matching column to learn
# from. Disclosed here so nobody mistakes it for a real per-source counter.
AUTH_SERVICES = {"telnet", "ftp", "ssh"}


def add_engineered_features(df):
    df = df.copy()
    is_auth = df["service"].isin(AUTH_SERVICES)
    df["auth_bruteforce_score"] = np.where(is_auth, df["dst_host_srv_count"], 0).astype(float)
    return df


def load_raw(path):
    df = pd.read_csv(path, names=COLUMNS)
    df = df.drop(columns=["difficulty"])
    # Binary label: normal vs attack (any of the ~22 attack types -> 'attack')
    df["binary_label"] = df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
    df = add_engineered_features(df)
    return df


def build_preprocessor(train_df):
    """Fit encoders/scaler on TRAIN data only, return fitted objects."""
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        le.fit(train_df[col])
        encoders[col] = le

    numeric_cols = [c for c in train_df.columns if c not in CATEGORICAL_COLS + ["label", "binary_label"]]

    scaler = StandardScaler()
    return encoders, numeric_cols, scaler


def transform(df, encoders, numeric_cols, scaler, fit_scaler=False):
    df = df.copy()
    for col, le in encoders.items():
        # handle unseen categories at test time gracefully
        known = set(le.classes_)
        df[col] = df[col].apply(lambda x: x if x in known else le.classes_[0])
        df[col] = le.transform(df[col])

    feature_cols = list(encoders.keys()) + numeric_cols
    X = df[feature_cols].values.astype(float)

    if fit_scaler:
        X = scaler.fit_transform(X)
    else:
        X = scaler.transform(X)

    return X, feature_cols


if __name__ == "__main__":
    import os
    _data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
    train_df = load_raw(os.path.join(_data_dir, "KDDTrain.txt"))
    test_df = load_raw(os.path.join(_data_dir, "KDDTest.txt"))

    print("=== Train shape ===", train_df.shape)
    print("=== Test shape ===", test_df.shape)
    print("\n=== Binary label distribution (train) ===")
    print(train_df["binary_label"].value_counts())
    print("\n=== Top attack types (train) ===")
    print(train_df["label"].value_counts().head(10))
    print("\n=== Protocol types ===", train_df["protocol_type"].unique())
