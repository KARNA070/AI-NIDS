"""
preprocess_data.py
------------------
Loads and preprocesses the NSL-KDD dataset for training.
Handles encoding, scaling, and feature selection.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# NSL-KDD column names (41 features + label + difficulty)
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

# Map raw NSL-KDD labels to attack categories
ATTACK_MAPPING = {
    "normal": "Normal",
    # DoS attacks
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "worm": "DoS",
    # Port Scan / Probe attacks
    "ipsweep": "PortScan", "nmap": "PortScan", "portsweep": "PortScan",
    "satan": "PortScan", "mscan": "PortScan", "saint": "PortScan",
    # Brute Force / R2L attacks
    "ftp_write": "BruteForce", "guess_passwd": "BruteForce", "imap": "BruteForce",
    "multihop": "BruteForce", "phf": "BruteForce", "spy": "BruteForce",
    "warezclient": "BruteForce", "warezmaster": "BruteForce", "sendmail": "BruteForce",
    "named": "BruteForce", "snmpattack": "BruteForce", "snmpguess": "BruteForce",
    "xlock": "BruteForce", "xsnoop": "BruteForce", "httptunnel": "BruteForce",
    # Privilege Escalation / U2R attacks
    "buffer_overflow": "Exploit", "loadmodule": "Exploit", "perl": "Exploit",
    "rootkit": "Exploit", "sqlattack": "Exploit", "xterm": "Exploit",
    "ps": "Exploit",
}

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
FEATURES_TO_USE = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]


def load_dataset(filepath: str) -> pd.DataFrame:
    """Load NSL-KDD dataset from CSV."""
    logger.info(f"Loading dataset from: {filepath}")
    try:
        df = pd.read_csv(filepath, header=None, names=COLUMN_NAMES)
        logger.info(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        return df
    except FileNotFoundError:
        logger.error(f"Dataset not found at {filepath}")
        raise


def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map raw labels to attack categories."""
    df = df.copy()
    # Strip whitespace and dots from labels
    df["label"] = df["label"].str.strip().str.rstrip(".")
    df["attack_category"] = df["label"].str.lower().map(ATTACK_MAPPING)
    # Any unmapped label → 'Other'
    df["attack_category"] = df["attack_category"].fillna("Other")
    logger.info(f"Label distribution:\n{df['attack_category'].value_counts()}")
    return df


def encode_categoricals(df: pd.DataFrame, encoders: dict = None, fit: bool = True):
    """Label-encode categorical columns. Returns (df, encoders)."""
    df = df.copy()
    if encoders is None:
        encoders = {}

    for col in CATEGORICAL_COLS:
        if fit:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
        else:
            le = encoders[col]
            # Handle unseen labels gracefully
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else 0
            )
    return df, encoders


def scale_features(X: np.ndarray, scaler=None, fit: bool = True):
    """Standardise feature matrix. Returns (X_scaled, scaler)."""
    if fit:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)
    return X_scaled, scaler


def preprocess(filepath: str, save_dir: str = "model/"):
    """
    Full preprocessing pipeline.
    Returns X_train, X_test, y_train, y_test plus saved artefacts.
    """
    df = load_dataset(filepath)
    df = map_labels(df)
    df, encoders = encode_categoricals(df, fit=True)

    X = df[FEATURES_TO_USE].values
    y = df["attack_category"].values

    X_scaled, scaler = scale_features(X, fit=True)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    os.makedirs(save_dir, exist_ok=True)
    joblib.dump(encoders, os.path.join(save_dir, "encoders.pkl"))
    joblib.dump(scaler, os.path.join(save_dir, "scaler.pkl"))
    logger.info(f"Encoders and scaler saved to {save_dir}")

    return X_train, X_test, y_train, y_test, encoders, scaler


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, _, _ = preprocess("dataset/nsl_kdd.csv")
    logger.info(f"Train: {X_train.shape}, Test: {X_test.shape}")
