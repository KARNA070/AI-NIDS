"""
train_model.py
--------------
Trains a Random Forest classifier on the NSL-KDD dataset.
Evaluates performance and saves the trained model.
"""

import os
import logging
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score
)

from preprocess_data import preprocess

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH = "model/intrusion_model.pkl"
DATASET_PATH = "dataset/nsl_kdd.csv"
MODEL_DIR = "model/"


def train(dataset_path: str = DATASET_PATH, model_dir: str = MODEL_DIR):
    """Train the intrusion detection model and persist all artefacts."""

    # ── 1. Preprocess ────────────────────────────────────────────────────────
    logger.info("Starting preprocessing …")
    X_train, X_test, y_train, y_test, encoders, scaler = preprocess(
        dataset_path, save_dir=model_dir
    )

    # ── 2. Train ─────────────────────────────────────────────────────────────
    logger.info("Training Random Forest classifier …")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,          # use all CPU cores
        random_state=42,
        class_weight="balanced",  # handle class imbalance
    )
    clf.fit(X_train, y_train)
    logger.info("Training complete.")

    # ── 3. Evaluate ──────────────────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"Test Accuracy: {acc * 100:.2f}%")
    logger.info("\nClassification Report:\n" + classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    logger.info(f"Classes: {clf.classes_}")
    logger.info(f"Confusion Matrix:\n{cm}")

    # ── 4. Save model ────────────────────────────────────────────────────────
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "intrusion_model.pkl")
    joblib.dump(clf, model_path)
    logger.info(f"Model saved to {model_path}")

    # Save class labels for reference
    labels_path = os.path.join(model_dir, "class_labels.pkl")
    joblib.dump(list(clf.classes_), labels_path)
    logger.info(f"Class labels saved to {labels_path}")

    return clf, acc


if __name__ == "__main__":
    train()
