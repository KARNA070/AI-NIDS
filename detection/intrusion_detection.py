"""
intrusion_detection.py
----------------------
Loads the trained ML model and classifies incoming packet feature vectors.
Assigns a severity level to each detection.
"""

import os
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import joblib

logger = logging.getLogger(__name__)

# ── Severity configuration ────────────────────────────────────────────────────

SEVERITY_MAP = {
    "Normal":    "INFO",
    "DoS":       "HIGH",
    "PortScan":  "MEDIUM",
    "BruteForce":"HIGH",
    "Exploit":   "CRITICAL",
    "Other":     "LOW",
}

SEVERITY_COLOUR = {
    "INFO":     "\033[92m",   # green
    "LOW":      "\033[96m",   # cyan
    "MEDIUM":   "\033[93m",   # yellow
    "HIGH":     "\033[91m",   # red
    "CRITICAL": "\033[95m",   # magenta
}
RESET = "\033[0m"


@dataclass
class DetectionResult:
    src_ip: str
    dst_ip: str
    protocol: str
    service: str
    attack_type: str
    severity: str
    confidence: float
    timestamp: float = field(default_factory=time.time)
    blocked: bool = False

    def severity_coloured(self) -> str:
        colour = SEVERITY_COLOUR.get(self.severity, "")
        return f"{colour}{self.severity}{RESET}"

    def to_dict(self) -> dict:
        return {
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "protocol":    self.protocol,
            "service":     self.service,
            "attack_type": self.attack_type,
            "severity":    self.severity,
            "confidence":  round(self.confidence * 100, 1),
            "timestamp":   self.timestamp,
            "blocked":     self.blocked,
        }


class IntrusionDetector:
    """
    Wraps the trained RandomForest model.
    Exposes a single .detect(packet_features) → DetectionResult method.
    """

    def __init__(self, model_dir: str = "model/"):
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.encoders = None
        self._load_artefacts()

    # ── Artefact loading ──────────────────────────────────────────────────────

    def _load_artefacts(self):
        model_path   = os.path.join(self.model_dir, "intrusion_model.pkl")
        scaler_path  = os.path.join(self.model_dir, "scaler.pkl")
        encoder_path = os.path.join(self.model_dir, "encoders.pkl")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. "
                "Run model/train_model.py first."
            )

        self.model   = joblib.load(model_path)
        self.scaler  = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
        self.encoders = joblib.load(encoder_path) if os.path.exists(encoder_path) else None
        logger.info(f"Model loaded from {model_path}")
        logger.info(f"Classes: {self.model.classes_}")

    # ── Core detection ────────────────────────────────────────────────────────

    def detect(self, packet_features) -> DetectionResult:
        """
        Accept a PacketFeatures object, run inference, return DetectionResult.
        Falls back to 'Normal' on any error.
        """
        try:
            feature_vector = packet_features.to_nsl_vector()
            X = np.array(feature_vector, dtype=float).reshape(1, -1)

            if self.scaler is not None:
                X = self.scaler.transform(X)

            attack_type = self.model.predict(X)[0]
            proba = self.model.predict_proba(X)[0]
            confidence = float(np.max(proba))

        except Exception as e:
            logger.warning(f"Detection error ({e}) – defaulting to Normal.")
            attack_type = "Normal"
            confidence = 1.0

        severity = SEVERITY_MAP.get(attack_type, "LOW")

        return DetectionResult(
            src_ip=packet_features.src_ip,
            dst_ip=packet_features.dst_ip,
            protocol=packet_features.protocol,
            service=packet_features.service,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            timestamp=packet_features.timestamp,
        )

    # ── Batch detection (testing/offline analysis) ────────────────────────────

    def detect_batch(self, feature_matrix: np.ndarray) -> list:
        """Run detection on a 2-D numpy array (rows = packets)."""
        if self.scaler is not None:
            feature_matrix = self.scaler.transform(feature_matrix)
        predictions = self.model.predict(feature_matrix)
        probas = self.model.predict_proba(feature_matrix)
        return [
            {"attack_type": pred, "confidence": float(np.max(prob)),
             "severity": SEVERITY_MAP.get(pred, "LOW")}
            for pred, prob in zip(predictions, probas)
        ]
