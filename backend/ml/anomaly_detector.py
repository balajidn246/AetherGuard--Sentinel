"""
ML Anomaly Detector — IsolationForest based anomaly scoring for log events.
Trains on synthetic baseline data, scores each event 0-1.
"""
import logging
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

FEATURE_KEYS = ["risk_score", "anomaly_score"]


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self._trained = False
        self._train_on_synthetic()

    def _train_on_synthetic(self):
        """Train on synthetic baseline data so scoring works immediately."""
        np.random.seed(42)
        # Normal baseline: low risk, low anomaly score
        normal = np.column_stack([
            np.random.normal(20, 10, 1000).clip(0, 100),   # risk_score
            np.random.uniform(0.0, 0.3, 1000),              # anomaly_score
        ])
        # Inject some anomalies
        anomalies = np.column_stack([
            np.random.normal(85, 10, 50).clip(0, 100),
            np.random.uniform(0.7, 1.0, 50),
        ])
        X = np.vstack([normal, anomalies])
        self.model.fit(X)
        self._trained = True
        logger.info("✅ AnomalyDetector trained on synthetic baseline")

    def score(self, log: dict) -> float:
        """Return anomaly score 0-1 (higher = more anomalous)."""
        if not self._trained:
            return 0.0
        features = np.array([[
            float(log.get("risk_score", 20)),
            float(log.get("anomaly_score", 0.1)),
        ]])
        # IsolationForest returns -1 (anomaly) or 1 (normal)
        raw = self.model.decision_function(features)[0]
        # Normalise to 0-1: decision_function range is roughly [-0.5, 0.5]
        score = 1.0 - (raw + 0.5)
        return float(max(0.0, min(1.0, score)))

    def is_anomalous(self, log: dict, threshold: float = 0.6) -> bool:
        return self.score(log) >= threshold
