"""
ML Anomaly Detector - IsolationForest based anomaly scoring for log events.
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
        self._buffer = []
        self._max_buffer = 5000

    def _fit_incremental(self, log: dict):
        self._buffer.append([
            float(log.get("risk_score", 20)),
            float(log.get("anomaly_score", 0.1)),
        ])
        if len(self._buffer) > self._max_buffer:
            self._buffer.pop(0)

        # Retrain model periodically on real data
        if not self._trained and len(self._buffer) >= 50:
            self.model.fit(np.array(self._buffer))
            self._trained = True
            logger.info(f"[ANOMALY] Detector trained on {len(self._buffer)} real events")
        elif self._trained and len(self._buffer) % 500 == 0:
            self.model.fit(np.array(self._buffer))

    def score(self, log: dict) -> float:
        """Return anomaly score 0-1 (higher = more anomalous)."""
        self._fit_incremental(log)
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
