"""Risk scorer — composite risk score for users/hosts."""
import logging

logger = logging.getLogger(__name__)


class RiskScorer:
    def __init__(self, ueba_engine, anomaly_detector):
        self.ueba = ueba_engine
        self.anomaly = anomaly_detector

    def score_log(self, log: dict) -> int:
        base = log.get("risk_score", 20)
        anomaly_boost = int(self.anomaly.score(log) * 40)
        return min(100, base + anomaly_boost)

    def get_entity_risk(self, entity: str, entity_type: str = "user") -> dict:
        if entity_type == "user":
            profile = self.ueba.get_user_profile(entity)
            return {
                "entity": entity,
                "type": entity_type,
                "risk_score": min(100, int(profile.get("avg_risk_score", 20))),
                "anomaly_flag": profile.get("anomaly_flag", False),
                "profile": profile,
            }
        return {"entity": entity, "type": entity_type, "risk_score": 50}


# ml package
