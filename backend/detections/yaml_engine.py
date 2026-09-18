import yaml
import os
import re
from typing import List, Dict, Any
from backend.core.logging import get_logger

logger = get_logger(__name__)

class YamlDetectionRule:
    def __init__(self, filepath: str):
        with open(filepath, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.id = self.config.get("id")
        self.name = self.config.get("name", "Unnamed Rule")
        self.severity = self.config.get("severity", "medium")
        self.conditions = self.config.get("conditions", [])
        self.mitre = self.config.get("mitre", [])
        
    def evaluate(self, event: Dict[str, Any]) -> bool:
        """Evaluate the event against the YAML conditions (AND logic)."""
        if not self.conditions:
            return False
            
        for condition in self.conditions:
            field = condition.get("field")
            operator = condition.get("operator", "equals")
            value = condition.get("value")
            
            event_val = event.get(field)
            if event_val is None:
                return False
                
            if operator == "equals" and str(event_val).lower() != str(value).lower():
                return False
            elif operator == "contains" and str(value).lower() not in str(event_val).lower():
                return False
            elif operator == "regex" and not re.search(str(value), str(event_val), re.IGNORECASE):
                return False
                
        return True

class YamlDetectionEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules: List[YamlDetectionRule] = []
        self.load_rules()
        
    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return
            
        for filename in os.listdir(self.rules_dir):
            if filename.endswith((".yml", ".yaml")):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    rule = YamlDetectionRule(filepath)
                    self.rules.append(rule)
                except Exception as e:
                    logger.error(f"Failed to load rule {filename}", error=str(e))
        logger.info(f"Loaded {len(self.rules)} YAML detection rules")
        
    def evaluate_event(self, event: Any) -> List[Dict[str, Any]]:
        """Evaluate an event against all rules. Returns list of matches."""
        if hasattr(event, "model_dump"):
            event_dict = event.model_dump()
            # Map common legacy fields for YAML rules
            event_dict["event_type"] = event_dict.get("class_name", "").lower()
            event_dict["source_ip"] = event_dict.get("src_ip", "")
            event_dict["dest_ip"] = event_dict.get("dst_ip", "")
            event_dict["dest_port"] = event_dict.get("dst_port", 0)
        else:
            event_dict = event
            
        matches = []
        for rule in self.rules:
            if rule.evaluate(event_dict):
                matches.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "mitre": rule.mitre
                })
        return matches
