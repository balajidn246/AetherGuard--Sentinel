from typing import List, Dict, Any, Literal
from pydantic import BaseModel, Field

class AIInvestigationResult(BaseModel):
    verdict: Literal["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "INSUFFICIENT_EVIDENCE"] = "UNKNOWN"
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    summary: str = Field(default="")
    observed_facts: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    provider: str = Field(default="ollama")
