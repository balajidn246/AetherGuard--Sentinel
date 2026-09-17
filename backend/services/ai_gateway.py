"""
AI Security Gateway - Production-grade abstraction for AI reasoning:
1. Secret & PII Scrubbing (prevent leakage to LLM context)
2. Prompt Injection Detection (prevent instruction manipulation)
3. Strict Output Schema Validation (via Pydantic AIInvestigationResult)
4. Comprehensive Audit Logging for AI accountability
"""
import re
import json
import logging
from typing import List, Dict, Any
from sqlalchemy import select
from backend.schemas.ai_output import AIInvestigationResult
from backend.services.ai_service import ai_service
from backend.services.audit_service import audit_service
from backend.db.postgres import AsyncSessionLocal
from backend.models.signal import SecuritySignal

try:
    from backend.core.metrics import AI_INVESTIGATIONS
    _metrics_enabled = True
except Exception:
    _metrics_enabled = False

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)[\s:=]+([^\s,;&"\']+)'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{20,})'), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(?i)(api[_-]?key|secret|token)[\s:=]+([a-zA-Z0-9_\-]{16,})'), r'\1=[REDACTED_SECRET]'),
    (re.compile(r'-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----.*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----', re.DOTALL), '[REDACTED_PRIVATE_KEY]'),
]

INJECTION_PATTERNS = [
    re.compile(r'(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|directions)'),
    re.compile(r'(?i)you\s+are\s+now\s+(a|an|in)\s+(developer\s+mode|dan|jailbreak|unrestricted)'),
    re.compile(r'(?i)disregard\s+(system\s+message|safety\s+guidelines)'),
    re.compile(r'(?i)system\s*:\s*override'),
]

class AISecurityGateway:
    @staticmethod
    def sanitize_text(text: str) -> str:
        """Strip secrets and credentials from raw log text before LLM context ingestion."""
        if not text:
            return ""
        sanitized = text
        for pattern, replacement in SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    @staticmethod
    def sanitize_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Clean all evidence events before sending to AI service."""
        clean = []
        for e in events:
            c = e.copy()
            if "message" in c:
                c["message"] = AISecurityGateway.sanitize_text(str(c["message"]))
            if "raw_data" in c:
                c["raw_data"] = AISecurityGateway.sanitize_text(str(c["raw_data"]))
            clean.append(c)
        return clean

    @staticmethod
    def detect_prompt_injection(text: str) -> bool:
        """Returns True if input text contains suspicious instruction override patterns."""
        if not text:
            return False
        for p in INJECTION_PATTERNS:
            if p.search(text):
                logger.warning(f"[AI GATEWAY] Potential prompt injection detected: {text[:80]}...")
                return True
        return False

    @staticmethod
    async def investigate_signal(
        signal_dict: Dict[str, Any],
        evidence_events: List[Dict[str, Any]],
        actor_id: str = "system",
        actor_username: str = "ai_agent",
        tenant_id: str = "default",
        ws_manager = None
    ) -> AIInvestigationResult:
        # 1. Prompt injection check
        combined_text = " ".join([str(e.get("message", "")) for e in evidence_events])
        is_injected = AISecurityGateway.detect_prompt_injection(combined_text)
        if is_injected:
            logger.warning("[AI GATEWAY] Flagging analysis due to detected prompt injection attempt in evidence logs")

        # 2. Sanitize context
        sanitized_evidence = AISecurityGateway.sanitize_events(evidence_events)

        # 3. Request analysis through core ai_service
        raw_res = await ai_service.investigate_signal(sanitized_evidence, signal_dict)

        # 4. Strict schema validation
        try:
            raw_verdict = str(raw_res.get("verdict", "UNKNOWN")).strip().lower()

            verdict_map = {
                "true_positive": "MALICIOUS",
                "false_positive": "BENIGN",
                "malicious": "MALICIOUS",
                "suspicious": "SUSPICIOUS",
                "benign": "BENIGN",
                "insufficient_evidence": "INSUFFICIENT_EVIDENCE",
                "unknown": "UNKNOWN",
            }

            verdict_str = verdict_map.get(raw_verdict, "UNKNOWN")

            confidence_val = 0.5
            try:
                conf_raw = raw_res.get("confidence")
                if isinstance(conf_raw, (int, float)):
                    confidence_val = float(conf_raw)
                elif isinstance(conf_raw, str):
                    conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
                    confidence_val = conf_map.get(conf_raw.lower(), 0.5)
            except Exception:
                confidence_val = 0.5

            first_ev = evidence_events[0] if evidence_events else {}
            src_ip = signal_dict.get('source_ip') or first_ev.get('src_ip') or first_ev.get('source_ip') or 'unknown'
            host = signal_dict.get('hostname') or first_ev.get('host_name') or first_ev.get('hostname') or 'unknown'
            user = signal_dict.get('username') or first_ev.get('user_name') or first_ev.get('username') or 'unknown'
            attack_type = signal_dict.get('attack_type') or first_ev.get('attack_type') or 'unknown'
            rule_name = signal_dict.get('rule_name', 'unknown')

            validated = AIInvestigationResult(
                verdict=verdict_str,
                severity=signal_dict.get("severity", "medium").lower(),
                confidence=confidence_val,
                summary=raw_res.get("analysis", ""),
                observed_facts=[
                    f"Source IP: {src_ip}",
                    f"Host: {host}",
                    f"User: {user}",
                    f"Attack type: {attack_type}",
                    f"Rule: {rule_name}",
                ],
                mitre_attack=signal_dict.get("mitre_techniques", []),
                evidence_refs=[str(e.get("id") or e.get("event_id") or e.get("_id")) for e in evidence_events if e.get("id") or e.get("event_id") or e.get("_id")],
                recommended_actions=[
                    raw_res.get(
                        "recommended_action",
                        "Review source IP history and related host activity."
                    )
                ],
                provider=raw_res.get("provider", "ollama")
            )
        except Exception as vexc:
            logger.error(f"[AI GATEWAY] Schema validation fallback: {vexc}")
            validated = AIInvestigationResult(
                verdict="INSUFFICIENT_EVIDENCE",
                severity="medium",
                confidence=0.3,
                summary="Analysis could not be safely validated against production schema.",
                provider="fallback"
            )

        # 5. Persist to PostgreSQL SecuritySignal
        sig_id = signal_dict.get("id") or signal_dict.get("_id")
        if sig_id:
            try:
                async with AsyncSessionLocal() as session:
                    stmt = select(SecuritySignal).where(SecuritySignal.id == sig_id)
                    s = (await session.execute(stmt)).scalar_one_or_none()
                    if s:
                        s.ai_verdict = validated.verdict
                        s.ai_confidence = str(validated.confidence)
                        s.ai_analysis = validated.summary
                        await session.commit()
                        logger.info(f"[AI GATEWAY] Persisted AI findings to signal {sig_id}")
            except Exception as pexc:
                logger.error(f"[AI GATEWAY] Failed to update SecuritySignal in DB: {pexc}")

        # 6. Immutable Audit Log
        await audit_service.log_action(
            actor_id=actor_id,
            actor_username=actor_username,
            action="ai.investigate",
            resource="security_signal",
            resource_id=str(sig_id),
            details={
                "verdict": validated.verdict,
                "confidence": validated.confidence,
                "provider": validated.provider,
                "prompt_injection_detected": is_injected,
            },
            tenant_id=tenant_id
        )

        # 7. Real-Time Broadcast
        if ws_manager and sig_id:
            try:
                await ws_manager.broadcast({
                    "type": "AI_INVESTIGATION_COMPLETE",
                    "signal_id": sig_id,
                    "verdict": validated.verdict,
                    "confidence": validated.confidence,
                    "severity": validated.severity,
                    "summary": validated.summary,
                    "observed_facts": validated.observed_facts,
                    "mitre_attack": validated.mitre_attack,
                    "recommended_actions": validated.recommended_actions,
                    "evidence_refs": validated.evidence_refs,
                    "provider": validated.provider,
                }, tenant_id=tenant_id)
            except Exception as wexc:
                logger.debug(f"[AI GATEWAY] WS broadcast notice: {wexc}")

        # 8. Prometheus increment
        if _metrics_enabled:
            AI_INVESTIGATIONS.labels(
                verdict=validated.verdict,
                provider=validated.provider or "unknown",
                tenant_id=tenant_id
            ).inc()

        return validated

ai_gateway = AISecurityGateway()
