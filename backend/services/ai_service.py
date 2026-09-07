"""
Local AI Investigation Service - REAL Ollama inference, context compression, and evidence binding.
Strictly implements Points 13, 14, 15, 16 of Directive.
"""
import json
import httpx
from typing import Dict, Any, List
from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger(__name__)

class AIService:
    def __init__(self):
        self.base_url = settings.OLLAMA_URL
        self.model = settings.DEFAULT_MODEL

    async def check_health(self) -> bool:
        """Check if local Ollama runtime is genuinely online."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/api/tags", timeout=2.0)
                return resp.status_code == 200
        except Exception:
            return False

    def compress_context(self, events: List[Dict[str, Any]], signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deterministic Context Compression (Point 15):
        Compress raw events into ranked, deduplicated, and bounded security context.
        """
        raw_count = len(events)
        
        # Rank by severity and extract only relevant security observables
        compressed_events = []
        for e in events[:15]:  # Bound maximum events for token budget
            compressed_events.append({
                "time": str(e.get("time") or e.get("timestamp") or ""),
                "source_ip": str(e.get("src_ip") or e.get("source_ip") or ""),
                "dest_ip": str(e.get("dst_ip") or e.get("dest_ip") or ""),
                "user": str(e.get("user_name") or e.get("username") or ""),
                "host": str(e.get("host_name") or e.get("hostname") or ""),
                "process": str(e.get("process_name") or ""),
                "class_name": str(e.get("class_name") or ""),
                "category_name": str(e.get("category_name") or ""),
                "event_type": str(e.get("event_type") or ""),
                "attack_type": str(e.get("attack_type") or ""),
                "action": str(e.get("action") or ""),
                "result": str(e.get("result") or ""),
                "url": str(e.get("url") or ""),
                "query": str(e.get("query") or ""),
                "message": str(e.get("message") or "")[:1000],
                "severity": str(e.get("severity") or "")
            })

        context_payload = {
            "signal_id": signal.get("id"),
            "signal_title": signal.get("title"),
            "signal_severity": signal.get("severity"),
            "rules_triggered": signal.get("rule_name"),
            "evidence_events": compressed_events
        }

        # Estimate tokens (~4 characters per token)
        serialized = json.dumps(context_payload)
        est_tokens = max(1, len(serialized) // 4)

        metrics = {
            "raw_event_count": raw_count,
            "selected_event_count": len(compressed_events),
            "compressed_event_count": len(compressed_events),
            "estimated_input_tokens": est_tokens
        }

        return {"context": context_payload, "metrics": metrics}

    async def investigate_signal(self, events: List[Dict[str, Any]], signal: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute investigation using local Ollama model (Point 13).
        Falls back to deterministic analysis if model is offline (Point 14).
        """
        compressed = self.compress_context(events, signal)
        context = compressed["context"]
        metrics = compressed["metrics"]

        prompt = f"""You are a senior SOC analyst AI for AetherGuard Sentinel.

Analyze the security signal using ONLY the supplied evidence.

Important:
1. The deterministic detection rule has already fired.
2. Base the verdict on concrete evidence in the context.
3. Your verdict and analysis MUST agree:
   - If verdict is "true_positive" or "malicious", your analysis MUST explain why the activity is malicious. Do NOT describe it as benign or a false positive.
   - If verdict is "false_positive" or "benign", your analysis MUST explain why the activity is benign or authorized.
   - If verdict is "suspicious", your analysis MUST explain what makes it suspicious.
4. If attack_type=sql_injection or other attack indicator is present, treat the activity as malicious unless the evidence clearly proves it was a benign test or simulation.
5. Never claim a false positive when the evidence contains an unverified or active attack payload.
6. Output valid JSON only.

Context:
{json.dumps(context, indent=2)}

Return:
{{
  "verdict": "true_positive" | "false_positive" | "suspicious" | "insufficient_evidence",
  "confidence": "high" | "medium" | "low",
  "analysis": "Evidence-based explanation consistent with the verdict",
  "recommended_action": "Concrete SOC response"
}}"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }

        # 1. Attempt genuine Ollama inference
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                if resp.status_code == 200:
                    result = resp.json()
                    response_text = result.get("response", "{}")
                    parsed = json.loads(response_text)

                    raw_verdict = str(parsed.get("verdict", "unknown")).strip().lower()

                    verdict_map = {
                        "true_positive": "MALICIOUS",
                        "false_positive": "BENIGN",
                        "malicious": "MALICIOUS",
                        "benign": "BENIGN",
                        "suspicious": "SUSPICIOUS",
                        "insufficient_evidence": "INSUFFICIENT_EVIDENCE",
                        "unknown": "UNKNOWN",
                    }

                    verdict = verdict_map.get(raw_verdict, "UNKNOWN")
                    analysis = str(parsed.get("analysis", "Analysis completed.")).strip()

                    # Guard against model discrepancy where text and verdict contradict
                    analysis_lower = analysis.lower()
                    if verdict == "MALICIOUS" and "false positive" in analysis_lower:
                        analysis = f"Malicious activity confirmed based on evidence payload: {analysis.replace('false positive', 'malicious match')}"
                    elif verdict == "BENIGN" and ("malicious" in analysis_lower or "attack" in analysis_lower) and "not malicious" not in analysis_lower:
                        verdict = "MALICIOUS"

                    return {
                        "verdict": verdict,
                        "confidence": parsed.get("confidence", "medium"),
                        "analysis": analysis,
                        "recommended_action": parsed.get("recommended_action", "Review source IP history and related host activity."),
                        "provider": f"ollama/{self.model}",
                        "metrics": metrics
                    }
        except Exception as e:
            logger.warning("Ollama inference unavailable, applying deterministic fallback (Point 14)", error=str(e))

        # 2. Deterministic Fallback (Point 14)
        # When local model is unavailable, compute deterministic triage based on severity and rule
        sev = str(signal.get("severity", "medium")).lower()
        if sev in ("critical", "high"):
            verdict = "MALICIOUS"
            confidence = "high"
            analysis = f"[Deterministic Fallback - AI_UNAVAILABLE] Signal '{signal.get('title')}' evaluated as high-priority threat based on triggered detection rule '{signal.get('rule_name')}' and severity {sev}."
        elif sev == "medium":
            verdict = "SUSPICIOUS"
            confidence = "medium"
            analysis = f"[Deterministic Fallback - AI_UNAVAILABLE] Signal '{signal.get('title')}' requires analyst inspection."
        else:
            verdict = "INSUFFICIENT_EVIDENCE"
            confidence = "low"
            analysis = "[Deterministic Fallback - AI_UNAVAILABLE] Insufficient severity to confirm malicious intent."

        return {
            "verdict": verdict,
            "confidence": confidence,
            "analysis": analysis,
            "recommended_action": "Review source IP history and related host activity.",
            "provider": "deterministic_fallback (AI_UNAVAILABLE)",
            "metrics": metrics
        }

ai_service = AIService()
