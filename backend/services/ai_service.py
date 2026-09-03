import json
import httpx
from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger(__name__)

class AIService:
    """
    Local AI Investigation Service interacting with Ollama.
    Guarantees zero-cost inference and strict data privacy (logs never leave the network).
    """
    def __init__(self):
        self.base_url = settings.OLLAMA_URL
        self.model = settings.DEFAULT_MODEL
        
    async def check_health(self) -> bool:
        """Check if the local Ollama instance is online."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{self.base_url}/api/tags", timeout=2.0)
                return resp.status_code == 200
        except Exception:
            return False

    async def investigate_signal(self, signal_context: dict) -> dict:
        """
        Takes bounded context from the Deterministic Funnel and asks the local AI 
        to render a verdict on the Security Signal.
        """
        prompt = f"""
        You are an expert SOC analyst AI. 
        Analyze the following security signal and its evidence context.
        Determine if this is a True Positive, False Positive, or Suspicious.
        
        Signal Context:
        {json.dumps(signal_context, indent=2)}
        
        Respond strictly in JSON format with exactly these keys:
        - verdict (string: "true_positive", "false_positive", or "suspicious")
        - confidence (string: "high", "medium", "low")
        - analysis (string: detailed explanation citing the specific evidence provided)
        """
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        try:
            logger.info(f"Submitting investigation to Ollama model {self.model}")
            # Extended timeout for local CPU/GPU inference
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                resp.raise_for_status()
                result = resp.json()
                
                response_text = result.get("response", "{}")
                try:
                    parsed = json.loads(response_text)
                    return parsed
                except json.JSONDecodeError:
                    logger.error("AI returned invalid JSON format", response=response_text)
                    return {
                        "verdict": "unknown", 
                        "confidence": "low", 
                        "analysis": "AI returned malformed response."
                    }
                    
        except Exception as e:
            logger.error("Ollama investigation failed", error=str(e))
            return {
                "verdict": "error", 
                "confidence": "none", 
                "analysis": f"Local AI service unavailable: {str(e)}"
            }

ai_service = AIService()
