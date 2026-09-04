import redis.asyncio as aioredis
from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

_redis_client = None

def get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_timeout=3.0,
                socket_connect_timeout=3.0
            )
        except Exception as e:
            logger.error("Failed to initialize Redis client", error=str(e))
    return _redis_client

async def check_redis_health() -> bool:
    try:
        r = get_redis()
        if r:
            pong = await r.ping()
            return pong is True
    except Exception as e:
        logger.warning(f"Redis ping failed: {e}")
    return False
