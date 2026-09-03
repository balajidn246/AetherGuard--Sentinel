import clickhouse_connect
from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

class ClickHouseClient:
    _client = None

    @classmethod
    def get_client(cls):
        if cls._client is None:
            try:
                cls._client = clickhouse_connect.get_client(
                    host=settings.CLICKHOUSE_HOST,
                    port=settings.CLICKHOUSE_HTTP_PORT,
                    username=settings.CLICKHOUSE_USER,
                    password=settings.CLICKHOUSE_PASSWORD,
                    database=settings.CLICKHOUSE_DB
                )
                logger.info("Connected to ClickHouse")
            except Exception as e:
                logger.error("Failed to connect to ClickHouse", error=str(e))
                # Do not crash here, allow fallback/graceful degradation if DB is offline in dev
        return cls._client

def get_clickhouse():
    """Dependency for FastAPI to get the ClickHouse client."""
    return ClickHouseClient.get_client()
