from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "aetherguard-sentinel-ultra-secure-key-2024-production-soc"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Ingestion & Security
    INGEST_API_KEY: str = "aetherguard-telemetry-ingest-key-2024"
    ENVIRONMENT: str = "development"
    
    APP_NAME: str = "AetherGuard--Sentinel"
    VERSION: str = "1.0.0"
    DEBUG: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
