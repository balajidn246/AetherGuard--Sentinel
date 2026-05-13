from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = "aetherguard-sentinel-ultra-secure-key-2024-production-soc"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "aetherguard"
    SQLITE_URL: str = "sqlite+aiosqlite:///./aetherguard.db"
    APP_NAME: str = "AetherGuard Sentinel"
    VERSION: str = "1.0.0"
    DEBUG: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
