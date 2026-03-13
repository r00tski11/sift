"""Application configuration via environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration loaded from environment variables."""

    DATABASE_URL: str = "postgresql://postgres:postgres@db:5432/ios_security"
    REDIS_URL: str = "redis://redis:6379/0"
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    UPLOAD_DIR: str = "/tmp/uploads"
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    model_config = {"env_prefix": "", "case_sensitive": True}


settings = Settings()
