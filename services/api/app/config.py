"""Configuration settings for SentinelX API service."""

import os
from pathlib import Path


class Settings:
    """Application configuration loaded from environment variables."""

    SENTINELX_ENV: str = os.getenv("SENTINELX_ENV", "dev")
    SENTINELX_DB_PATH: Path = Path(os.getenv("SENTINELX_DB_PATH", "./data/sentinelx.db"))

    @property
    def cors_origins(self) -> list[str]:
        raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
        return [origin.strip() for origin in raw.split(",") if origin.strip()]


settings = Settings()
