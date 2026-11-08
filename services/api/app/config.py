"""Configuration settings for SentinelX API service."""

import os
from pathlib import Path


class Settings:
    """Application configuration loaded from environment variables."""

    SENTINELX_ENV: str = os.getenv("SENTINELX_ENV", "dev")
    SENTINELX_DB_PATH: Path = Path(os.getenv("SENTINELX_DB_PATH", "./data/sentinelx.db"))
    SENTINELX_INGEST_MODE: str = os.getenv("SENTINELX_INGEST_MODE", "off")
    SENTINELX_LOG_ROOT: Path = Path(os.getenv("SENTINELX_LOG_ROOT", "./data/logs"))
    SENTINELX_REPLAY_SPEED: str = os.getenv("SENTINELX_REPLAY_SPEED", "1.0")
    SENTINELX_INGEST_MODE: str = os.getenv("SENTINELX_INGEST_MODE", "off")
    SENTINELX_LOG_ROOT: Path = Path(os.getenv("SENTINELX_LOG_ROOT", "./data/logs"))
    SENTINELX_REPLAY_SPEED: str = os.getenv("SENTINELX_REPLAY_SPEED", "1.0")

    @property
    def cors_origins(self) -> list[str]:
        raw = os.getenv("CORS_ORIGINS", "http://localhost:3000")
        return [origin.strip() for origin in raw.split(",") if origin.strip()]


settings = Settings()
