"""Entity baseline profiles and statistics models for SentinelX."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class EntityProfile(BaseModel):
    """Learned behavioral baseline for a single entity (user, host, or user-host pair)."""

    entity_id: str
    entity_type: str  # "user", "host", "user_host"
    active_hours: list[int] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_zones: list[str] = Field(default_factory=list)
    allowed_commands: list[str] = Field(default_factory=list)
    typical_event_rate_per_hour: float = 0.0
    max_events_per_hour: int = 100
    total_observations: int = 0


class BaselineModel(BaseModel):
    """Collection of learned entity profiles across benign captures."""

    profiles: dict[str, EntityProfile] = Field(default_factory=dict)
    known_users: list[str] = Field(default_factory=list)
    known_hosts: list[str] = Field(default_factory=list)
    known_zones: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_profile(self, entity_id: str) -> EntityProfile | None:
        return self.profiles.get(entity_id)

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)

    @classmethod
    def load(cls, file_path: Path | str) -> "BaselineModel":
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Baseline model file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)
