"""Graph baseline models and known interaction edge sets for SentinelX."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class GraphModel(BaseModel):
    """Known benign interaction edges learned from training captures."""

    known_edges: list[list[str]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def is_known(self, u: str, v: str) -> bool:
        """Check whether edge (u, v) is in known benign set."""
        return [u, v] in self.known_edges

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2)

    @classmethod
    def load(cls, file_path: Path | str) -> "GraphModel":
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Graph model file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)
