"""MITRE ATT&CK and ATT&CK-ICS enrichment catalog and helpers."""

import json
from functools import lru_cache
from pathlib import Path

from sentinelx.schemas.common import Technique


class MitreCatalog:
    """Catalog of supported MITRE Enterprise and ICS techniques."""

    def __init__(self, techniques: dict[str, Technique]):
        self._techniques = techniques

    def get(self, technique_id: str) -> Technique | None:
        """Lookup technique by ID (e.g. 'T1078.003' or 'T0855')."""
        return self._techniques.get(technique_id.strip().upper())

    def resolve(self, technique_id: str) -> Technique:
        """Resolve technique or raise ValueError if unknown."""
        tech = self.get(technique_id)
        if tech is None:
            raise ValueError(f"Unknown MITRE technique ID: {technique_id}")
        return tech

    def resolve_many(self, technique_ids: list[str]) -> list[Technique]:
        """Resolve a list of technique IDs, failing loudly on unknown ID."""
        return [self.resolve(tid) for tid in technique_ids]

    def all_techniques(self) -> list[Technique]:
        """Return all cataloged techniques."""
        return list(self._techniques.values())

    def __contains__(self, technique_id: str) -> bool:
        return technique_id.strip().upper() in self._techniques

    def __len__(self) -> int:
        return len(self._techniques)


def load_mitre_catalog(content_dir: Path | str | None = None) -> MitreCatalog:
    """Load curated enterprise and ICS MITRE ATT&CK technique maps."""
    if content_dir is None:
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        mitre_dir = repo_root / "content" / "mitre"
    else:
        mitre_dir = Path(content_dir)

    enterprise_path = mitre_dir / "enterprise_map.json"
    ics_path = mitre_dir / "ics_map.json"

    techniques: dict[str, Technique] = {}

    if enterprise_path.is_file():
        with open(enterprise_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for tid, item in data.items():
                tech = Technique.model_validate(item)
                techniques[tid.upper()] = tech

    if ics_path.is_file():
        with open(ics_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for tid, item in data.items():
                tech = Technique.model_validate(item)
                techniques[tid.upper()] = tech

    return MitreCatalog(techniques)


@lru_cache(maxsize=1)
def get_mitre_catalog() -> MitreCatalog:
    """Return cached singleton MITRE catalog."""
    return load_mitre_catalog()
