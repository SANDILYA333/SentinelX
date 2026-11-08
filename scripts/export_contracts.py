#!/usr/bin/env python3
"""Export Pydantic v2 data contracts to JSON Schema files."""

import json
from pathlib import Path

from sentinelx.schemas import (
    Entity,
    Event,
    GuardDecision,
    Incident,
    Signal,
    SourceHealth,
    Technique,
    TelemetryStats,
    WSMessage,
)
from sentinelx.schemas.api_models import (
    AssetResponse,
    BudgetStatusResponse,
    SystemStatusResponse,
)

MODELS = {
    "Event": Event,
    "Signal": Signal,
    "Incident": Incident,
    "GuardDecision": GuardDecision,
    "WSMessage": WSMessage,
    "Entity": Entity,
    "Technique": Technique,
    "SourceHealth": SourceHealth,
    "TelemetryStats": TelemetryStats,
    "AssetResponse": AssetResponse,
    "BudgetStatusResponse": BudgetStatusResponse,
    "SystemStatusResponse": SystemStatusResponse,
}


def export_schemas() -> None:
    """Generate JSON schema files for all core SentinelX models."""
    output_dir = Path(__file__).resolve().parent.parent / "packages" / "contracts" / "schemas"
    output_dir.mkdir(parents=True, exist_ok=True)

    for name, model in MODELS.items():
        schema = model.model_json_schema()
        # Set title if not already present
        schema["title"] = name
        target_file = output_dir / f"{name}.json"
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(schema, f, indent=2)
            f.write("\n")
        print(f"Exported schema: {target_file}")


if __name__ == "__main__":
    export_schemas()
