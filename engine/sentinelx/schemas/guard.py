"""Response safety and guard decision schema for automated containment."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from sentinelx.schemas.common import UtcDatetime

GuardAction = Literal[
    "isolate_host",
    "block_ip",
    "disable_account",
    "block_modbus_write",
    "kill_process",
]

GuardOutcome = Literal["allow", "deny", "needs_human"]

AssetCriticality = Literal["low", "medium", "high", "process_critical"]


class GuardDecision(BaseModel):
    """Response safety policy decision evaluating proposed containment action."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str
    ts: UtcDatetime
    incident_id: str | None = None
    action: GuardAction
    target: str
    decision: GuardOutcome
    reasons: list[str]
    rule_ids: list[str]
    asset_criticality: AssetCriticality | None = None
    requested_by: str
