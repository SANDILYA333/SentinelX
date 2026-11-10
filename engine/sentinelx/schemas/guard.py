"""Response safety and guard decision schema for automated containment."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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

ApprovalStatus = Literal["not_required", "pending_review", "approved", "rejected"]


class GuardPolicyEvaluationResult(BaseModel):
    """Result of evaluating an individual response safety policy."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str
    policy_name: str
    result: Literal["pass", "fail", "review"]
    explanation: str


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
    target_zone: str | None = None
    safety_risk: str | None = None
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    policy_evaluations: list[GuardPolicyEvaluationResult] = Field(default_factory=list)
    approval_status: ApprovalStatus = "not_required"
    approved_by: str | None = None
    approved_at: UtcDatetime | None = None
    approval_notes: str | None = None


class ResponseRecommendation(BaseModel):
    """Candidate containment action recommended for an incident and pre-evaluated by the Guard."""

    model_config = ConfigDict(extra="forbid")

    recommendation_id: str
    incident_id: str
    action: GuardAction
    title: str
    description: str
    target: str
    target_zone: str
    risk_level: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    decision: GuardDecision
    suggested_alternative: str | None = None


class ApprovalActionRequest(BaseModel):
    """Payload to approve or reject a human-review required Guard decision."""

    model_config = ConfigDict(extra="ignore")

    actor: str = "analyst"
    operator_name: str | None = None
    notes: str | None = None

    @property
    def effective_actor(self) -> str:
        return self.operator_name or self.actor
