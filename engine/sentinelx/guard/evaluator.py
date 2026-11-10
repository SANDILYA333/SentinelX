"""Response safety policy evaluator for SentinelX automated containment."""

import hashlib
import json
import logging
import sqlite3
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.common import new_id
from sentinelx.schemas.guard import (
    ApprovalStatus,
    AssetCriticality,
    GuardAction,
    GuardDecision,
    GuardOutcome,
    GuardPolicyEvaluationResult,
    ResponseRecommendation,
)
from sentinelx.store.sqlite import (
    get_guard_decision_by_id,
    init_db,
    insert_guard_decision,
    update_guard_decision,
)

logger = logging.getLogger(__name__)


class GuardEvaluator:
    """Evaluates proposed containment actions against response safety policies."""

    def __init__(self, content_dir: Path | str | None = None, db: Any = None):
        if content_dir is None:
            repo_root = Path(__file__).resolve().parent.parent.parent.parent
            self._guard_dir = repo_root / "content" / "guard"
        else:
            self._guard_dir = Path(content_dir)

        if isinstance(db, sqlite3.Connection):
            self._db = db
        elif db is not None:
            self._db = init_db(db)
        else:
            self._db = None
        self._actions = self._load_actions()
        self._policies = self._load_policies()
        self._assets = get_assets()

    def _load_actions(self) -> dict[str, Any]:
        actions_file = self._guard_dir / "actions.yaml"
        if not actions_file.is_file():
            return {}
        with open(actions_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("actions", {})

    def _load_policies(self) -> list[dict[str, Any]]:
        policies_file = self._guard_dir / "policies.yaml"
        if not policies_file.is_file():
            return []
        with open(policies_file, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("policies", [])

    def resolve_target_criticality(self, target: str) -> AssetCriticality:
        """Resolve asset criticality from assets inventory."""
        target_clean = target.strip()
        host = self._assets.get_host_by_name(target_clean) or self._assets.get_host_by_ip(
            target_clean
        )
        if host:
            return host.criticality  # type: ignore[return-value]

        # Check if target is a known attacker or external IP
        if target_clean in ("10.10.1.5", "attacker"):
            return "low"

        # Check zone fallback
        zone = self._assets.get_zone_for_ip(target_clean)
        if zone == "ot":
            return "process_critical"
        if zone == "mgmt":
            return "high"
        if zone in ("it", "dmz"):
            return "medium"

        # Unknown targets outside authoritative inventory are conservatively treated as high criticality
        return "high"

    def resolve_target_zone(self, target: str) -> str:
        """Resolve network zone for target asset or IP."""
        target_clean = target.strip()
        host = self._assets.get_host_by_name(target_clean) or self._assets.get_host_by_ip(
            target_clean
        )
        if host:
            return host.zone
        if target_clean in ("10.10.1.5", "attacker"):
            return "it"
        if target_clean in (
            "10.10.2.20",
            "10.10.2.30",
            "backup-srv-02",
            "db-prod-02",
            "cowrie",
            "opencanary",
        ):
            return "dmz"
        if target_clean in ("10.10.3.40", "10.10.3.60", "plc-sim", "decoy-plc"):
            return "ot"
        zone = self._assets.get_zone_for_ip(target_clean)
        return zone or "unknown"

    def query_live_plc_state(self) -> dict[str, Any]:
        """Query live plc-sim /state if running, otherwise return baseline state."""
        urls = ["http://127.0.0.1:8080/state", "http://localhost:8080/state"]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SentinelX-Guard/1.0"})
                with urllib.request.urlopen(req, timeout=0.25) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if isinstance(data, dict):
                            return data
            except Exception:
                continue
        return {"flag": "normal", "tank_level": 50.0, "valve_open": True}

    def evaluate(
        self,
        action: GuardAction,
        target: str,
        incident_id: str | None = None,
        plc_state: dict[str, Any] | None = None,
        requested_by: str = "sentinelx_guard",
        supporting_evidence_ids: list[str] | None = None,
    ) -> GuardDecision:
        """Evaluate a proposed containment action against loaded safety policies."""
        criticality = self.resolve_target_criticality(target)
        target_zone = self.resolve_target_zone(target)
        action_meta = self._actions.get(action, {})
        safety_risk = action_meta.get("safety_risk", "medium")

        # Resolve live or passed PLC physics state
        if plc_state is None:
            plc_state = self.query_live_plc_state()

        flag = str(plc_state.get("flag", "normal")).lower()

        # Track evaluations for every policy
        policy_evaluations: list[GuardPolicyEvaluationResult] = []
        chosen_policy: dict[str, Any] | None = None

        for pol in self._policies:
            pol_id = pol.get("id", "GUARD-DEFAULT")
            pol_name = pol.get("name", pol_id)
            conds = pol.get("conditions", {})

            matched = True
            mismatch_reasons: list[str] = []

            if "actions" in conds and action not in conds["actions"]:
                matched = False
                mismatch_reasons.append(f"Action '{action}' not covered by {conds['actions']}")

            if "target_criticality" in conds and criticality not in conds["target_criticality"]:
                matched = False
                mismatch_reasons.append(
                    f"Criticality '{criticality}' not in {conds['target_criticality']}"
                )

            if "plc_state_not" in conds and flag == conds["plc_state_not"].lower():
                matched = False
                mismatch_reasons.append(
                    f"PLC flag '{flag}' equals restricted '{conds['plc_state_not']}'"
                )

            if "plc_state" in conds and flag != conds["plc_state"].lower():
                matched = False
                mismatch_reasons.append(f"PLC flag '{flag}' != required '{conds['plc_state']}'")

            outcome = pol.get("outcome", "needs_human")
            if matched:
                res_type = (
                    "pass" if outcome == "allow" else ("fail" if outcome == "deny" else "review")
                )
                explanation = pol.get("reasons", ["Policy matched."])[0]
                policy_evaluations.append(
                    GuardPolicyEvaluationResult(
                        policy_id=pol_id,
                        policy_name=pol_name,
                        result=res_type,
                        explanation=explanation,
                    )
                )
                if chosen_policy is None:
                    chosen_policy = pol
            else:
                policy_evaluations.append(
                    GuardPolicyEvaluationResult(
                        policy_id=pol_id,
                        policy_name=pol_name,
                        result="pass",
                        explanation="; ".join(mismatch_reasons)
                        if mismatch_reasons
                        else "Not applicable",
                    )
                )

        if chosen_policy is None:
            decision_outcome: GuardOutcome = "needs_human"
            reasons = [
                "No matching policy found; escalating to SOC analyst for human safety review."
            ]
            rule_ids = ["GUARD-DEFAULT"]
        else:
            decision_outcome = chosen_policy.get("outcome", "needs_human")
            reasons = list(chosen_policy.get("reasons", []))
            rule_ids = [chosen_policy.get("id", "GUARD-DEFAULT")]

        if incident_id:
            raw_hash = hashlib.sha256(
                f"{incident_id}:{action}:{target}:{requested_by}".encode()
            ).hexdigest()[:16]
            decision_id = f"dec_{raw_hash}"
        else:
            decision_id = new_id("dec")

        approval_status: ApprovalStatus = (
            "pending_review" if decision_outcome == "needs_human" else "not_required"
        )

        decision = GuardDecision(
            decision_id=decision_id,
            ts=datetime.now(UTC),
            incident_id=incident_id,
            action=action,
            target=target,
            decision=decision_outcome,
            reasons=reasons,
            rule_ids=rule_ids,
            asset_criticality=criticality,
            requested_by=requested_by,
            target_zone=target_zone,
            safety_risk=safety_risk,
            supporting_evidence_ids=supporting_evidence_ids or [],
            policy_evaluations=policy_evaluations,
            approval_status=approval_status,
        )

        # Persist decision to database if available
        if self._db is not None:
            try:
                insert_guard_decision(self._db, decision)
            except Exception as e:
                logger.warning(f"Failed to persist guard decision to db: {e}")

        return decision

    def approve_decision(
        self,
        decision_id: str,
        actor: str = "analyst",
        notes: str | None = None,
        operator_name: str | None = None,
    ) -> GuardDecision:
        """Approve a response action requiring human review.

        Industrial Safety Constraint:
        Approval CANNOT bypass an explicit DENY. Denied actions are fundamentally prohibited.
        """
        effective_actor = operator_name or actor
        if self._db is None:
            raise RuntimeError("Database connection required to record approval.")

        decision = get_guard_decision_by_id(self._db, decision_id)
        if not decision:
            raise ValueError(f"Decision {decision_id} not found.")

        if decision.decision == "deny":
            raise ValueError(
                f"Safety Policy Violation: Decision {decision_id} was DENIED by policy "
                f"'{decision.rule_ids[0]}'. Human approval cannot override an explicit safety denial."
            )

        if decision.decision == "allow":
            raise ValueError(
                f"Redundant Approval: Decision {decision_id} is already permitted (ALLOW) by policy "
                f"'{decision.rule_ids[0]}'. Human approval is not required."
            )

        if decision.approval_status == "approved":
            raise ValueError(
                f"State Conflict: Decision {decision_id} is already approved by {decision.approved_by}."
            )

        if decision.approval_status == "rejected":
            raise ValueError(
                f"State Conflict: Decision {decision_id} was already rejected by {decision.approved_by}. "
                "A rejected decision cannot be approved. Submit a new evaluation request."
            )

        now = datetime.now(UTC)
        updated = decision.model_copy(
            update={
                "approval_status": "approved",
                "approved_by": effective_actor,
                "approved_at": now,
                "approval_notes": notes or "Approved by authorized human operator.",
            }
        )
        update_guard_decision(self._db, updated)
        return updated

    def reject_decision(
        self,
        decision_id: str,
        actor: str = "analyst",
        notes: str | None = None,
        operator_name: str | None = None,
    ) -> GuardDecision:
        """Reject a proposed response action."""
        effective_actor = operator_name or actor
        if self._db is None:
            raise RuntimeError("Database connection required to record rejection.")

        decision = get_guard_decision_by_id(self._db, decision_id)
        if not decision:
            raise ValueError(f"Decision {decision_id} not found.")

        if decision.decision == "deny":
            raise ValueError(
                f"Redundant Rejection: Decision {decision_id} was already DENIED by safety policy "
                f"'{decision.rule_ids[0]}'."
            )

        if decision.approval_status == "rejected":
            raise ValueError(
                f"State Conflict: Decision {decision_id} has already been rejected by {decision.approved_by}."
            )

        if decision.approval_status == "approved":
            raise ValueError(
                f"State Conflict: Decision {decision_id} was already approved by {decision.approved_by}. "
                "An approved decision cannot be unilaterally rejected. Submit a new evaluation request."
            )

        now = datetime.now(UTC)
        updated = decision.model_copy(
            update={
                "approval_status": "rejected",
                "approved_by": effective_actor,
                "approved_at": now,
                "approval_notes": notes or "Rejected by analyst during safety review.",
            }
        )
        update_guard_decision(self._db, updated)
        return updated

    def generate_incident_recommendations(
        self,
        incident: Any,
        events: list[Any] | None = None,
        signals: list[Any] | None = None,
    ) -> list[ResponseRecommendation]:
        """Generate candidate response recommendations for an incident, pre-evaluated by the Guard."""
        inc_id = getattr(incident, "incident_id", str(incident))
        evidence_ids: list[str] = getattr(incident, "event_ids", [])
        if events and not evidence_ids:
            evidence_ids = [getattr(e, "event_id", str(e)) for e in events]

        candidates: list[dict[str, Any]] = []

        # 1. Attacker IP blocking (Perimeter boundary rule)
        candidates.append(
            {
                "action": "block_ip",
                "target": "10.10.1.5",
                "title": "Block Attacker IP at Boundary Firewall",
                "description": "Install perimeter drop rule for untrusted attacker IP (10.10.1.5) to sever external ingress.",
                "risk_level": "low",
            }
        )

        # 2. Compromised user account disabling
        has_backup_user = any(
            getattr(e, "user", None) == "svc_backup"
            or "svc_backup" in str(getattr(e, "cmdline", ""))
            for e in (events or [])
        )
        if has_backup_user or any(
            "svc_backup" in str(getattr(ent, "value", ""))
            for ent in getattr(incident, "entities", [])
        ):
            candidates.append(
                {
                    "action": "disable_account",
                    "target": "svc_backup",
                    "title": "Disable Compromised Account (svc_backup)",
                    "description": "Revoke active authentication sessions and tokens for compromised backup service account.",
                    "risk_level": "medium",
                }
            )

        # 3. Intermediate jump host containment
        candidates.append(
            {
                "action": "isolate_host",
                "target": "jump-host",
                "title": "Isolate Jump Host (Inter-Zone Bridge)",
                "description": "Sever network interfaces on jump-host to cut off lateral movement between IT, DMZ, and MGMT.",
                "risk_level": "high",
            }
        )

        # 4. Engineering workstation containment
        candidates.append(
            {
                "action": "isolate_host",
                "target": "eng-ws",
                "title": "Isolate Engineering Workstation (OT Boundary)",
                "description": "Sever network connectivity on eng-ws to prevent further unauthorized OT controller manipulation.",
                "risk_level": "high",
            }
        )

        # 5. OT Controller Protection (Modbus Filtering)
        candidates.append(
            {
                "action": "block_modbus_write",
                "target": "plc-sim",
                "title": "Filter Modbus Actuator Writes on PLC",
                "description": "Drop unauthorized Function Code 06/16 Modbus write commands directed at physical PLC controller.",
                "risk_level": "critical",
            }
        )

        # 6. Critical OT Controller Isolation (Expected to be DENIED / NEEDS_HUMAN)
        candidates.append(
            {
                "action": "isolate_host",
                "target": "plc-sim",
                "title": "Isolate Industrial PLC Controller",
                "description": "Sever physical network interfaces on operational industrial PLC controller.",
                "risk_level": "critical",
            }
        )

        recommendations: list[ResponseRecommendation] = []
        for i, cand in enumerate(candidates):
            # Pre-evaluate each candidate through the Guard
            decision = self.evaluate(
                action=cand["action"],
                target=cand["target"],
                incident_id=inc_id,
                supporting_evidence_ids=evidence_ids[:10],
                requested_by="recommendation_engine",
            )

            # Suggest safer alternative if denied
            alternative = None
            if decision.decision == "deny":
                for r in decision.reasons:
                    if "safer alternative" in r.lower():
                        alternative = r
                        break

            rec_id = f"rec_{inc_id}_{i + 1:02d}_{cand['action']}_{cand['target'].replace('.', '_')}"
            recommendations.append(
                ResponseRecommendation(
                    recommendation_id=rec_id,
                    incident_id=inc_id,
                    action=cand["action"],
                    title=cand["title"],
                    description=cand["description"],
                    target=cand["target"],
                    target_zone=decision.target_zone or "it",
                    risk_level=cand["risk_level"],
                    supporting_evidence_ids=evidence_ids[:10],
                    decision=decision,
                    suggested_alternative=alternative,
                )
            )

        return recommendations
