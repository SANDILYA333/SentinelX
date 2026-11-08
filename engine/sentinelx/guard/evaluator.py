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
from sentinelx.schemas.guard import AssetCriticality, GuardAction, GuardDecision, GuardOutcome
from sentinelx.store.sqlite import init_db, insert_guard_decision

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

        return "low"

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
    ) -> GuardDecision:
        """Evaluate a proposed containment action against loaded safety policies."""
        criticality = self.resolve_target_criticality(target)

        # Resolve live or passed PLC physics state
        if plc_state is None:
            plc_state = self.query_live_plc_state()

        flag = str(plc_state.get("flag", "normal")).lower()

        # Iterate policies in declaration order
        chosen_policy: dict[str, Any] | None = None
        for pol in self._policies:
            conds = pol.get("conditions", {})
            if not conds:
                # Default policy matches anything
                chosen_policy = pol
                break

            # Action check
            if "actions" in conds and action not in conds["actions"]:
                continue

            # Criticality check
            if "target_criticality" in conds and criticality not in conds["target_criticality"]:
                continue

            # PLC state check
            if "plc_state_not" in conds and flag == conds["plc_state_not"].lower():
                continue
            if "plc_state" in conds and flag != conds["plc_state"].lower():
                continue

            # All specified conditions match
            chosen_policy = pol
            break

        if chosen_policy is None:
            decision_outcome: GuardOutcome = "needs_human"
            reasons = ["No matching policy found; escalating to SOC analyst."]
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
        )

        # Persist decision to database if available
        if self._db is not None:
            try:
                insert_guard_decision(self._db, decision)
            except Exception as e:
                logger.warning(f"Failed to persist guard decision to db: {e}")

        return decision
