"""Context-aware rules engine for SentinelX telemetry detection."""

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from sentinelx.detect.rules.models import RuleDefinition
from sentinelx.detect.utils import extract_event_entities
from sentinelx.enrich.mitre import MitreCatalog, get_mitre_catalog
from sentinelx.normalize.assets import AssetInventory, get_assets
from sentinelx.schemas.common import Technique
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal

logger = logging.getLogger("rules_engine")

SEVERITY_CONFIDENCE_MAP: dict[str, tuple[float, float]] = {
    "critical": (0.95, 0.95),
    "high": (0.85, 0.85),
    "medium": (0.65, 0.70),
    "low": (0.40, 0.50),
}


def extract_field_value(event: Event, field_path: str) -> Any:
    """Safely extract nested fields from Event using dot notation."""
    parts = field_path.split(".")
    curr: Any = event
    for p in parts:
        if curr is None:
            return None
        if isinstance(curr, Event):
            if hasattr(curr, p):
                curr = getattr(curr, p)
            elif curr.raw and isinstance(curr.raw, dict) and p in curr.raw:
                curr = curr.raw[p]
            else:
                return None
        elif isinstance(curr, dict):
            curr = curr.get(p)
        elif hasattr(curr, p):
            curr = getattr(curr, p)
        else:
            return None
    return curr


def evaluate_condition_tree(cond: dict[str, Any], event: Event) -> bool:
    """Evaluate safe condition tree against an Event without using eval()."""
    if "all_of" in cond:
        sub_conds = cond["all_of"]
        if not isinstance(sub_conds, list):
            raise ValueError(f"all_of must be a list of condition nodes, got: {type(sub_conds)}")
        return all(evaluate_condition_tree(sub, event) for sub in sub_conds)

    if "any_of" in cond:
        sub_conds = cond["any_of"]
        if not isinstance(sub_conds, list):
            raise ValueError(f"any_of must be a list of condition nodes, got: {type(sub_conds)}")
        return any(evaluate_condition_tree(sub, event) for sub in sub_conds)

    if "not" in cond:
        sub_cond = cond["not"]
        if not isinstance(sub_cond, dict):
            raise ValueError(f"not condition must be a condition dict, got: {type(sub_cond)}")
        return not evaluate_condition_tree(sub_cond, event)

    # Leaf node comparison
    field_name = cond.get("field")
    op = cond.get("operator")
    expected = cond.get("value")

    if not field_name or not op:
        raise ValueError(f"Malformed condition leaf (missing field or operator): {cond}")

    actual = extract_field_value(event, field_name)

    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "in":
        if isinstance(expected, (list, tuple, set)):
            return actual in expected
        return False
    if op == "not_in":
        if isinstance(expected, (list, tuple, set)):
            return actual not in expected
        return True
    if op == "contains":
        if actual is None:
            return False
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        return str(expected) in str(actual)
    if op == "contains_any":
        if actual is None or not isinstance(expected, (list, tuple, set)):
            return False
        actual_str = str(actual)
        return any(str(sub) in actual_str for sub in expected)
    if op == "startswith":
        return bool(actual and str(actual).startswith(str(expected)))
    if op == "endswith":
        return bool(actual and str(actual).endswith(str(expected)))
    if op == "regex":
        if actual is None:
            return False
        return bool(re.search(str(expected), str(actual), re.IGNORECASE))
    if op in ("gt", "gte", "lt", "lte"):
        try:
            num_actual = float(actual)
            num_exp = float(expected)
            if op == "gt":
                return num_actual > num_exp
            if op == "gte":
                return num_actual >= num_exp
            if op == "lt":
                return num_actual < num_exp
            if op == "lte":
                return num_actual <= num_exp
        except (ValueError, TypeError):
            return False

    raise ValueError(f"Unknown condition operator: {op}")


class RulesEngine:
    """Detection engine evaluating events against declarative YAML rule definitions."""

    def __init__(
        self,
        rules: list[RuleDefinition],
        assets: AssetInventory | None = None,
        mitre: MitreCatalog | None = None,
    ):
        self.rules = rules
        self.assets = assets or get_assets()
        self.mitre = mitre or get_mitre_catalog()
        self._validate_rules()

        # In-memory session tracking for stateful context rules (e.g. cross_zone_pivot)
        self._seen_transitions: set[str] = set()

    def reset_state(self):
        """Reset stateful session caches (used between replay runs)."""
        self._seen_transitions.clear()

    def _validate_rules(self):
        """Validate loaded rules at initialization: fail loudly on any defect."""
        seen_ids: set[str] = set()
        for rule in self.rules:
            if not rule.id:
                raise ValueError("Rule missing mandatory 'id'")
            if rule.id in seen_ids:
                raise ValueError(f"Duplicate rule id detected: {rule.id}")
            seen_ids.add(rule.id)

            # Validate MITRE techniques
            for tid in rule.technique_ids:
                if tid not in self.mitre:
                    raise ValueError(f"Rule {rule.id} references unknown MITRE technique ID: {tid}")

            # Test condition structure
            try:
                # Mock event to verify condition parse tree
                t = event_time_placeholder()
                mock_event = Event(
                    event_id="evt_validation_test",
                    ts=t,
                    ingested_at=t,
                    source_tool="generic",
                    domain="it",
                    category="process",
                    action="test",
                    outcome="success",
                    raw_ref={"file": "test", "offset": 0},
                    raw={"test": True},
                )
                evaluate_condition_tree(rule.condition, mock_event)
            except Exception as exc:
                raise ValueError(f"Rule {rule.id} has invalid condition: {exc}") from exc

    def evaluate_event(self, event: Event) -> list[Signal]:
        """Evaluate a single Event against all loaded rules, returning emitted Signals."""
        # Ensure context-aware tag is present if evaluating a bare/un-enriched event
        if (
            event.action == "ssh_login"
            and "unauthorized_ssh_source" not in event.tags
            and not self.assets.is_ssh_source_authorized(
                src_ip=event.src_ip,
                dst_host=event.host,
                dst_ip=event.dst_ip,
            )
        ):
            event = event.model_copy(
                update={"tags": list(event.tags) + ["unauthorized_ssh_source"]}
            )

        if (
            event.ot
            and event.ot.is_write
            and "unauthorized_ot_write" not in event.tags
            and not self.assets.is_ot_write_authorized(
                event_ts=event.ts,
                src_ip=event.src_ip,
                src_host=event.host if event.src_ip is None and event.host != "plc-sim" else None,
                dst_host=event.host,
                dst_ip=event.dst_ip,
                user=event.user,
            )
        ):
            event = event.model_copy(update={"tags": list(event.tags) + ["unauthorized_ot_write"]})

        signals: list[Signal] = []

        for rule in self.rules:
            # 1. Check applies_to pre-filters
            if rule.applies_to:
                matched_filter = False
                for flt in rule.applies_to:
                    if flt.source_tool and event.source_tool.value != flt.source_tool:
                        continue
                    if flt.category and event.category != flt.category:
                        continue
                    if flt.domain and event.domain.value != flt.domain:
                        continue
                    if flt.action and event.action != flt.action:
                        continue
                    matched_filter = True
                    break
                if not matched_filter:
                    continue

            # 2. Evaluate condition tree
            if not evaluate_condition_tree(rule.condition, event):
                continue

            # 3. Context constraints validation
            if rule.context:
                ctx = rule.context
                # Maintenance window constraint from assets policy / benign config
                is_maint = self.assets.is_in_maintenance_window(event.ts)

                if ctx.outside_maintenance_window and is_maint:
                    # Rule only applies outside maintenance window
                    continue
                if ctx.maintenance_window_only and not is_maint:
                    # Rule only applies inside maintenance window
                    continue

                if ctx.authorized_sources:
                    src_host_obj = (
                        self.assets.get_host_by_ip(event.src_ip) if event.src_ip else None
                    )
                    src_host_name = src_host_obj.name if src_host_obj else None
                    if (
                        (event.host and event.host in ctx.authorized_sources)
                        or (event.src_ip and event.src_ip in ctx.authorized_sources)
                        or (src_host_name and src_host_name in ctx.authorized_sources)
                    ):
                        # Legitimate authorized source, suppress alert
                        continue

                if ctx.forbidden_sources:
                    if not (
                        (event.host and event.host in ctx.forbidden_sources)
                        or (event.src_ip and event.src_ip in ctx.forbidden_sources)
                    ):
                        continue

                if ctx.track_session_history:
                    # Stateful check: transition key host+user+tag
                    zone_tags = [t for t in event.tags if t.startswith("cross_zone:")]
                    if zone_tags:
                        t_key = (
                            f"{event.host or event.src_ip}_{event.user or 'none'}_{zone_tags[0]}"
                        )
                        if t_key in self._seen_transitions:
                            # Prior history in this session, do not re-alert on routine pivot
                            continue
                        self._seen_transitions.add(t_key)

            # 4. Construct Signal
            sig = self._create_signal(rule, event)
            signals.append(sig)

        return signals

    def _create_signal(self, rule: RuleDefinition, event: Event) -> Signal:
        """Construct normalized Signal object from rule match."""
        # Calculate scores from severity hint or explicit overrides
        default_score, default_conf = SEVERITY_CONFIDENCE_MAP.get(
            rule.severity_hint, (rule.score, rule.confidence)
        )
        score = rule.score if rule.score != 0.7 else default_score
        confidence = rule.confidence if rule.confidence != 0.7 else default_conf

        metadata = dict(rule.metadata)
        metadata["rule_id"] = rule.id
        metadata["severity_hint"] = rule.severity_hint
        metadata["tags"] = list(event.tags)

        # Task 5: Deception Handling & Confirmed Honeytoken Elevation
        is_decoy_touch = event.domain.value == "decoy" or rule.id == "RULE-DECOY-001"
        is_honey_user = self.assets.is_honey_user(event.user) or "honey_user" in event.tags
        is_honey_file = (
            self.assets.is_honey_file(event.cmdline)
            or "honey_file" in event.tags
            or (event.cmdline and ".db_creds" in event.cmdline)
        )

        detector_type = "rule"
        if is_decoy_touch and (is_honey_user or is_honey_file):
            score = 0.99
            confidence = 0.99
            detector_type = "deception"
            metadata["confirmed_honeytoken"] = True
            if "confirmed_honeytoken" not in metadata["tags"]:
                metadata["tags"].append("confirmed_honeytoken")
        elif is_decoy_touch:
            detector_type = "deception"
            metadata["decoy_interaction"] = True

        # Resolve techniques
        techniques: list[Technique] = []
        for tid in rule.technique_ids:
            tech = self.mitre.get(tid)
            if tech:
                techniques.append(tech)

        # Format explanation using a flat, well-defined context dict.
        # OT nested fields (ot.register, ot.value) are flattened to ot_register, ot_value, etc.
        # to avoid KeyError on dotted placeholder syntax (e.g. "{ot.register}").
        ot = event.ot
        format_ctx: dict = {
            "host": event.host or "unknown-host",
            "user": event.user or "unknown-user",
            "src_ip": event.src_ip or "unknown-ip",
            "dst_ip": event.dst_ip or "unknown-ip",
            "cmdline": event.cmdline or event.action or "",
            "action": event.action,
            # OT flattened fields – safe fallbacks when OT metadata is missing or partial
            "ot_register": str(ot.register) if ot and ot.register is not None else "unknown",
            "ot_value": str(ot.value) if ot and ot.value is not None else "unknown",
            "ot_operation": ("write" if (ot and ot.is_write) else ("read" if ot else "unknown")),
        }
        try:
            explanation = rule.explanation_template.format_map(format_ctx)
        except (KeyError, IndexError, ValueError) as exc:
            logger.warning(
                "Narrative template formatting failed for rule %s (event %s): %s — "
                "returning raw template to avoid silent data loss",
                rule.id,
                event.event_id,
                exc,
            )
            explanation = rule.explanation_template

        # Deterministic signal ID: hash of rule ID + evidence event IDs
        id_material = f"{rule.id}_{event.event_id}"
        sig_hash = hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:16]
        signal_id = f"sig_{sig_hash}"

        return Signal(
            signal_id=signal_id,
            ts=event.ts,
            detector=detector_type,
            rule_id=rule.id,
            title=rule.title,
            score=round(score, 3),
            confidence=round(confidence, 3),
            entities=extract_event_entities(event),
            evidence_event_ids=[event.event_id],
            techniques=techniques,
            explanation=explanation,
            metadata=metadata,
        )


def event_time_placeholder():
    from datetime import UTC, datetime

    return datetime.now(UTC)


def load_rules(rules_dir: Path | str | None = None) -> list[RuleDefinition]:
    """Load all YAML rule definitions from content/rules/."""
    if rules_dir is None:
        repo_root = Path(__file__).resolve().parents[4]
        r_dir = repo_root / "content" / "rules"
    else:
        r_dir = Path(rules_dir)

    rules: list[RuleDefinition] = []
    for yaml_path in sorted(r_dir.glob("*.yaml")):
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not data:
                continue
            rule = RuleDefinition.model_validate(data)
            rules.append(rule)

    return rules
