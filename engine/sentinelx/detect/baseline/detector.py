"""Per-entity behavioral deviation baseline detector."""

import hashlib
import logging
from pathlib import Path

from sentinelx.detect.baseline.model import BaselineModel
from sentinelx.detect.utils import extract_event_entities
from sentinelx.enrich.mitre import MitreCatalog, get_mitre_catalog
from sentinelx.schemas.common import Technique
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal

logger = logging.getLogger("baseline_detector")


class BaselineDetector:
    """Detects statistical and behavioral deviations against learned per-entity baselines."""

    def __init__(
        self,
        model: BaselineModel | None = None,
        model_path: Path | str | None = None,
        mitre: MitreCatalog | None = None,
        threshold: float = 0.60,
    ):
        if model is not None:
            self.model = model
        elif model_path is not None:
            self.model = BaselineModel.load(model_path)
        else:
            default_path = (
                Path(__file__).resolve().parents[4] / "data" / "models" / "baseline_stats.json"
            )
            if default_path.is_file():
                self.model = BaselineModel.load(default_path)
            else:
                self.model = BaselineModel()

        self.mitre = mitre or get_mitre_catalog()
        self.threshold = threshold

    def reset_state(self) -> None:
        """Reset state if needed (stateless across single events, baselines are persistent)."""
        pass

    def evaluate_event(self, event: Event) -> list[Signal]:
        """Evaluate event against baseline profiles and emit Signal if deviation >= threshold."""
        if not self.model.profiles and not self.model.known_users:
            return []

        score = 0.0
        factors: list[str] = []
        reasons: list[str] = []
        technique_ids: list[str] = []

        user = event.user
        host = event.host
        cmd = event.cmdline or event.process

        if user:
            if user not in self.model.known_users:
                score += 0.60
                factors.append("unknown_user")
                reasons.append(f"Unknown user '{user}' never observed in benign training")
                technique_ids.append("T1078.003")
            else:
                profile = self.model.get_profile(f"user:{user}")
                if profile:
                    # Check host access
                    if host and host not in profile.allowed_hosts:
                        score += 0.40
                        factors.append("rare_host_for_user")
                        reasons.append(f"User '{user}' accessing unprecedented host '{host}'")
                        technique_ids.append("T1021.004")

                    # Check command execution
                    if cmd:
                        clean_cmd = cmd.strip()
                        is_allowed = any(
                            clean_cmd.startswith(ac) or ac.startswith(clean_cmd)
                            for ac in profile.allowed_commands
                        )
                        if not is_allowed:
                            score += 0.50
                            factors.append("unseen_command")
                            reasons.append(
                                f"Unseen command '{clean_cmd}' executed by user '{user}'"
                            )
                            technique_ids.append("T1059.004")

                    # Check zone
                    if event.domain and event.domain.value not in profile.allowed_zones:
                        score += 0.40
                        factors.append("rare_zone")
                        reasons.append(
                            f"User '{user}' active in unprecedented zone '{event.domain.value}'"
                        )
                        technique_ids.append("T1021.004")

        elif host:
            # Check host profile without user
            if host not in self.model.known_hosts:
                score += 0.40
                factors.append("unknown_host")
                reasons.append(f"Unknown host '{host}' never observed in benign training")
                technique_ids.append("T1046")

        if score < self.threshold:
            return []

        # Resolve techniques
        if not technique_ids:
            technique_ids.append("T1078")
        techniques: list[Technique] = []
        for tid in sorted(set(technique_ids)):
            t = self.mitre.get(tid)
            if t:
                techniques.append(t)

        normalized_score = min(round(score, 3), 1.0)
        confidence = min(round(score * 0.9, 3), 0.95)

        # Deterministic signal ID: hash of rule + evidence event ID
        id_material = f"BASE-DEV-001_{event.event_id}"
        sig_hash = hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:16]
        signal_id = f"sig_{sig_hash}"

        explanation = f"Baseline deviation (score {normalized_score:.2f}): {'; '.join(reasons)}"

        sig = Signal(
            signal_id=signal_id,
            ts=event.ts,
            detector="baseline",
            rule_id="BASE-DEV-001",
            title=f"Baseline Behavioral Deviation ({user or host or 'Entity'})",
            score=normalized_score,
            confidence=confidence,
            entities=extract_event_entities(event),
            evidence_event_ids=[event.event_id],
            techniques=techniques,
            explanation=explanation,
            metadata={
                "deviation_score": normalized_score,
                "factors": factors,
                "reasons": reasons,
            },
        )
        return [sig]
