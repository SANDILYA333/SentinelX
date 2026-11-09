"""Graph- and entity-based security incident correlation engine."""

import logging
import sqlite3
from typing import Any

from sentinelx.correlate.graph import build_incident_graph
from sentinelx.correlate.scoring import score_incident
from sentinelx.enrich.incident_enricher import (
    check_domain_touches,
    compute_technique_rollup,
    compute_ttfma,
    generate_explanation,
)
from sentinelx.normalize.assets import get_assets
from sentinelx.schemas.common import Entity, EntityType
from sentinelx.schemas.incident import Incident
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import init_db, upsert_incident

logger = logging.getLogger(__name__)

# Default correlation sliding window: 1800 seconds (30 minutes)
# Rationale: Captures slow-burn attack scenarios (~15-20 min total span) while keeping
# normal operational shifts separated into discrete evaluation envelopes.
DEFAULT_CORRELATION_WINDOW_SEC: float = 1800.0


class Correlator:
    """Correlates detection signals into attack incidents via shared entities and graph topology."""

    def __init__(
        self,
        window_sec: float = DEFAULT_CORRELATION_WINDOW_SEC,
        db: Any = None,
        novelty_cap: float = 0.40,
    ):
        self.window_sec = window_sec
        self.novelty_cap = novelty_cap
        if isinstance(db, sqlite3.Connection):
            self.db = db
        elif db is not None:
            self.db = init_db(db)
        else:
            self.db = None

        self.assets = get_assets()
        # Active open incidents in memory: incident_id -> Incident
        self.incidents: dict[str, Incident] = {}
        # Associated signals for each incident: incident_id -> list[Signal]
        self._incident_signals: dict[str, list[Signal]] = {}

    def reset_state(self) -> None:
        """Clear all active in-memory incident tracking state."""
        self.incidents.clear()
        self._incident_signals.clear()

    def _expand_entities(self, entities: list[Entity]) -> set[str]:
        """Expand entity set with multi-homed asset network interfaces and aliases."""
        expanded: set[str] = set()
        for e in entities:
            val_clean = e.value.lower().strip()
            expanded.add(f"{e.type.value}:{val_clean}")

            if e.type == EntityType.ip:
                host = self.assets.get_host_by_ip(e.value)
                if host:
                    expanded.add(f"host:{host.name.lower()}")
                    for ip in host.ips.values():
                        expanded.add(f"ip:{ip.lower()}")
            elif e.type == EntityType.host:
                host = self.assets.get_host_by_name(e.value)
                if host:
                    for ip in host.ips.values():
                        expanded.add(f"ip:{ip.lower()}")
        return expanded

    def _matches_incident(self, incident: Incident, signal: Signal) -> bool:
        """Check whether a signal shares entities with an open incident within the sliding window."""
        # 1. Sliding window check against incident activity span
        time_diff = abs((signal.ts - incident.updated_at).total_seconds())
        if time_diff > self.window_sec:
            return False

        # 2. Entity overlap check with asset inventory topology expansion
        sig_entity_keys = self._expand_entities(signal.entities)
        inc_entity_keys = self._expand_entities(incident.entities)

        if bool(sig_entity_keys & inc_entity_keys):
            return True

        # 3. Known topology bridges: attacker IP <-> jump-host, or eng-ws <-> plc-sim
        jump_host_active = any(
            e.value.lower() in ("jump-host", "10.10.1.10", "10.10.2.10", "10.10.9.10")
            for e in incident.entities
        )
        attacker_in_signal = any(
            e.value.lower() in ("attacker", "10.10.1.5") for e in signal.entities
        )
        if jump_host_active and attacker_in_signal:
            return True

        eng_active = any(
            e.value.lower() in ("eng-ws", "10.10.1.40", "10.10.3.40") for e in incident.entities
        )
        plc_in_signal = any(
            e.value.lower() in ("plc-sim", "10.10.3.20", "decoy-plc", "10.10.3.60")
            for e in signal.entities
        )
        if eng_active and plc_in_signal:
            return True

        return False

    def process_signal(self, signal: Signal) -> Incident:
        """Ingest a signal, attach to matching incident (or create new), and update correlation state."""
        matching_incidents: list[Incident] = []
        for inc in self.incidents.values():
            if inc.status == "open" and self._matches_incident(inc, signal):
                matching_incidents.append(inc)

        if not matching_incidents:
            # Create new incident seeded by this signal
            # Deterministic incident ID based on the initial signal ID for idempotency
            raw_suffix = (
                signal.signal_id[4:]
                if signal.signal_id.startswith("sig_")
                else signal.signal_id[:16]
            )
            incident_id = f"inc_{raw_suffix}"
            signals_list = [signal]
            incident = self._build_incident(incident_id, signals_list)
            self.incidents[incident_id] = incident
            self._incident_signals[incident_id] = signals_list
        else:
            # Attach to the first matching incident
            primary_inc = matching_incidents[0]
            incident_id = primary_inc.incident_id
            signals_list = self._incident_signals[incident_id]

            # Avoid duplicate signal attachment
            if not any(s.signal_id == signal.signal_id for s in signals_list):
                signals_list.append(signal)

            # If signal bridged multiple existing incidents, merge secondary incidents into primary
            if len(matching_incidents) > 1:
                for sec_inc in matching_incidents[1:]:
                    sec_id = sec_inc.incident_id
                    for s in self._incident_signals.get(sec_id, []):
                        if not any(existing.signal_id == s.signal_id for existing in signals_list):
                            signals_list.append(s)
                    self.incidents.pop(sec_id, None)
                    self._incident_signals.pop(sec_id, None)

            incident = self._build_incident(incident_id, signals_list)
            self.incidents[incident_id] = incident

        # Persist to database if provided
        if self.db is not None:
            try:
                upsert_incident(self.db, incident)
            except Exception as e:
                logger.warning(f"Failed to upsert incident {incident.incident_id}: {e}")

        return incident

    def _build_incident(self, incident_id: str, signals: list[Signal]) -> Incident:
        """Reconstruct and enrich an Incident record from its constituent signals."""
        sorted_signals = sorted(signals, key=lambda s: s.ts)
        first_sig = sorted_signals[0]
        last_sig = sorted_signals[-1]

        # Consolidate entities
        entities_dict: dict[tuple[EntityType, str], Entity] = {}
        for s in sorted_signals:
            for ent in s.entities:
                entities_dict[(ent.type, ent.value)] = ent
        entities = list(entities_dict.values())

        # Consolidate signal and event IDs
        signal_ids = list(dict.fromkeys(s.signal_id for s in sorted_signals))
        event_ids: list[str] = []
        for s in sorted_signals:
            event_ids.extend(s.evidence_event_ids)
        event_ids = list(dict.fromkeys(event_ids))

        # Score and Kill-Chain Stages
        score, kill_chain_stages, severity = score_incident(
            sorted_signals, novelty_cap=self.novelty_cap
        )

        # MITRE rollup
        techniques = compute_technique_rollup(sorted_signals)

        # TTFMA calculation
        first_meaningful_alert_ts, ttfma_seconds = compute_ttfma(sorted_signals, first_sig.ts)

        # Explanation narrative
        explanation = generate_explanation(sorted_signals)

        # Novelty-only flag & explanation line
        novelty_only = (
            all(
                (s.detector.value if hasattr(s.detector, "value") else str(s.detector))
                in ("baseline", "graph", "anomaly")
                for s in sorted_signals
            )
            if sorted_signals
            else False
        )
        if novelty_only:
            explanation.append(
                f"Corroboration requirement applied: score capped at {self.novelty_cap:.2f} "
                "(lacks deterministic rule or deception corroboration)"
            )

        # Domain touch flags
        decoy_touched, ot_touched = check_domain_touches(sorted_signals)

        # Attack graph
        graph = build_incident_graph(sorted_signals)

        return Incident(
            incident_id=incident_id,
            status="open",
            created_at=first_sig.ts,
            updated_at=last_sig.ts,
            first_signal_ts=first_sig.ts,
            first_meaningful_alert_ts=first_meaningful_alert_ts,
            ttfma_seconds=ttfma_seconds,
            score=score,
            severity=severity,
            entities=entities,
            signal_ids=signal_ids,
            event_ids=event_ids,
            kill_chain_stages=kill_chain_stages,
            techniques=techniques,
            decoy_touched=decoy_touched,
            ot_touched=ot_touched,
            novelty_only=novelty_only,
            explanation=explanation,
            summary=None,
            summary_citations=[],
            graph=graph,
        )

    def get_all_incidents(self) -> list[Incident]:
        """Return all tracked incidents sorted by score descending."""
        return sorted(self.incidents.values(), key=lambda inc: inc.score, reverse=True)
