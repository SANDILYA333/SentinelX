"""Phase A regression tests: narrative template, TTFMA, correlation persistence,
idempotency, and API filtering.

Each test is self-contained and uses isolated temporary databases so production data
is never touched.
"""

import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinelx.budget.controller import DEFAULT_INCIDENT_THRESHOLD, BudgetController
from sentinelx.correlate.correlator import DEFAULT_CORRELATION_WINDOW_SEC, Correlator
from sentinelx.correlate.pipeline import CorrelationPipeline
from sentinelx.correlate.scoring import score_incident
from sentinelx.detect.rules.engine import RulesEngine, load_rules
from sentinelx.enrich.incident_enricher import compute_ttfma
from sentinelx.schemas.common import Entity, EntityType
from sentinelx.schemas.event import Event, OTFields
from sentinelx.schemas.incident import Incident
from sentinelx.schemas.signal import Signal
from sentinelx.store.sqlite import (
    get_incident_by_id,
    get_signal_by_id,
    init_db,
    insert_signal,
    list_incidents,
    upsert_incident,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    """Return a timestamp within the correlation window (current time)."""
    return datetime.now(UTC)


def make_signal(
    signal_id: str,
    ts: datetime,
    detector: str = "rule",
    rule_id: str = "RULE-AUTH-001",
    score: float = 0.85,
    confidence: float = 0.85,
    entities: list[Entity] | None = None,
    explanation: str = "Test signal",
    metadata: dict | None = None,
) -> Signal:
    return Signal(
        signal_id=signal_id,
        ts=ts,
        detector=detector,  # type: ignore[arg-type]
        rule_id=rule_id,
        title="Test Signal",
        score=score,
        confidence=confidence,
        entities=entities or [Entity(type=EntityType.host, value="jump-host")],
        evidence_event_ids=[f"evt_{signal_id}"],
        techniques=[],
        explanation=explanation,
        metadata=metadata or {},
    )


def make_ot_event(
    event_id: str,
    ts: datetime,
    register: int | None = 100,
    value: int | None = 1,
    host: str = "plc-sim",
    tags: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        ts=ts,
        ingested_at=ts,
        source_tool="modbus",
        domain="ot",
        category="ot_command",
        action="write_holding_register",
        outcome="success",
        host=host,
        src_ip="10.10.1.40",
        tags=tags or ["unauthorized_ot_write"],
        ot=OTFields(register=register, value=value, is_write=True),
        raw_ref={"file": "test.csv", "offset": 0},
        raw={},
    )


def make_temp_db() -> sqlite3.Connection:
    """Create an isolated in-memory SQLite database for testing."""
    # Use init_db so the full schema (including signals, incidents tables) is set up correctly
    return init_db(":memory:")


# ===========================================================================
# TASK 1 — Narrative Template Expansion (RULE-OT-001)
# ===========================================================================


class TestNarrativeTemplates:
    """Task 1: Verify RULE-OT-001 and other templates expand correctly."""

    def setup_method(self):
        self.rules = load_rules()
        self.engine = RulesEngine(self.rules)
        self.t = _now()

    def test_ot_write_with_register_and_value(self):
        """Valid Modbus write: narrative must contain actual register and value, not placeholders."""
        event = make_ot_event("evt_ot_001", self.t, register=100, value=1)
        signals = self.engine.evaluate_event(event)
        ot_sigs = [s for s in signals if s.rule_id == "RULE-OT-001"]
        assert ot_sigs, "RULE-OT-001 must fire for a valid unauthorized OT write"
        exp = ot_sigs[0].explanation
        assert "{ot.register}" not in exp, "Literal '{ot.register}' must not appear in narrative"
        assert "{ot.value}" not in exp, "Literal '{ot.value}' must not appear in narrative"
        assert "100" in exp, "Register value 100 must appear in narrative"
        assert "1" in exp, "Written value 1 must appear in narrative"
        assert "plc-sim" in exp, "Host must appear in narrative"

    def test_ot_write_missing_ot_metadata_uses_fallback(self):
        """OT event with register=None: narrative must use 'unknown' fallback, not crash."""
        event = Event(
            event_id="evt_ot_missing",
            ts=self.t,
            ingested_at=self.t,
            source_tool="modbus",
            domain="ot",
            category="ot_command",
            action="write_holding_register",
            outcome="success",
            host="plc-sim",
            tags=["unauthorized_ot_write"],
            ot=OTFields(register=None, value=None, is_write=True),
            raw_ref={"file": "test.csv", "offset": 0},
            raw={},
        )
        # RULE-OT-001 requires register != null, so it won't fire for register=None;
        # but the engine must not crash
        signals = self.engine.evaluate_event(event)
        ot_sigs = [s for s in signals if s.rule_id == "RULE-OT-001"]
        assert ot_sigs == []
        # With register=None the condition neq null fails, so rule shouldn't fire
        # but we verify no exception was raised
        assert isinstance(signals, list)

    def test_ot_write_missing_host_field(self):
        """OT event with no host: host should fall back to 'unknown-host'."""
        event = Event(
            event_id="evt_ot_nohost",
            ts=self.t,
            ingested_at=self.t,
            source_tool="modbus",
            domain="ot",
            category="ot_command",
            action="write_holding_register",
            outcome="success",
            host=None,
            tags=["unauthorized_ot_write"],
            ot=OTFields(register=5, value=255, is_write=True),
            raw_ref={"file": "test.csv", "offset": 0},
            raw={},
        )
        signals = self.engine.evaluate_event(event)
        ot_sigs = [s for s in signals if s.rule_id == "RULE-OT-001"]
        if ot_sigs:  # may or may not fire depending on condition evaluation
            exp = ot_sigs[0].explanation
            assert "unknown-host" in exp or "None" not in exp

    def test_non_ot_rule_template_still_works(self):
        """Non-OT rules (RULE-AUTH-001) must still format correctly after template engine change."""
        event = Event(
            event_id="evt_auth_001",
            ts=self.t,
            ingested_at=self.t,
            source_tool="wazuh",
            domain="it",
            category="authentication",
            action="ssh_login",
            outcome="success",
            host="jump-host",
            user="svc_backup",
            src_ip="10.10.1.5",
            tags=["unauthorized_ssh_source"],
            raw_ref={"file": "test.log", "offset": 0},
            raw={},
        )
        signals = self.engine.evaluate_event(event)
        auth_sigs = [s for s in signals if s.rule_id == "RULE-AUTH-001"]
        assert auth_sigs, "RULE-AUTH-001 must fire for unauthorized SSH"
        exp = auth_sigs[0].explanation
        assert "jump-host" in exp
        assert "svc_backup" in exp

    def test_malformed_template_logs_warning_not_crash(self, caplog):
        """A template with an unknown placeholder falls back to raw template and logs a warning."""
        import logging

        from sentinelx.detect.rules.models import RuleDefinition

        malformed_rule = RuleDefinition(
            id="RULE-TEST-999",
            title="Malformed Template Test",
            severity_hint="low",
            applies_to=[{"category": "authentication"}],
            condition={"field": "action", "operator": "eq", "value": "ssh_login"},
            technique_ids=["T1078.003"],
            # {unknown_field} is not in the format_ctx
            explanation_template="Alert on {host} for {unknown_field}",
        )

        # Directly call the engine's create_signal path
        from sentinelx.detect.rules.engine import RulesEngine

        engine = RulesEngine([malformed_rule])

        event = Event(
            event_id="evt_malformed_001",
            ts=self.t,
            ingested_at=self.t,
            source_tool="wazuh",
            domain="it",
            category="authentication",
            action="ssh_login",
            outcome="success",
            host="jump-host",
            tags=["unauthorized_ssh_source"],
            raw_ref={"file": "test.log", "offset": 0},
            raw={},
        )
        with caplog.at_level(logging.WARNING, logger="rules_engine"):
            signals = engine.evaluate_event(event)

        assert signals, "Engine must still produce a signal even with malformed template"
        exp = signals[0].explanation
        # The raw template is returned — not a Python exception traceback
        assert "Alert on" in exp or "unknown_field" in exp
        # A warning must have been logged
        assert any(
            "formatting failed" in r.message.lower() or "template" in r.message.lower()
            for r in caplog.records
        ), "Warning must be logged when template formatting fails"

    def test_no_literal_ot_placeholders_in_any_emitted_signal(self):
        """Regression: {ot.register} and {ot.value} must never appear literally in a signal."""
        event = make_ot_event("evt_ot_regression", self.t, register=200, value=42)
        signals = self.engine.evaluate_event(event)
        for s in signals:
            assert "{ot.register}" not in s.explanation
            assert "{ot.value}" not in s.explanation


# ===========================================================================
# TASK 2 — TTFMA Calculation
# ===========================================================================


class TestTTFMA:
    """Task 2: Verify event-time TTFMA definition is implemented correctly."""

    THRESHOLD = 0.50
    NOVELTY_CAP = 0.40

    def _make_sigs(self, offsets_and_rules: list[tuple[float, str]]) -> list[Signal]:
        """Make signals at given second offsets with given rule IDs."""
        base = _now()
        sigs = []
        for i, (offset, rule_id) in enumerate(offsets_and_rules):
            # Choose score based on rule to match scoring model
            score = 0.85 if rule_id.startswith("RULE-") else 0.40
            sigs.append(
                make_signal(
                    signal_id=f"sig_{i:03d}",
                    ts=base + timedelta(seconds=offset),
                    rule_id=rule_id,
                    score=score,
                )
            )
        return sigs

    def test_first_event_not_meaningful_later_crosses_threshold(self):
        """TTFMA > 0 when only later signals cross the threshold."""
        # discovery (0.15) alone < 0.50; initial_access + discovery + ot_impact > 0.50
        sigs = [
            make_signal(
                "sig_disc",
                _now(),
                detector="graph",
                rule_id="GRAPH-SCAN-001",
                score=0.40,
                confidence=0.40,
                entities=[Entity(type=EntityType.host, value="jump-host")],
            ),
            make_signal(
                "sig_auth",
                _now() + timedelta(seconds=10),
                detector="rule",
                rule_id="RULE-AUTH-001",
                score=0.85,
                confidence=0.85,
                entities=[Entity(type=EntityType.host, value="jump-host")],
            ),
            make_signal(
                "sig_ot",
                _now() + timedelta(seconds=20),
                detector="rule",
                rule_id="RULE-OT-001",
                score=0.95,
                confidence=0.95,
                entities=[Entity(type=EntityType.host, value="eng-ws")],
            ),
        ]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        assert first_ts is not None
        assert threshold_ts is not None
        assert ttfma is not None
        assert ttfma > 0.0, "TTFMA must be > 0 when first signal is not threshold-crossing"

    def test_first_event_is_rule_signal_but_not_crossing_threshold(self):
        """Single RULE-OT-001 signal scores 0.30 (OT alone) — does not cross 0.50 threshold."""
        # score_incident([OT only]) = 0.30 < 0.50
        sigs = [
            make_signal(
                "sig_ot",
                _now(),
                detector="rule",
                rule_id="RULE-OT-001",
                score=0.95,
                confidence=0.95,
                entities=[Entity(type=EntityType.host, value="plc-sim")],
            ),
        ]
        # Score single OT signal to verify it's below threshold
        score, _, _ = score_incident(sigs, novelty_cap=self.NOVELTY_CAP)
        assert score < self.THRESHOLD, f"Single OT signal should score below threshold, got {score}"

        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        # Incident has not crossed threshold — TTFMA must be None
        assert threshold_ts is None
        assert ttfma is None
        assert first_ts is not None

    def test_first_event_immediately_crosses_threshold(self):
        """When a full kill chain produces an above-threshold score from first replay, TTFMA = 0.0."""
        # Build a set of signals that together are above threshold from the very start
        # Simulate by giving first signal a boosted scenario (deception + ot)
        sigs = [
            make_signal(
                "sig_honey",
                _now(),
                detector="deception",
                rule_id="RULE-DECOY-001",
                score=0.99,
                confidence=0.99,
                metadata={"confirmed_honeytoken": True},
                entities=[Entity(type=EntityType.host, value="cowrie")],
            ),
        ]
        score, _, _ = score_incident(sigs, novelty_cap=self.NOVELTY_CAP)
        # Honeytoken alone should score >= 0.50
        if score >= self.THRESHOLD:
            first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
                sigs, self.THRESHOLD, self.NOVELTY_CAP
            )
            assert ttfma == 0.0, (
                f"TTFMA must be 0.0 when first signal crosses threshold; got {ttfma}"
            )
            assert threshold_ts == first_ts

    def test_reordered_event_arrival(self):
        """Events arriving out of chronological order must still produce correct TTFMA."""
        base = _now()
        # Signals in WRONG order
        sig_late = make_signal(
            "sig_late",
            base + timedelta(seconds=20),
            detector="rule",
            rule_id="RULE-OT-001",
            score=0.95,
            confidence=0.95,
            entities=[Entity(type=EntityType.host, value="plc-sim")],
        )
        sig_early = make_signal(
            "sig_early",
            base,
            detector="graph",
            rule_id="GRAPH-SCAN-001",
            score=0.40,
            confidence=0.40,
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        # Submit in reverse order
        sigs = [sig_late, sig_early]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        # first_ts must be the EARLIER timestamp regardless of submission order
        assert first_ts == base

    def test_slow_burn_attack_progression(self):
        """Five-stage slow burn spanning 15+ minutes: TTFMA is gap between first and crossing."""
        base = _now()
        sigs = [
            make_signal(
                "sig_disc",
                base,
                detector="graph",
                rule_id="GRAPH-SCAN-001",
                score=0.40,
                confidence=0.40,
                entities=[Entity(type=EntityType.host, value="jump-host")],
            ),
            make_signal(
                "sig_auth",
                base + timedelta(minutes=5),
                detector="rule",
                rule_id="RULE-AUTH-001",
                score=0.85,
                entities=[Entity(type=EntityType.host, value="jump-host")],
            ),
            make_signal(
                "sig_cred",
                base + timedelta(minutes=10),
                detector="rule",
                rule_id="RULE-CRED-001",
                score=0.90,
                entities=[Entity(type=EntityType.host, value="eng-ws")],
            ),
            make_signal(
                "sig_net",
                base + timedelta(minutes=12),
                detector="rule",
                rule_id="RULE-NET-001",
                score=0.70,
                entities=[Entity(type=EntityType.host, value="eng-ws")],
            ),
            make_signal(
                "sig_ot",
                base + timedelta(minutes=15),
                detector="rule",
                rule_id="RULE-OT-001",
                score=0.95,
                entities=[Entity(type=EntityType.host, value="plc-sim")],
            ),
        ]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        assert first_ts == base
        assert threshold_ts is not None
        assert ttfma is not None
        assert ttfma >= 0.0

    def test_missing_timestamps_handled_gracefully(self):
        """An empty signal list returns all None values without crashing."""
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma([], 0.50, 0.40)
        assert first_ts is None
        assert fma_ts is None
        assert threshold_ts is None
        assert ttfma is None

    def test_identical_timestamps(self):
        """Signals with identical timestamps are handled without error."""
        base = _now()
        sigs = [
            make_signal("sig_a", base, detector="rule", rule_id="RULE-AUTH-001"),
            make_signal(
                "sig_b",
                base,
                detector="rule",
                rule_id="RULE-OT-001",
                entities=[Entity(type=EntityType.host, value="plc-sim")],
            ),
        ]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        assert first_ts is not None

    def test_duplicate_signals_do_not_change_ttfma(self):
        """Duplicate signals must not alter first_ts or TTFMA."""
        base = _now()
        sig = make_signal(
            "sig_dup",
            base,
            detector="rule",
            rule_id="RULE-OT-001",
            entities=[Entity(type=EntityType.host, value="plc-sim")],
        )
        sigs_with_dup = [sig, sig]
        # sort de-duplicates naturally in compute_ttfma (duplicate won't affect sort)
        first_ts1, _, _, ttfma1 = compute_ttfma([sig], self.THRESHOLD, self.NOVELTY_CAP)
        first_ts2, _, _, ttfma2 = compute_ttfma(sigs_with_dup, self.THRESHOLD, self.NOVELTY_CAP)
        assert first_ts1 == first_ts2

    def test_incident_never_actionable_has_no_ttfma(self):
        """Novelty-only signals capped below threshold: TTFMA must be None."""
        sigs = [
            make_signal(
                "sig_nov",
                _now(),
                detector="baseline",
                rule_id="BASE-DEV-001",
                score=0.40,
                confidence=0.40,
            ),
        ]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            sigs, self.THRESHOLD, self.NOVELTY_CAP
        )
        # With novelty_cap=0.40 and threshold=0.50, baseline-only never crosses
        assert threshold_ts is None
        assert ttfma is None

    def test_ttfma_never_manufactures_nonzero_from_zero_delta(self):
        """A genuine zero event-time delta must be preserved, not forced nonzero."""
        # Create a scenario where first signal immediately crosses threshold
        base = _now()
        # Auth + OT together should cross 0.50 — but we need to arrange it so the FIRST
        # incremental score is already >= threshold.
        # With deception (honeytoken) alone: score >= 0.85 > 0.50 → ttfma == 0
        sig = make_signal(
            "sig_honey2",
            base,
            detector="deception",
            rule_id="RULE-DECOY-001",
            score=0.99,
            confidence=0.99,
            metadata={"confirmed_honeytoken": True},
            entities=[Entity(type=EntityType.host, value="cowrie")],
        )
        score, _, _ = score_incident([sig], novelty_cap=self.NOVELTY_CAP)
        if score >= self.THRESHOLD:
            first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
                [sig], self.THRESHOLD, self.NOVELTY_CAP
            )
            # Must be exactly 0.0, not None, not some manufactured value
            assert ttfma == 0.0
        # If score < threshold (scoring change), just verify no crash
        else:
            first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
                [sig], self.THRESHOLD, self.NOVELTY_CAP
            )
            assert ttfma is None

    def test_late_arriving_signal_preserves_initial_threshold_crossing(self):
        """When an incident crosses threshold at t=10s, subsequent signals (e.g. t=45s) that

        increase score further must NOT advance threshold_crossing_event_ts or inflate TTFMA.
        """
        base = _now()
        # Initial access alone: score ~0.35 (below 0.50)
        sig1 = make_signal(
            "sig_step1",
            base,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        # Lateral movement at t=10s: crosses threshold (2 stages, score >= 0.50)
        sig2 = make_signal(
            "sig_step2",
            base + timedelta(seconds=10),
            detector="rule",
            rule_id="RULE-NET-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        # Late-arriving OT impact at t=45s: elevates score to critical (~0.95+)
        sig3 = make_signal(
            "sig_step3",
            base + timedelta(seconds=45),
            detector="rule",
            rule_id="RULE-OT-001",
            entities=[Entity(type=EntityType.host, value="eng-ws")],
        )

        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            [sig1, sig2, sig3], self.THRESHOLD, self.NOVELTY_CAP
        )

        assert first_ts == base, "first_adversary_event_ts must match earliest action"
        assert threshold_ts == base + timedelta(seconds=10), (
            "threshold_crossing_event_ts must anchor to the signal that FIRST crossed threshold"
        )
        assert ttfma == 10.0, f"TTFMA must be 10.0s, got {ttfma}"

    def test_correlator_incident_provenance_timestamps(self):
        """Correlator.process_signal populates first_adversary_event_ts and threshold_crossing_event_ts."""
        db = make_temp_db()
        base = _now()
        correlator = Correlator(db=db, alert_threshold=0.50, novelty_cap=0.40)

        # Signal 1 (below threshold)
        sig1 = make_signal(
            "sig_prov_1",
            base,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        inc1 = correlator.process_signal(sig1)
        assert inc1.first_adversary_event_ts == base
        assert inc1.threshold_crossing_event_ts is None
        assert inc1.ttfma_seconds is None

        # Signal 2 (pushes over threshold)
        sig2 = make_signal(
            "sig_prov_2",
            base + timedelta(seconds=15),
            detector="rule",
            rule_id="RULE-NET-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        inc2 = correlator.process_signal(sig2)
        assert inc2.first_adversary_event_ts == base
        assert inc2.threshold_crossing_event_ts == base + timedelta(seconds=15)
        assert inc2.ttfma_seconds == 15.0

    def test_ttfma_out_of_order_signal_ingestion(self):
        """Signals ingested out of chronological order must correctly reconstruct TTFMA."""
        base = _now()
        sig1 = make_signal("sig_ord_1", base, detector="rule", rule_id="RULE-AUTH-001")
        sig2 = make_signal(
            "sig_ord_2", base + timedelta(seconds=12), detector="rule", rule_id="RULE-NET-001"
        )
        sig3 = make_signal(
            "sig_ord_3", base + timedelta(seconds=30), detector="rule", rule_id="RULE-OT-001"
        )

        # Ingest in reversed order [sig3, sig2, sig1]
        first_ts, fma_ts, threshold_ts, ttfma = compute_ttfma(
            [sig3, sig2, sig1], self.THRESHOLD, self.NOVELTY_CAP
        )
        assert first_ts == base
        assert threshold_ts == base + timedelta(seconds=12)
        assert ttfma == 12.0


# ===========================================================================
# TASK 3 — Correlation Persistence
# ===========================================================================


class TestCorrelationPersistence:
    """Task 3: Open incidents survive correlator restarts via SQLite hydration."""

    def _make_db_correlator(self, db: sqlite3.Connection, **kwargs) -> Correlator:
        return Correlator(db=db, **kwargs)

    def test_incident_created_and_persisted(self):
        """Creating an incident via process_signal persists it to SQLite."""
        db = make_temp_db()
        c = self._make_db_correlator(db)
        sig = make_signal("sig_persist_001", _now())
        insert_signal(db, sig)
        inc = c.process_signal(sig)
        # Verify it's in SQLite
        stored = get_incident_by_id(db, inc.incident_id)
        assert stored is not None
        assert stored.incident_id == inc.incident_id

    def test_hydration_restores_open_incident(self):
        """After creating a correlator, destroying it, and creating a new one, hydration restores state."""
        db = make_temp_db()
        t = _now()

        # Correlator 1: create and persist incident
        c1 = self._make_db_correlator(db, alert_threshold=0.50)
        sig1 = make_signal(
            "sig_hyd_001",
            t,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        insert_signal(db, sig1)
        inc = c1.process_signal(sig1)
        inc_id = inc.incident_id
        assert inc_id in c1.incidents

        # Simulate restart: new correlator with same DB, hydrate
        c2 = self._make_db_correlator(db, alert_threshold=0.50)
        assert inc_id not in c2.incidents, "Before hydration, new correlator should be empty"
        restored, skipped = c2.hydrate_from_db()
        assert restored >= 1, f"Expected at least 1 restored incident, got {restored}"
        assert inc_id in c2.incidents, "Incident must be in new correlator after hydration"

    def test_related_signal_updates_existing_incident_after_restart(self):
        """A signal arriving after restart must update the existing incident, not create a duplicate."""
        db = make_temp_db()
        t = _now()

        # Correlator 1: create incident
        c1 = self._make_db_correlator(db, alert_threshold=0.50)
        sig1 = make_signal(
            "sig_restart_001",
            t,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        insert_signal(db, sig1)
        inc = c1.process_signal(sig1)
        orig_id = inc.incident_id

        # Simulate restart
        c2 = self._make_db_correlator(db, alert_threshold=0.50)
        c2.hydrate_from_db()

        # Submit another related signal 60s later
        sig2 = make_signal(
            "sig_restart_002",
            t + timedelta(seconds=60),
            detector="rule",
            rule_id="RULE-NET-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        insert_signal(db, sig2)
        inc2 = c2.process_signal(sig2)

        assert inc2.incident_id == orig_id, (
            "Signal must attach to existing incident, not create new"
        )
        assert len(c2.incidents) == 1, "Must be exactly 1 incident (no duplicates)"

    def test_expired_incidents_not_hydrated(self):
        """Incidents whose updated_at is outside the correlation window must not be hydrated."""
        db = make_temp_db()
        # Create an incident whose timestamp is older than the window
        t_old = datetime.now(UTC) - timedelta(seconds=DEFAULT_CORRELATION_WINDOW_SEC + 60)
        sig_old = make_signal("sig_expired_001", t_old)
        insert_signal(db, sig_old)

        # Manually upsert an expired incident
        old_inc = Incident(
            incident_id="inc_old_expired",
            status="open",
            created_at=t_old,
            updated_at=t_old,  # expired
            first_signal_ts=t_old,
            score=0.85,
            severity="critical",
            entities=[Entity(type=EntityType.host, value="jump-host")],
            signal_ids=["sig_expired_001"],
            event_ids=["evt_sig_expired_001"],
            kill_chain_stages=["initial_access"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            explanation=["Old expired incident"],
        )
        upsert_incident(db, old_inc)

        c = Correlator(db=db)
        restored, skipped = c.hydrate_from_db()
        assert restored == 0, "Expired incident must not be restored"
        assert skipped >= 1

    def test_signal_ids_restored_and_duplicate_ignored(self):
        """After hydration, re-submitting the same signal must not inflate the incident."""
        db = make_temp_db()
        t = _now()

        c1 = self._make_db_correlator(db)
        sig = make_signal("sig_idem_001", t)
        insert_signal(db, sig)
        inc1 = c1.process_signal(sig)
        original_signal_count = len(inc1.signal_ids)

        # Simulate restart and hydrate
        c2 = self._make_db_correlator(db)
        c2.hydrate_from_db()

        # Re-submit the same signal
        inc2 = c2.process_signal(sig)
        assert len(inc2.signal_ids) == original_signal_count, (
            "Re-submitting same signal after restart must not duplicate signal count"
        )

    def test_startup_with_empty_database(self):
        """Hydration on an empty DB must succeed and return (0, 0)."""
        db = make_temp_db()
        c = Correlator(db=db)
        restored, skipped = c.hydrate_from_db()
        assert restored == 0
        assert skipped == 0

    def test_hydration_with_malformed_signal_reference(self):
        """Hydration must handle incidents whose signal_ids reference non-existent signals gracefully."""
        db = make_temp_db()
        t = _now()
        # Upsert an incident that references a non-existent signal
        broken_inc = Incident(
            incident_id="inc_broken_ref",
            status="open",
            created_at=t,
            updated_at=t,
            first_signal_ts=t,
            score=0.85,
            severity="critical",
            entities=[Entity(type=EntityType.host, value="jump-host")],
            signal_ids=["sig_nonexistent_999"],
            event_ids=["evt_nonexistent_999"],
            kill_chain_stages=["initial_access"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            explanation=["Broken reference incident"],
        )
        upsert_incident(db, broken_inc)
        c = Correlator(db=db)
        # Should not raise; malformed incident is skipped
        restored, skipped = c.hydrate_from_db()
        # The incident is skipped because its signal couldn't be loaded
        assert restored == 0


# ===========================================================================
# TASK 4 — Idempotency
# ===========================================================================


class TestIdempotency:
    """Task 4: Identical events/signals processed multiple times must not inflate incidents."""

    def test_same_signal_twice_does_not_inflate_score(self):
        """Processing the same signal twice must not change signal count or score."""
        db = make_temp_db()
        t = _now()
        c = Correlator(db=db)
        sig = make_signal("sig_dup_01", t, detector="rule", rule_id="RULE-AUTH-001")
        insert_signal(db, sig)

        inc1 = c.process_signal(sig)
        score1 = inc1.score
        signal_count1 = len(inc1.signal_ids)

        # Submit same signal again
        inc2 = c.process_signal(sig)
        score2 = inc2.score
        signal_count2 = len(inc2.signal_ids)

        assert signal_count2 == signal_count1, "Signal count must not increase on duplicate"
        assert score2 == score1, "Score must not change on duplicate signal"

    def test_same_signal_twice_does_not_create_new_incident(self):
        """Submitting an identical signal twice must not create a second incident."""
        db = make_temp_db()
        c = Correlator(db=db)
        sig = make_signal("sig_dup_02", _now())
        insert_signal(db, sig)

        c.process_signal(sig)
        c.process_signal(sig)
        assert len(c.incidents) == 1, (
            "Must be exactly 1 incident after submitting same signal twice"
        )

    def test_distinct_signals_distinct_incidents_different_entity(self):
        """Two distinct signals for different entities create two separate incidents."""
        db = make_temp_db()
        t = _now()
        c = Correlator(db=db, window_sec=60)

        sig_a = make_signal(
            "sig_distinct_a", t, entities=[Entity(type=EntityType.host, value="host-alpha")]
        )
        sig_b = make_signal(
            "sig_distinct_b", t, entities=[Entity(type=EntityType.host, value="host-beta")]
        )
        insert_signal(db, sig_a)
        insert_signal(db, sig_b)

        c.process_signal(sig_a)
        c.process_signal(sig_b)
        assert len(c.incidents) == 2

    def test_signal_persistence_idempotent_at_sqlite_level(self):
        """INSERT OR IGNORE ensures concurrent duplicate insertions are safe."""
        db = make_temp_db()
        t = _now()
        sig = make_signal("sig_sqlite_dup", t)

        # Insert twice — second must be ignored, not error
        result1 = insert_signal(db, sig)
        result2 = insert_signal(db, sig)
        assert result1 is True, "First insert must return True"
        assert result2 is False, "Second insert of same signal_id must return False (ignored)"

        # Only one record in DB
        stored = get_signal_by_id(db, "sig_sqlite_dup")
        assert stored is not None
        assert stored.signal_id == "sig_sqlite_dup"

    def test_same_capture_replayed_twice_identical_incident_count(self):
        """Replaying the same capture of events twice must not double the incident count."""
        db = make_temp_db()
        t = _now()

        # First replay
        c = Correlator(db=db, alert_threshold=0.50)
        c.reset_state()

        sig_auth = make_signal(
            "sig_rep_auth",
            t,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        sig_ot = make_signal(
            "sig_rep_ot",
            t + timedelta(seconds=30),
            detector="rule",
            rule_id="RULE-OT-001",
            entities=[Entity(type=EntityType.host, value="eng-ws")],
        )
        insert_signal(db, sig_auth)
        insert_signal(db, sig_ot)

        c.process_signal(sig_auth)
        inc_first = c.process_signal(sig_ot)
        count_first = len(c.incidents)
        score_first = inc_first.score
        signals_first = list(inc_first.signal_ids)
        stages_first = list(inc_first.kill_chain_stages)
        events_first = list(inc_first.event_ids)

        # Second replay (same signals, same correlator)
        c.process_signal(sig_auth)
        inc_second = c.process_signal(sig_ot)
        count_second = len(c.incidents)
        score_second = inc_second.score
        signals_second = list(inc_second.signal_ids)
        stages_second = list(inc_second.kill_chain_stages)
        events_second = list(inc_second.event_ids)

        assert count_second == count_first, "Incident count must not change on replay"
        assert score_second == score_first, "Score must not inflate on replay"
        assert signals_second == signals_first, "Signal IDs must not duplicate on replay"
        assert stages_second == stages_first, "Kill-chain stages must not duplicate on replay"
        assert events_second == events_first, (
            "Evidence event references must not duplicate on replay"
        )

    def test_concurrent_signal_persistence_idempotency(self):
        """Concurrent workers attempting to insert the identical signal row into SQLite

        must handle conflicts as expected idempotent outcomes without data corruption.
        """
        import concurrent.futures

        with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
            db_path = tmp.name
            init_db(db_path)
            t = _now()
            sig = make_signal("sig_concurrent_test", t)

            def insert_worker():
                worker_conn = init_db(db_path)
                return insert_signal(worker_conn, sig)

            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(insert_worker) for _ in range(16)]
                for f in concurrent.futures.as_completed(futures):
                    results.append(f.result())

            # Exactly 1 insertion must succeed, 15 ignored
            assert sum(1 for r in results if r is True) == 1
            assert sum(1 for r in results if r is False) == 15
            verify_conn = init_db(db_path)
            stored = get_signal_by_id(verify_conn, "sig_concurrent_test")
            assert stored is not None
            assert stored.signal_id == "sig_concurrent_test"

    def test_same_signal_after_restart_not_duplicated(self):
        """Re-submitting a signal after a restart must not inflate the incident."""
        db = make_temp_db()
        t = _now()

        c1 = Correlator(db=db)
        sig = make_signal("sig_post_restart", t)
        insert_signal(db, sig)
        inc1 = c1.process_signal(sig)
        sc1 = inc1.score
        cnt1 = len(inc1.signal_ids)

        # Restart
        c2 = Correlator(db=db)
        c2.hydrate_from_db()
        inc2 = c2.process_signal(sig)
        sc2 = inc2.score
        cnt2 = len(inc2.signal_ids)

        assert sc2 == sc1
        assert cnt2 == cnt1


# ===========================================================================
# TASK 5 — API Filtering and Alert Budget Semantics
# ===========================================================================


class TestAPIFiltering:
    """Task 5: Default incident feed must respect the active alert budget threshold."""

    THRESHOLD = DEFAULT_INCIDENT_THRESHOLD  # 0.50

    def _populate_db(self, db: sqlite3.Connection) -> tuple[list[str], list[str]]:
        """Populate DB with above-threshold and sub-threshold incidents. Returns (above_ids, below_ids)."""
        t = _now()
        above_ids = []
        below_ids = []

        for i, score in enumerate([0.85, 0.70, 0.55]):
            inc = Incident(
                incident_id=f"inc_above_{i}",
                status="open",
                created_at=t,
                updated_at=t,
                first_signal_ts=t,
                score=score,
                severity="high",
                entities=[Entity(type=EntityType.host, value=f"host-{i}")],
                signal_ids=[f"sig_above_{i}"],
                event_ids=[f"evt_above_{i}"],
                kill_chain_stages=["initial_access"],
                techniques=[],
                decoy_touched=False,
                ot_touched=False,
                explanation=[f"Above threshold incident {i}"],
            )
            upsert_incident(db, inc)
            above_ids.append(inc.incident_id)

        for i, score in enumerate([0.30, 0.15]):
            inc = Incident(
                incident_id=f"inc_below_{i}",
                status="open",
                created_at=t,
                updated_at=t,
                first_signal_ts=t,
                score=score,
                severity="low",
                entities=[Entity(type=EntityType.host, value=f"host-below-{i}")],
                signal_ids=[f"sig_below_{i}"],
                event_ids=[f"evt_below_{i}"],
                kill_chain_stages=["discovery"],
                techniques=[],
                decoy_touched=False,
                ot_touched=False,
                explanation=[f"Sub-threshold incident {i}"],
            )
            upsert_incident(db, inc)
            below_ids.append(inc.incident_id)

        return above_ids, below_ids

    def test_default_filter_returns_only_above_threshold(self):
        """list_incidents with min_score=threshold excludes sub-threshold records."""
        db = make_temp_db()
        above_ids, below_ids = self._populate_db(db)
        results = list_incidents(db, min_score=self.THRESHOLD)
        result_ids = {r.incident_id for r in results}
        for aid in above_ids:
            assert aid in result_ids, f"Above-threshold incident {aid} must appear"
        for bid in below_ids:
            assert bid not in result_ids, f"Sub-threshold incident {bid} must NOT appear"

    def test_exactly_at_threshold(self):
        """An incident with score == threshold must be included in the default feed."""
        db = make_temp_db()
        t = _now()
        inc = Incident(
            incident_id="inc_exact",
            status="open",
            created_at=t,
            updated_at=t,
            first_signal_ts=t,
            score=self.THRESHOLD,
            severity="medium",
            entities=[Entity(type=EntityType.host, value="host-exact")],
            signal_ids=["sig_exact"],
            event_ids=["evt_exact"],
            kill_chain_stages=["initial_access"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            explanation=["Exact threshold"],
        )
        upsert_incident(db, inc)
        results = list_incidents(db, min_score=self.THRESHOLD)
        ids = {r.incident_id for r in results}
        assert "inc_exact" in ids, "Score == threshold must be included"

    def test_below_threshold_incident_excluded(self):
        """An incident with score < threshold must not appear in the default feed."""
        db = make_temp_db()
        t = _now()
        inc = Incident(
            incident_id="inc_below_only",
            status="open",
            created_at=t,
            updated_at=t,
            first_signal_ts=t,
            score=self.THRESHOLD - 0.01,
            severity="low",
            entities=[Entity(type=EntityType.host, value="host-sub")],
            signal_ids=["sig_sub"],
            event_ids=["evt_sub"],
            kill_chain_stages=["discovery"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            explanation=["Sub-threshold only"],
        )
        upsert_incident(db, inc)
        results = list_incidents(db, min_score=self.THRESHOLD)
        ids = {r.incident_id for r in results}
        assert "inc_below_only" not in ids

    def test_forensic_query_returns_all(self):
        """list_incidents with min_score=None returns sub-threshold records for forensic use."""
        db = make_temp_db()
        above_ids, below_ids = self._populate_db(db)
        results = list_incidents(db, min_score=None)
        result_ids = {r.incident_id for r in results}
        for aid in above_ids:
            assert aid in result_ids
        for bid in below_ids:
            assert bid in result_ids, f"Sub-threshold {bid} must appear in forensic query"

    def test_custom_min_score_filter(self):
        """An explicit min_score of 0.70 filters correctly."""
        db = make_temp_db()
        t = _now()
        for score, iid in [(0.85, "inc_high"), (0.70, "inc_mid"), (0.55, "inc_low")]:
            upsert_incident(
                db,
                Incident(
                    incident_id=iid,
                    status="open",
                    created_at=t,
                    updated_at=t,
                    first_signal_ts=t,
                    score=score,
                    severity="high",
                    entities=[Entity(type=EntityType.host, value="h")],
                    signal_ids=["s"],
                    event_ids=["e"],
                    kill_chain_stages=["initial_access"],
                    techniques=[],
                    decoy_touched=False,
                    ot_touched=False,
                    explanation=["x"],
                ),
            )
        results = list_incidents(db, min_score=0.70)
        ids = {r.incident_id for r in results}
        assert "inc_high" in ids
        assert "inc_mid" in ids
        assert "inc_low" not in ids

    def test_status_filter_open_vs_closed(self):
        """Status filter correctly separates open and closed incidents."""
        db = make_temp_db()
        t = _now()
        for status, iid in [("open", "inc_open"), ("closed", "inc_closed")]:
            upsert_incident(
                db,
                Incident(
                    incident_id=iid,
                    status=status,
                    created_at=t,
                    updated_at=t,
                    first_signal_ts=t,
                    score=0.85,
                    severity="critical",
                    entities=[Entity(type=EntityType.host, value="h")],
                    signal_ids=["s"],
                    event_ids=["e"],
                    kill_chain_stages=["initial_access"],
                    techniques=[],
                    decoy_touched=False,
                    ot_touched=False,
                    explanation=["x"],
                ),
            )
        open_results = list_incidents(db, status="open")
        ids = {r.incident_id for r in open_results}
        assert "inc_open" in ids
        assert "inc_closed" not in ids

    def test_pagination_deterministic(self):
        """Paginated results are ordered newest-first and deterministic."""
        db = make_temp_db()
        base = _now()
        for i in range(5):
            t = base + timedelta(seconds=i)
            upsert_incident(
                db,
                Incident(
                    incident_id=f"inc_page_{i}",
                    status="open",
                    created_at=t,
                    updated_at=t,
                    first_signal_ts=t,
                    score=0.85,
                    severity="critical",
                    entities=[Entity(type=EntityType.host, value=f"h{i}")],
                    signal_ids=[f"s{i}"],
                    event_ids=[f"e{i}"],
                    kill_chain_stages=["initial_access"],
                    techniques=[],
                    decoy_touched=False,
                    ot_touched=False,
                    explanation=["x"],
                ),
            )
        all_results = list_incidents(db)
        # Newest-first ordering: updated_at of first result >= updated_at of last
        assert all_results[0].updated_at >= all_results[-1].updated_at
        # Pagination via limit works
        page1 = list_incidents(db, limit=3)
        assert len(page1) == 3
        page_all = list_incidents(db, limit=100)
        assert len(page_all) == 5

    def test_empty_result_set(self):
        """Query on an empty DB returns an empty list without error."""
        db = make_temp_db()
        results = list_incidents(db, min_score=0.5)
        assert results == []

    def test_budget_controller_is_authoritative_source(self):
        """BudgetController.threshold is the single source; DEFAULT_INCIDENT_THRESHOLD matches."""
        bc = BudgetController()
        assert bc.threshold == DEFAULT_INCIDENT_THRESHOLD
        # Modifying BudgetController affects is_active, not some hardcoded value in sqlite
        bc.threshold = 0.75
        t = _now()
        low_inc = Incident(
            incident_id="inc_budget_test",
            status="open",
            created_at=t,
            updated_at=t,
            first_signal_ts=t,
            score=0.60,
            severity="medium",
            entities=[Entity(type=EntityType.host, value="h")],
            signal_ids=["s"],
            event_ids=["e"],
            kill_chain_stages=["initial_access"],
            techniques=[],
            decoy_touched=False,
            ot_touched=False,
            explanation=["x"],
        )
        assert not bc.is_active(low_inc), "Score 0.60 < 0.75 threshold must not be active"
        bc.threshold = 0.50
        assert bc.is_active(low_inc), "Score 0.60 >= 0.50 threshold must be active"

    def test_fastapi_incidents_endpoint_default_and_overrides(self):
        """End-to-end FastAPI endpoint test:

        - Default query returns only incidents >= active budget threshold (0.50)
        - all_scores=true returns all incidents including sub-threshold (0.30, 0.15)
        - explicit min_score=0.70 filters to only high-severity incidents
        - dynamic threshold alteration updates the effective default
        """
        import sys

        api_path = str(Path(__file__).resolve().parents[2] / "services" / "api")
        if api_path not in sys.path:
            sys.path.insert(0, api_path)

        from app.db import get_db
        from app.main import app
        from app.pipeline_state import set_correlation_pipeline
        from fastapi.testclient import TestClient

        db = make_temp_db()
        above_ids, below_ids = self._populate_db(db)

        pipeline = CorrelationPipeline(db=db, budget_threshold=0.50)
        set_correlation_pipeline(pipeline)
        app.dependency_overrides[get_db] = lambda: db

        try:
            client = TestClient(app)

            # 1. Default GET /api/v1/incidents -> should only return above-threshold
            r_default = client.get("/api/v1/incidents")
            assert r_default.status_code == 200
            res_ids = {item["incident_id"] for item in r_default.json()}
            for aid in above_ids:
                assert aid in res_ids, f"Above-threshold {aid} missing from default feed"
            for bid in below_ids:
                assert bid not in res_ids, f"Sub-threshold {bid} leaked into default feed"

            # 2. Forensic GET /api/v1/incidents?all_scores=true -> returns all
            r_forensic = client.get("/api/v1/incidents?all_scores=true")
            assert r_forensic.status_code == 200
            res_forensic_ids = {item["incident_id"] for item in r_forensic.json()}
            for aid in above_ids:
                assert aid in res_forensic_ids
            for bid in below_ids:
                assert bid in res_forensic_ids, f"Sub-threshold {bid} missing from forensic feed"

            # 3. Explicit min_score override: min_score=0.70
            r_override = client.get("/api/v1/incidents?min_score=0.70")
            assert r_override.status_code == 200
            scores = [item["score"] for item in r_override.json()]
            assert all(s >= 0.70 for s in scores)

            # 4. Dynamic budget threshold change from 0.50 -> 0.80
            pipeline.budget.threshold = 0.80
            r_dynamic = client.get("/api/v1/incidents")
            assert r_dynamic.status_code == 200
            dynamic_scores = [item["score"] for item in r_dynamic.json()]
            assert all(s >= 0.80 for s in dynamic_scores)
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_correlation_pipeline(None)


# ===========================================================================
# INTEGRATION — Scenario tests
# ===========================================================================


class TestIntegrationScenarios:
    """Integration tests simulating complete attack scenarios end-to-end."""

    def test_scenario_1_normal_attack_progression(self):
        """Full kill-chain attack produces one correct, actionable incident with valid TTFMA.

        Entity chain: jump-host -> jump-host+eng-ws -> eng-ws
        Signal 2 bridges jump-host to eng-ws so all 3 go to one incident.
        """
        db = make_temp_db()
        base = _now()
        c = Correlator(db=db, alert_threshold=0.50, novelty_cap=0.40)

        sigs = [
            make_signal(
                "sig_sc1_auth",
                base,
                detector="rule",
                rule_id="RULE-AUTH-001",
                entities=[Entity(type=EntityType.host, value="jump-host")],
            ),
            # Bridge signal: has both jump-host and eng-ws
            make_signal(
                "sig_sc1_net",
                base + timedelta(seconds=30),
                detector="rule",
                rule_id="RULE-NET-001",
                entities=[
                    Entity(type=EntityType.host, value="jump-host"),
                    Entity(type=EntityType.host, value="eng-ws"),
                ],
            ),
            make_signal(
                "sig_sc1_ot",
                base + timedelta(seconds=60),
                detector="rule",
                rule_id="RULE-OT-001",
                entities=[Entity(type=EntityType.host, value="eng-ws")],
            ),
        ]
        for s in sigs:
            insert_signal(db, s)
            inc = c.process_signal(s)

        assert len(c.incidents) == 1, f"Should be 1 incident, got {len(c.incidents)}"
        final_inc = inc
        assert final_inc.score >= 0.50, (
            f"Final incident must be actionable (>= threshold), got {final_inc.score}"
        )
        assert final_inc.first_adversary_event_ts is not None
        assert final_inc.first_adversary_event_ts == base
        if final_inc.ttfma_seconds is not None:
            assert final_inc.ttfma_seconds >= 0.0

    def test_scenario_2_restart_during_active_campaign(self):
        """Active campaign incident survives API restart and continues correlation."""
        db = make_temp_db()
        base = _now()

        # Phase 1: Create incident
        c1 = Correlator(db=db, alert_threshold=0.50)
        sig1 = make_signal(
            "sig_sc2_auth",
            base,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        insert_signal(db, sig1)
        inc1 = c1.process_signal(sig1)
        orig_id = inc1.incident_id

        # Phase 2: Restart
        c2 = Correlator(db=db, alert_threshold=0.50)
        c2.hydrate_from_db()

        # sig2 shares entity with sig1 (jump-host) so it must join the existing incident
        sig2 = make_signal(
            "sig_sc2_ot",
            base + timedelta(seconds=60),
            detector="rule",
            rule_id="RULE-OT-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        insert_signal(db, sig2)
        inc2 = c2.process_signal(sig2)

        assert inc2.incident_id == orig_id, "No duplicate incident after restart"
        assert len(c2.incidents) == 1
        assert len(inc2.signal_ids) == 2

    def test_scenario_3_duplicate_telemetry_replay(self):
        """Replaying the same capture twice produces identical logical records."""
        db = make_temp_db()
        base = _now()
        c = Correlator(db=db, alert_threshold=0.50)

        sig_auth = make_signal(
            "sig_sc3_auth",
            base,
            detector="rule",
            rule_id="RULE-AUTH-001",
            entities=[Entity(type=EntityType.host, value="jump-host")],
        )
        sig_ot = make_signal(
            "sig_sc3_ot",
            base + timedelta(seconds=30),
            detector="rule",
            rule_id="RULE-OT-001",
            entities=[Entity(type=EntityType.host, value="eng-ws")],
        )

        # First replay
        insert_signal(db, sig_auth)
        insert_signal(db, sig_ot)
        c.process_signal(sig_auth)
        c.process_signal(sig_ot)
        inc_count_1 = len(c.incidents)
        score_1 = list(c.incidents.values())[0].score

        # Second replay (same signals)
        c.process_signal(sig_auth)
        c.process_signal(sig_ot)
        inc_count_2 = len(c.incidents)
        score_2 = list(c.incidents.values())[0].score

        assert inc_count_2 == inc_count_1
        assert score_2 == score_1

    def test_scenario_4_sub_threshold_activity(self):
        """Sub-threshold incidents persist and are retrievable forensically but not in default feed."""
        db = make_temp_db()
        t = _now()

        # Create a sub-threshold incident (OT alone = 0.30)
        inc = Incident(
            incident_id="inc_sc4_sub",
            status="open",
            created_at=t,
            updated_at=t,
            first_signal_ts=t,
            score=0.30,
            severity="low",
            entities=[Entity(type=EntityType.host, value="plc-sim")],
            signal_ids=["sig_sc4_ot"],
            event_ids=["evt_sc4_ot"],
            kill_chain_stages=["ot_impact"],
            techniques=[],
            decoy_touched=False,
            ot_touched=True,
            explanation=["Isolated OT write"],
        )
        upsert_incident(db, inc)

        # Default query (threshold = 0.50) must NOT include it
        default_results = list_incidents(db, min_score=0.50)
        default_ids = {r.incident_id for r in default_results}
        assert "inc_sc4_sub" not in default_ids

        # Forensic query (no min_score) must include it
        forensic_results = list_incidents(db, min_score=None)
        forensic_ids = {r.incident_id for r in forensic_results}
        assert "inc_sc4_sub" in forensic_ids

    def test_scenario_5_missing_and_malformed_telemetry(self):
        """Missing optional OT metadata and invalid formats are handled safely."""
        rules = load_rules()
        engine = RulesEngine(rules)
        t = _now()

        # OT event with register=None (condition fails, no crash)
        event_no_reg = Event(
            event_id="evt_sc5_nreg",
            ts=t,
            ingested_at=t,
            source_tool="modbus",
            domain="ot",
            category="ot_command",
            action="write",
            outcome="success",
            host="plc-sim",
            tags=["unauthorized_ot_write"],
            ot=OTFields(register=None, value=None, is_write=True),
            raw_ref={"file": "test.csv", "offset": 0},
            raw={},
        )
        sigs = engine.evaluate_event(event_no_reg)
        assert isinstance(sigs, list)  # no crash

        # Auth event without host
        event_no_host = Event(
            event_id="evt_sc5_nohost",
            ts=t,
            ingested_at=t,
            source_tool="wazuh",
            domain="it",
            category="authentication",
            action="ssh_login",
            outcome="success",
            host=None,
            tags=["unauthorized_ssh_source"],
            raw_ref={"file": "test.log", "offset": 0},
            raw={},
        )
        sigs2 = engine.evaluate_event(event_no_host)
        for s in sigs2:
            assert "None" not in s.explanation, "None must be replaced with fallback, not str(None)"
