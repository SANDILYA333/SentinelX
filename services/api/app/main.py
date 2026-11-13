"""FastAPI main entrypoint for SentinelX backend API service."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sentinelx.correlate.pipeline import CorrelationPipeline
from sentinelx.deception.lotl.monitor import InteractionMonitor
from sentinelx.deception.lotl.registry import LureRegistry
from sentinelx.detect.runtime import DetectorPipeline
from sentinelx.guard.evaluator import GuardEvaluator
from sentinelx.ingest.runtime import Ingestor
from sentinelx.schemas.common import SCHEMA_VERSION, WSMessage
from sentinelx.schemas.event import Event

from app.config import settings
from app.db import close_db, get_db
from app.ingest import set_ingestor
from app.pipeline_state import set_correlation_pipeline, set_guard_evaluator
from app.routes.assets import router as assets_router
from app.routes.budget import router as budget_router
from app.routes.deception import router as deception_router
from app.routes.eval import router as eval_router
from app.routes.evaluation import router as evaluation_router
from app.routes.events import router as events_router
from app.routes.guard import router as guard_router
from app.routes.health import router as health_router
from app.routes.incidents import router as incidents_router
from app.routes.lotl import router as lotl_router
from app.routes.mitre import router as mitre_router
from app.routes.signals import router as signals_router
from app.routes.sources import router as sources_router
from app.routes.status import router as status_router
from app.ws import manager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to setup DB, Ingestor, Detectors, and Correlator."""
    db = get_db()
    lotl_registry = LureRegistry(db)
    lotl_monitor = InteractionMonitor(lotl_registry, db)
    detector_pipeline = DetectorPipeline(db=db)
    correlation_pipeline = CorrelationPipeline(
        db=db,
        on_incident=manager.broadcast_incident,
    )
    guard_evaluator = GuardEvaluator(db=db)

    set_correlation_pipeline(correlation_pipeline)
    set_guard_evaluator(guard_evaluator)

    # Task 3 — Restore open incident state from SQLite before accepting new signals.
    # Order is deliberate: DB init -> pipeline init -> hydration -> ingestion start.
    try:
        restored, skipped = await correlation_pipeline.hydrate_from_db()
        logger.info(
            "Correlator hydration: %d incident(s) restored, %d expired/skipped.",
            restored,
            skipped,
        )
    except Exception as hydration_exc:
        # Hydration failure is logged as an error; the system continues in degraded state
        # (empty correlator) rather than crashing the entire API process.
        logger.error("Correlator hydration failed: %s", hydration_exc)

    # Callback when Ingestor flushes events
    async def on_event(ev: Event) -> None:
        await manager.broadcast_event(ev)
        lotl_act = lotl_monitor.evaluate_event(ev)
        if lotl_act:
            await manager.broadcast_lotl_interaction(lotl_act)
        signals = detector_pipeline.process_event(ev)
        for sig in signals:
            await manager.broadcast_signal(sig)
            await correlation_pipeline.process_signal(sig)

    ingestor = Ingestor(
        log_root=settings.SENTINELX_LOG_ROOT,
        db=db,
        mode=settings.SENTINELX_INGEST_MODE,  # type: ignore[arg-type]
        on_event=on_event,
        speed=settings.SENTINELX_REPLAY_SPEED,
    )
    set_ingestor(ingestor)

    if settings.SENTINELX_INGEST_MODE in ("live", "replay"):
        logger.info(f"Starting Ingestor in {settings.SENTINELX_INGEST_MODE} mode...")
        await ingestor.start()

    ticker_task = asyncio.create_task(manager.start_health_ticker())

    yield

    ticker_task.cancel()
    try:
        await ticker_task
    except asyncio.CancelledError:
        pass

    if ingestor.running:
        await ingestor.stop()
    set_ingestor(None)
    set_correlation_pipeline(None)
    set_guard_evaluator(None)
    close_db()


app = FastAPI(
    title="SentinelX API",
    description="IT/OT threat detection and deception platform API",
    version=SCHEMA_VERSION,
    lifespan=lifespan,
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Standard endpoints
app.include_router(health_router)
app.include_router(status_router)
app.include_router(events_router)
app.include_router(signals_router)
app.include_router(incidents_router)
app.include_router(guard_router)
app.include_router(deception_router)
app.include_router(lotl_router)
app.include_router(budget_router)
app.include_router(sources_router)
app.include_router(assets_router)
app.include_router(mitre_router)
app.include_router(eval_router)
app.include_router(evaluation_router)

# Dev-only endpoints
if settings.SENTINELX_ENV == "dev":
    from app.routes.dev import router as dev_router

    app.include_router(dev_router)


@app.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    """WebSocket stream emitting real-time telemetry events, signals, and incidents."""
    await manager.connect(websocket)
    try:
        # Send initial hello message with schema_version
        hello_msg = WSMessage(
            type="hello",
            ts=datetime.now(UTC),
            payload={"schema_version": SCHEMA_VERSION, "status": "connected"},
        )
        await websocket.send_text(hello_msg.model_dump_json())

        # Listen for client ping or incoming frames
        while True:
            text = await websocket.receive_text()
            if text.strip() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:  # noqa: BLE001 - silently drop client on disconnect
        manager.disconnect(websocket)
