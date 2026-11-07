"""FastAPI main entrypoint for SentinelX backend API service."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sentinelx.ingest.runtime import Ingestor
from sentinelx.schemas.common import SCHEMA_VERSION, WSMessage
from sentinelx.schemas.event import Event

from app.config import settings
from app.db import close_db, get_db
from app.ingest import set_ingestor
from app.routes.events import router as events_router
from app.routes.health import router as health_router
from app.routes.sources import router as sources_router
from app.ws import manager

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to setup DB, Ingestor, and background tasks."""
    db = get_db()

    # Callback when Ingestor flushes events
    async def on_event(ev: Event) -> None:
        await manager.broadcast_event(ev)

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
app.include_router(events_router)
app.include_router(sources_router)

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
