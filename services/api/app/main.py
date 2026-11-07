"""FastAPI main entrypoint for SentinelX backend API service."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sentinelx.schemas.common import SCHEMA_VERSION, WSMessage

from app.config import settings
from app.db import close_db, get_db
from app.routes.events import router as events_router
from app.routes.health import router as health_router
from app.ws import manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to setup and teardown database resources."""
    get_db()
    yield
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
