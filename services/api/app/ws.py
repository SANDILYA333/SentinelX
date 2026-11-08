"""WebSocket connection manager for real-time streaming with UI rate limiting."""

import asyncio
import json
import logging
import time
from datetime import UTC, datetime

from fastapi import WebSocket
from sentinelx.schemas.common import WSMessage
from sentinelx.schemas.event import Event
from sentinelx.schemas.signal import Signal

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections, broadcasts envelopes, and rate-limits UI frames."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self.dropped_for_ui: int = 0
        self._current_sec: int = 0
        self._events_this_sec: int = 0
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept new WebSocket connection and track it."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: WSMessage) -> None:
        """Broadcast a message to all connected clients, dropping dead clients silently."""
        dead_connections: list[WebSocket] = []
        payload_text = message.model_dump_json()

        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload_text)
            except Exception:  # noqa: BLE001
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    async def broadcast_event(self, event: Event) -> bool:
        """Broadcast an event to UI clients, rate-limited to at most 20 events/sec.

        Returns True if sent, False if dropped for UI.
        """
        now_sec = int(time.time())
        async with self._lock:
            if now_sec != self._current_sec:
                self._current_sec = now_sec
                self._events_this_sec = 0

            if self._events_this_sec >= 20:
                self.dropped_for_ui += 1
                return False

            self._events_this_sec += 1

        msg = WSMessage(
            type="event",
            ts=event.ts,
            payload=json.loads(event.model_dump_json()),
        )
        await self.broadcast(msg)
        return True

    async def broadcast_signal(self, signal: Signal) -> None:
        """Broadcast a detection Signal envelope to connected UI clients."""
        msg = WSMessage(
            type="signal",
            ts=signal.ts,
            payload=json.loads(signal.model_dump_json()),
        )
        await self.broadcast(msg)

    async def start_health_ticker(self) -> None:
        """Emits a periodic health message every 2 seconds reporting dropped_for_ui."""
        while True:
            await asyncio.sleep(2.0)
            if self.active_connections:
                health_msg = WSMessage(
                    type="health",
                    ts=datetime.now(UTC),
                    payload={
                        "status": "healthy",
                        "active_clients": len(self.active_connections),
                        "dropped_for_ui": self.dropped_for_ui,
                    },
                )
                await self.broadcast(health_msg)


manager = ConnectionManager()
