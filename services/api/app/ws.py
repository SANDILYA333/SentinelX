"""WebSocket connection manager for real-time streaming."""

import logging

from fastapi import WebSocket
from sentinelx.schemas.common import WSMessage

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts WSMessage envelopes."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

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
            except Exception:  # noqa: BLE001 - silently drop dead connections
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)


manager = ConnectionManager()
