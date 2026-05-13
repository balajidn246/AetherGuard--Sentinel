"""
WebSocket connection manager — broadcasts logs, alerts, and system events
to all connected SOC analyst clients in real time.
"""
import json
import logging
import asyncio
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info(f"WS connected. Total clients: {len(self._connections)}")

    def disconnect(self, websocket: WebSocket):
        self._connections.discard(websocket)
        logger.info(f"WS disconnected. Total clients: {len(self._connections)}")

    async def broadcast(self, message: dict):
        """Send a JSON message to all connected clients."""
        if not self._connections:
            return

        payload = json.dumps(message, default=str)
        dead = set()

        async with self._lock:
            clients = list(self._connections)

        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                self._connections -= dead

    async def send_log(self, log: dict):
        await self.broadcast({"type": "log", "data": log})

    async def send_alert(self, alert: dict):
        await self.broadcast({"type": "alert", "data": alert})

    async def send_incident(self, incident: dict):
        await self.broadcast({"type": "incident", "data": incident})

    async def send_stats(self, stats: dict):
        await self.broadcast({"type": "stats", "data": stats})

    async def handle_client_message(self, websocket: WebSocket, data: str):
        """Handle messages sent from the client (e.g., subscription filters)."""
        try:
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
        except Exception:
            pass

    @property
    def client_count(self) -> int:
        return len(self._connections)
