"""
WebSocket connection manager - broadcasts logs, alerts, and system events
to all connected SOC analyst clients in real time.
"""
import json
import logging
import asyncio
from typing import Set, Dict
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self._tenant_connections: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, tenant_id: str):
        await websocket.accept()
        async with self._lock:
            if tenant_id not in self._tenant_connections:
                self._tenant_connections[tenant_id] = set()
            self._tenant_connections[tenant_id].add(websocket)
        logger.info(f"WS connected (tenant {tenant_id}). Total clients: {self.client_count}")

    def disconnect(self, websocket: WebSocket, tenant_id: str):
        if tenant_id in self._tenant_connections:
            self._tenant_connections[tenant_id].discard(websocket)
            if not self._tenant_connections[tenant_id]:
                del self._tenant_connections[tenant_id]
        logger.info(f"WS disconnected (tenant {tenant_id}). Total clients: {self.client_count}")

    async def broadcast(self, message: dict, tenant_id: str = "default"):
        """Send a JSON message to all connected clients for a specific tenant."""
        payload = json.dumps(message, default=str)
        dead = set()

        async with self._lock:
            if tenant_id not in self._tenant_connections:
                return
            clients = list(self._tenant_connections[tenant_id])

        for ws in clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                if tenant_id in self._tenant_connections:
                    self._tenant_connections[tenant_id] -= dead
                    if not self._tenant_connections[tenant_id]:
                        del self._tenant_connections[tenant_id]

    async def send_log(self, log: dict, tenant_id: str = "default"):
        await self.broadcast({"type": "log", "data": log}, tenant_id)

    async def send_alert(self, alert: dict, tenant_id: str = "default"):
        await self.broadcast({"type": "alert", "data": alert}, tenant_id)

    async def send_incident(self, incident: dict, tenant_id: str = "default"):
        await self.broadcast({"type": "incident", "data": incident}, tenant_id)

    async def send_stats(self, stats: dict, tenant_id: str = "default"):
        await self.broadcast({"type": "stats", "data": stats}, tenant_id)

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
        return sum(len(c) for c in self._tenant_connections.values())
