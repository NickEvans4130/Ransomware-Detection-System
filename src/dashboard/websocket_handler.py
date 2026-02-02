"""WebSocket handler for real-time dashboard updates.

Manages connected clients and broadcasts events (file events, threat
alerts, status changes) to all listeners on /ws/live.
"""

import json
import logging
import threading

logger = logging.getLogger(__name__)


class WebSocketHandler:
    """Thread-safe registry of WebSocket clients with broadcast."""

    def __init__(self):
        self._clients: list = []
        self._lock = threading.Lock()

    def register(self, ws):
        with self._lock:
            self._clients.append(ws)
        logger.debug("WebSocket client connected (%d total)", len(self._clients))

    def unregister(self, ws):
        with self._lock:
            try:
                self._clients.remove(ws)
            except ValueError:
                pass
        logger.debug("WebSocket client disconnected (%d remaining)", len(self._clients))

    def broadcast(self, event_type: str, data: dict):
        """Send a JSON message to all connected clients."""
        message = json.dumps({"type": event_type, "data": data})
        dead = []
        with self._lock:
            for ws in self._clients:
                try:
                    ws.send(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                try:
                    self._clients.remove(ws)
                except ValueError:
                    pass

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)
