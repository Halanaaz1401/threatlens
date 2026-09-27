import logging
import asyncio
from typing import List, Optional
from fastapi import WebSocket
from app.core.config import settings
from app.core.redis import redis_manager

logger = logging.getLogger("threatlens.websocket")

class ConnectionManager:
    """
    Manages active authenticated WebSocket connections and real-time alert broadcasts.
    Subscribes to Redis Pub/Sub channel and fans out incoming security events to connected clients.
    Thread-safe to support asynchronous workers and synchronous request handlers.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._listener_task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        
        # Connect to local fallback event bus so synchronous and local publishes fan out immediately
        redis_manager.register_local_subscriber(self._on_bus_event)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        logger.info(f"WebSocket client connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active connections: {len(self.active_connections)}")

    def _on_bus_event(self, channel: str, event_data: dict):
        """Callback from RedisManager event bus."""
        if channel == settings.REDIS_ALERT_CHANNEL or channel.endswith("alerts"):
            # If we captured the running loop of the active WebSocket connections, schedule thread-safely
            if self._loop is not None and self._loop.is_running():
                try:
                    asyncio.run_coroutine_threadsafe(self.broadcast_alert(event_data), self._loop)
                    return
                except Exception as e:
                    logger.debug(f"run_coroutine_threadsafe failed: {e}")

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.broadcast_alert(event_data))
            except Exception as e:
                logger.debug(f"Could not schedule broadcast_alert on local loop: {e}")

    async def broadcast_alert(self, message: dict):
        """Fan out alert message to all active WebSocket clients."""
        if not self.active_connections:
            return

        dead_connections = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Failed to send to client: {e}")
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    async def start_redis_listener(self):
        """Start background task listening to external Redis Pub/Sub channel."""
        if self._listener_task is not None and not self._listener_task.done():
            return

        self._stop_event = asyncio.Event()
        self._listener_task = asyncio.create_task(
            redis_manager.listen_redis_channel(
                channel=settings.REDIS_ALERT_CHANNEL,
                callback=self.broadcast_alert,
                stop_event=self._stop_event
            )
        )
        logger.info(f"Started Redis Pub/Sub listener on channel {settings.REDIS_ALERT_CHANNEL}")

    async def stop_redis_listener(self):
        """Gracefully stop background Redis listener task."""
        if self._stop_event is not None:
            self._stop_event.set()
        if self._listener_task is not None:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
            self._listener_task = None
        logger.info("Stopped Redis Pub/Sub listener")

ws_manager = ConnectionManager()

__all__ = ["ws_manager", "ConnectionManager"]
