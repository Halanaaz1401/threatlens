import time
import json
import logging
import asyncio
from typing import Optional, Dict, Any, Callable, List
from app.core.config import settings

logger = logging.getLogger("threatlens.redis")

# Safe dynamic import of redis
try:
    import redis
    import redis.asyncio as aioredis
except ImportError:
    redis = None
    aioredis = None

# In-memory revocation cache for development or when Redis service is offline
_in_memory_revocations: Dict[str, float] = {}

class RedisManager:
    """
    Manages Redis connection, token revocation, Pub/Sub event bus, and health diagnostics.
    Provides graceful fallback to in-memory store when Redis is unavailable.
    Includes offline cooldown circuit breaker to avoid latency spikes when Redis is down.
    """
    def __init__(self, url: str):
        self.url = url
        self._client: Optional[Any] = None
        self._local_subscribers: List[Callable[[str, dict], Any]] = []
        self._last_offline_time: float = 0.0
        self._offline_cooldown: float = 10.0  # Skip connection retries for 10s if offline

    def get_client(self) -> Optional[Any]:
        # Circuit breaker: if Redis was recently unreachable, return None immediately
        if time.time() - self._last_offline_time < self._offline_cooldown:
            return None

        if self._client is None and redis is not None:
            try:
                self._client = redis.from_url(
                    self.url,
                    decode_responses=True,
                    socket_connect_timeout=0.5,
                    socket_timeout=0.5
                )
            except Exception as e:
                logger.debug(f"Redis initialization attempt failed: {e}")
                self._last_offline_time = time.time()
                self._client = None
        return self._client

    def ping(self) -> bool:
        """Probe live Redis connectivity."""
        client = self.get_client()
        if client is not None:
            try:
                return bool(client.ping())
            except Exception:
                self._last_offline_time = time.time()
                return False
        return False

    def revoke_token(self, jti: str, ttl_seconds: int) -> bool:
        """
        Store revoked JWT jti with TTL matching remaining token lifetime.
        Automatically expires when token validity period lapses.
        """
        if not jti:
            return False

        effective_ttl = max(1, int(ttl_seconds))
        client = self.get_client()
        if client is not None:
            try:
                client.set(f"threatlens:revoked:{jti}", "revoked", ex=effective_ttl)
                return True
            except Exception as e:
                self._last_offline_time = time.time()
                logger.warning(f"Redis set failed, falling back to memory: {e}")

        # Local in-memory TTL fallback
        _in_memory_revocations[jti] = time.time() + effective_ttl
        return True

    def is_token_revoked(self, jti: str) -> bool:
        """Check if JWT jti has been marked revoked."""
        if not jti:
            return False

        client = self.get_client()
        if client is not None:
            try:
                exists = client.exists(f"threatlens:revoked:{jti}")
                return bool(exists)
            except Exception as e:
                self._last_offline_time = time.time()
                logger.debug(f"Redis exists check failed, checking memory fallback: {e}")

        # Check local in-memory fallback
        exp_time = _in_memory_revocations.get(jti)
        if exp_time is not None:
            if time.time() < exp_time:
                return True
            else:
                _in_memory_revocations.pop(jti, None)
        return False

    # -------------------------------------------------------------
    # Pub/Sub Event Bus (Phase 3)
    # -------------------------------------------------------------

    def register_local_subscriber(self, callback: Callable[[str, dict], Any]):
        """Register local callback for events (used by in-memory bus or test suites)."""
        if callback not in self._local_subscribers:
            self._local_subscribers.append(callback)

    def unregister_local_subscriber(self, callback: Callable[[str, dict], Any]):
        """Unregister local callback."""
        if callback in self._local_subscribers:
            self._local_subscribers.remove(callback)

    def publish_event(self, channel: str, event_data: dict) -> bool:
        """
        Publish structured security event to Redis channel.
        Falls back to local subscribers if Redis is offline or unavailable.
        """
        success = False
        payload_str = json.dumps(event_data)

        # 1. Publish to Redis if connected
        client = self.get_client()
        if client is not None:
            try:
                client.publish(channel, payload_str)
                success = True
            except Exception as e:
                self._last_offline_time = time.time()
                logger.warning(f"Redis publish failed on channel {channel}: {e}")

        # 2. Dispatch to local subscribers (in-memory fallback / testing)
        for cb in list(self._local_subscribers):
                try:
                    res = cb(channel, event_data)
                    if asyncio.iscoroutine(res):
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                loop.create_task(res)
                        except Exception:
                            pass
                except Exception as err:
                    logger.error(f"Local subscriber callback failed: {err}")

        return success or len(self._local_subscribers) > 0

    async def listen_redis_channel(
        self,
        channel: str,
        callback: Callable[[dict], Any],
        stop_event: Optional[asyncio.Event] = None
    ):
        """
        Asynchronously subscribe to Redis channel and forward messages to callback.
        Re-attempts connection if temporarily disconnected.
        """
        if aioredis is None:
            logger.info("aioredis not available, skipping Redis background subscriber")
            return

        while stop_event is None or not stop_event.is_set():
            try:
                async_client = aioredis.from_url(
                    self.url,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                    socket_timeout=5.0
                )
                pubsub = async_client.pubsub()
                await pubsub.subscribe(channel)
                logger.info(f"Subscribed to Redis Pub/Sub channel: {channel}")

                while stop_event is None or not stop_event.is_set():
                    try:
                        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                        if message and message.get("type") == "message":
                            data_raw = message.get("data")
                            try:
                                payload = json.loads(data_raw)
                                res = callback(payload)
                                if asyncio.iscoroutine(res):
                                    await res
                            except Exception as parse_err:
                                logger.error(f"Failed to parse Redis Pub/Sub event: {parse_err}")
                        await asyncio.sleep(0.01)
                    except asyncio.CancelledError:
                        break
                    except Exception as loop_err:
                        logger.debug(f"Redis subscriber get_message error: {loop_err}")
                        break

                await pubsub.unsubscribe(channel)
                await async_client.close()
            except asyncio.CancelledError:
                break
            except Exception as conn_err:
                logger.debug(f"Redis subscriber connection attempt failed: {conn_err}")
                await asyncio.sleep(5.0)  # Wait before reconnection attempt

    def get_health(self) -> Dict[str, Any]:
        """Return Redis health report without sensitive credentials."""
        start = time.time()
        is_healthy = self.ping()
        latency_ms = round((time.time() - start) * 1000, 2)
        if is_healthy:
            return {
                "status": "healthy",
                "backend": "redis",
                "latency_ms": latency_ms
            }
        return {
            "status": "unavailable",
            "backend": "in_memory_fallback",
            "message": "Redis service not responding, using resilient in-memory revocation and event bus"
        }

redis_manager = RedisManager(settings.REDIS_URL)

def publish_enrichment_event(event_type: str, data: dict) -> bool:
    """
    Publish structured threat intelligence enrichment event (Phase 4B).
    Events: ENRICHMENT_STARTED, ENRICHMENT_COMPLETED, ENRICHMENT_PARTIAL, ENRICHMENT_FAILED.
    Publishes to REDIS_ENRICHMENT_CHANNEL and REDIS_ALERT_CHANNEL for real-time frontend streaming.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_ENRICHMENT_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    res1 = redis_manager.publish_event(settings.REDIS_ENRICHMENT_CHANNEL, payload)
    res2 = redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, payload)
    return res1 or res2

def publish_ioc_event(event_type: str, data: dict) -> bool:
    """
    Publish structured IOC lifecycle/TTL event (Phase 4D-C).
    Events: IOC_CREATED, IOC_UPDATED, IOC_EXPIRED, IOC_REVOKED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_IOC_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    return redis_manager.publish_event(settings.REDIS_IOC_CHANNEL, payload)

def publish_feed_event(event_type: str, data: dict) -> bool:
    """
    Publish structured threat feed management event (Phase 4D-C).
    Events: FEED_ENABLED, FEED_DISABLED, FEED_FETCH_STARTED, FEED_FETCH_SUCCEEDED, FEED_FETCH_FAILED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_FEED_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    return redis_manager.publish_event(settings.REDIS_FEED_CHANNEL, payload)

def publish_security_event(event_type: str, data: dict) -> bool:
    """
    Publish structured inbound SIEM/EDR or TAXII integration event (Phase 4D-D).
    Events: SECURITY_EVENT_INGESTED, SECURITY_EVENT_DEDUPLICATED, SECURITY_EVENT_REJECTED,
            TAXII_POLL_STARTED, TAXII_POLL_SUCCEEDED, TAXII_POLL_FAILED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_INTEGRATION_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    return redis_manager.publish_event(settings.REDIS_INTEGRATION_CHANNEL, payload)

def publish_case_event(event_type: str, data: dict) -> bool:
    """
    Publish structured case management event (Phase 4E).
    Events: CASE_CREATED, CASE_UPDATED, CASE_STATUS_CHANGED, CASE_ASSIGNED,
            INCIDENT_LINKED, INCIDENT_UNLINKED, EVIDENCE_ADDED, NOTE_ADDED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_CASE_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    res1 = redis_manager.publish_event(settings.REDIS_CASE_CHANNEL, payload)
    res2 = redis_manager.publish_event(settings.REDIS_ALERT_CHANNEL, payload)
    return res1 or res2

def publish_report_event(event_type: str, data: dict) -> bool:
    """
    Publish structured reporting event (Phase 4E).
    Events: REPORT_GENERATED, REPORT_DOWNLOADED, REPORT_FAILED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_REPORT_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    return redis_manager.publish_event(settings.REDIS_REPORT_CHANNEL, payload)

def publish_dashboard_event(event_type: str, data: dict) -> bool:
    """
    Publish structured dashboard management event (Phase 4F).
    Events: DASHBOARD_CREATED, DASHBOARD_UPDATED, DASHBOARD_DELETED,
            WIDGET_CREATED, WIDGET_UPDATED, WIDGET_DELETED, LAYOUT_UPDATED.
    """
    from datetime import datetime, timezone
    payload = {
        "type": event_type,
        "event": event_type,
        "channel": settings.REDIS_DASHBOARD_CHANNEL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    return redis_manager.publish_event(settings.REDIS_DASHBOARD_CHANNEL, payload)

__all__ = [
    "redis_manager",
    "RedisManager",
    "publish_enrichment_event",
    "publish_ioc_event",
    "publish_feed_event",
    "publish_security_event",
    "publish_case_event",
    "publish_report_event",
    "publish_dashboard_event"
]
