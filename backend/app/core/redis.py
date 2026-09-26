import time
import logging
from typing import Optional, Dict, Any
from app.core.config import settings

logger = logging.getLogger("threatlens.redis")

# Safe dynamic import of redis
try:
    import redis
except ImportError:
    redis = None

# In-memory revocation cache for development or when Redis service is offline
_in_memory_revocations: Dict[str, float] = {}

class RedisManager:
    """
    Manages Redis connection, token revocation, and health diagnostics.
    Provides graceful fallback to in-memory store when Redis is unavailable.
    """
    def __init__(self, url: str):
        self.url = url
        self._client: Optional[Any] = None

    def get_client(self) -> Optional[Any]:
        if self._client is None and redis is not None:
            try:
                self._client = redis.from_url(
                    self.url,
                    decode_responses=True,
                    socket_connect_timeout=1.5,
                    socket_timeout=1.5
                )
            except Exception as e:
                logger.debug(f"Redis initialization attempt failed: {e}")
                self._client = None
        return self._client

    def ping(self) -> bool:
        """Probe live Redis connectivity."""
        client = self.get_client()
        if client is not None:
            try:
                return bool(client.ping())
            except Exception:
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
                client.setex(f"threatlens:revoked:{jti}", effective_ttl, "revoked")
                return True
            except Exception as e:
                logger.warning(f"Redis setex failed, falling back to memory: {e}")

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
                logger.debug(f"Redis exists check failed, checking memory fallback: {e}")

        # Check local in-memory fallback
        exp_time = _in_memory_revocations.get(jti)
        if exp_time is not None:
            if time.time() < exp_time:
                return True
            else:
                _in_memory_revocations.pop(jti, None)
        return False

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
            "message": "Redis service not responding, using resilient in-memory revocation store"
        }

redis_manager = RedisManager(settings.REDIS_URL)

__all__ = ["redis_manager", "RedisManager"]
