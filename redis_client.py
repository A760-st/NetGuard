"""
redis_client.py
---------------
Phase 4 — Redis Ingestion Buffer & Queue Manager
NTRO Non-IoC Network Flow Anomaly Detection Project

Provides a thin async wrapper around redis-py for pushing raw network-flow
records into a Redis list queue ("ntro:flow_queue") and consuming them in
batches via blocking-pop.  Acts as the decoupling layer between the live
packet sniffer (Phase 5) / FastAPI ingestion endpoint and the heavy ML
inference worker.

Design
------
  Queue type: Redis LIST  (RPUSH to tail, BLPOP from head — reliable FIFO)
  Payload:    JSON-encoded dict per flow record
  Queue name: ntro:flow_queue  (configurable via REDIS_QUEUE_NAME env var)

Environment variables
---------------------
  REDIS_URL          — full Redis URL (default: redis://localhost:6379/0)
  REDIS_QUEUE_NAME   — queue key name  (default: ntro:flow_queue)
  REDIS_MAX_CONN     — connection-pool size (default: 20)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import ConnectionError as RedisConnectionError, RedisError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
QUEUE_NAME: str = os.getenv("REDIS_QUEUE_NAME", "ntro:flow_queue")
MAX_CONNECTIONS: int = int(os.getenv("REDIS_MAX_CONN", "20"))

# Dead-letter queue: flows that fail repeated processing end up here
DLQ_NAME: str = f"{QUEUE_NAME}:dlq"


# ---------------------------------------------------------------------------
# Singleton connection pool
# ---------------------------------------------------------------------------

_pool: Optional[ConnectionPool] = None


def _get_pool() -> ConnectionPool:
    """Return (creating if needed) the shared async connection pool."""
    global _pool
    if _pool is None:
        _pool = aioredis.ConnectionPool.from_url(
            REDIS_URL,
            max_connections=MAX_CONNECTIONS,
            decode_responses=True,  # always return str, not bytes
        )
        logger.info(
            "Redis connection pool created: url=%s max_connections=%d",
            REDIS_URL,
            MAX_CONNECTIONS,
        )
    return _pool


def get_redis_client() -> Redis:
    """Return a Redis client backed by the shared connection pool.

    The client is lightweight (no network I/O at creation time) and safe
    to call from any async context.
    """
    return aioredis.Redis(connection_pool=_get_pool())


async def ping() -> bool:
    """Check Redis connectivity. Returns True on success."""
    try:
        r = get_redis_client()
        return await r.ping()
    except RedisConnectionError as exc:
        logger.error("Redis ping failed: %s", exc)
        return False


async def close_pool() -> None:
    """Gracefully close the connection pool (call on application shutdown)."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
        logger.info("Redis connection pool closed.")


# ---------------------------------------------------------------------------
# FlowQueueManager
# ---------------------------------------------------------------------------

class FlowQueueManager:
    """High-level queue operations for the NTRO flow ingestion pipeline.

    Parameters
    ----------
    queue_name:
        Redis LIST key to use (default: ``QUEUE_NAME`` from env).
    dlq_name:
        Dead-letter queue key for unprocessable messages.
    """

    def __init__(
        self,
        queue_name: str = QUEUE_NAME,
        dlq_name: str = DLQ_NAME,
    ) -> None:
        self.queue_name = queue_name
        self.dlq_name = dlq_name

    # ------------------------------------------------------------------
    # Producer side
    # ------------------------------------------------------------------

    async def push(self, flow: Dict[str, Any]) -> int:
        """Serialise a single flow dict and push it to the tail of the queue.

        Parameters
        ----------
        flow:
            A raw flow record dict (must be JSON-serialisable).

        Returns
        -------
        int
            New length of the queue after the push.
        """
        r = get_redis_client()
        try:
            payload = json.dumps(flow, default=str)
            length: int = await r.rpush(self.queue_name, payload)
            logger.debug("Pushed 1 flow → queue length: %d", length)
            return length
        except (RedisError, TypeError) as exc:
            logger.error("Failed to push flow to Redis: %s", exc)
            raise

    async def push_batch(self, flows: List[Dict[str, Any]]) -> int:
        """Push multiple flow records to the queue atomically via a pipeline.

        Parameters
        ----------
        flows:
            List of raw flow record dicts.

        Returns
        -------
        int
            Queue length after all pushes.
        """
        if not flows:
            return 0
        r = get_redis_client()
        try:
            async with r.pipeline(transaction=False) as pipe:
                for flow in flows:
                    pipe.rpush(self.queue_name, json.dumps(flow, default=str))
                results = await pipe.execute()
            final_len: int = results[-1] if results else 0
            logger.info(
                "Pushed %d flows → queue length: %d", len(flows), final_len
            )
            return final_len
        except RedisError as exc:
            logger.error("Failed to push batch to Redis: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Consumer side
    # ------------------------------------------------------------------

    async def blocking_pop(
        self,
        timeout: float = 5.0,
    ) -> Optional[Dict[str, Any]]:
        """Block until a single flow is available and return it decoded.

        Parameters
        ----------
        timeout:
            Seconds to wait before returning ``None`` (0 = block forever).

        Returns
        -------
        dict or None
            Decoded flow record, or ``None`` on timeout.
        """
        r = get_redis_client()
        try:
            result = await r.blpop(self.queue_name, timeout=timeout)
            if result is None:
                return None  # timeout expired
            _, raw = result  # (queue_name, value)
            return json.loads(raw)
        except RedisError as exc:
            logger.error("blpop error: %s", exc)
            raise

    async def pop_batch(
        self,
        batch_size: int = 100,
        timeout: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """Drain up to ``batch_size`` items from the queue.

        Uses a single blocking-pop to wait for the first item (preventing
        a busy-loop when the queue is empty), then drains additional
        available items non-blocking via a pipeline.

        Parameters
        ----------
        batch_size:
            Maximum number of records to return per call.
        timeout:
            Seconds to block waiting for the first item.

        Returns
        -------
        list[dict]
            Decoded flow records (may be empty on timeout).
        """
        r = get_redis_client()

        # 1. Blocking pop for the first item
        try:
            result = await r.blpop(self.queue_name, timeout=timeout)
        except RedisError as exc:
            logger.error("blpop error in pop_batch: %s", exc)
            raise

        if result is None:
            return []  # queue was empty for `timeout` seconds

        _, first_raw = result
        records: List[Dict[str, Any]] = [json.loads(first_raw)]

        # 2. Non-blocking drain of remaining items up to batch_size - 1
        if batch_size > 1:
            try:
                async with r.pipeline(transaction=False) as pipe:
                    for _ in range(batch_size - 1):
                        pipe.lpop(self.queue_name)
                    raws = await pipe.execute()

                for raw in raws:
                    if raw is None:
                        break  # queue exhausted
                    try:
                        records.append(json.loads(raw))
                    except json.JSONDecodeError as exc:
                        logger.warning("Skipping malformed payload: %s", exc)
            except RedisError as exc:
                logger.error("Pipeline drain error: %s", exc)
                # Return what we have so far rather than losing the first item

        logger.debug("pop_batch: retrieved %d flow(s).", len(records))
        return records

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    async def queue_length(self) -> int:
        """Return the current number of items waiting in the queue."""
        r = get_redis_client()
        return await r.llen(self.queue_name)

    async def dlq_length(self) -> int:
        """Return the number of items in the dead-letter queue."""
        r = get_redis_client()
        return await r.llen(self.dlq_name)

    async def move_to_dlq(self, raw_payload: str) -> None:
        """Push an unprocessable raw payload to the DLQ for inspection."""
        r = get_redis_client()
        await r.rpush(self.dlq_name, raw_payload)
        logger.warning("Moved 1 message to DLQ (%s).", self.dlq_name)
