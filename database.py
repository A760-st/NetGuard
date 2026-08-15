"""
database.py
-----------
Phase 3 — Prisma / Neon Database Client
NTRO Non-IoC Network Flow Anomaly Detection Project

Initialises a singleton Prisma async client backed by Neon PostgreSQL.
The DATABASE_URL environment variable must be set (see schema.prisma).

Usage
-----
    from database import get_db_client, connect_db, disconnect_db

    # In FastAPI lifespan / startup:
    await connect_db()

    # In a route or service:
    db = get_db_client()
    await db.networkflowlog.create(data={...})

    # In shutdown:
    await disconnect_db()
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from prisma import Prisma

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton client
# ---------------------------------------------------------------------------

_client: Optional[Prisma] = None


def get_db_client() -> Prisma:
    """Return the initialised Prisma client.

    Raises
    ------
    RuntimeError
        If ``connect_db()`` has not been awaited yet.
    """
    if _client is None:
        raise RuntimeError(
            "Prisma client has not been initialised. "
            "Ensure `await connect_db()` is called during application startup."
        )
    return _client


async def connect_db() -> Prisma:
    """Connect the Prisma client to Neon PostgreSQL.

    Creates the singleton on first call; safe to call multiple times
    (subsequent calls are no-ops if already connected).

    Returns
    -------
    Prisma
        The connected client instance.

    Raises
    ------
    EnvironmentError
        If the ``DATABASE_URL`` environment variable is missing.
    """
    global _client

    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise EnvironmentError(
            "DATABASE_URL environment variable is not set. "
            "Add it to your .env file:\n"
            '  DATABASE_URL="postgresql://<user>:<password>@<host>/<db>?sslmode=require"'
        )

    if _client is not None and _client.is_connected():
        logger.debug("Prisma client already connected — skipping reconnect.")
        return _client

    _client = Prisma()
    await _client.connect()
    logger.info("Prisma client connected to Neon PostgreSQL.")
    return _client


async def disconnect_db() -> None:
    """Gracefully close the Prisma connection.

    Safe to call even if the client was never connected.
    """
    global _client
    if _client is not None and _client.is_connected():
        await _client.disconnect()
        logger.info("Prisma client disconnected.")
    _client = None
