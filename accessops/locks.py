"""Postgres advisory locks: one cleanup at a time across the CLI, accessops-api and n8n.

The lock lives as long as its connection: if the process dies, Postgres releases it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from accessops.config import Settings
from accessops.db import connect

# Any fixed 64-bit number; every process that cleans up must use the same one.
CLEANUP_LOCK_ID = 7_412_001


class AdvisoryLock:
    def __init__(self, settings: Settings, lock_id: int = CLEANUP_LOCK_ID) -> None:
        self._settings = settings
        self._lock_id = lock_id

    @contextmanager
    def hold(self) -> Iterator[bool]:
        """Yield True if we got the lock, False if someone else holds it. Never waits."""
        with connect(self._settings, self._settings.pg_admin_db, autocommit=True) as conn:
            row = conn.execute("SELECT pg_try_advisory_lock(%s)", (self._lock_id,)).fetchone()
            acquired = bool(row and row[0])
            try:
                yield acquired
            finally:
                if acquired:
                    conn.execute("SELECT pg_advisory_unlock(%s)", (self._lock_id,))
