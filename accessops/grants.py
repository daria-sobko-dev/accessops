"""access_grants: the source of truth for which access should exist."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

import psycopg
from psycopg.rows import class_row

from accessops.config import Settings
from accessops.db import connect
from accessops.errors import ConflictError

GRANTS_SQL = Path(__file__).parent / "sql" / "grants.sql"


@dataclass(frozen=True)
class Grant:
    id: int
    subject: str
    system: str
    role: str
    ticket_id: str | None
    actor: str
    approved_by: str | None
    granted_at: datetime
    expires_at: datetime | None
    status: str
    revoked_at: datetime | None
    revoked_by: str | None


class GrantStore:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _connect(self) -> psycopg.Connection:
        return connect(self._settings, self._settings.pg_admin_db)

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(GRANTS_SQL.read_text(encoding="utf-8"))

    def record_grant(
        self,
        *,
        subject: str,
        system: str,
        role: str,
        ticket_id: str | None,
        actor: str,
        approved_by: str | None,
        now: datetime,
        expires_at: datetime | None,
    ) -> Grant:
        """Insert an active grant, or refresh the existing active one (never a second row)."""
        with self._connect() as conn, conn.cursor(row_factory=class_row(Grant)) as cur:
            cur.execute(
                "SELECT * FROM access_grants WHERE subject = %s AND system = %s "
                "AND status = 'active' FOR UPDATE",
                (subject, system),
            )
            current = cur.fetchone()
            if current is not None and current.role != role:
                raise ConflictError(
                    f"access_grants already has role '{current.role}' for '{subject}' "
                    f"in {system}; revoke it first."
                )
            if current is not None:
                cur.execute(
                    """
                    UPDATE access_grants
                    SET expires_at = %s, actor = %s, approved_by = %s,
                        ticket_id = coalesce(%s, ticket_id)
                    WHERE id = %s
                    RETURNING *
                    """,
                    (expires_at, actor, approved_by, ticket_id, current.id),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO access_grants
                        (subject, system, role, ticket_id, actor, approved_by,
                         granted_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                    """,
                    (subject, system, role, ticket_id, actor, approved_by, now, expires_at),
                )
            return cur.fetchone()

    def record_revoke(
        self,
        *,
        subject: str,
        system: str,
        now: datetime,
        revoked_by: str,
        status: Literal["revoked", "expired"] = "revoked",
    ) -> Grant | None:
        with self._connect() as conn, conn.cursor(row_factory=class_row(Grant)) as cur:
            cur.execute(
                """
                UPDATE access_grants
                SET status = %s, revoked_at = %s, revoked_by = %s
                WHERE subject = %s AND system = %s AND status = 'active'
                RETURNING *
                """,
                (status, now, revoked_by, subject, system),
            )
            return cur.fetchone()

    def active(self) -> list[Grant]:
        with self._connect() as conn, conn.cursor(row_factory=class_row(Grant)) as cur:
            cur.execute(
                "SELECT * FROM access_grants WHERE status = 'active' ORDER BY subject, system"
            )
            return cur.fetchall()

    def expired(self, now: datetime) -> list[Grant]:
        with self._connect() as conn, conn.cursor(row_factory=class_row(Grant)) as cur:
            cur.execute(
                "SELECT * FROM access_grants WHERE status = 'active' AND expires_at <= %s "
                "ORDER BY expires_at, subject, system",
                (now,),
            )
            return cur.fetchall()
