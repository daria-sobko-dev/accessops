"""Audit log: every grant/revoke attempt is stored in access_audit (append-only)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field

from accessops.config import Settings
from accessops.db import connect
from accessops.errors import ConfigError

AUDIT_SQL = Path(__file__).parent / "sql" / "audit.sql"


class AuditEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str
    approved_by: str | None = None
    action: Literal["grant", "revoke"]
    system: Literal["postgres", "rabbitmq", "linux"]
    subject: str
    role: str | None = None
    ticket_id: str | None = None
    result: Literal["success", "denied", "error"]
    details: dict[str, Any] = Field(default_factory=dict)


class AuditLog:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _connect(self) -> psycopg.Connection:
        return connect(self._settings, self._settings.pg_admin_db)

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(AUDIT_SQL.read_text(encoding="utf-8"))

    def check_ready(self) -> None:
        """Fail before changing anything if the audit log cannot be written."""
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1 FROM access_audit LIMIT 0")
        except psycopg.errors.UndefinedTable:
            raise ConfigError(
                "Audit table access_audit does not exist. Run `python -m accessops init` first."
            ) from None

    def write(self, entry: AuditEntry) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO access_audit
                    (actor, approved_by, action, system, subject, role, ticket_id, result, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    entry.actor,
                    entry.approved_by,
                    entry.action,
                    entry.system,
                    entry.subject,
                    entry.role,
                    entry.ticket_id,
                    entry.result,
                    Jsonb(entry.details),
                ),
            ).fetchone()
        return row[0]

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM access_audit ORDER BY id DESC LIMIT %s", (limit,))
            return cur.fetchall()
