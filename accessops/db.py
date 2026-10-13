"""Postgres connection helper for the admin account."""

from __future__ import annotations

import psycopg

from accessops.config import Settings


def connect(settings: Settings, dbname: str, *, autocommit: bool = False) -> psycopg.Connection:
    return psycopg.connect(
        host=settings.pg_host,
        port=settings.pg_port,
        user=settings.pg_admin_user,
        password=settings.pg_admin_password,
        dbname=dbname,
        autocommit=autocommit,
        connect_timeout=5,
    )
