"""Integration tests against the running docker compose stack.

Run with: pytest -m integration
Every test uses a random user name and cleans up after itself.
Audit records written by these tests stay in the log (it is append-only by design).
"""

import secrets
from dataclasses import replace

import psycopg
import pytest

from accessops.audit import AuditEntry, AuditLog
from accessops.catalog import load_catalog
from accessops.config import load_settings
from accessops.credentials import read_credentials
from accessops.db import connect
from accessops.errors import PolicyDeniedError
from accessops.grants import GrantStore
from accessops.linux import LinuxBackend
from accessops.postgres import PostgresBackend
from accessops.rabbitmq import RabbitBackend
from accessops.service import AccessService

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = replace(load_settings(), credentials_dir=tmp_path_factory.mktemp("credentials"))
    catalog = load_catalog(settings.catalog_path)
    audit = AuditLog(settings)
    pg = PostgresBackend(settings, catalog)
    rabbit = RabbitBackend(settings, catalog)
    audit.ensure_schema()
    GrantStore(settings).ensure_schema()
    pg.setup()
    rabbit.setup()
    service = AccessService(
        catalog,
        audit,
        {"postgres": pg, "rabbitmq": rabbit, "linux": LinuxBackend(settings, catalog)},
        grants=GrantStore(settings),
        reserved_names={settings.pg_admin_user, settings.rabbit_admin_user},
    )
    yield settings, catalog, service, audit, pg, rabbit
    rabbit.close()


@pytest.fixture
def subject(env):
    _, _, service, *_ = env
    name = f"it_{secrets.token_hex(4)}"
    yield name
    service.revoke(subject=name, actor="pytest")


def user_connect(settings, subject):
    creds = read_credentials(settings.credentials_dir / f"{subject}-postgres.txt")
    return psycopg.connect(
        host=creds["host"],
        port=creds["port"],
        dbname=creds["dbname"],
        user=creds["user"],
        password=creds["password"],
        connect_timeout=5,
    )


def test_grant_repeat_and_revoke_developer(env, subject):
    settings, catalog, service, _, pg, rabbit = env

    first = service.grant(subject=subject, role_name="developer", actor="pytest", ticket_id="IT")
    assert [o.changed for o in first] == [True, True, True]
    for o in first:
        assert o.credentials_file.stat().st_mode & 0o777 == 0o600

    # The user can really log in and read the data.
    with user_connect(settings, subject) as conn:
        assert conn.execute("SELECT count(*) FROM app.customers").fetchone()[0] > 0

    assert rabbit.get_user(subject) is not None
    assert rabbit.get_permissions(subject) == catalog.role("developer").rabbitmq.model_dump()

    # Repeated grant: no error, no change, no duplicates.
    second = service.grant(subject=subject, role_name="developer", actor="pytest")
    assert [o.changed for o in second] == [False, False, False]
    assert pg.list_assignments().count((subject, "developer")) == 1
    assert rabbit.list_assignments().count((subject, "developer")) == 1

    creds_file = settings.credentials_dir / f"{subject}-postgres.txt"
    revoked = service.revoke(subject=subject, actor="pytest")
    assert [o.changed for o in revoked] == [True, True, True]
    assert not creds_file.exists()
    assert rabbit.get_user(subject) is None

    # Revoking again is a no-op, not an error.
    again = service.revoke(subject=subject, actor="pytest")
    assert [o.changed for o in again] == [False, False, False]


def test_revoked_user_cannot_connect(env, subject):
    settings, _, service, *_ = env
    service.grant(subject=subject, role_name="developer", actor="pytest", systems=("postgres",))
    creds_file = settings.credentials_dir / f"{subject}-postgres.txt"
    creds = read_credentials(creds_file)
    service.revoke(subject=subject, actor="pytest", systems=("postgres",))
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(
            host=creds["host"],
            port=creds["port"],
            dbname=creds["dbname"],
            user=subject,
            password=creds["password"],
            connect_timeout=5,
        )


def test_analyst_cannot_write(env, subject):
    settings, _, service, *_ = env
    service.grant(subject=subject, role_name="analyst", actor="pytest", systems=("postgres",))
    with user_connect(settings, subject) as conn:
        assert conn.execute("SELECT count(*) FROM app.products").fetchone()[0] > 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO app.customers (name, email) VALUES ('x', 'x@example.com')")


def test_granted_user_cannot_read_audit_db(env, subject):
    settings, _, service, *_ = env
    service.grant(subject=subject, role_name="developer", actor="pytest", systems=("postgres",))
    creds = read_credentials(settings.credentials_dir / f"{subject}-postgres.txt")
    with pytest.raises(psycopg.OperationalError, match="permission denied"):
        psycopg.connect(
            host=creds["host"],
            port=creds["port"],
            dbname=settings.pg_admin_db,
            user=subject,
            password=creds["password"],
            connect_timeout=5,
        )


def test_privileged_without_approval_is_denied_and_audited(env, subject):
    _, _, service, audit, pg, _ = env
    with pytest.raises(PolicyDeniedError):
        service.grant(subject=subject, role_name="devops_admin", actor="pytest")
    latest = [r for r in audit.recent(10) if r["subject"] == subject]
    assert {r["result"] for r in latest} == {"denied"}
    assert all(name != subject for name, _ in pg.list_assignments())


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE access_audit SET result = 'success' WHERE id = %s",
        "DELETE FROM access_audit WHERE id = %s",
    ],
)
def test_audit_rows_cannot_be_changed(env, statement):
    settings, _, _, audit, *_ = env
    entry_id = audit.write(
        AuditEntry(
            actor="pytest",
            action="grant",
            system="postgres",
            subject="trigger_check",
            result="denied",
            details={"test": "append-only"},
        )
    )
    with connect(settings, settings.pg_admin_db) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            conn.execute(statement, (entry_id,))


def test_audit_cannot_be_truncated(env):
    settings, *_ = env
    with connect(settings, settings.pg_admin_db) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            conn.execute("TRUNCATE access_audit")
