"""Temporary access is really revoked by cleanup. Time is injected, nobody waits.

Run with: pytest -m integration
"""

import secrets
import subprocess
from dataclasses import replace
from datetime import timedelta

import psycopg
import pytest

from accessops.audit import AuditLog
from accessops.catalog import load_catalog
from accessops.clock import utcnow
from accessops.config import PROJECT_ROOT, load_settings
from accessops.credentials import read_credentials
from accessops.grants import GrantStore
from accessops.linux import LinuxBackend
from accessops.postgres import PostgresBackend
from accessops.rabbitmq import RabbitBackend
from accessops.service import CLEANUP_ACTOR, AccessService

pytestmark = pytest.mark.integration


class ShiftableClock:
    """Real time plus an offset we can move forward."""

    def __init__(self):
        self.offset = timedelta(0)

    def __call__(self):
        return utcnow() + self.offset


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = replace(load_settings(), credentials_dir=tmp_path_factory.mktemp("credentials"))
    catalog = load_catalog(settings.catalog_path)
    audit, grants = AuditLog(settings), GrantStore(settings)
    audit.ensure_schema()
    grants.ensure_schema()
    rabbit = RabbitBackend(settings, catalog)
    backends = {
        "postgres": PostgresBackend(settings, catalog),
        "rabbitmq": rabbit,
        "linux": LinuxBackend(settings, catalog),
    }
    clock = ShiftableClock()
    service = AccessService(catalog, audit, backends, grants=grants, clock=clock)
    yield settings, service, grants, audit, rabbit, clock
    rabbit.close()


@pytest.fixture
def subject(env):
    _, service, _, _, _, clock = env
    name = f"it_{secrets.token_hex(4)}"
    yield name
    clock.offset = timedelta(0)
    service.revoke(subject=name, actor="pytest")


def test_short_ttl_is_revoked_everywhere_by_cleanup(env, subject):
    settings, service, grants, audit, rabbit, clock = env
    service.grant(subject=subject, role_name="qa", actor="pytest", ttl="30m")
    active = [g for g in grants.active() if g.subject == subject]
    assert sorted(g.system for g in active) == ["linux", "postgres", "rabbitmq"]
    creds = read_credentials(settings.credentials_dir / f"{subject}-postgres.txt")

    # Not expired yet: cleanup leaves it alone.
    clock.offset = timedelta(minutes=29)
    assert service.cleanup(subject=subject) == []

    # 31 minutes later: revoked in all three systems.
    clock.offset = timedelta(minutes=31)
    items = service.cleanup(subject=subject)
    assert sorted((i.grant.system, i.result) for i in items) == [
        ("linux", "revoked"),
        ("postgres", "revoked"),
        ("rabbitmq", "revoked"),
    ]

    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(
            host=creds["host"], port=creds["port"], dbname=creds["dbname"],
            user=subject, password=creds["password"], connect_timeout=5,
        )  # fmt: skip
    assert rabbit.get_user(subject) is None
    getent = subprocess.run(
        ["docker", "compose", "exec", "-T", "linux-target", "getent", "passwd", subject],
        cwd=PROJECT_ROOT, capture_output=True, timeout=30,
    )  # fmt: skip
    assert getent.returncode == 2

    assert not [g for g in grants.active() if g.subject == subject]
    records = [r for r in audit.recent(10) if r["subject"] == subject and r["action"] == "revoke"]
    assert {(r["actor"], r["result"]) for r in records} == {(CLEANUP_ACTOR, "success")}
    assert len(records) == 3


def test_repeated_grant_keeps_one_active_row(env, subject):
    _, service, grants, *_ = env
    service.grant(subject=subject, role_name="analyst", actor="pytest", systems=("postgres",))
    service.grant(
        subject=subject, role_name="analyst", actor="pytest", ttl="2h", systems=("postgres",)
    )
    rows = [g for g in grants.active() if g.subject == subject]
    assert len(rows) == 1
    assert rows[0].expires_at is not None
