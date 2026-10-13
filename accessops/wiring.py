"""Builds the real service and backends. Shared by the CLI and accessops-api."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from accessops.audit import AuditLog
from accessops.catalog import Catalog
from accessops.clock import utcnow
from accessops.config import Settings
from accessops.grants import GrantStore
from accessops.linux import LinuxBackend
from accessops.locks import AdvisoryLock
from accessops.postgres import PostgresBackend
from accessops.rabbitmq import RabbitBackend
from accessops.reports import compute_drift
from accessops.service import AccessService, CleanupItem


@contextmanager
def open_backends(settings: Settings, catalog: Catalog) -> Iterator[dict]:
    rabbit = RabbitBackend(settings, catalog)
    try:
        yield {
            "postgres": PostgresBackend(settings, catalog),
            "rabbitmq": rabbit,
            "linux": LinuxBackend(settings, catalog),
        }
    finally:
        rabbit.close()


def build_service(settings: Settings, catalog: Catalog, backends: dict) -> AccessService:
    reserved = {settings.pg_admin_user, settings.rabbit_admin_user}
    return AccessService(
        catalog,
        AuditLog(settings),
        backends,
        grants=GrantStore(settings),
        reserved_names=reserved,
        clock=utcnow,
        cleanup_lock=AdvisoryLock(settings).hold,
    )


class LiveJobs:
    """The jobs accessops-api runs on request, against the real systems."""

    def __init__(self, settings: Settings, catalog: Catalog) -> None:
        self._settings = settings
        self._catalog = catalog

    def cleanup(self) -> list[CleanupItem]:
        with open_backends(self._settings, self._catalog) as backends:
            return build_service(self._settings, self._catalog, backends).cleanup()

    def drift(self) -> list[tuple[str, str, str, str, str]]:
        grants = GrantStore(self._settings).active()
        with open_backends(self._settings, self._catalog) as backends:
            inventories = {name: backend.inventory() for name, backend in backends.items()}
        return compute_drift(grants, inventories)
