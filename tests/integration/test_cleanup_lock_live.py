"""Two cleanups at the same time: the real Postgres advisory lock lets only one run.

Run with: pytest -m integration
"""

import threading
from contextlib import ExitStack
from dataclasses import replace

import pytest

from accessops.config import load_settings
from accessops.errors import BusyError
from accessops.locks import AdvisoryLock
from accessops.service import AccessService
from tests.test_service import CATALOG, FakeAudit, FakeBackend, FakeGrants

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def settings():
    return load_settings()


def test_lock_is_exclusive_and_released(settings):
    first, second = AdvisoryLock(settings), AdvisoryLock(settings)
    with first.hold() as got_first:
        assert got_first is True
        with second.hold() as got_second:
            assert got_second is False
    with second.hold() as got_after:
        assert got_after is True


def test_lock_is_released_when_the_holder_dies(settings):
    # A crashed process closes its connection: Postgres frees the lock by itself.
    stack = ExitStack()
    assert stack.enter_context(AdvisoryLock(settings).hold()) is True
    stack.close()
    with AdvisoryLock(settings).hold() as acquired:
        assert acquired is True


def test_two_cleanups_at_once_only_one_runs(settings):
    started, release = threading.Event(), threading.Event()

    class SlowBackend(FakeBackend):
        def revoke(self, subject, *, dry_run):
            started.set()
            assert release.wait(timeout=10)
            return super().revoke(subject, dry_run=dry_run)

    def make_service(grants):
        backends = {"postgres": SlowBackend("postgres")}
        return AccessService(
            CATALOG, FakeAudit(), backends, grants=grants,
            cleanup_lock=AdvisoryLock(settings).hold,
        )  # fmt: skip

    grants = FakeGrants()
    service = make_service(grants)
    service.grant(subject="carl", role_name="qa", actor="pytest", ttl="1m", systems=("postgres",))
    grants.rows[0] = replace(grants.rows[0], expires_at=grants.rows[0].granted_at)  # expired

    results = {}

    def first_run():
        results["first"] = service.cleanup()

    worker = threading.Thread(target=first_run)
    worker.start()
    try:
        assert started.wait(timeout=10), "first cleanup did not start"
        # The first cleanup is in the middle of revoking: a second one must not start.
        with pytest.raises(BusyError):
            make_service(grants).cleanup()
    finally:
        release.set()
        worker.join(timeout=10)

    assert [i.result for i in results["first"]] == ["revoked"]
    assert grants.active() == []
