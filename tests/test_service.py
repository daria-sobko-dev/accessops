"""Service rules with fake backends, fake grants and a fake clock: no Docker needed."""

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from accessops.catalog import load_catalog
from accessops.errors import BusyError, InvalidInputError, PolicyDeniedError
from accessops.grants import Grant
from accessops.outcome import Outcome
from accessops.service import CLEANUP_ACTOR, AccessService

CATALOG = load_catalog(Path(__file__).resolve().parent.parent / "roles.yaml")
T0 = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


class FakeAudit:
    def __init__(self):
        self.entries = []

    def check_ready(self):
        pass

    def write(self, entry):
        self.entries.append(entry)
        return len(self.entries)


class FakeGrants:
    """In-memory access_grants with the same rules as the real table."""

    def __init__(self):
        self.rows = []

    def active(self):
        return [g for g in self.rows if g.status == "active"]

    def _find(self, subject, system):
        return next((g for g in self.active() if (g.subject, g.system) == (subject, system)), None)

    def record_grant(
        self, *, subject, system, role, ticket_id, actor, approved_by, now, expires_at
    ):
        current = self._find(subject, system)
        if current is not None:
            updated = replace(current, expires_at=expires_at, actor=actor, approved_by=approved_by)
            self.rows[self.rows.index(current)] = updated
            return updated
        grant = Grant(
            len(self.rows) + 1, subject, system, role, ticket_id, actor, approved_by,
            now, expires_at, "active", None, None,
        )  # fmt: skip
        self.rows.append(grant)
        return grant

    def record_revoke(self, *, subject, system, now, revoked_by, status="revoked"):
        current = self._find(subject, system)
        if current is None:
            return None
        closed = replace(current, status=status, revoked_at=now, revoked_by=revoked_by)
        self.rows[self.rows.index(current)] = closed
        return closed

    def expired(self, now):
        return [g for g in self.active() if g.expires_at is not None and g.expires_at <= now]


class FakeBackend:
    def __init__(self, system):
        self.system = system
        self.calls = []
        self.fail_revoke = False

    def grant(self, subject, role_name, *, dry_run):
        self.calls.append(("grant", subject, role_name, dry_run))
        return Outcome(self.system, True, role_name, ["fake step"])

    def revoke(self, subject, *, dry_run):
        self.calls.append(("revoke", subject, dry_run))
        if self.fail_revoke:
            raise RuntimeError("connection refused")
        return Outcome(self.system, True, "developer", ["fake step"])


@pytest.fixture
def env():
    audit, grants, clock = FakeAudit(), FakeGrants(), FakeClock()
    backends = {name: FakeBackend(name) for name in ("postgres", "rabbitmq", "linux")}
    service = AccessService(
        CATALOG, audit, backends, grants=grants, reserved_names={"accessops"}, clock=clock
    )
    return service, audit, backends, grants, clock


# ---- grant / revoke ---------------------------------------------------------


def test_grant_writes_success_per_system(env):
    service, audit, _, grants, _ = env
    service.grant(subject="anna", role_name="developer", actor="ivan", ticket_id="ACC-1")
    assert [(e.system, e.result) for e in audit.entries] == [
        ("postgres", "success"),
        ("rabbitmq", "success"),
        ("linux", "success"),
    ]
    assert audit.entries[0].ticket_id == "ACC-1"
    assert [(g.system, g.expires_at) for g in grants.active()] == [
        ("postgres", None),
        ("rabbitmq", None),
        ("linux", None),
    ]


def test_ttl_sets_expiry_in_grants_audit_and_outcome(env):
    service, audit, _, grants, _ = env
    outcomes = service.grant(subject="anna", role_name="developer", actor="ivan", ttl="8h")
    expected = T0 + timedelta(hours=8)
    assert {g.expires_at for g in grants.active()} == {expected}
    assert audit.entries[0].details["expires_at"] == expected.isoformat()
    assert outcomes[0].expires_at == expected


def test_repeated_grant_keeps_one_active_record(env):
    service, _, _, grants, clock = env
    service.grant(subject="anna", role_name="developer", actor="ivan", ttl="1h")
    clock.advance(minutes=30)
    service.grant(subject="anna", role_name="developer", actor="ivan", ttl="2h")
    active = grants.active()
    assert len(active) == 3
    assert {g.expires_at for g in active} == {T0 + timedelta(minutes=30, hours=2)}


def test_revoke_closes_grants(env):
    service, _, _, grants, _ = env
    service.grant(subject="anna", role_name="developer", actor="ivan")
    service.revoke(subject="anna", actor="ivan")
    assert grants.active() == []
    assert {(g.status, g.revoked_by) for g in grants.rows} == {("revoked", "ivan")}


@pytest.mark.parametrize("approver", [None, "ai", "ivan"])
def test_privileged_denied_is_audited_and_nothing_changes(env, approver):
    service, audit, backends, grants, _ = env
    with pytest.raises(PolicyDeniedError):
        service.grant(
            subject="anna", role_name="devops_admin", actor="ivan", approved_by=approver, ttl="4h"
        )
    assert {e.result for e in audit.entries} == {"denied"}
    assert len(audit.entries) == 3
    assert all(b.calls == [] for b in backends.values())
    assert grants.rows == []


def test_ai_actor_cannot_grant_privileged_even_with_ai_approver(env):
    service, audit, *_ = env
    with pytest.raises(PolicyDeniedError):
        service.grant(
            subject="anna", role_name="devops_admin", actor="ai", approved_by="ai", ttl="1h"
        )
    assert all(e.result == "denied" for e in audit.entries)


@pytest.mark.parametrize(
    ("ttl", "message"),
    [(None, "must be temporary"), ("48h", "longer than the 24h limit"), ("13h", "max_ttl 12h")],
)
def test_privileged_ttl_rules_are_denied_and_audited(env, ttl, message):
    service, audit, backends, grants, _ = env
    with pytest.raises(PolicyDeniedError, match=message):
        service.grant(
            subject="boris", role_name="devops_admin", actor="ivan", approved_by="olga", ttl=ttl
        )
    assert {e.result for e in audit.entries} == {"denied"}
    assert all(b.calls == [] for b in backends.values())
    assert grants.rows == []


def test_privileged_with_human_approver_and_ttl_is_allowed(env):
    service, audit, _, grants, _ = env
    service.grant(
        subject="anna", role_name="devops_admin", actor="ivan", approved_by="olga", ttl="4h"
    )
    assert all(e.result == "success" and e.approved_by == "olga" for e in audit.entries)
    assert {g.expires_at for g in grants.active()} == {T0 + timedelta(hours=4)}


def test_role_max_ttl_requires_ttl(env):
    service, audit, *_ = env
    with pytest.raises(PolicyDeniedError, match="max_ttl 7d"):
        service.grant(subject="carl", role_name="qa", actor="ivan")
    with pytest.raises(PolicyDeniedError, match="longer than its max_ttl 7d"):
        service.grant(subject="carl", role_name="qa", actor="ivan", ttl="8d")
    assert {e.result for e in audit.entries} == {"denied"}


def test_invalid_ttl_is_audited_as_error(env):
    service, audit, backends, *_ = env
    with pytest.raises(InvalidInputError, match="Invalid --ttl"):
        service.grant(subject="anna", role_name="developer", actor="ivan", ttl="forever")
    assert {e.result for e in audit.entries} == {"error"}
    assert all(b.calls == [] for b in backends.values())


def test_invalid_name_is_audited_as_error(env):
    service, audit, backends, *_ = env
    with pytest.raises(InvalidInputError):
        service.grant(subject="Robert'); DROP", role_name="developer", actor="ivan")
    assert {e.result for e in audit.entries} == {"error"}
    assert all(b.calls == [] for b in backends.values())


def test_backend_failure_is_audited_as_error(env):
    service, audit, backends, grants, _ = env

    def boom(*args, **kwargs):
        raise RuntimeError("connection refused")

    backends["postgres"].grant = boom
    with pytest.raises(RuntimeError):
        service.grant(subject="anna", role_name="developer", actor="ivan")
    assert audit.entries[-1].result == "error"
    assert "connection refused" in audit.entries[-1].details["error"]
    assert grants.rows == []


def test_dry_run_writes_nothing(env):
    service, audit, backends, grants, _ = env
    service.grant(subject="anna", role_name="developer", actor="ivan", dry_run=True)
    assert audit.entries == [] and grants.rows == []
    assert backends["postgres"].calls == [("grant", "anna", "developer", True)]


def test_revoke_records_role_from_backend(env):
    service, audit, *_ = env
    service.revoke(subject="anna", actor="ivan", systems=("postgres",))
    assert len(audit.entries) == 1
    assert audit.entries[0].role == "developer"
    assert audit.entries[0].action == "revoke"


# ---- cleanup with a fake clock -------------------------------------------------


def test_cleanup_before_expiry_does_nothing(env):
    service, audit, backends, grants, clock = env
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="2m")
    audit.entries.clear()
    clock.advance(minutes=1, seconds=59)
    assert service.cleanup() == []
    assert audit.entries == []
    assert len(grants.active()) == 3


def test_cleanup_after_expiry_revokes_all_systems(env):
    service, audit, backends, grants, clock = env
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="2m")
    service.grant(subject="anna", role_name="developer", actor="ivan")  # permanent
    audit.entries.clear()
    clock.advance(minutes=2)

    items = service.cleanup()

    assert [(i.grant.subject, i.grant.system, i.result) for i in items] == [
        ("carl", "postgres", "revoked"),
        ("carl", "rabbitmq", "revoked"),
        ("carl", "linux", "revoked"),
    ]
    assert {(e.actor, e.action, e.result) for e in audit.entries} == {
        (CLEANUP_ACTOR, "revoke", "success")
    }
    assert all(e.details["reason"] == "expired" for e in audit.entries)
    closed = [g for g in grants.rows if g.subject == "carl"]
    assert {(g.status, g.revoked_by) for g in closed} == {("expired", CLEANUP_ACTOR)}
    assert [g.subject for g in grants.active()] == ["anna"] * 3


def test_cleanup_failure_in_one_system_continues_and_keeps_grant(env):
    service, audit, backends, grants, clock = env
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="30m")
    audit.entries.clear()
    backends["rabbitmq"].fail_revoke = True
    clock.advance(hours=1)

    items = service.cleanup()

    assert [(i.grant.system, i.result) for i in items] == [
        ("postgres", "revoked"),
        ("rabbitmq", "error"),
        ("linux", "revoked"),
    ]
    assert [(e.system, e.result) for e in audit.entries] == [
        ("postgres", "success"),
        ("rabbitmq", "error"),
        ("linux", "success"),
    ]
    assert "connection refused" in audit.entries[1].details["error"]
    assert [g.system for g in grants.active()] == ["rabbitmq"]

    # Next cleanup retries only the failed system.
    backends["rabbitmq"].fail_revoke = False
    retry = service.cleanup()
    assert [(i.grant.system, i.result) for i in retry] == [("rabbitmq", "revoked")]
    assert grants.active() == []


def test_cleanup_dry_run_changes_nothing(env):
    service, audit, backends, grants, clock = env
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="2m")
    audit.entries.clear()
    clock.advance(minutes=5)
    items = service.cleanup(dry_run=True)
    assert {i.result for i in items} == {"would revoke"}
    assert audit.entries == []
    assert len(grants.active()) == 3
    assert backends["linux"].calls[-1] == ("revoke", "carl", True)


class FakeLock:
    """Behaves like the Postgres advisory lock: only one holder at a time."""

    def __init__(self):
        self.held = False

    @contextmanager
    def hold(self):
        if self.held:
            yield False
            return
        self.held = True
        try:
            yield True
        finally:
            self.held = False


def test_second_cleanup_is_skipped_while_first_runs(env):
    service, audit, backends, grants, clock = env
    lock = FakeLock()
    service._cleanup_lock = lock.hold
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="2m")
    audit.entries.clear()
    clock.advance(minutes=5)

    lock.held = True  # the first cleanup is still running somewhere else
    with pytest.raises(BusyError, match="already running"):
        service.cleanup()
    assert audit.entries == []
    assert len(grants.active()) == 3
    assert all(call[0] == "grant" for b in backends.values() for call in b.calls)

    lock.held = False  # the first one finished: the next run works and frees the lock
    assert len(service.cleanup()) == 3
    assert grants.active() == []
    assert lock.held is False


def test_cleanup_dry_run_ignores_the_lock(env):
    service, _, _, _, clock = env
    lock = FakeLock()
    lock.held = True
    service._cleanup_lock = lock.hold
    service.grant(subject="carl", role_name="qa", actor="ivan", ttl="2m")
    clock.advance(minutes=5)
    assert len(service.cleanup(dry_run=True)) == 3
