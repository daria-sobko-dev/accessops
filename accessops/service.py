"""Orchestrates grant/revoke/cleanup: validation, policy, backends, grants and audit.

Every attempt that is not a dry run is written to the audit log: success, denied or error.
Every successful change also updates access_grants (the source of truth).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol, TypeVar

from accessops.audit import AuditEntry
from accessops.catalog import Catalog
from accessops.clock import Clock, utcnow
from accessops.errors import (
    AccessOpsError,
    BusyError,
    InvalidInputError,
    PolicyDeniedError,
)
from accessops.grants import Grant
from accessops.outcome import Outcome
from accessops.policy import (
    check_grant_policy,
    check_ttl_policy,
    validate_person,
    validate_username,
)
from accessops.ttl import parse_ttl

SYSTEMS = ("postgres", "rabbitmq", "linux")
CLEANUP_ACTOR = "system:cleanup"
T = TypeVar("T")


class Backend(Protocol):
    system: str

    def grant(self, subject: str, role_name: str, *, dry_run: bool) -> Outcome: ...

    def revoke(self, subject: str, *, dry_run: bool) -> Outcome: ...


class AuditWriter(Protocol):
    def check_ready(self) -> None: ...

    def write(self, entry: AuditEntry) -> int: ...


class GrantWriter(Protocol):
    def record_grant(self, **kwargs: Any) -> Grant: ...

    def record_revoke(self, **kwargs: Any) -> Grant | None: ...

    def expired(self, now: datetime) -> list[Grant]: ...


@dataclass
class CleanupItem:
    grant: Grant
    result: Literal["revoked", "would revoke", "error"]
    steps: list[str] = field(default_factory=list)


class AccessService:
    def __init__(
        self,
        catalog: Catalog,
        audit: AuditWriter,
        backends: dict[str, Backend],
        *,
        grants: GrantWriter,
        reserved_names: Iterable[str] = (),
        clock: Clock = utcnow,
        cleanup_lock: Callable[[], AbstractContextManager[bool]] | None = None,
    ) -> None:
        self._catalog = catalog
        self._audit = audit
        self._backends = backends
        self._grants = grants
        self._reserved = frozenset(reserved_names)
        self._clock = clock
        # Without a lock (unit tests, dry runs) cleanup always runs.
        self._cleanup_lock = cleanup_lock or (lambda: nullcontext(True))

    def grant(
        self,
        *,
        subject: str,
        role_name: str,
        actor: str,
        approved_by: str | None = None,
        ticket_id: str | None = None,
        ttl: str | None = None,
        systems: Sequence[str] = SYSTEMS,
        dry_run: bool = False,
    ) -> list[Outcome]:
        now = self._clock()
        base = {
            "actor": actor,
            "approved_by": approved_by,
            "action": "grant",
            "subject": subject,
            "role": role_name,
            "ticket_id": ticket_id,
        }
        if not dry_run:
            self._audit.check_ready()

        def validate() -> timedelta | None:
            validate_person(actor, "actor")
            if approved_by is not None:
                validate_person(approved_by, "approved-by")
            validate_username(subject, self._reserved)
            role = self._catalog.role(role_name)
            try:
                duration = parse_ttl(ttl) if ttl is not None else None
            except ValueError as exc:
                raise InvalidInputError(f"Invalid --ttl: {exc}.") from None
            check_grant_policy(role_name=role_name, role=role, actor=actor, approved_by=approved_by)
            check_ttl_policy(role_name=role_name, role=role, ttl=duration)
            return duration

        duration = self._validate(validate, base, systems, dry_run)
        expires_at = now + duration if duration else None
        extra = {"expires_at": expires_at.isoformat() if expires_at else None, "ttl": ttl}

        def after_success(system: str, outcome: Outcome) -> None:
            outcome.expires_at = expires_at
            if dry_run:
                return
            self._grants.record_grant(
                subject=subject,
                system=system,
                role=role_name,
                ticket_id=ticket_id,
                actor=actor,
                approved_by=approved_by,
                now=now,
                expires_at=expires_at,
            )

        return [
            self._run(
                base,
                system,
                lambda b: b.grant(subject, role_name, dry_run=dry_run),
                dry_run,
                extra=extra,
                after_success=after_success,
            )
            for system in systems
        ]

    def revoke(
        self,
        *,
        subject: str,
        actor: str,
        ticket_id: str | None = None,
        systems: Sequence[str] = SYSTEMS,
        dry_run: bool = False,
    ) -> list[Outcome]:
        now = self._clock()
        base = {
            "actor": actor,
            "action": "revoke",
            "subject": subject,
            "ticket_id": ticket_id,
        }
        if not dry_run:
            self._audit.check_ready()

        def validate() -> None:
            validate_person(actor, "actor")
            validate_username(subject, self._reserved)

        def after_success(system: str, outcome: Outcome) -> None:
            if not dry_run:
                self._grants.record_revoke(
                    subject=subject, system=system, now=now, revoked_by=actor
                )

        self._validate(validate, base, systems, dry_run)
        return [
            self._run(
                base,
                system,
                lambda b: b.revoke(subject, dry_run=dry_run),
                dry_run,
                after_success=after_success,
            )
            for system in systems
        ]

    def cleanup(self, *, dry_run: bool = False, subject: str | None = None) -> list[CleanupItem]:
        """Revoke every active grant whose expires_at has passed, system by system.

        A failure in one system is audited and does not stop the others; the failed grant
        stays active, so the next cleanup tries again.
        Only one real cleanup runs at a time: a second one raises BusyError and changes nothing.
        """
        if dry_run:
            return self._cleanup(dry_run=True, subject=subject)
        self._audit.check_ready()
        with self._cleanup_lock() as acquired:
            if not acquired:
                raise BusyError("Another cleanup is already running; this one was skipped.")
            return self._cleanup(dry_run=False, subject=subject)

    def _cleanup(self, *, dry_run: bool, subject: str | None) -> list[CleanupItem]:
        now = self._clock()
        items = []
        for grant in self._grants.expired(now):
            if subject is not None and grant.subject != subject:
                continue
            base = {
                "actor": CLEANUP_ACTOR,
                "action": "revoke",
                "subject": grant.subject,
                "role": grant.role,
                "ticket_id": grant.ticket_id,
            }
            reason = {"reason": "expired", "expires_at": grant.expires_at.isoformat()}
            try:
                outcome = self._backends[grant.system].revoke(grant.subject, dry_run=dry_run)
                if not dry_run:
                    self._grants.record_revoke(
                        subject=grant.subject,
                        system=grant.system,
                        now=now,
                        revoked_by=CLEANUP_ACTOR,
                        status="expired",
                    )
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                self._record(base, grant.system, "error", reason | {"error": error}, dry_run)
                items.append(CleanupItem(grant, "error", [error]))
                continue
            details = reason | {"changed": outcome.changed, "steps": outcome.steps}
            self._record(base, grant.system, "success", details, dry_run)
            items.append(
                CleanupItem(grant, "would revoke" if dry_run else "revoked", outcome.steps)
            )
        return items

    # ---- internals -------------------------------------------------------

    def _validate(
        self,
        check: Callable[[], T],
        base: dict[str, Any],
        systems: Sequence[str],
        dry_run: bool,
    ) -> T:
        try:
            return check()
        except PolicyDeniedError as exc:
            for system in systems:
                self._record(base, system, "denied", {"reason": str(exc)}, dry_run)
            raise
        except AccessOpsError as exc:
            for system in systems:
                self._record(base, system, "error", {"reason": str(exc)}, dry_run)
            raise

    def _run(
        self,
        base: dict[str, Any],
        system: str,
        operation: Callable[[Backend], Outcome],
        dry_run: bool,
        *,
        extra: dict[str, Any] | None = None,
        after_success: Callable[[str, Outcome], None] | None = None,
    ) -> Outcome:
        try:
            outcome = operation(self._backends[system])
            if after_success is not None:
                after_success(system, outcome)
        except Exception as exc:
            details = (extra or {}) | {"error": f"{type(exc).__name__}: {exc}"}
            self._record(base, system, "error", details, dry_run)
            raise
        details: dict[str, Any] = (extra or {}) | {
            "changed": outcome.changed,
            "steps": outcome.steps,
        }
        if outcome.credentials_file is not None:
            details["credentials_file"] = outcome.credentials_file.name
        self._record(base | {"role": outcome.role}, system, "success", details, dry_run)
        return outcome

    def _record(
        self,
        base: dict[str, Any],
        system: str,
        result: Literal["success", "denied", "error"],
        details: dict[str, Any],
        dry_run: bool,
    ) -> None:
        if dry_run:
            return
        self._audit.write(AuditEntry(**base, system=system, result=result, details=details))
