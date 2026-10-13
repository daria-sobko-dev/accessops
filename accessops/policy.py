"""Security rules enforced in code: input validation and approval policy."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import timedelta

from accessops.catalog import MAX_PRIVILEGED_TTL, MAX_PRIVILEGED_TTL_TEXT, Role
from accessops.errors import InvalidInputError, PolicyDeniedError
from accessops.ttl import format_duration

# Lowercase latin letters, digits, underscore; starts with a letter; max 63 (Postgres limit).
USERNAME_RE = re.compile(r"[a-z][a-z0-9_]{1,62}")
PERSON_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
RESERVED_PREFIXES = ("pg_", "ao_")
RESERVED_NAMES = frozenset(
    {"postgres", "public", "guest", "ai", "admin", "root"}
    # Accounts that already exist on Linux servers.
    | {"ansible", "ubuntu", "nobody", "daemon", "bin", "sys", "sync", "sshd", "backup"}
)
AI_ACTOR = "ai"


def validate_username(name: str, extra_reserved: Iterable[str] = ()) -> str:
    if not USERNAME_RE.fullmatch(name):
        raise InvalidInputError(
            f"Invalid user name {name!r}: use 2-63 characters (lowercase latin letters, "
            "digits, underscore), starting with a letter."
        )
    if name.startswith(RESERVED_PREFIXES) or name in RESERVED_NAMES or name in extra_reserved:
        raise InvalidInputError(f"User name {name!r} is reserved and cannot be managed.")
    return name


def validate_person(value: str, field: str) -> str:
    if not PERSON_RE.fullmatch(value):
        raise InvalidInputError(
            f"Invalid {field} {value!r}: use latin letters, digits, '_', '.', '-'."
        )
    return value


def check_grant_policy(*, role_name: str, role: Role, actor: str, approved_by: str | None) -> None:
    """Privileged roles need a human approver who is not the actor."""
    if not role.privileged:
        return
    if not approved_by:
        raise PolicyDeniedError(
            f"Role '{role_name}' is privileged and requires --approved-by (a human approver)."
        )
    approver = approved_by.strip().lower()
    if approver == AI_ACTOR:
        raise PolicyDeniedError(
            f"Role '{role_name}' is privileged: AI cannot approve privileged access."
        )
    if approver == actor.strip().lower():
        raise PolicyDeniedError(
            f"Role '{role_name}' is privileged: the approver must be a different person "
            "than the actor (no self-approval)."
        )


def check_ttl_policy(*, role_name: str, role: Role, ttl: timedelta | None) -> None:
    """Privileged access is temporary (max 24h); roles may set their own max_ttl."""
    limit_text = MAX_PRIVILEGED_TTL_TEXT
    if role.privileged and ttl is None:
        raise PolicyDeniedError(
            f"Role '{role_name}' is privileged: access must be temporary, "
            f"use --ttl (at most {limit_text})."
        )
    if role.privileged and ttl > MAX_PRIVILEGED_TTL:
        raise PolicyDeniedError(
            f"Role '{role_name}' is privileged: --ttl {format_duration(ttl)} is longer "
            f"than the {limit_text} limit."
        )
    if role.max_ttl is not None:
        max_text = format_duration(role.max_ttl)
        if ttl is None:
            raise PolicyDeniedError(
                f"Role '{role_name}' has max_ttl {max_text}: use --ttl (at most {max_text})."
            )
        if ttl > role.max_ttl:
            raise PolicyDeniedError(
                f"Role '{role_name}': --ttl {format_duration(ttl)} is longer than "
                f"its max_ttl {max_text}."
            )
