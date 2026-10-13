"""Role catalog: Pydantic schema and loader for roles.yaml."""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from accessops.errors import CatalogError, InvalidInputError
from accessops.ttl import format_duration, parse_ttl

# Durations in roles.yaml are written like 30m, 8h, 3d.
Duration = Annotated[timedelta, BeforeValidator(parse_ttl)]
# Privileged access is always temporary and never longer than this.
MAX_PRIVILEGED_TTL = timedelta(hours=24)
MAX_PRIVILEGED_TTL_TEXT = "24h"

Name = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
TablePrivilege = Literal[
    "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"
]
# Table privileges that change table structure/behaviour rather than data.
ADMIN_TABLE_PRIVILEGES = frozenset({"TRUNCATE", "REFERENCES", "TRIGGER"})
LinuxGroup = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]
# Membership in these groups gives root-level power on a typical Linux server.
ADMIN_LINUX_GROUPS = frozenset(
    {"root", "sudo", "admin", "wheel", "adm", "docker", "lxd", "disk", "shadow"}
)


class _Strict(BaseModel):
    """Unknown fields are an error, so typos in roles.yaml are never ignored."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class PostgresTarget(_Strict):
    database: Name
    schema_name: Name = Field(alias="schema")


class RabbitTarget(_Strict):
    vhost: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]


class Targets(_Strict):
    postgres: PostgresTarget
    rabbitmq: RabbitTarget


class PostgresGrant(_Strict):
    table_privileges: list[TablePrivilege] = Field(min_length=1)
    schema_create: bool = False

    @field_validator("table_privileges")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate privileges")
        return value


class LinuxGrant(_Strict):
    groups: list[LinuxGroup] = Field(min_length=1)
    sudo: bool = False

    @field_validator("groups")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate groups")
        return value


class RabbitPermissions(_Strict):
    """RabbitMQ vhost permissions: regular expressions over resource names."""

    configure: str
    write: str
    read: str

    @field_validator("configure", "write", "read")
    @classmethod
    def _valid_regex(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"not a valid regular expression: {exc}") from exc
        return value


class Role(_Strict):
    description: str = Field(min_length=1)
    privileged: bool
    postgres: PostgresGrant
    rabbitmq: RabbitPermissions
    linux: LinuxGrant
    # Longest allowed access for this role. If set, every grant must use --ttl.
    max_ttl: Duration | None = None

    @model_validator(mode="after")
    def _privileged_max_ttl_within_limit(self) -> Role:
        if self.privileged and self.max_ttl and self.max_ttl > MAX_PRIVILEGED_TTL:
            raise ValueError(
                f"max_ttl {format_duration(self.max_ttl)} is longer than the "
                f"{MAX_PRIVILEGED_TTL_TEXT} limit for privileged roles"
            )
        return self

    @model_validator(mode="after")
    def _admin_rights_require_privileged(self) -> Role:
        reasons = []
        if self.postgres.schema_create:
            reasons.append("postgres.schema_create")
        admin = ADMIN_TABLE_PRIVILEGES.intersection(self.postgres.table_privileges)
        if admin:
            reasons.append("postgres " + ", ".join(sorted(admin)))
        if self.rabbitmq.configure:
            reasons.append("rabbitmq.configure")
        if self.linux.sudo:
            reasons.append("linux.sudo")
        admin_groups = ADMIN_LINUX_GROUPS.intersection(self.linux.groups)
        if admin_groups:
            reasons.append("linux groups " + ", ".join(sorted(admin_groups)))
        if reasons and not self.privileged:
            raise ValueError(
                "role grants admin-level rights (" + "; ".join(reasons) + ") "
                "but is not marked privileged: true"
            )
        return self


class Catalog(_Strict):
    version: Literal[1]
    targets: Targets
    roles: dict[Name, Role] = Field(min_length=1)

    def role(self, name: str) -> Role:
        try:
            return self.roles[name]
        except KeyError:
            known = ", ".join(sorted(self.roles))
            raise InvalidInputError(f"Unknown role '{name}'. Known roles: {known}.") from None


def _format_errors(error: ValidationError) -> str:
    lines = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "(root)"
        lines.append(f"  - {location}: {item['msg']}")
    return "\n".join(lines)


def parse_catalog(data: object, source: str = "roles.yaml") -> Catalog:
    try:
        return Catalog.model_validate(data)
    except ValidationError as exc:
        raise CatalogError(f"Invalid role catalog {source}:\n{_format_errors(exc)}") from None


def load_catalog(path: Path) -> Catalog:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CatalogError(f"Role catalog not found: {path}") from None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CatalogError(f"Role catalog {path.name} is not valid YAML: {exc}") from None
    return parse_catalog(data, path.name)
