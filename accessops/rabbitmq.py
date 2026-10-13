"""RabbitMQ access via the Management HTTP API.

A managed user carries the tag `accessops-role-<role>`; users without it are never touched.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from accessops.catalog import Catalog
from accessops.config import Settings
from accessops.credentials import delete_credentials, new_password, save_credentials
from accessops.errors import ConflictError
from accessops.outcome import Inventory, Outcome

TAG_PREFIX = "accessops-role-"
PERMISSION_KEYS = ("configure", "write", "read")


def _q(name: str) -> str:
    return quote(name, safe="")


class RabbitBackend:
    system = "rabbitmq"

    def __init__(
        self, settings: Settings, catalog: Catalog, client: httpx.Client | None = None
    ) -> None:
        self._settings = settings
        self._catalog = catalog
        self._vhost = catalog.targets.rabbitmq.vhost
        self._client = client or httpx.Client(
            base_url=settings.rabbit_api_url,
            auth=(settings.rabbit_admin_user, settings.rabbit_admin_password),
            timeout=10.0,
        )

    def close(self) -> None:
        self._client.close()

    # ---- helpers ---------------------------------------------------------

    def setup(self) -> list[str]:
        self._client.put(f"/api/vhosts/{_q(self._vhost)}").raise_for_status()
        return [f"vhost {self._vhost} is ready"]

    def get_user(self, name: str) -> dict[str, Any] | None:
        response = self._client.get(f"/api/users/{_q(name)}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    def get_permissions(self, name: str) -> dict[str, str] | None:
        response = self._client.get(f"/api/permissions/{_q(self._vhost)}/{_q(name)}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        return {key: data[key] for key in PERMISSION_KEYS}

    @staticmethod
    def _managed_role(user: dict[str, Any]) -> str | None:
        tags = user.get("tags", [])
        if isinstance(tags, str):
            tags = [t for t in tags.split(",") if t]
        for tag in tags:
            if tag.startswith(TAG_PREFIX):
                return tag[len(TAG_PREFIX) :]
        return None

    def _set_permissions(self, subject: str, permissions: dict[str, str]) -> None:
        self._client.put(
            f"/api/permissions/{_q(self._vhost)}/{_q(subject)}", json=permissions
        ).raise_for_status()

    def _delete_user(self, subject: str) -> None:
        response = self._client.delete(f"/api/users/{_q(subject)}")
        if response.status_code != 404:
            response.raise_for_status()

    # ---- grant / revoke --------------------------------------------------

    def grant(self, subject: str, role_name: str, *, dry_run: bool) -> Outcome:
        desired = self._catalog.role(role_name).rabbitmq.model_dump()
        user = self.get_user(subject)
        perms_text = ", ".join(f"{k}={desired[k]!r}" for k in PERMISSION_KEYS)

        if user is not None:
            current = self._managed_role(user)
            if current is None:
                raise ConflictError(
                    f"RabbitMQ user '{subject}' exists but is not managed by AccessOps; "
                    "refusing to touch it."
                )
            if current != role_name:
                raise ConflictError(
                    f"'{subject}' already has role '{current}' in rabbitmq; revoke it first."
                )
            if self.get_permissions(subject) == desired:
                unchanged = [f"{subject} already has {role_name}"]
                return Outcome(self.system, False, role_name, unchanged)
            steps = [f"set permissions on vhost {self._vhost}: {perms_text}"]
            if not dry_run:
                self._set_permissions(subject, desired)
            return Outcome(self.system, True, role_name, steps)

        steps = [
            f"create user {subject} with a random password, tag {TAG_PREFIX}{role_name}",
            f"set permissions on vhost {self._vhost}: {perms_text}",
        ]
        if dry_run:
            return Outcome(self.system, True, role_name, steps)

        password = new_password()
        path = save_credentials(
            self._settings.credentials_dir,
            subject,
            self.system,
            {
                "amqp_port": str(self._settings.rabbit_amqp_port),
                "vhost": self._vhost,
                "user": subject,
                "password": password,
            },
        )
        try:
            self._client.put(
                f"/api/users/{_q(subject)}",
                json={"password": password, "tags": f"{TAG_PREFIX}{role_name}"},
            ).raise_for_status()
            self._set_permissions(subject, desired)
        except Exception:
            path.unlink(missing_ok=True)
            self._delete_user(subject)
            raise
        return Outcome(self.system, True, role_name, steps, path)

    def revoke(self, subject: str, *, dry_run: bool) -> Outcome:
        user = self.get_user(subject)
        if user is None:
            return Outcome(self.system, False, None, [f"{subject} does not exist"])
        role = self._managed_role(user)
        if role is None:
            raise ConflictError(
                f"RabbitMQ user '{subject}' exists but is not managed by AccessOps; "
                "refusing to touch it."
            )
        steps = [f"delete user {subject} (also closes its connections)"]
        if dry_run:
            return Outcome(self.system, True, role, steps)
        self._delete_user(subject)
        if delete_credentials(self._settings.credentials_dir, subject, self.system):
            steps.append("delete credentials file")
        return Outcome(self.system, True, role, steps)

    def inventory(self) -> Inventory:
        response = self._client.get("/api/users")
        response.raise_for_status()
        managed, foreign = [], []
        for user in response.json():
            role = self._managed_role(user)
            if role is None:
                foreign.append(user["name"])
            else:
                managed.append((user["name"], role))
        return Inventory(managed=sorted(managed), foreign=sorted(foreign))

    def list_assignments(self) -> list[tuple[str, str | None]]:
        return self.inventory().managed
