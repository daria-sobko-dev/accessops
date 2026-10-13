"""Linux access on linux-target via ansible-playbook (ansible/users.yml).

Python validates the request and reads the catalog; Ansible applies it on the server.
Dry run = `ansible-playbook --check`: Ansible reports what it would change, changes nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from accessops.catalog import Catalog
from accessops.config import PROJECT_ROOT, Settings
from accessops.credentials import delete_ssh_key, generate_ssh_key
from accessops.envfile import ENV_FILE, set_env_var
from accessops.errors import AccessOpsError, ConflictError, InvalidInputError
from accessops.outcome import Inventory, Outcome

PLAYBOOK = PROJECT_ROOT / "ansible" / "users.yml"
ANSIBLE_CONFIG = PROJECT_ROOT / "ansible.cfg"
SERVICE_KEY = PROJECT_ROOT / ".credentials" / "ansible_ed25519"
ENV_KEY_VAR = "ANSIBLE_AUTHORIZED_KEY"
KNOWN_HOSTS = PROJECT_ROOT / ".credentials" / "known_hosts"
MAX_LINUX_NAME = 32
# Used only in dry run when the user's key does not exist yet.
NEW_KEY_PLACEHOLDER = "ssh-ed25519 AAAA-new-key-will-be-generated accessops"

STATE_TASK = "Report previous role"
LIST_TASK = "Report managed users"


class AnsibleError(AccessOpsError):
    """ansible-playbook failed or returned unreadable output."""


@dataclass
class PlaybookRun:
    stats: dict[str, int]
    changed_tasks: list[str] = field(default_factory=list)
    messages: dict[str, Any] = field(default_factory=dict)

    def recap(self) -> str:
        keys = ("ok", "changed", "unreachable", "failures", "skipped")
        return "ansible: " + " ".join(f"{k}={self.stats.get(k, 0)}" for k in keys)


def parse_playbook_output(stdout: str) -> PlaybookRun:
    """Read the output of the accessops_json stdout callback. Failed tasks raise errors."""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        raise AnsibleError("ansible-playbook returned output that is not JSON.") from None
    stats = next(iter(data.get("stats", {}).values()), {})
    run = PlaybookRun(stats=stats)
    for play in data.get("plays", []):
        for task in play.get("tasks", []):
            name = task["task"]["name"]
            for result in task.get("hosts", {}).values():
                if result.get("unreachable"):
                    raise AnsibleError(f"linux-target is unreachable: {result.get('msg', '')}")
                if result.get("failed"):
                    message = result.get("msg") or result.get("stderr") or "unknown error"
                    if name.startswith("Refuse"):
                        raise ConflictError(message)
                    raise AnsibleError(f"Ansible task '{name}' failed: {message}")
                if result.get("changed"):
                    run.changed_tasks.append(name)
                if name in (STATE_TASK, LIST_TASK) and "msg" in result:
                    run.messages[name] = result["msg"]
    return run


class AnsibleRunner:
    def run(self, extra_vars: dict[str, Any], *, check: bool) -> PlaybookRun:
        env = os.environ | {
            "ANSIBLE_CONFIG": str(ANSIBLE_CONFIG),
            "ANSIBLE_STDOUT_CALLBACK": "accessops_json",
            "ANSIBLE_NOCOLOR": "1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            vars_file = Path(tmp) / "vars.json"
            vars_file.write_text(json.dumps(extra_vars), encoding="utf-8")
            command = [
                str(Path(sys.executable).parent / "ansible-playbook"),
                str(PLAYBOOK),
                "--extra-vars",
                f"@{vars_file}",
            ]
            if check:
                command.append("--check")
            proc = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=300,
            )
        if not proc.stdout.strip():
            tail = proc.stderr.strip().splitlines()[-3:]
            raise AnsibleError(f"ansible-playbook failed (rc={proc.returncode}): {' '.join(tail)}")
        return parse_playbook_output(proc.stdout)


def bootstrap_service_key() -> list[str]:
    """Create the Ansible service key and publish its public half for linux-target."""
    rel = SERVICE_KEY.relative_to(PROJECT_ROOT)
    if SERVICE_KEY.exists():
        steps = [f"service key {rel} already exists"]
    else:
        generate_ssh_key(SERVICE_KEY, "ansible@accessops")
        steps = [f"created service key {rel}"]
    public = SERVICE_KEY.with_name(SERVICE_KEY.name + ".pub").read_text(encoding="utf-8").strip()
    set_env_var(
        ENV_FILE, ENV_KEY_VAR, public,
        "Public key of the Ansible service account (written by ssh-bootstrap)",
    )  # fmt: skip
    steps += [
        f"public key written to .env as {ENV_KEY_VAR}",
        "next: docker compose up -d --force-recreate linux-target",
    ]
    return steps


class LinuxBackend:
    system = "linux"

    def __init__(
        self, settings: Settings, catalog: Catalog, runner: AnsibleRunner | None = None
    ) -> None:
        self._settings = settings
        self._catalog = catalog
        self._runner = runner or AnsibleRunner()

    def key_path(self, subject: str) -> Path:
        return self._settings.credentials_dir / f"{subject}-linux_ed25519"

    @staticmethod
    def _check_name(subject: str) -> None:
        if len(subject) > MAX_LINUX_NAME:
            raise InvalidInputError(
                f"User name '{subject}' is too long for Linux (max {MAX_LINUX_NAME})."
            )

    @staticmethod
    def _steps(run: PlaybookRun, dry_run: bool) -> list[str]:
        prefix = "would: " if dry_run else ""
        return [f"{prefix}{task}" for task in run.changed_tasks] + [run.recap()]

    def setup(self) -> list[str]:
        self._runner.run({"access_action": "list"}, check=False)
        return ["ssh to linux-target as 'ansible' with sudo works"]

    def grant(self, subject: str, role_name: str, *, dry_run: bool) -> Outcome:
        self._check_name(subject)
        linux = self._catalog.role(role_name).linux
        key = self.key_path(subject)
        created_key: Path | None = None
        if key.exists():
            public_key = key.with_name(key.name + ".pub").read_text(encoding="utf-8").strip()
        elif dry_run:
            public_key = NEW_KEY_PLACEHOLDER
        else:
            created_key = generate_ssh_key(key, f"{subject}@accessops")
            public_key = key.with_name(key.name + ".pub").read_text(encoding="utf-8").strip()

        extra_vars = {
            "access_action": "grant",
            "subject": subject,
            "role_name": role_name,
            "linux_groups": linux.groups,
            "sudo": linux.sudo,
            "public_key": public_key,
        }
        try:
            run = self._runner.run(extra_vars, check=dry_run)
        except Exception:
            if created_key is not None:
                delete_ssh_key(created_key)
            raise
        changed = bool(run.stats.get("changed", 0))
        steps = self._steps(run, dry_run)
        if dry_run and not key.exists():
            steps.insert(0, f"would: generate SSH key {key.name}")
        return Outcome(self.system, changed, role_name, steps, created_key)

    def revoke(self, subject: str, *, dry_run: bool) -> Outcome:
        self._check_name(subject)
        run = self._runner.run({"access_action": "revoke", "subject": subject}, check=dry_run)
        role = run.messages.get(STATE_TASK) or None
        changed = bool(run.stats.get("changed", 0))
        steps = self._steps(run, dry_run)
        if not changed and role is None:
            steps.insert(0, f"{subject} does not exist")
        if not dry_run and delete_ssh_key(self.key_path(subject)):
            steps.append("delete SSH key files")
        return Outcome(self.system, changed, role, steps)

    def inventory(self) -> Inventory:
        run = self._runner.run({"access_action": "list"}, check=False)
        raw = run.messages.get(LIST_TASK, "{}")
        data = json.loads(raw) if isinstance(raw, str) else raw
        managed = sorted((name, role or None) for name, role in data.get("managed", []))
        return Inventory(managed=managed, foreign=sorted(data.get("foreign", [])))

    def list_assignments(self) -> list[tuple[str, str | None]]:
        return self.inventory().managed
