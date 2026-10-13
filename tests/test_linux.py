"""LinuxBackend logic with a fake Ansible runner: no Docker needed."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from accessops.catalog import load_catalog
from accessops.config import load_settings
from accessops.errors import ConflictError, InvalidInputError
from accessops.linux import (
    LIST_TASK,
    NEW_KEY_PLACEHOLDER,
    STATE_TASK,
    AnsibleError,
    LinuxBackend,
    PlaybookRun,
    parse_playbook_output,
)

CATALOG = load_catalog(Path(__file__).resolve().parent.parent / "roles.yaml")


def ansible_output(tasks, changed=0):
    return json.dumps(
        {
            "plays": [{"tasks": [{"task": {"name": n}, "hosts": {"h": r}} for n, r in tasks]}],
            "stats": {"h": {"ok": len(tasks), "changed": changed, "failures": 0}},
        }
    )


def test_parse_counts_changed_tasks_and_messages():
    run = parse_playbook_output(
        ansible_output(
            [
                ("Create user", {"changed": True}),
                ("Install key", {"changed": False}),
                (STATE_TASK, {"changed": False, "msg": "developer"}),
            ],
            changed=1,
        )
    )
    assert run.changed_tasks == ["Create user"]
    assert run.messages[STATE_TASK] == "developer"
    assert "changed=1" in run.recap()


def test_parse_refuse_task_is_conflict():
    output = ansible_output([("Refuse a second role", {"failed": True, "msg": "has role qa"})])
    with pytest.raises(ConflictError, match="has role qa"):
        parse_playbook_output(output)


def test_parse_other_failure_and_unreachable():
    with pytest.raises(AnsibleError, match="task 'Create user' failed: boom"):
        parse_playbook_output(ansible_output([("Create user", {"failed": True, "msg": "boom"})]))
    with pytest.raises(AnsibleError, match="unreachable"):
        parse_playbook_output(ansible_output([("Gather", {"unreachable": True, "msg": "x"})]))


def test_parse_rejects_non_json():
    with pytest.raises(AnsibleError, match="not JSON"):
        parse_playbook_output("PLAY [all] ****")


class FakeRunner:
    def __init__(self, run=None):
        self.calls = []
        self.result = run or PlaybookRun(stats={"changed": 0})

    def run(self, extra_vars, *, check):
        self.calls.append((extra_vars, check))
        return self.result


@pytest.fixture
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("POSTGRES_USER", "u")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p")
    monkeypatch.setenv("POSTGRES_DB", "d")
    monkeypatch.setenv("RABBITMQ_DEFAULT_USER", "u")
    monkeypatch.setenv("RABBITMQ_DEFAULT_PASS", "p")
    settings = replace(load_settings(tmp_path / "no.env"), credentials_dir=tmp_path / "creds")
    runner = FakeRunner()
    return LinuxBackend(settings, CATALOG, runner), runner, settings


def test_grant_passes_catalog_groups_and_sudo(backend):
    linux, runner, settings = backend
    outcome = linux.grant("boris", "devops_admin", dry_run=False)
    extra_vars, check = runner.calls[0]
    assert check is False
    assert extra_vars["linux_groups"] == ["devops", "developers"]
    assert extra_vars["sudo"] is True
    assert extra_vars["public_key"].startswith("ssh-ed25519 ")
    key = settings.credentials_dir / "boris-linux_ed25519"
    assert outcome.credentials_file == key
    assert key.stat().st_mode & 0o777 == 0o600


def test_non_privileged_role_never_gets_sudo(backend):
    linux, runner, _ = backend
    linux.grant("anna", "developer", dry_run=False)
    assert runner.calls[0][0]["sudo"] is False


def test_dry_run_uses_check_mode_and_creates_no_key(backend):
    linux, runner, settings = backend
    outcome = linux.grant("anna", "developer", dry_run=True)
    extra_vars, check = runner.calls[0]
    assert check is True
    assert extra_vars["public_key"] == NEW_KEY_PLACEHOLDER
    assert not (settings.credentials_dir / "anna-linux_ed25519").exists()
    assert outcome.steps[0].startswith("would: generate SSH key")


def test_repeat_grant_reuses_existing_key(backend):
    linux, runner, _ = backend
    linux.grant("anna", "developer", dry_run=False)
    second = linux.grant("anna", "developer", dry_run=False)
    assert runner.calls[0][0]["public_key"] == runner.calls[1][0]["public_key"]
    assert second.credentials_file is None


def test_failed_playbook_removes_new_key(backend):
    linux, runner, settings = backend

    def boom(extra_vars, *, check):
        raise AnsibleError("boom")

    runner.run = boom
    with pytest.raises(AnsibleError):
        linux.grant("anna", "developer", dry_run=False)
    assert not (settings.credentials_dir / "anna-linux_ed25519").exists()


def test_revoke_reports_previous_role(backend):
    linux, runner, _ = backend
    runner.result = PlaybookRun(stats={"changed": 3}, messages={STATE_TASK: "qa"})
    outcome = linux.revoke("anna", dry_run=False)
    assert outcome.role == "qa" and outcome.changed


def test_inventory_parses_json_message(backend):
    linux, runner, _ = backend
    message = ' {"managed": [["boris", "devops_admin"]], "foreign": ["ubuntu", "ansible"]}'
    runner.result = PlaybookRun(stats={}, messages={LIST_TASK: message})
    inventory = linux.inventory()
    assert inventory.managed == [("boris", "devops_admin")]
    assert inventory.foreign == ["ansible", "ubuntu"]
    assert linux.list_assignments() == [("boris", "devops_admin")]


def test_too_long_name_for_linux(backend):
    linux, _, _ = backend
    with pytest.raises(InvalidInputError, match="too long for Linux"):
        linux.grant("a" * 33, "developer", dry_run=True)
