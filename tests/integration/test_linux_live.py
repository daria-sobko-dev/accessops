"""Linux integration tests: real ansible-playbook runs against linux-target.

Run with: pytest -m integration
"""

import secrets
import subprocess
from dataclasses import replace

import pytest

from accessops.audit import AuditLog
from accessops.catalog import load_catalog
from accessops.config import PROJECT_ROOT, load_settings
from accessops.grants import GrantStore
from accessops.linux import KNOWN_HOSTS, LinuxBackend
from accessops.service import AccessService

pytestmark = pytest.mark.integration
LINUX = ("linux",)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = replace(load_settings(), credentials_dir=tmp_path_factory.mktemp("credentials"))
    catalog = load_catalog(settings.catalog_path)
    audit = AuditLog(settings)
    audit.ensure_schema()
    linux = LinuxBackend(settings, catalog)
    linux.setup()
    grants = GrantStore(settings)
    grants.ensure_schema()
    service = AccessService(catalog, audit, {"linux": linux}, grants=grants)
    return service, linux, audit


@pytest.fixture
def subject(env):
    service, *_ = env
    name = f"it_{secrets.token_hex(4)}"
    yield name
    service.revoke(subject=name, actor="pytest", systems=LINUX)


def ssh(key, user, *command, options=()):
    return subprocess.run(
        [
            "ssh", "-p", "2222", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=5", *(["-i", str(key)] if key else []), *options,
            f"{user}@127.0.0.1", *command,
        ],
        capture_output=True, text=True, timeout=30,
    )  # fmt: skip


def on_server(*command):
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "linux-target", *command],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=30,
    )  # fmt: skip


def test_full_lifecycle(env, subject):
    service, linux, audit = env
    key = linux.key_path(subject)

    [first] = service.grant(subject=subject, role_name="developer", actor="pytest", systems=LINUX)
    assert first.changed and first.credentials_file == key
    assert key.stat().st_mode & 0o777 == 0o600

    # Logs in with the key; groups come from the catalog.
    result = ssh(key, subject, "whoami; id -nG; stat -c %a ~/.ssh ~/.ssh/authorized_keys")
    assert result.returncode == 0, result.stderr
    name, groups, ssh_dir_mode, keys_mode = result.stdout.split("\n")[:4]
    assert name == subject
    assert "developers" in groups.split()
    assert (ssh_dir_mode, keys_mode) == ("700", "600")

    # No password login, no sudo.
    no_password = ssh(
        None, subject, "whoami",
        options=("-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"),
    )  # fmt: skip
    assert no_password.returncode == 255
    assert "Permission denied (publickey)" in no_password.stderr
    assert ssh(key, subject, "sudo -n true").returncode != 0

    # Second run: Ansible reports changed=0.
    [second] = service.grant(subject=subject, role_name="developer", actor="pytest", systems=LINUX)
    assert not second.changed
    assert "changed=0" in second.steps[-1]

    # Revoke: cannot log in, user is gone, key files deleted.
    [revoked] = service.revoke(subject=subject, actor="pytest", systems=LINUX)
    assert revoked.changed and revoked.role == "developer"
    assert ssh(key.with_suffix(".gone"), subject, "true").returncode == 255
    assert on_server("getent", "passwd", subject).returncode == 2
    assert not key.exists()

    records = [r for r in audit.recent(10) if r["subject"] == subject]
    assert {(r["system"], r["result"]) for r in records} == {("linux", "success")}


def test_privileged_role_gets_sudo(env, subject):
    service, linux, _ = env
    service.grant(
        subject=subject, role_name="devops_admin", actor="pytest", approved_by="olga", ttl="1h",
        systems=LINUX,
    )  # fmt: skip
    result = ssh(linux.key_path(subject), subject, "sudo -n whoami")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "root"


def test_revoke_kills_active_session(env, subject):
    service, linux, _ = env
    service.grant(subject=subject, role_name="qa", actor="pytest", ttl="1h", systems=LINUX)
    session = subprocess.Popen(
        ["ssh", "-p", "2222", "-i", str(linux.key_path(subject)), "-o", "BatchMode=yes",
         "-o", "IdentitiesOnly=yes", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
         f"{subject}@127.0.0.1", "sleep 300"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        for _ in range(50):
            if on_server("pgrep", "-u", subject, "sleep").returncode == 0:
                break
            subprocess.run(["sleep", "0.1"])
        service.revoke(subject=subject, actor="pytest", systems=LINUX)
        assert session.wait(timeout=15) != 0
    finally:
        session.kill()


def test_dry_run_changes_nothing(env, subject):
    service, linux, _ = env
    [plan] = service.grant(
        subject=subject, role_name="developer", actor="pytest", systems=LINUX, dry_run=True
    )
    assert plan.changed
    assert on_server("getent", "passwd", subject).returncode == 2
    assert not linux.key_path(subject).exists()
