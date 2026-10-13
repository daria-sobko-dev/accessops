"""accessops-api with fake jobs: tokens, responses, busy and errors. No Docker needed."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from accessops.api import create_app
from accessops.errors import BusyError, ConfigError
from accessops.grants import Grant
from accessops.service import CleanupItem

TOKEN = "t" * 40
NOW = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)


def grant(subject, system, role="qa"):
    return Grant(
        1, subject, system, role, None, "ivan", None, NOW - timedelta(hours=1),
        NOW - timedelta(minutes=1), "active", None, None,
    )  # fmt: skip


class FakeJobs:
    def __init__(self):
        self.cleanup_items = []
        self.drift_rows = []
        self.cleanup_error = None
        self.cleanup_calls = 0

    def cleanup(self):
        self.cleanup_calls += 1
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return self.cleanup_items

    def drift(self):
        return self.drift_rows


@pytest.fixture
def jobs():
    return FakeJobs()


@pytest.fixture
def client(jobs):
    app = create_app(TOKEN, jobs, clock=lambda: NOW)
    return TestClient(app, raise_server_exceptions=False)


AUTH = {"Authorization": f"Bearer {TOKEN}"}


# ---- tokens ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},  # no token at all
        {"Authorization": "Bearer wrong-token"},
        {"Authorization": f"Bearer {TOKEN}x"},  # almost right is still wrong
        {"Authorization": f"Basic {TOKEN}"},  # wrong scheme
        {"Authorization": TOKEN},  # no scheme
    ],
)
@pytest.mark.parametrize(("method", "path"), [("post", "/cleanup"), ("get", "/drift")])
def test_without_valid_token_is_401_and_runs_nothing(client, jobs, headers, method, path):
    response = client.request(method, path, headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {"detail": "Missing or invalid token."}
    assert jobs.cleanup_calls == 0


def test_health_needs_no_token_and_shows_nothing(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "detail": ""}


def test_api_docs_are_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


@pytest.mark.parametrize("token", ["", "short"])
def test_short_or_missing_server_token_refuses_to_start(jobs, token):
    with pytest.raises(ConfigError, match="at least 32"):
        create_app(token, jobs)


# ---- /cleanup -------------------------------------------------------------------------


def test_cleanup_with_token_reports_revoked(client, jobs):
    jobs.cleanup_items = [CleanupItem(grant("carl", "postgres"), "revoked", ["drop role"])]
    response = client.post("/cleanup", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["errors"] == []
    assert [(g["subject"], g["system"]) for g in body["revoked"]] == [("carl", "postgres")]
    assert jobs.cleanup_calls == 1


def test_cleanup_with_nothing_to_do(client):
    body = client.post("/cleanup", headers=AUTH).json()
    assert body == {
        "status": "ok",
        "checked_at": "2026-10-13T09:00:00Z",
        "revoked": [],
        "errors": [],
    }


def test_cleanup_partial_failure_is_reported(client, jobs):
    jobs.cleanup_items = [
        CleanupItem(grant("carl", "postgres"), "revoked", []),
        CleanupItem(grant("carl", "rabbitmq"), "error", ["RuntimeError: connection refused"]),
    ]
    body = client.post("/cleanup", headers=AUTH).json()
    assert body["status"] == "failed"
    assert body["errors"][0]["system"] == "rabbitmq"
    assert body["errors"][0]["error"] == "RuntimeError: connection refused"


def test_cleanup_already_running_is_409(client, jobs):
    jobs.cleanup_error = BusyError("Another cleanup is already running; this one was skipped.")
    response = client.post("/cleanup", headers=AUTH)
    assert response.status_code == 409
    assert response.json()["status"] == "busy"


def test_unexpected_error_is_500_without_internals(client, jobs):
    jobs.cleanup_error = KeyError("secret-looking-detail")
    response = client.post("/cleanup", headers=AUTH)
    assert response.status_code == 500
    assert response.json() == {"status": "error", "detail": "KeyError"}


def test_get_is_not_allowed_on_cleanup(client):
    # Changing things needs POST: a link opened by accident must not revoke access.
    assert client.get("/cleanup", headers=AUTH).status_code == 405


# ---- /drift ---------------------------------------------------------------------------


def test_drift_splits_problems_and_foreign(client, jobs):
    jobs.drift_rows = [
        ("extra", "rabbitmq", "ghost", "", "analyst"),
        ("missing", "linux", "carl", "qa", ""),
        ("role_mismatch", "postgres", "dina", "qa", "analyst"),
        ("foreign", "linux", "ubuntu", "", ""),
    ]
    response = client.get("/drift", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert [(p["category"], p["subject"]) for p in body["problems"]] == [
        ("extra", "ghost"),
        ("missing", "carl"),
        ("role_mismatch", "dina"),
    ]
    assert body["foreign"] == [{"system": "linux", "subject": "ubuntu"}]
    assert body["checked_at"] == "2026-10-13T09:00:00Z"


# ---- api-bootstrap --------------------------------------------------------------------


def test_bootstrap_creates_token_once_and_encodes_key(tmp_path):
    import base64

    from accessops.api import bootstrap_secrets
    from accessops.envfile import read_env

    env, key = tmp_path / ".env", tmp_path / "ansible_ed25519"
    env.write_text("POSTGRES_USER=admin\n")
    key.write_bytes(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"
    )

    steps = bootstrap_secrets(env, key)
    values = read_env(env)
    token = values["ACCESSOPS_API_TOKEN"]
    assert len(token) >= 32
    assert base64.b64decode(values["ANSIBLE_SSH_PRIVATE_KEY_B64"]) == key.read_bytes()
    assert values["POSTGRES_USER"] == "admin"
    assert env.stat().st_mode & 0o777 == 0o600
    assert not any(token in step for step in steps)  # secrets are never in the output

    bootstrap_secrets(env, key)  # second run keeps the token: n8n has a copy of it
    assert read_env(env)["ACCESSOPS_API_TOKEN"] == token
    bootstrap_secrets(env, key, rotate=True)
    assert read_env(env)["ACCESSOPS_API_TOKEN"] != token


def test_bootstrap_needs_the_service_key(tmp_path):
    from accessops.api import bootstrap_secrets

    with pytest.raises(ConfigError, match="ssh-bootstrap"):
        bootstrap_secrets(tmp_path / ".env", tmp_path / "missing")
