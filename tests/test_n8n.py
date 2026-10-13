"""n8n workflow file: placeholders, sanitizing and the secret check. No Docker needed."""

import json

import pytest

from accessops.n8n import (
    CHAT_PLACEHOLDER,
    WORKFLOWS_FILE,
    N8nError,
    credentials_payload,
    export,
    find_leaks,
    render_workflows,
    sanitize_export,
    setup,
)

ENV = {
    "ACCESSOPS_API_TOKEN": "api-token-" + "a" * 32,
    "TELEGRAM_BOT_TOKEN": "123456:bot-token-value",
    "TELEGRAM_CHAT_ID": "987654321",
    "POSTGRES_PASSWORD": "pg-password-value",
    "POSTGRES_PORT": "5433",
}


def template():
    return json.loads(WORKFLOWS_FILE.read_text(encoding="utf-8"))


def nodes_of(workflow, node_type):
    return [n for n in workflow["nodes"] if n["type"] == f"n8n-nodes-base.{node_type}"]


class FakeN8n:
    def __init__(self, exported=None):
        self.imports = []
        self.published = []
        self.restarted = False
        self.exported = exported or []

    def import_file(self, kind, content):
        self.imports.append((kind, json.loads(content)))

    def publish(self, workflow_id):
        self.published.append(workflow_id)

    def export_workflows(self):
        return self.exported

    def restart(self):
        self.restarted = True


def test_file_in_git_has_no_secrets_and_a_chat_placeholder():
    text = WORKFLOWS_FILE.read_text(encoding="utf-8")
    assert find_leaks(text, ENV) == []
    for workflow in template():
        assert [n["parameters"]["chatId"] for n in nodes_of(workflow, "telegram")] == [
            CHAT_PLACEHOLDER
        ]


def test_workflows_call_the_api_by_container_name_with_credentials():
    for workflow in template():
        for node in nodes_of(workflow, "httpRequest"):
            assert node["parameters"]["url"].startswith("http://accessops-api:8000/")
            assert node["credentials"]["httpHeaderAuth"]["id"] == "AccessOpsApiCred"
            # Errors of the call itself must reach the "Anything wrong?" step, not vanish.
            assert node["onError"] == "continueErrorOutput"


def test_schedules():
    cleanup, drift = sorted(template(), key=lambda w: w["id"])
    assert nodes_of(cleanup, "scheduleTrigger")[0]["parameters"]["rule"]["interval"] == [
        {"field": "minutes", "minutesInterval": 5}
    ]
    assert nodes_of(drift, "scheduleTrigger")[0]["parameters"]["rule"]["interval"] == [
        {"field": "hours", "hoursInterval": 1}
    ]
    assert nodes_of(drift, "manualTrigger")
    assert {w["settings"]["timezone"] for w in (cleanup, drift)} == {"Europe/Madrid"}


def test_render_then_sanitize_round_trip():
    rendered = render_workflows(template(), ENV["TELEGRAM_CHAT_ID"])
    assert all(
        n["parameters"]["chatId"] == "987654321" for w in rendered for n in nodes_of(w, "telegram")
    )
    # n8n adds runtime state on export: it must not reach git.
    exported = [
        w
        | {
            "active": True,
            "versionId": "v1",
            "staticData": {"global": {"foreign": ["linux:ubuntu"]}},
        }
        for w in rendered
    ] + [{"id": "SomeoneElsesFlow", "name": "other", "nodes": [], "connections": {}}]
    clean = sanitize_export(exported, ENV["TELEGRAM_CHAT_ID"])
    assert clean == sorted(template(), key=lambda w: w["id"])


def test_credentials_payload_holds_the_secrets_for_n8n_only():
    api, telegram = credentials_payload(ENV)
    assert api["type"] == "httpHeaderAuth"
    assert api["data"] == {"name": "Authorization", "value": f"Bearer {ENV['ACCESSOPS_API_TOKEN']}"}
    assert telegram["type"] == "telegramApi"
    assert telegram["data"]["accessToken"] == ENV["TELEGRAM_BOT_TOKEN"]


def test_setup_imports_publishes_and_restarts():
    n8n = FakeN8n()
    steps = setup(ENV, n8n)
    assert [kind for kind, _ in n8n.imports] == ["credentials", "workflow"]
    assert sorted(n8n.published) == ["AccessOpsCleanup", "AccessOpsDrift01"]
    assert n8n.restarted
    assert find_leaks("\n".join(steps), ENV) == []


def test_setup_needs_all_variables():
    env = {k: v for k, v in ENV.items() if k != "TELEGRAM_CHAT_ID"}
    with pytest.raises(Exception, match="TELEGRAM_CHAT_ID"):
        setup(env, FakeN8n())


def test_export_writes_clean_file(tmp_path):
    rendered = render_workflows(template(), ENV["TELEGRAM_CHAT_ID"])
    path = tmp_path / "accessops.json"
    export(ENV, FakeN8n(exported=rendered), path)
    assert json.loads(path.read_text()) == sorted(template(), key=lambda w: w["id"])


def test_export_refuses_a_file_with_a_secret(tmp_path):
    rendered = render_workflows(template(), ENV["TELEGRAM_CHAT_ID"])
    # Someone pasted the bot token straight into a node instead of using credentials.
    rendered[0]["nodes"][0]["parameters"]["note"] = ENV["TELEGRAM_BOT_TOKEN"]
    path = tmp_path / "accessops.json"
    with pytest.raises(N8nError, match="TELEGRAM_BOT_TOKEN") as error:
        export(ENV, FakeN8n(exported=rendered), path)
    assert ENV["TELEGRAM_BOT_TOKEN"] not in str(error.value)
    assert not path.exists()


def test_find_leaks_ignores_non_secret_values():
    assert find_leaks("port 5433", ENV) == []
    assert find_leaks("password pg-password-value", ENV) == ["POSTGRES_PASSWORD"]


def test_telegram_messages_use_escaped_html():
    # Names like ghost_user broke Markdown; HTML mode + escaping shows any name as is.
    for workflow in template():
        telegram = nodes_of(workflow, "telegram")[0]
        assert telegram["parameters"]["additionalFields"]["parse_mode"] == "HTML"
        code = nodes_of(workflow, "code")[0]["parameters"]["jsCode"]
        assert code.count("text: ") == code.count("text: html(")
