"""Load the AccessOps workflows into n8n and export them back, without secrets.

Secrets (API token, bot token) go only into n8n's encrypted credential store; the workflow
JSON refers to credentials by id. The chat id lives in .env: the file in git holds a
placeholder that is filled in on import and put back on export.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from accessops.config import PROJECT_ROOT
from accessops.errors import AccessOpsError, ConfigError

WORKFLOWS_FILE = PROJECT_ROOT / "n8n" / "workflows" / "accessops.json"
CHAT_PLACEHOLDER = "__TELEGRAM_CHAT_ID__"
API_CREDENTIAL = {"id": "AccessOpsApiCred", "name": "AccessOps API token"}
TELEGRAM_CREDENTIAL = {"id": "AccessOpsTgCred1", "name": "AccessOps Telegram bot"}
REQUIRED_VARS = ("ACCESSOPS_API_TOKEN", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")
# Workflow fields worth keeping in git; the rest is n8n runtime state (versions, dates,
# static data with remembered account names, sharing).
EXPORT_FIELDS = ("id", "name", "nodes", "connections", "settings")
# .env variables whose values must never appear in an exported file.
SECRET_NAME = re.compile(r"(PASS|PASSWORD|KEY|TOKEN|SECRET|_B64|CHAT_ID)$")


class N8nError(AccessOpsError):
    """An n8n CLI command failed."""


def secret_values(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if SECRET_NAME.search(k) and len(v) >= 6}


def find_leaks(text: str, env: dict[str, str]) -> list[str]:
    """Names (never values) of secret .env variables whose value appears in text."""
    return sorted(name for name, value in secret_values(env).items() if value in text)


def _telegram_nodes(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [n for n in workflow["nodes"] if n["type"] == "n8n-nodes-base.telegram"]


def render_workflows(template: list[dict[str, Any]], chat_id: str) -> list[dict[str, Any]]:
    """Template from git -> workflows for n8n: the real chat id, inactive until published."""
    workflows = copy.deepcopy(template)
    for workflow in workflows:
        for node in _telegram_nodes(workflow):
            if node["parameters"].get("chatId") == CHAT_PLACEHOLDER:
                node["parameters"]["chatId"] = chat_id
        workflow["active"] = False
    return workflows


def sanitize_export(exported: list[dict[str, Any]], chat_id: str) -> list[dict[str, Any]]:
    """Workflows from n8n -> template for git: only our workflows, no state, no chat id."""
    ours = {"AccessOpsCleanup", "AccessOpsDrift01"}
    result = []
    for workflow in sorted(exported, key=lambda w: w["id"]):
        if workflow["id"] not in ours:
            continue
        clean = {key: copy.deepcopy(workflow[key]) for key in EXPORT_FIELDS if key in workflow}
        for node in _telegram_nodes(clean):
            if node["parameters"].get("chatId") == chat_id:
                node["parameters"]["chatId"] = CHAT_PLACEHOLDER
        result.append(clean)
    return result


def dump(workflows: list[dict[str, Any]]) -> str:
    return json.dumps(workflows, indent=2, ensure_ascii=False) + "\n"


def credentials_payload(env: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            **API_CREDENTIAL,
            "type": "httpHeaderAuth",
            "data": {"name": "Authorization", "value": f"Bearer {env['ACCESSOPS_API_TOKEN']}"},
        },
        {
            **TELEGRAM_CREDENTIAL,
            "type": "telegramApi",
            "data": {
                "accessToken": env["TELEGRAM_BOT_TOKEN"],
                "baseUrl": "https://api.telegram.org",
            },
        },
    ]


def require_vars(env: dict[str, str]) -> None:
    missing = [name for name in REQUIRED_VARS if not env.get(name)]
    if missing:
        raise ConfigError(
            f"Missing in .env: {', '.join(missing)} (see api-bootstrap and telegram-setup)."
        )


class N8nContainer:
    """Runs the n8n CLI inside the n8n container. Input files exist there only briefly."""

    def _exec(self, script: str, stdin: str | None = None) -> str:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "n8n", "sh", "-c", script],
            cwd=PROJECT_ROOT, input=stdin, capture_output=True, text=True, timeout=300,
        )  # fmt: skip
        if proc.returncode != 0:
            # n8n prints its own log lines; show the last ones, they never hold our input.
            tail = " ".join((proc.stderr or proc.stdout).strip().splitlines()[-3:])
            raise N8nError(f"n8n command failed (rc={proc.returncode}): {tail}")
        return proc.stdout

    def import_file(self, kind: str, content: str) -> None:
        # umask 077 + rm: the file with secrets is private and removed even on failure.
        self._exec(
            'umask 077; f=$(mktemp); trap \'rm -f "$f"\' EXIT; cat > "$f"; '
            f'n8n import:{kind} --input="$f" >/dev/null',
            stdin=content,
        )

    def publish(self, workflow_id: str) -> None:
        self._exec(f"n8n publish:workflow --id={workflow_id} >/dev/null")

    def export_workflows(self) -> list[dict[str, Any]]:
        out = self._exec(
            "f=$(mktemp); trap 'rm -f \"$f\"' EXIT; "
            'n8n export:workflow --all --output="$f" >/dev/null && cat "$f"'
        )
        return json.loads(out)

    def restart(self) -> None:
        subprocess.run(
            ["docker", "compose", "restart", "n8n"],
            cwd=PROJECT_ROOT, capture_output=True, check=True, timeout=120,
        )  # fmt: skip


def setup(env: dict[str, str], n8n: N8nContainer, path: Path = WORKFLOWS_FILE) -> list[str]:
    require_vars(env)
    template = json.loads(path.read_text(encoding="utf-8"))
    n8n.import_file("credentials", json.dumps(credentials_payload(env)))
    steps = [
        f"credentials '{API_CREDENTIAL['name']}' and '{TELEGRAM_CREDENTIAL['name']}' "
        "saved in n8n (encrypted)"
    ]
    workflows = render_workflows(template, env["TELEGRAM_CHAT_ID"])
    n8n.import_file("workflow", json.dumps(workflows))
    for workflow in workflows:
        n8n.publish(workflow["id"])
        steps.append(f"workflow '{workflow['name']}' imported and published")
    n8n.restart()
    steps.append("n8n restarted: the schedules are running")
    return steps


def export(env: dict[str, str], n8n: N8nContainer, path: Path = WORKFLOWS_FILE) -> list[str]:
    require_vars(env)
    workflows = sanitize_export(n8n.export_workflows(), env["TELEGRAM_CHAT_ID"])
    if not workflows:
        raise N8nError("No AccessOps workflows in n8n: run python -m accessops n8n-setup first.")
    text = dump(workflows)
    leaks = find_leaks(text, env)
    if leaks:
        raise N8nError(f"Export refused: it contains values of {', '.join(leaks)}.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    names = ", ".join(w["name"] for w in workflows)
    return [f"exported {len(workflows)} workflow(s): {names}", "checked: no .env secrets inside"]
