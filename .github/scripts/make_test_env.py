"""Write a throwaway .env for CI: fresh random secrets on every run, nothing from GitHub.

Each secret is registered with ::add-mask:: first, so GitHub hides it if it ever shows up
in a log. Values are never printed otherwise.
"""

import secrets
from pathlib import Path

SECRETS = ("POSTGRES_PASSWORD", "RABBITMQ_DEFAULT_PASS", "N8N_ENCRYPTION_KEY")
PLAIN = {
    "POSTGRES_USER": "accessops",
    "POSTGRES_DB": "accessops",
    "POSTGRES_PORT": "5433",
    "RABBITMQ_DEFAULT_USER": "accessops",
    "N8N_PORT": "5678",
    "GENERIC_TIMEZONE": "Europe/Madrid",
}

lines = ["# Generated in CI for one run. Not a real environment."]
lines += [f"{name}={value}" for name, value in PLAIN.items()]
for name in SECRETS:
    value = secrets.token_urlsafe(24)
    print(f"::add-mask::{value}")
    lines.append(f"{name}={value}")

env = Path(".env")
env.write_text("\n".join(lines) + "\n", encoding="utf-8")
env.chmod(0o600)
print(f"wrote .env with {len(PLAIN)} plain settings and {len(SECRETS)} random secrets")
