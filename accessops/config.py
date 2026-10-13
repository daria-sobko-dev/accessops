"""Runtime settings loaded from environment variables and .env."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

from accessops.errors import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    pg_host: str
    pg_port: int
    pg_admin_user: str
    pg_admin_password: str = field(repr=False)
    pg_admin_db: str
    rabbit_api_url: str
    rabbit_amqp_port: int
    rabbit_admin_user: str
    rabbit_admin_password: str = field(repr=False)
    catalog_path: Path
    credentials_dir: Path


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Environment variable {name} is not set (see .env.example).")
    return value


def load_settings(env_file: Path | None = None) -> Settings:
    load_dotenv(env_file or PROJECT_ROOT / ".env")
    return Settings(
        pg_host=os.environ.get("POSTGRES_HOST", "localhost"),
        pg_port=int(os.environ.get("POSTGRES_PORT", "5433")),
        pg_admin_user=_require("POSTGRES_USER"),
        pg_admin_password=_require("POSTGRES_PASSWORD"),
        pg_admin_db=_require("POSTGRES_DB"),
        rabbit_api_url=os.environ.get("RABBITMQ_API_URL", "http://localhost:15672"),
        rabbit_amqp_port=int(os.environ.get("RABBITMQ_AMQP_PORT", "5672")),
        rabbit_admin_user=_require("RABBITMQ_DEFAULT_USER"),
        rabbit_admin_password=_require("RABBITMQ_DEFAULT_PASS"),
        catalog_path=Path(os.environ.get("ACCESSOPS_CATALOG", PROJECT_ROOT / "roles.yaml")),
        credentials_dir=Path(
            os.environ.get("ACCESSOPS_CREDENTIALS_DIR", PROJECT_ROOT / ".credentials")
        ),
    )
