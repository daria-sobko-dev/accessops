"""Small helpers for the local .env file. Values are never printed."""

from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values

from accessops.config import PROJECT_ROOT

ENV_FILE = PROJECT_ROOT / ".env"


def read_env(path: Path = ENV_FILE) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


def set_env_var(path: Path, name: str, value: str, comment: str) -> None:
    """Replace or append NAME="value" without touching other lines. The file stays 600."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    entry = f'{name}="{value}"'
    for i, line in enumerate(lines):
        if line.startswith(f"{name}="):
            lines[i] = entry
            break
    else:
        lines += ["", f"# {comment}", entry]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
