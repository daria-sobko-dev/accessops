"""Credential files: one file per user and system, readable only by the owner."""

from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path


def new_password() -> str:
    return secrets.token_urlsafe(24)


def credentials_path(directory: Path, subject: str, system: str) -> Path:
    return directory / f"{subject}-{system}.txt"


def save_credentials(directory: Path, subject: str, system: str, fields: dict[str, str]) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = credentials_path(directory, subject, system)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # The file may have existed with wider permissions: restrict before writing.
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for key, value in fields.items():
            handle.write(f"{key}={value}\n")
    return path


def read_credentials(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            result[key] = value
    return result


def delete_credentials(directory: Path, subject: str, system: str) -> bool:
    path = credentials_path(directory, subject, system)
    if path.exists():
        path.unlink()
        return True
    return False


def generate_ssh_key(private_path: Path, comment: str) -> Path:
    """Create an ed25519 key pair (private 600, .pub next to it). Returns the private path."""
    private_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(private_path.parent, 0o700)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(private_path)],
        check=True,
        capture_output=True,
    )
    os.chmod(private_path, 0o600)
    return private_path


def delete_ssh_key(private_path: Path) -> bool:
    existed = private_path.exists()
    private_path.unlink(missing_ok=True)
    private_path.with_name(private_path.name + ".pub").unlink(missing_ok=True)
    return existed
