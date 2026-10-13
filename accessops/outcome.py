"""Results of operations in one system."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Outcome:
    system: str
    changed: bool
    role: str | None
    steps: list[str] = field(default_factory=list)
    credentials_file: Path | None = None
    expires_at: datetime | None = None


@dataclass
class Inventory:
    """What really exists in a system right now."""

    # Users created by AccessOps (carry its marker) and their role.
    managed: list[tuple[str, str | None]]
    # Login accounts without the AccessOps marker. Reported, never touched.
    foreign: list[str]
