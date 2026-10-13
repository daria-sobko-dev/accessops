"""Reports over access_grants and the real systems. Pure functions: easy to test."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from accessops.catalog import Catalog
from accessops.grants import Grant
from accessops.outcome import Inventory
from accessops.ttl import format_remaining, format_time


@dataclass
class Report:
    title: str
    headers: list[str]
    rows: list[list[str]]


GRANT_HEADERS = [
    "subject", "system", "role", "privileged", "granted_at", "expires_at", "remaining",
    "ticket_id", "actor", "approved_by",
]  # fmt: skip


def _is_privileged(catalog: Catalog, role: str) -> bool:
    found = catalog.roles.get(role)
    # A role removed from the catalog is unknown: treat it as privileged to be safe.
    return found is None or found.privileged


def _grant_row(grant: Grant, catalog: Catalog, now: datetime) -> list[str]:
    return [
        grant.subject,
        grant.system,
        grant.role,
        "yes" if _is_privileged(catalog, grant.role) else "no",
        format_time(grant.granted_at),
        format_time(grant.expires_at),
        format_remaining(grant.expires_at, now),
        grant.ticket_id or "",
        grant.actor,
        grant.approved_by or "",
    ]


def access_report(grants: Sequence[Grant], catalog: Catalog, now: datetime) -> Report:
    rows = [_grant_row(g, catalog, now) for g in grants]
    return Report("Active access (source of truth: access_grants)", GRANT_HEADERS, rows)


def expiring_report(
    grants: Sequence[Grant], catalog: Catalog, now: datetime, within: timedelta
) -> Report:
    """Active temporary grants that expire within the window (overdue ones included)."""
    soon = [g for g in grants if g.expires_at is not None and g.expires_at <= now + within]
    soon.sort(key=lambda g: (g.expires_at, g.subject, g.system))
    rows = [_grant_row(g, catalog, now) for g in soon]
    return Report("Access expiring soon", GRANT_HEADERS, rows)


def privileged_report(grants: Sequence[Grant], catalog: Catalog, now: datetime) -> Report:
    rows = [_grant_row(g, catalog, now) for g in grants if _is_privileged(catalog, g.role)]
    return Report("Active privileged access", GRANT_HEADERS, rows)


DRIFT_HEADERS = ["category", "system", "subject", "expected_role", "actual_role", "meaning"]
DRIFT_MEANING = {
    "extra": "has the AccessOps marker but no active grant: revoke it or grant it properly",
    "missing": "active grant, but the user does not exist in the system: re-grant or revoke",
    "role_mismatch": "user exists with another role than access_grants says",
    "foreign": "not created by AccessOps: shown only, never touched",
}
_DRIFT_ORDER = {name: i for i, name in enumerate(DRIFT_MEANING)}


def compute_drift(
    grants: Sequence[Grant], inventories: dict[str, Inventory]
) -> list[tuple[str, str, str, str, str]]:
    """Compare expected (active grants) with actual (inventories) per system.

    Returns tuples (category, system, subject, expected_role, actual_role).
    """
    items = []
    for system, inventory in inventories.items():
        expected = {g.subject: g.role for g in grants if g.system == system}
        actual = {name: role or "" for name, role in inventory.managed}
        for subject, role in actual.items():
            if subject not in expected:
                items.append(("extra", system, subject, "", role))
            elif expected[subject] != role:
                items.append(("role_mismatch", system, subject, expected[subject], role))
        for subject, role in expected.items():
            if subject not in actual:
                items.append(("missing", system, subject, role, ""))
        items += [("foreign", system, name, "", "") for name in inventory.foreign]
    items.sort(key=lambda item: (_DRIFT_ORDER[item[0]], item[1], item[2]))
    return items


def drift_report(grants: Sequence[Grant], inventories: dict[str, Inventory]) -> Report:
    rows = [[*item, DRIFT_MEANING[item[0]]] for item in compute_drift(grants, inventories)]
    return Report("Drift: access_grants vs real systems", DRIFT_HEADERS, rows)


def write_csv(report: Report, path: Path) -> Path:
    """UTF-8 CSV with a header row: opens directly in Google Sheets (File > Import)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(report.headers)
        writer.writerows(report.rows)
    return path


def format_table(report: Report) -> str:
    if not report.rows:
        return f"{report.title}: nothing to show."
    headers = [h.upper() for h in report.headers]
    widths = [
        max(len(str(v)) for v in column) for column in zip(headers, *report.rows, strict=True)
    ]
    lines = [report.title, ""]
    for row in [headers, *report.rows]:
        lines.append("  ".join(str(v).ljust(w) for v, w in zip(row, widths, strict=True)).rstrip())
    lines.append(f"\n{len(report.rows)} row(s)")
    return "\n".join(lines)
