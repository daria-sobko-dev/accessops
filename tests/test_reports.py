"""Reports and drift logic with fake data: no Docker needed."""

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path

from accessops.catalog import load_catalog
from accessops.grants import Grant
from accessops.outcome import Inventory
from accessops.reports import (
    access_report,
    compute_drift,
    drift_report,
    expiring_report,
    format_table,
    privileged_report,
    write_csv,
)

CATALOG = load_catalog(Path(__file__).resolve().parent.parent / "roles.yaml")
NOW = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)


def grant(subject, system, role, expires_in=None):
    expires_at = NOW + expires_in if expires_in is not None else None
    granted_at = NOW - timedelta(days=1)
    return Grant(
        1, subject, system, role, "ACC-1", "ivan", None, granted_at, expires_at,
        "active", None, None,
    )  # fmt: skip


def test_access_report_shows_expiry():
    report = access_report(
        [grant("anna", "postgres", "developer"), grant("carl", "linux", "qa", timedelta(hours=2))],
        CATALOG,
        NOW,
    )
    by_subject = {row[0]: dict(zip(report.headers, row, strict=True)) for row in report.rows}
    assert by_subject["anna"]["expires_at"] == "never"
    assert by_subject["anna"]["remaining"] == "permanent"
    # 11:00 UTC is 13:00 in Madrid (summer time, CEST = UTC+2).
    assert by_subject["carl"]["expires_at"] == "2026-10-13 13:00 CEST"
    assert by_subject["carl"]["remaining"] == "2h"


def test_expiring_report_window_and_overdue():
    grants = [
        grant("anna", "postgres", "developer"),  # permanent: never in the report
        grant("carl", "linux", "qa", timedelta(hours=2)),
        grant("dina", "linux", "qa", timedelta(days=3)),  # outside 24h
        grant("eve", "linux", "qa", timedelta(minutes=-5)),  # overdue, not cleaned yet
    ]
    report = expiring_report(grants, CATALOG, NOW, timedelta(hours=24))
    assert [row[0] for row in report.rows] == ["eve", "carl"]
    assert report.rows[0][6] == "overdue 5m"


def test_privileged_report():
    grants = [
        grant("anna", "postgres", "developer"),
        grant("boris", "linux", "devops_admin", timedelta(hours=4)),
        grant("old", "linux", "removed_role"),  # unknown role: treated as privileged
    ]
    report = privileged_report(grants, CATALOG, NOW)
    assert [row[0] for row in report.rows] == ["boris", "old"]


def test_drift_categories():
    grants = [
        grant("anna", "rabbitmq", "developer"),  # ok
        grant("carl", "rabbitmq", "qa"),  # missing in system
        grant("dina", "rabbitmq", "qa"),  # role mismatch
        grant("anna", "linux", "developer"),  # ok
    ]
    inventories = {
        "rabbitmq": Inventory(
            managed=[("anna", "developer"), ("dina", "analyst"), ("ghost", "analyst")],
            foreign=["accessops", "manual_user"],
        ),
        "linux": Inventory(managed=[("anna", "developer")], foreign=["ubuntu"]),
    }
    assert compute_drift(grants, inventories) == [
        ("extra", "rabbitmq", "ghost", "", "analyst"),
        ("missing", "rabbitmq", "carl", "qa", ""),
        ("role_mismatch", "rabbitmq", "dina", "qa", "analyst"),
        ("foreign", "linux", "ubuntu", "", ""),
        ("foreign", "rabbitmq", "accessops", "", ""),
        ("foreign", "rabbitmq", "manual_user", "", ""),
    ]


def test_no_drift_when_everything_matches():
    grants = [grant("anna", "postgres", "developer")]
    inventories = {"postgres": Inventory(managed=[("anna", "developer")], foreign=[])}
    assert compute_drift(grants, inventories) == []
    assert "nothing to show" in format_table(drift_report(grants, inventories))


def test_write_csv(tmp_path):
    report = access_report([grant("anna", "postgres", "developer")], CATALOG, NOW)
    path = write_csv(report, tmp_path / "reports" / "access.csv")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == report.headers
    assert rows[1][:3] == ["anna", "postgres", "developer"]


def test_format_table_aligns_columns():
    report = access_report([grant("anna", "postgres", "developer")], CATALOG, NOW)
    text = format_table(report)
    assert text.splitlines()[2].startswith("SUBJECT")
    assert "1 row(s)" in text
