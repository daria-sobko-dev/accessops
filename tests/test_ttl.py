from datetime import UTC, datetime, timedelta

import pytest

from accessops.ttl import format_duration, format_remaining, format_time, parse_ttl


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30m", timedelta(minutes=30)),
        ("8h", timedelta(hours=8)),
        ("3d", timedelta(days=3)),
        (" 2m ", timedelta(minutes=2)),
        ("9999d", timedelta(days=9999)),
    ],
)
def test_parse_valid(text, expected):
    assert parse_ttl(text) == expected


@pytest.mark.parametrize(
    "text", ["", "0m", "30", "m", "1w", "1.5h", "-1h", "1h30m", "8H", "10000d", "forever"]
)
def test_parse_invalid(text):
    with pytest.raises(ValueError, match="invalid duration"):
        parse_ttl(text)


def test_parse_rejects_non_string():
    with pytest.raises(ValueError):
        parse_ttl(30)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (timedelta(0), "0m"),
        (timedelta(minutes=45), "45m"),
        (timedelta(hours=24), "1d"),
        (timedelta(days=1, hours=2, minutes=5), "1d 2h 5m"),
    ],
)
def test_format_duration(value, text):
    assert format_duration(value) == text


def test_format_remaining():
    now = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
    assert format_remaining(None, now) == "permanent"
    assert format_remaining(now + timedelta(hours=2), now) == "2h"
    assert format_remaining(now - timedelta(minutes=5), now) == "overdue 5m"
    assert format_remaining(now + timedelta(seconds=20), now) == "<1m"


def test_format_time_is_shown_in_madrid():
    summer = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
    winter = datetime(2026, 12, 1, 9, 0, tzinfo=UTC)
    assert format_time(summer) == "2026-10-13 11:00 CEST"
    assert format_time(winter) == "2026-12-01 10:00 CET"
    assert format_time(None) == "never"
