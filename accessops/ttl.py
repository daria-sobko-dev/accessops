"""Time-to-live values like 30m, 8h, 3d."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TTL_RE = re.compile(r"([1-9][0-9]{0,3})([mhd])")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

# Times are stored in UTC; people see them in their own timezone (the user is in Spain).
DISPLAY_TZ_NAME = "Madrid"
DISPLAY_TZ = ZoneInfo("Europe/Madrid")


def parse_ttl(text: str) -> timedelta:
    """Parse '30m', '8h' or '3d'. Raises ValueError with a readable message."""
    match = TTL_RE.fullmatch(text.strip()) if isinstance(text, str) else None
    if match is None:
        raise ValueError(
            f"invalid duration {text!r}: use a number and a unit m/h/d, e.g. 30m, 8h, 3d"
        )
    amount, unit = match.groups()
    return timedelta(**{_UNITS[unit]: int(amount)})


def format_duration(value: timedelta) -> str:
    """Human-readable duration: '1d 2h 5m', '45m', '0m'."""
    minutes = int(value.total_seconds() // 60)
    days, rest = divmod(minutes, 24 * 60)
    hours, mins = divmod(rest, 60)
    parts = [f"{days}d"] * bool(days) + [f"{hours}h"] * bool(hours) + [f"{mins}m"] * bool(mins)
    return " ".join(parts) or "0m"


def format_time(value: datetime | None) -> str:
    """'2026-10-13 11:00 CEST' (Europe/Madrid, CET in winter) or 'never'."""
    return value.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M %Z") if value else "never"


def format_remaining(expires_at: datetime | None, now: datetime) -> str:
    if expires_at is None:
        return "permanent"
    left = expires_at - now
    if left.total_seconds() <= 0:
        return f"overdue {format_duration(-left)}"
    if left < timedelta(minutes=1):
        return "<1m"
    return format_duration(left)
