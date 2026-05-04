"""True during configured quiet hours (separate from night risk bonus)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class QuietHoursConfig:
    enabled: bool = False
    start_hour: int = 23
    end_hour: int = 7
    timezone: str = "UTC"
    suppress_alerts: bool = True


def _in_window(hour: int, start_h: int, end_h: int) -> bool:
    a, b = start_h % 24, end_h % 24
    if a == b:
        return False
    if a > b:
        return hour >= a or hour < b
    return a <= hour < b


def is_quiet_hours(cfg: QuietHoursConfig) -> bool:
    if not cfg.enabled:
        return False
    tz_name = (cfg.timezone or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except (KeyError, OSError):
        tz = ZoneInfo("UTC")
    hour = datetime.now(tz).hour
    return _in_window(hour, cfg.start_hour, cfg.end_hour)
